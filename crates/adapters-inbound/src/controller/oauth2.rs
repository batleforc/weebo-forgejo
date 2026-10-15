use std::sync::Arc;
use std::time::Instant;

use api::namespace_policy::NamespacedKind;
use api::{ForgejoOAuth2Application, ForgejoUser};
use application::ports::{BoundInstance, ForgejoGateway, ForgejoRef, RefKind};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_oauth2::{
    OAuth2Input, cleanup_oauth2, reconcile_oauth2, revoke_denied_oauth2,
};
use application::use_cases::refs::resolve_identity_required;
use application::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};

use super::status::{current_ref, owner_id, secret_pending};
use super::{
    Ctx, Error, FINALIZER, ScopedWatches, allows_disruptive_update, error_policy, requeue_after,
    rotate_nonce, status,
};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoOAuth2Application";
const KIND_POLICY: NamespacedKind = NamespacedKind::ForgejoOAuth2Application;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(
        ctx.scope.api::<ForgejoOAuth2Application>(client.clone()),
        &ctx.scope,
    );
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    let apps = controller.store();
    let results = controller
        .watches_in::<ForgejoUser, _>(&ctx, &client, move |user| {
            let (name, ns) = (user.name_any(), user.namespace());
            apps.state()
                .into_iter()
                .filter(|a| {
                    a.spec.owner_ref.as_ref().is_some_and(|o| {
                        o.points_at(a.namespace().as_deref(), ns.as_deref(), &name)
                    })
                })
                .map(|a| ObjectRef::from_obj(a.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<api::ForgejoNamespacePolicy, _>(&ctx, &client, move |_| {
            by_policy
                .state()
                .into_iter()
                .map(|o| ObjectRef::from_obj(o.as_ref()))
                .collect::<Vec<_>>()
        })
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<ForgejoOAuth2Application>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoOAuth2Application> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(app) => apply(&api, &app, &ctx).await,
            FinalizerEvent::Cleanup(app) => {
                super::finalize(app.as_ref(), &ctx, cleanup(&app, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

/// The owner, or `None` for the admin account.
async fn owner(
    app: &ForgejoOAuth2Application,
    instance: &BoundInstance,
    gateway: &dyn ForgejoGateway,
    ctx: &Ctx,
) -> Result<Result<Option<ForgejoRef>, Failure>, Error> {
    let Some(owner_ref) = &app.spec.owner_ref else {
        return Ok(Ok(None));
    };
    let ns = app.namespace().unwrap_or_default();
    let from = super::referrer(ctx, &ns, instance, Some(gateway));
    let user = resolve_identity_required(&from, RefKind::User, owner_ref);
    Ok(user.await?.map(Some))
}

async fn apply(
    api: &Api<ForgejoOAuth2Application>,
    app: &ForgejoOAuth2Application,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&app.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);

    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(owned, f),
        Ok(bound) => bound_outcome(&current, &bound, ctx).await?.on(bound),
    };

    record_reconcile(
        "ForgejoOAuth2Application",
        outcome.reason(),
        started.elapsed(),
    );
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

/// The outcome of an application bound to `bound`. Refused because its
/// owner (`ownerRef`) is a site admin the namespace may not hold
/// credentials of (it became one since, or a rule was removed), the
/// application issued earlier is deleted, not left to live. One without
/// `ownerRef` (the operator's admin account) is only refused, never
/// deleted: what was issued to the admin account stays where it is.
async fn bound_outcome(
    current: &ForgejoOAuth2Application,
    bound: &BoundInstance,
    ctx: &Ctx,
) -> Result<Outcome, Error> {
    let owned = current_ref(current);
    let (name, ns) = (current.name_any(), current.namespace().unwrap_or_default());
    // Re-checked here too: a policy may have changed since admission.
    let admitted = enforce_on(
        ctx.policies.as_ref(),
        ctx.refs.as_ref(),
        &ns,
        current,
        Some(bound),
    )
    .await?;
    let (gateway, secrets) = match super::backends(ctx, bound).await {
        Ok(b) => b,
        Err(f) => return Ok(Outcome::failed(owned, admitted.err().unwrap_or(f))),
    };
    let gw = gateway.as_ref();
    let stored_owner = owner_id(&current.status);
    if let Err(f) = admitted {
        return denied(ctx, bound, gw, &ns, owned, stored_owner, f).await;
    }
    let owner = match owner(current, bound, gw, ctx).await? {
        Ok(owner) => owner,
        Err(f) => return Ok(Outcome::failed(owned, f)),
    };
    // The owner may be a site admin in Forgejo whatever its CR declares
    // (no owner: the admin account, already checked).
    let logins: Vec<String> = owner.iter().map(|o| o.name.clone()).collect();
    if let Err(f) = super::remote_admins(ctx, bound, gw, &ns, KIND_POLICY, &logins).await? {
        // The application issued earlier is this admin's own (same
        // account, whatever its login now): deleted without asking again.
        let same_owner = owner.as_ref().is_some_and(|o| stored_owner == Some(o.id));
        if same_owner && f.reason == ReasonCode::NamespaceNotAllowed {
            return Ok(revoked(gw, owned, stored_owner, f).await);
        }
        return denied(ctx, bound, gw, &ns, owned, stored_owner, f).await;
    }
    let input = OAuth2Input {
        spec: &current.spec,
        cr_name: &name,
        namespace: &ns,
        owner_id: owner.as_ref().map(|o| o.id),
        owner: owner.map(|o| o.name),
        current: owned,
        current_owner_id: stored_owner,
        secret_pending: secret_pending(&current.status),
        rotate_nonce: rotate_nonce(&current.metadata),
        last_rotation: current
            .status
            .as_ref()
            .and_then(|s| s.last_rotation.clone()),
        allow_disruptive_update: allows_disruptive_update(&current.metadata),
    };
    Ok(reconcile_oauth2(input, gw, secrets.as_ref()).await)
}

/// Refused with `failure`: the application issued earlier is deleted when
/// Forgejo says its owner — the account of `status.ownerId`, under its
/// login now (`status.forgejoName` is stale after a rename) — is a site
/// admin the namespace isn't allowed; otherwise it is kept, not ready.
async fn denied(
    ctx: &Ctx,
    bound: &BoundInstance,
    gateway: &dyn ForgejoGateway,
    ns: &str,
    owned: Option<ForgejoRef>,
    owner_id: Option<i64>,
    failure: Failure,
) -> Result<Outcome, Error> {
    let revoke = match &owned {
        Some(c) => {
            let (kind, login) = (KIND_POLICY, c.name.as_str());
            !super::owner_admin_allowed(ctx, bound, gateway, ns, kind, login, owner_id).await?
        }
        None => false,
    };
    if !revoke {
        return Ok(Outcome::failed(owned, failure));
    }
    Ok(revoked(gateway, owned, owner_id, failure).await)
}

/// The application is deleted; its status forgets it once it's gone.
async fn revoked(
    gateway: &dyn ForgejoGateway,
    owned: Option<ForgejoRef>,
    owner_id: Option<i64>,
    failure: Failure,
) -> Outcome {
    let had = owned.is_some();
    match revoke_denied_oauth2(gateway, owned, owner_id).await {
        Some(kept) => Outcome::failed(Some(kept), failure),
        None if had => Outcome::failed(None, failure).released(),
        None => Outcome::failed(None, failure),
    }
}

async fn cleanup(app: &ForgejoOAuth2Application, ctx: &Ctx) -> Result<Action, Error> {
    let instance = super::cleanup_instance(ctx, app).await;
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    let secrets = super::cleanup_secrets(ctx, &instance).await;
    cleanup_oauth2(
        &app.spec,
        &app.name_any(),
        &app.namespace().unwrap_or_default(),
        current_ref(app).as_ref(),
        owner_id(&app.status),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
