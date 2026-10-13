use std::sync::Arc;
use std::time::Instant;

use api::namespace_policy::NamespacedKind;
use api::{ForgejoAccessToken, ForgejoRepository, ForgejoUser};
use application::ports::{BoundInstance, ForgejoGateway, ForgejoRef, RefKind};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_token::{
    TokenInput, cleanup_token, reconcile_token, revoke_denied, token_name,
};
use application::use_cases::refs::{resolve_identity_required, resolve_required};
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

const KIND: &str = "ForgejoAccessToken";
const KIND_POLICY: NamespacedKind = NamespacedKind::ForgejoAccessToken;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(
        ctx.scope.api::<ForgejoAccessToken>(client.clone()),
        &ctx.scope,
    );
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    let by_user = controller.store();
    let by_repo = controller.store();
    let results = controller
        .watches_in::<ForgejoUser, _>(&ctx, &client, move |user| {
            let (name, ns) = (user.name_any(), user.namespace());
            by_user
                .state()
                .into_iter()
                .filter(|t| {
                    let token_ns = t.namespace();
                    t.spec
                        .user_ref
                        .points_at(token_ns.as_deref(), ns.as_deref(), &name)
                })
                .map(|t| ObjectRef::from_obj(t.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoRepository, _>(&ctx, &client, move |repo| {
            let (name, ns) = (repo.name_any(), repo.namespace());
            by_repo
                .state()
                .into_iter()
                .filter(|t| {
                    t.namespace() == ns && t.spec.repository_refs.iter().any(|r| r.name == name)
                })
                .map(|t| ObjectRef::from_obj(t.as_ref()))
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

async fn reconcile(obj: Arc<ForgejoAccessToken>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoAccessToken> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(token) => apply(&api, &token, &ctx).await,
            FinalizerEvent::Cleanup(token) => {
                super::finalize(token.as_ref(), &ctx, cleanup(&token, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

/// `(user, repository full names)`.
async fn resolve_inputs(
    token: &ForgejoAccessToken,
    instance: &BoundInstance,
    gateway: &dyn ForgejoGateway,
    ctx: &Ctx,
) -> Result<Result<(ForgejoRef, Vec<String>), Failure>, Error> {
    let refs = ctx.refs.as_ref();
    let ns = token.namespace().unwrap_or_default();
    let from = super::referrer(ctx, &ns, instance, Some(gateway));
    let user = match resolve_identity_required(&from, RefKind::User, &token.spec.user_ref).await? {
        Ok(u) => u,
        Err(f) => return Ok(Err(f)),
    };
    let mut repositories = Vec::with_capacity(token.spec.repository_refs.len());
    for r in &token.spec.repository_refs {
        match resolve_required(refs, RefKind::Repository, &ns, &r.name, instance).await? {
            Ok(repo) => repositories.push(repo.name),
            Err(f) => return Ok(Err(f)),
        }
    }
    Ok(Ok((user, repositories)))
}

async fn apply(
    api: &Api<ForgejoAccessToken>,
    token: &ForgejoAccessToken,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&token.name_any()).await?;
    let started = Instant::now();

    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(current_ref(&current), f),
        Ok(bound) => issue(&current, &bound, ctx).await?.on(bound),
    };

    record_reconcile("ForgejoAccessToken", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn issue(
    current: &ForgejoAccessToken,
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
    let stored_owner = owner_id(&current.status);
    if let Err(f) = admitted {
        // The token issued earlier may be a site admin's now (its user
        // made one since): refused, it is revoked, not just left to live.
        let revoke = match &owned {
            Some(c) => {
                let gw = gateway.as_ref();
                !super::admin_allowed(ctx, bound, gw, &ns, KIND_POLICY, &c.name).await?
            }
            None => false,
        };
        if revoke {
            return Ok(revoked(gateway.as_ref(), owned, stored_owner, f).await);
        }
        return Ok(Outcome::failed(owned, f));
    }
    let (user, repositories) = match resolve_inputs(current, bound, gateway.as_ref(), ctx).await? {
        Ok(resolved) => resolved,
        Err(f) => return Ok(Outcome::failed(owned, f)),
    };
    // What the CRs say isn't all: the account may be a site admin in
    // Forgejo whatever its CR declares.
    let logins = [user.name.clone()];
    match super::remote_admins(ctx, bound, gateway.as_ref(), &ns, KIND_POLICY, &logins).await? {
        Ok(()) => {}
        Err(f) if f.reason == ReasonCode::NamespaceNotAllowed => {
            return Ok(revoked(gateway.as_ref(), owned, stored_owner, f).await);
        }
        Err(f) => return Ok(Outcome::failed(owned, f)),
    }
    // The unique claim (D8): token names are unique per user, so another
    // CR issuing the same name for the same account would revoke this
    // one's at each rotation — refused before the first issue.
    if owned.is_none() {
        let token = token_name(&current.spec, &ns, &name);
        let me = format!("{KIND}/{ns}/{name}");
        let claimants = ctx.refs.token_claimants(&user.name, &token, bound).await?;
        if let Some(other) = claimants.iter().find(|c| **c != me) {
            let f = Failure::new(
                ReasonCode::RemoteObjectClaimed,
                format!(
                    "token {token:?} of user {:?} on this server is already issued by {other}: \
                     set another spec.name",
                    user.name
                ),
            );
            return Ok(Outcome::failed(owned, f));
        }
    }
    let input = TokenInput {
        spec: &current.spec,
        cr_name: &name,
        namespace: &ns,
        user: user.name,
        user_id: Some(user.id),
        repositories,
        current: owned,
        owner_id: stored_owner,
        secret_pending: secret_pending(&current.status),
        rotate_nonce: rotate_nonce(&current.metadata),
        last_rotation: current
            .status
            .as_ref()
            .and_then(|s| s.last_rotation.clone()),
        allow_disruptive_update: allows_disruptive_update(&current.metadata),
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default(),
    };
    Ok(reconcile_token(input, gateway.as_ref(), secrets.as_ref()).await)
}

/// The token is revoked; its status forgets it once it's gone.
async fn revoked(
    gateway: &dyn ForgejoGateway,
    owned: Option<ForgejoRef>,
    owner_id: Option<i64>,
    failure: Failure,
) -> Outcome {
    let had = owned.is_some();
    match revoke_denied(gateway, owned, owner_id).await {
        Some(kept) => Outcome::failed(Some(kept), failure),
        None if had => Outcome::failed(None, failure).released(),
        None => Outcome::failed(None, failure),
    }
}

async fn cleanup(token: &ForgejoAccessToken, ctx: &Ctx) -> Result<Action, Error> {
    let instance = super::cleanup_instance(ctx, token).await;
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    let secrets = super::cleanup_secrets(ctx, &instance).await;
    cleanup_token(
        &token.spec,
        &token.name_any(),
        &token.namespace().unwrap_or_default(),
        current_ref(token).as_ref(),
        owner_id(&token.status),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
