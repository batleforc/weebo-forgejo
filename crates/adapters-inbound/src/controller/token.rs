use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoAccessToken, ForgejoRepository, ForgejoUser};
use application::ports::{ForgejoRef, RefKind};
use application::use_cases::admission::enforce;
use application::use_cases::reconcile_token::{TokenInput, cleanup_token, reconcile_token};
use application::use_cases::refs::resolve_required;
use application::use_cases::{Failure, Outcome};
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, watcher};
use kube::{Client, ResourceExt};

use super::status::{current_ref, owner_id, secret_pending};
use super::{
    Ctx, Error, FINALIZER, allows_disruptive_update, error_policy, requeue_after, rotate_nonce,
    status,
};
use crate::metrics::record_reconcile;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let client_for_policies = client.clone();
    let controller = Controller::new(
        Api::<ForgejoAccessToken>::all(client.clone()),
        watcher::Config::default(),
    );
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    let by_user = controller.store();
    let by_repo = controller.store();
    controller
        .watches(
            Api::<ForgejoUser>::all(client.clone()),
            watcher::Config::default(),
            move |user| {
                let name = user.name_any();
                by_user
                    .state()
                    .into_iter()
                    .filter(|t| t.spec.user_ref.name == name)
                    .map(|t| ObjectRef::from_obj(t.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<ForgejoRepository>::all(client),
            watcher::Config::default(),
            move |repo| {
                let (name, ns) = (repo.name_any(), repo.namespace());
                by_repo
                    .state()
                    .into_iter()
                    .filter(|t| {
                        t.namespace() == ns && t.spec.repository_refs.iter().any(|r| r.name == name)
                    })
                    .map(|t| ObjectRef::from_obj(t.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .watches(
            Api::<api::ForgejoNamespacePolicy>::all(client_for_policies),
            watcher::Config::default(),
            move |_| {
                by_policy
                    .state()
                    .into_iter()
                    .map(|o| ObjectRef::from_obj(o.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(err) = res {
                tracing::debug!(error = %err, "ForgejoAccessToken reconcile failed");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<ForgejoAccessToken>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoAccessToken> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(token) => apply(&api, &token, &ctx).await,
            FinalizerEvent::Cleanup(token) => cleanup(&token, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

/// `(user, repository full names)`.
async fn resolve_inputs(
    token: &ForgejoAccessToken,
    ctx: &Ctx,
) -> Result<Result<(ForgejoRef, Vec<String>), Failure>, Error> {
    let instance = token.spec.instance_ref.as_deref();
    let refs = ctx.refs.as_ref();
    let ns = token.namespace().unwrap_or_default();
    let user_name = &token.spec.user_ref.name;
    let user = match resolve_required(refs, RefKind::User, &ns, user_name, instance).await? {
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
    let owned = current_ref(&current);
    let (name, ns) = (current.name_any(), current.namespace().unwrap_or_default());

    let namespace = current.namespace().unwrap_or_default();
    let outcome = match enforce(ctx.policies.as_ref(), &namespace, &current).await? {
        // Re-checked here too: a policy may have changed since admission.
        Err(f) => Outcome::failed(current_ref(&current), f),
        Ok(()) => match resolve_inputs(&current, ctx).await? {
            Err(f) => Outcome::failed(owned, f),
            Ok((user, repositories)) => {
                match super::backends(ctx, current.spec.instance_ref.as_deref()).await {
                    Ok((gateway, secrets)) => {
                        let input = TokenInput {
                            spec: &current.spec,
                            cr_name: &name,
                            namespace: &ns,
                            user: user.name,
                            user_id: Some(user.id),
                            repositories,
                            current: owned,
                            owner_id: owner_id(&current.status),
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
                        reconcile_token(input, gateway.as_ref(), secrets.as_ref()).await
                    }
                    Err(f) => Outcome::failed(owned, f),
                }
            }
        },
    };

    record_reconcile("ForgejoAccessToken", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn cleanup(token: &ForgejoAccessToken, ctx: &Ctx) -> Result<Action, Error> {
    let instance = token.spec.instance_ref.as_deref();
    let gateway = super::cleanup_gateway(ctx, instance).await;
    let secrets = super::cleanup_secrets(ctx, instance).await;
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
    .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
