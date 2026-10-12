use std::sync::Arc;
use std::time::Instant;

use api::common::ManagementPolicy;
use api::{ForgejoNamespacePolicy, ForgejoUser};
use application::ports::{BoundInstance, RefKind};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_user::{UserInput, cleanup_user, reconcile_user};
use application::use_cases::{Failure, Outcome};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};

use super::status::{current_ref, secret_pending, spec_changed};
use super::{Ctx, Error, FINALIZER, ScopedWatches, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoUser";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(ctx.scope.api::<ForgejoUser>(client.clone()), &ctx.scope);
    // A policy change may allow or forbid any CR of this kind.
    let by_policy = controller.store();
    let results = controller
        .watches_in::<ForgejoNamespacePolicy, _>(&ctx, &client, move |_| {
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

async fn reconcile(obj: Arc<ForgejoUser>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoUser> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(user) => apply(&api, &user, &ctx).await,
            FinalizerEvent::Cleanup(user) => {
                super::finalize(user.as_ref(), &ctx, cleanup(&user, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply(api: &Api<ForgejoUser>, user: &ForgejoUser, ctx: &Ctx) -> Result<Action, Error> {
    // Re-read from the API server, not the watch cache: the status patch of
    // the previous reconcile (carrying a fresh forgejoId) may not have
    // reached the cache yet, and acting on a stale `None` would attempt a
    // second create.
    let current = api.get(&user.name_any()).await?;
    let started = Instant::now();

    let (name, namespace) = (current.name_any(), current.namespace().unwrap_or_default());
    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(current_ref(&current), f),
        Ok(bound) => match checked(&current, &namespace, &bound, ctx).await? {
            Err(f) => Outcome::failed(current_ref(&current), f),
            Ok(()) => match super::backends(ctx, &bound).await {
                Ok((gateway, secrets)) => {
                    let input = UserInput {
                        spec: &current.spec,
                        namespace: &namespace,
                        cr_name: &name,
                        previous_owner: api::ANNOTATIONS.previous_owner(&current.metadata),
                        current: current_ref(&current),
                        spec_changed: spec_changed(&current),
                        secret_pending: secret_pending(&current.status),
                    };
                    reconcile_user(input, gateway.as_ref(), secrets.as_ref()).await
                }
                Err(f) => Outcome::failed(current_ref(&current), f),
            },
        }
        .on(bound),
    };

    record_reconcile("ForgejoUser", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

/// The namespace policy and — before a managed account is created — its
/// unique claim (an observed one owns nothing).
async fn checked(
    user: &ForgejoUser,
    namespace: &str,
    bound: &BoundInstance,
    ctx: &Ctx,
) -> Result<Result<(), Failure>, Error> {
    let (policies, refs) = (ctx.policies.as_ref(), ctx.refs.as_ref());
    if let Err(f) = enforce_on(policies, refs, namespace, user, Some(bound)).await? {
        return Ok(Err(f));
    }
    let manages = user.spec.management_policy == ManagementPolicy::Manage;
    if manages && current_ref(user).is_none() {
        let me = format!("{KIND}/{namespace}/{}", user.name_any());
        let claimed = super::claimed_elsewhere(ctx, RefKind::User, &user.spec.username, bound, &me);
        if let Some(f) = claimed.await? {
            return Ok(Err(f));
        }
    }
    Ok(Ok(()))
}

async fn cleanup(user: &ForgejoUser, ctx: &Ctx) -> Result<Action, Error> {
    let instance = super::cleanup_instance(ctx, user).await;
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    let secrets = super::cleanup_secrets(ctx, &instance).await;
    cleanup_user(
        &user.spec,
        &user.namespace().unwrap_or_default(),
        &user.name_any(),
        api::ANNOTATIONS.previous_owner(&user.metadata),
        current_ref(user).as_ref(),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
