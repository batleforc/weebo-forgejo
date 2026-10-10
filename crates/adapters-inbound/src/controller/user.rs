use std::sync::Arc;
use std::time::Instant;

use api::ForgejoUser;
use application::use_cases::Outcome;
use application::use_cases::reconcile_user::{UserInput, cleanup_user, reconcile_user};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, ResourceExt};

use super::status::{current_ref, secret_pending, spec_changed};
use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoUser";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = super::controller(Api::<ForgejoUser>::all(client))
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<ForgejoUser>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let api: Api<ForgejoUser> = Api::all(ctx.client.clone());
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

    let outcome = match super::backends(ctx, current.spec.instance_ref.as_deref()).await {
        Ok((gateway, secrets)) => {
            let name = current.name_any();
            let input = UserInput {
                spec: &current.spec,
                cr_name: &name,
                current: current_ref(&current),
                spec_changed: spec_changed(&current),
                secret_pending: secret_pending(&current.status),
            };
            reconcile_user(input, gateway.as_ref(), secrets.as_ref()).await
        }
        Err(f) => Outcome::failed(current_ref(&current), f),
    };

    record_reconcile("ForgejoUser", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn cleanup(user: &ForgejoUser, ctx: &Ctx) -> Result<Action, Error> {
    let instance = user.spec.instance_ref.as_deref();
    let gateway = super::cleanup_gateway(ctx, instance).await;
    let secrets = super::cleanup_secrets(ctx, instance).await;
    cleanup_user(
        &user.spec,
        &user.name_any(),
        current_ref(user).as_ref(),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
