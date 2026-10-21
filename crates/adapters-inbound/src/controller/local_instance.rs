//! `ForgejoLocalInstance`: the same connectivity / token / version check as
//! a `ForgejoInstance`, with the token of its own namespace. Its finalizer
//! holds the deletion while CRs are still bound to it.

use std::sync::Arc;
use std::time::Instant;

use api::ForgejoLocalInstance;
use application::ports::BoundInstance;
use application::use_cases::reconcile_instance::reconcile_instance;
use application::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::Store;
use kube::{Client, ResourceExt};

use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoLocalInstance";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(
        ctx.scope.api::<ForgejoLocalInstance>(client.clone()),
        &ctx.scope,
    );
    let instances = controller.store();
    let results = controller.graceful_shutdown_on(ctx.shutdown.wait()).run(
        move |obj, ctx| reconcile(obj, ctx, instances.clone()),
        error_policy,
        ctx,
    );
    super::drive(KIND, health, results).await;
}

async fn reconcile(
    obj: Arc<ForgejoLocalInstance>,
    ctx: Arc<Ctx>,
    instances: Store<ForgejoLocalInstance>,
) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoLocalInstance> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(instance) => apply(&api, instance, &ctx).await,
            FinalizerEvent::Cleanup(instance) => {
                super::finalize(
                    instance.as_ref(),
                    &ctx,
                    cleanup(&api, &instances, &instance, &ctx),
                )
                .await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

fn bound(instance: &ForgejoLocalInstance) -> BoundInstance {
    BoundInstance::local(
        instance.namespace().unwrap_or_default(),
        instance.name_any(),
    )
}

/// Released once no CR is bound to the instance any more.
async fn cleanup(
    api: &Api<ForgejoLocalInstance>,
    instances: &Store<ForgejoLocalInstance>,
    instance: &ForgejoLocalInstance,
    ctx: &Ctx,
) -> Result<Action, Error> {
    // Bound by default too when it is the only one of its namespace (in
    // scope, as the resolution counts them): from the controller's store
    // once it listed.
    let default = match instances.wait_until_ready().await {
        Ok(()) => {
            let ns = instance.namespace();
            let mut same_ns = instances
                .state()
                .into_iter()
                .filter(|l| l.namespace() == ns);
            same_ns.next().is_some() && same_ns.next().is_none()
        }
        Err(_) => api.list(&Default::default()).await?.items.len() == 1,
    };
    let bound = bound(instance);
    let dependents = ctx.refs.instance_dependents(&bound, default).await?;
    if dependents.is_empty() {
        return Ok(Action::await_change());
    }
    let shown: Vec<_> = dependents.iter().take(5).cloned().collect();
    Err(Error::Cleanup(Failure::new(
        ReasonCode::InstanceInUse,
        format!(
            "{} CR(s) still use {bound} (e.g. {}): delete them first",
            dependents.len(),
            shown.join(", ")
        ),
    )))
}

async fn apply(
    api: &Api<ForgejoLocalInstance>,
    obj: Arc<ForgejoLocalInstance>,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let started = Instant::now();
    let outcome = match ctx.gateways.gateway_for(&bound(&obj)).await {
        Ok(gateway) => reconcile_instance(gateway.as_ref(), false).await,
        Err(e) => Outcome::failed(None, Failure::new(e.reason(), e.to_string())),
    };

    record_reconcile(KIND, &outcome, started.elapsed());
    status::publish(api, &ctx.recorder, obj.as_ref(), &outcome).await?;
    Ok(requeue_after(obj.as_ref(), &outcome))
}
