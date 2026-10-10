//! `ForgejoInstance`: reconciling is a connectivity / token / version check
//! (`reconcile_instance`). Its finalizer holds the deletion while CRs are
//! still bound to it — their own finalizers need it to clean up, and would
//! otherwise stay stuck in Terminating.

use std::sync::Arc;
use std::time::Instant;

use api::ForgejoInstance;
use application::use_cases::reconcile_instance::reconcile_instance;
use application::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, ResourceExt};

use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoInstance";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = super::controller(Api::<ForgejoInstance>::all(client))
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<ForgejoInstance>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<ForgejoInstance> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(instance) => apply(&api, instance, &ctx).await,
            FinalizerEvent::Cleanup(instance) => {
                super::finalize(instance.as_ref(), &ctx, cleanup(&api, &instance, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

/// Released once no CR is bound to the instance any more.
async fn cleanup(
    api: &Api<ForgejoInstance>,
    instance: &ForgejoInstance,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let name = instance.name_any();
    // Bound by default too when it is the only instance.
    let default = api.list(&Default::default()).await?.items.len() == 1;
    let dependents = ctx.refs.instance_dependents(&name, default).await?;
    if dependents.is_empty() {
        return Ok(Action::await_change());
    }
    let shown: Vec<_> = dependents.iter().take(5).cloned().collect();
    Err(Error::Cleanup(Failure::new(
        ReasonCode::InstanceInUse,
        format!(
            "{} CR(s) still use ForgejoInstance {name:?} (e.g. {}): delete them first",
            dependents.len(),
            shown.join(", ")
        ),
    )))
}

async fn apply(
    api: &Api<ForgejoInstance>,
    obj: Arc<ForgejoInstance>,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let name = obj.name_any();
    let started = Instant::now();

    let outcome = match ctx.gateways.gateway_for(Some(&name)).await {
        Ok(gateway) => reconcile_instance(gateway.as_ref()).await,
        Err(e) => Outcome::failed(
            None,
            application::use_cases::Failure::new(e.reason(), e.to_string()),
        ),
    };

    record_reconcile("ForgejoInstance", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, obj.as_ref(), &outcome).await?;
    Ok(requeue_after(&outcome))
}
