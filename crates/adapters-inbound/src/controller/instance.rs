//! `ForgejoInstance`: reconciling is a connectivity / token / version check
//! (`reconcile_instance`). Its finalizer holds the deletion while CRs are
//! still bound to it — their own finalizers need it to clean up, and would
//! otherwise stay stuck in Terminating.

use std::sync::Arc;
use std::time::Instant;

use api::ForgejoInstance;
use application::ports::BoundInstance;
use application::use_cases::reconcile_instance::{check_path_grants, reconcile_instance};
use application::use_cases::{Failure, Outcome};
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::Store;
use kube::{Client, ResourceExt};

use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoInstance";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller =
        super::controller(ctx.scope.api::<ForgejoInstance>(client.clone()), &ctx.scope);
    let instances = controller.store();
    let results = controller.graceful_shutdown_on(ctx.shutdown.wait()).run(
        move |obj, ctx| reconcile(obj, ctx, instances.clone()),
        error_policy,
        ctx,
    );
    super::drive(KIND, health, results).await;
}

async fn reconcile(
    obj: Arc<ForgejoInstance>,
    ctx: Arc<Ctx>,
    instances: Store<ForgejoInstance>,
) -> Result<Action, Error> {
    let api: Api<ForgejoInstance> = Api::all(ctx.client.clone());
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

/// Released once no CR is bound to the instance any more.
async fn cleanup(
    api: &Api<ForgejoInstance>,
    instances: &Store<ForgejoInstance>,
    instance: &ForgejoInstance,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let name = instance.name_any();
    // Bound by default too when it is the only instance (in scope, as the
    // resolution counts them): from the controller's store once it listed.
    let default = match instances.wait_until_ready().await {
        Ok(()) => instances.state().len() == 1,
        Err(_) => api.list(&Default::default()).await?.items.len() == 1,
    };
    let bound = BoundInstance::cluster(&name);
    let dependents = ctx.refs.instance_dependents(&bound, default).await?;
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

    // Invalid Vault grants fail every Vault target: reported before the
    // connectivity check.
    let outcome = match check_path_grants(obj.spec.secret_store.vault.as_ref()) {
        Some(failure) => Outcome::failed(None, failure),
        None => match ctx
            .gateways
            .gateway_for(&BoundInstance::cluster(name))
            .await
        {
            Ok(gateway) => reconcile_instance(gateway.as_ref(), true).await,
            Err(e) => Outcome::failed(
                None,
                application::use_cases::Failure::new(e.reason(), e.to_string()),
            ),
        },
    };

    record_reconcile("ForgejoInstance", &outcome, started.elapsed());
    status::publish(api, &ctx.recorder, obj.as_ref(), &outcome).await?;
    Ok(requeue_after(obj.as_ref(), &outcome))
}
