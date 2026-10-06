//! `ForgejoInstance`: no Forgejo-side object, so no finalizer — reconciling
//! is a connectivity / token / version check (`reconcile_instance`).

use std::sync::Arc;
use std::time::Instant;

use api::ForgejoInstance;
use application::use_cases::Outcome;
use application::use_cases::reconcile_instance::reconcile_instance;
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::{Controller, watcher};
use kube::{Client, ResourceExt};

use super::{Ctx, Error, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    Controller::new(
        Api::<ForgejoInstance>::all(client),
        watcher::Config::default(),
    )
    .run(reconcile, error_policy, ctx)
    .for_each(|res| async move {
        if let Err(err) = res {
            tracing::debug!(error = %err, "ForgejoInstance reconcile failed");
        }
    })
    .await;
}

async fn reconcile(obj: Arc<ForgejoInstance>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<ForgejoInstance> = Api::all(ctx.client.clone());
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
    status::publish(&api, &ctx.recorder, obj.as_ref(), &outcome).await?;
    Ok(requeue_after(&outcome))
}
