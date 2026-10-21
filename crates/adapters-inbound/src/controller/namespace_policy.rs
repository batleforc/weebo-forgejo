//! `ForgejoNamespacePolicy`: purely Kubernetes-side (no finalizer, no
//! Forgejo object). Reconciling only validates the rules; enforcement
//! lives in the webhook and the namespaced reconcilers.

use std::sync::Arc;
use std::time::Instant;

use api::ForgejoNamespacePolicy;
use application::use_cases::reconcile_namespace_policy::reconcile_namespace_policy;
use kube::Client;
use kube::api::Api;
use kube::runtime::controller::Action;

use super::{Ctx, Error, error_policy, requeue_after, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoNamespacePolicy";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = super::primary::<ForgejoNamespacePolicy>(&ctx, &client)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<ForgejoNamespacePolicy>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<ForgejoNamespacePolicy> = Api::all(ctx.client.clone());
    let started = Instant::now();
    let outcome = reconcile_namespace_policy(&obj.spec);
    record_reconcile("ForgejoNamespacePolicy", &outcome, started.elapsed());
    status::publish(&api, &ctx.recorder, obj.as_ref(), &outcome).await?;
    Ok(requeue_after(obj.as_ref(), &outcome))
}
