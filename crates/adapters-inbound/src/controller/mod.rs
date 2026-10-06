//! One `kube::runtime::Controller` per CRD. Each controller resolves the
//! gateway and the `*Ref` fields (Kubernetes-side work), hands a plain
//! input to its `application::use_cases::reconcile_*`, and publishes the
//! resulting `Outcome` through [`status::publish`].

pub mod deploy_key;
pub mod instance;
pub mod namespace_policy;
pub mod oauth2;
pub mod organization;
pub mod refs;
pub mod repository;
pub mod status;
pub mod team;
pub mod token;
pub mod user;
pub mod user_key;
pub mod webhook;

use std::sync::Arc;
use std::time::Duration;

use application::ports::{GatewayFactory, SecretStoreFactory};
use application::use_cases::Outcome;
use kube::Client;
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;

pub use api::FINALIZER;

/// Shared by every controller. Concrete adapters are built and injected
/// once in `operator::main` (or by a test) — no controller names
/// `ForgejoHttpGateway`/`K8sSecretStore` directly.
pub struct Ctx {
    pub client: Client,
    pub gateways: Arc<dyn GatewayFactory>,
    pub secrets: Arc<dyn SecretStoreFactory>,
    pub recorder: Recorder,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    #[error("finalizer error: {0}")]
    Finalizer(String),
    /// A finalizer cleanup that couldn't complete: the CR stays until it
    /// can (it is retried by `error_policy`).
    #[error("cleanup failed: {0}")]
    Cleanup(String),
}

/// The gateway and secret store of a CR's `instanceRef`, for kinds that
/// emit secrets.
pub async fn backends(
    ctx: &Ctx,
    instance_ref: Option<&str>,
) -> Result<
    (
        Arc<dyn application::ports::ForgejoGateway>,
        Arc<dyn application::ports::SecretStore>,
    ),
    application::use_cases::Failure,
> {
    use application::use_cases::Failure;
    use domain::error::ReasonCode;
    let gateway = ctx
        .gateways
        .gateway_for(instance_ref)
        .await
        .map_err(|e| Failure::new(e.reason(), e.to_string()))?;
    let secrets = ctx
        .secrets
        .store_for(instance_ref)
        .await
        .map_err(|e| Failure::new(ReasonCode::SecretTargetFailed, e.to_string()))?;
    Ok((gateway, secrets))
}

/// Hard errors (kube API, finalizer, cleanup) retry on the short cadence.
pub fn error_policy<K>(_obj: Arc<K>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(error = %err, "reconcile error, retrying in 30s");
    Action::requeue(Duration::from_secs(30))
}

/// 300 s steady-state drift check after a success; 30 s after a failure,
/// which is often a dependency that isn't ready yet.
pub fn requeue_after(outcome: &Outcome) -> Action {
    if outcome.ready.is_ok() {
        Action::requeue(Duration::from_secs(300))
    } else {
        Action::requeue(Duration::from_secs(30))
    }
}

/// Value of the `forgejo.weebo.io/rotate-secret` annotation.
pub fn rotate_nonce(meta: &kube::api::ObjectMeta) -> Option<String> {
    meta.annotations
        .as_ref()
        .and_then(|a| a.get(api::ROTATE_SECRET_ANNOTATION))
        .cloned()
}

/// Whether the CR carries `forgejo.weebo.io/allow-disruptive-update: "true"`.
pub fn allows_disruptive_update(meta: &kube::api::ObjectMeta) -> bool {
    meta.annotations
        .as_ref()
        .and_then(|a| a.get(api::ALLOW_DISRUPTIVE_UPDATE_ANNOTATION))
        .is_some_and(|v| v == "true")
}

/// Whether the importer is still seeding this CR's status (see
/// `api::IMPORT_PENDING_ANNOTATION`). A deletion is always processed.
pub fn import_pending(meta: &kube::api::ObjectMeta) -> bool {
    meta.deletion_timestamp.is_none()
        && meta
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key(api::IMPORT_PENDING_ANNOTATION))
}
