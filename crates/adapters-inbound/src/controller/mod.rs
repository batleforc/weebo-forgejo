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

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};

use application::ports::{GatewayFactory, SecretStoreFactory};
use application::use_cases::Outcome;
use kube::Client;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;

pub use api::FINALIZER;

pub use api::KEY_OWNER_ANNOTATION;

/// Shared by every controller. Concrete adapters are built and injected
/// once in `operator::main` (or by a test) — no controller names
/// `ForgejoHttpGateway`/`K8sSecretStore` directly.
pub struct Ctx {
    pub client: Client,
    pub gateways: Arc<dyn GatewayFactory>,
    pub secrets: Arc<dyn SecretStoreFactory>,
    pub recorder: Recorder,
    pub shutdown: Shutdown,
}

/// Resolves once the process is asked to stop: every controller then stops
/// taking new work, lets its in-flight reconciles finish, and its `run`
/// returns (`Controller::graceful_shutdown_on`).
#[derive(Clone)]
pub struct Shutdown(Shared<BoxFuture<'static, ()>>);

impl Shutdown {
    pub fn new(trigger: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(trigger.boxed().shared())
    }

    /// For tests and tools whose controllers run until dropped.
    pub fn never() -> Self {
        Self::new(futures::future::pending())
    }

    pub fn wait(&self) -> impl Future<Output = ()> + Send + Sync + 'static {
        self.0.clone()
    }
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

/// The gateway for a finalizer cleanup. A resolution failure is handed to
/// the cleanup use-case rather than returned: it only matters if the
/// cleanup has to call Forgejo (`application::use_cases::CleanupGateway`).
pub async fn cleanup_gateway(
    ctx: &Ctx,
    instance_ref: Option<&str>,
) -> Result<Arc<dyn application::ports::ForgejoGateway>, application::use_cases::Failure> {
    ctx.gateways
        .gateway_for(instance_ref)
        .await
        .map_err(|e| application::use_cases::Failure::new(e.reason(), e.to_string()))
}

/// The secret store for a finalizer cleanup. Like [`cleanup_gateway`], a
/// resolution failure only surfaces if the cleanup has secrets to delete.
pub async fn cleanup_secrets(
    ctx: &Ctx,
    instance_ref: Option<&str>,
) -> Arc<dyn application::ports::SecretStore> {
    match ctx.secrets.store_for(instance_ref).await {
        Ok(store) => store,
        Err(e) => Arc::new(UnresolvedSecretStore(e)),
    }
}

/// Fails every call with the error the store couldn't be resolved with.
struct UnresolvedSecretStore(application::ports::SecretStoreError);

#[async_trait::async_trait]
impl application::ports::SecretStore for UnresolvedSecretStore {
    fn default_backend(&self) -> api::instance::SecretStoreBackend {
        api::instance::SecretStoreBackend::default()
    }
    async fn write(
        &self,
        _: &api::common::SecretTarget,
        _: Option<&str>,
        _: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), application::ports::SecretStoreError> {
        Err(self.0.clone())
    }
    async fn exists(
        &self,
        _: &api::common::SecretTarget,
        _: Option<&str>,
    ) -> Result<bool, application::ports::SecretStoreError> {
        Err(self.0.clone())
    }
    async fn delete(
        &self,
        _: &api::common::SecretTarget,
        _: Option<&str>,
    ) -> Result<(), application::ports::SecretStoreError> {
        Err(self.0.clone())
    }
}

/// Hard errors (kube API, finalizer, cleanup) retry on the short cadence.
pub fn error_policy<K>(_obj: Arc<K>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(error = %err, "reconcile error, retrying in 30s");
    Action::requeue(Duration::from_secs(30))
}

/// 300 s steady-state drift check after a success; 30 s after a failure,
/// which is often a dependency that isn't ready yet.
pub fn requeue_after(outcome: &Outcome) -> Action {
    let base = if outcome.ready.is_ok() { 300 } else { 30 };
    let secs = outcome.due_in.map_or(base, |due| due.min(base));
    Action::requeue(Duration::from_secs(secs))
}

/// Records in [`KEY_OWNER_ANNOTATION`] that the key now lives on
/// `resolved`, once `outcome` shows it: a success, or a new key. A failure
/// that kept the `previous` key leaves the record as it was — which is
/// where the next reconcile or the cleanup must look for it — even when
/// there is none yet (an imported or older key): nothing confirmed the key
/// is on `resolved`, it may still be on the ref's previous target, and
/// the cleanup already falls back to the parent's current name. Called
/// after the status is published, so a key just created is never lost to
/// a failed annotation patch.
pub async fn record_key_owner<K>(
    api: &Api<K>,
    obj: &K,
    resolved: Option<&str>,
    previous: Option<&application::ports::ForgejoRef>,
    outcome: &Outcome,
) -> Result<(), kube::Error>
where
    K: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    let Some(owner) = resolved else {
        return Ok(());
    };
    let recorded = key_owner(obj.meta());
    let on_owner = outcome
        .forgejo
        .as_ref()
        .is_some_and(|r| outcome.ready.is_ok() || Some(r) != previous);
    if !on_owner || recorded == Some(owner) {
        return Ok(());
    }
    let patch = serde_json::json!({
        "metadata": { "annotations": { KEY_OWNER_ANNOTATION: owner } }
    });
    api.patch(
        &kube::ResourceExt::name_any(obj),
        &PatchParams::apply(status::FIELD_MANAGER),
        &Patch::Merge(patch),
    )
    .await?;
    Ok(())
}

/// Where a key being deleted may live, most likely first: the owner
/// recorded when it was created, then the parent CR's current name (which
/// differs after a rename the annotation hasn't caught up with). Warns
/// when there's no record at all of a Forgejo key that should be deleted.
pub fn key_cleanup_owners<K>(key: &K, parent: Option<String>, delete: bool) -> Vec<String>
where
    K: kube::Resource<DynamicType = ()> + status::HasStatus,
{
    let mut owners: Vec<String> = key_owner(key.meta())
        .map(str::to_string)
        .into_iter()
        .collect();
    if let Some(parent) = parent
        && !owners.contains(&parent)
    {
        owners.push(parent);
    }
    if owners.is_empty() && delete && status::current_ref(key).is_some() {
        tracing::warn!(
            kind = %K::kind(&()),
            key = %kube::ResourceExt::name_any(key),
            "no record of the key's owner, the Forgejo key can't be deleted"
        );
    }
    owners
}

pub fn key_owner(meta: &kube::api::ObjectMeta) -> Option<&str> {
    meta.annotations
        .as_ref()
        .and_then(|a| a.get(KEY_OWNER_ANNOTATION))
        .map(String::as_str)
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
