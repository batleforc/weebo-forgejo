//! One `kube::runtime::Controller` per CRD. Each controller resolves the
//! gateway and the `*Ref` fields (through the `ReferenceReader` port and
//! `application::use_cases::refs`), hands a plain input to its
//! `application::use_cases::reconcile_*`, and publishes the resulting
//! `Outcome` through [`status::publish`].

pub mod deploy_key;
pub mod instance;
pub mod namespace_policy;
pub mod oauth2;
pub mod organization;
pub mod repository;
pub mod status;
pub mod team;
pub mod token;
pub mod user;
pub mod user_key;
pub mod webhook;

use std::sync::Arc;
use std::time::Duration;

use application::ports::{
    ClusterError, GatewayFactory, PolicySource, ReferenceReader, SecretStoreFactory,
};
use application::use_cases::Outcome;
use domain::error::ReasonCode;
use futures::{Stream, StreamExt};
use kube::Client;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{self as runtime_controller, Action};
use kube::runtime::events::Recorder;
use kube::runtime::predicates;
use kube::runtime::reflector::{self, ObjectRef};
use kube::runtime::utils::Predicate;
use kube::runtime::{Controller, WatchStreamExt, watcher};
use rand::Rng;
use weebo_kit_runtime::Health;

pub use api::FINALIZER;

pub use api::KEY_OWNER_ANNOTATION;

/// Shared by every controller. Concrete adapters are built and injected
/// once in `operator::main` (or by a test) — no controller names
/// `ForgejoHttpGateway`/`K8sSecretStore` directly. `client` only serves
/// the CRs' own lifecycle (finalizers, status, annotations, events).
pub struct Ctx {
    pub client: Client,
    pub gateways: Arc<dyn GatewayFactory>,
    pub secrets: Arc<dyn SecretStoreFactory>,
    /// What the `*Ref` fields point at.
    pub refs: Arc<dyn ReferenceReader>,
    /// The `ForgejoNamespacePolicy` rules, re-checked before any Forgejo call.
    pub policies: Arc<dyn PolicySource>,
    pub recorder: Recorder,
    pub shutdown: Shutdown,
    /// Liveness: controllers report their watch errors here.
    pub health: Arc<Health>,
}

/// Default of `WEEBO_RECONCILE_CONCURRENCY`: reconciles run at once per
/// controller. Bounded so a startup sweep or a policy change (which
/// re-checks every CR of 5 kinds) can't flood Forgejo and the apiserver.
pub const DEFAULT_CONCURRENCY: u16 = 4;

fn concurrency() -> u16 {
    std::env::var("WEEBO_RECONCILE_CONCURRENCY")
        .ok()
        .and_then(|c| c.parse().ok())
        .filter(|c| *c > 0)
        .unwrap_or(DEFAULT_CONCURRENCY)
}

/// Hash of `deletionTimestamp`: a deletion must always reach the finalizer.
fn deletion<K: kube::Resource>(obj: &K) -> Option<u64> {
    use std::hash::{DefaultHasher, Hash, Hasher};
    obj.meta().deletion_timestamp.as_ref().map(|t| {
        let mut h = DefaultHasher::new();
        t.0.to_string().hash(&mut h);
        h.finish()
    })
}

/// The controller of `api`'s kind. Its primary watch only fires on what
/// reconciling acts on — spec (`generation`), annotations, labels,
/// finalizers, deletion — never on the CR's own status patches, which
/// would otherwise re-trigger it (and, through the watches on referenced
/// kinds, its dependents) in a loop. Watch errors back off exponentially.
pub fn controller<K>(api: Api<K>) -> Controller<K>
where
    K: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + 'static,
{
    let (reader, writer) = reflector::store();
    let trigger = watcher(api, watcher::Config::default())
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        .predicate_filter(
            predicates::generation
                .combine(predicates::annotations)
                .combine(predicates::labels)
                .combine(predicates::finalizers)
                .combine(deletion),
            Default::default(),
        );
    Controller::for_stream(trigger, reader)
        .with_config(runtime_controller::Config::default().concurrency(concurrency()))
}

/// Drains a controller's result stream until shutdown, reporting watch
/// failures to `health` (reconcile failures are the CRs' own business:
/// they show in their status).
pub async fn drive<K, E, S>(kind: &'static str, health: Arc<Health>, results: S)
where
    K: kube::Resource,
    E: std::error::Error + Send + Sync + 'static,
    S: Stream<Item = Result<(ObjectRef<K>, Action), runtime_controller::Error<E, watcher::Error>>>,
{
    results
        .for_each(|res| {
            match res {
                Ok(_) => health.ok(kind),
                Err(runtime_controller::Error::QueueError(err)) => {
                    tracing::warn!(kind, error = %err, "watch error");
                    health.failed(kind, err.to_string());
                }
                Err(err) => tracing::debug!(kind, error = %err, "reconcile failed"),
            }
            futures::future::ready(())
        })
        .await;
}

/// Resolves once the process is asked to stop: every controller then stops
/// taking new work, lets its in-flight reconciles finish, and its `run`
/// returns (`Controller::graceful_shutdown_on`).
pub use weebo_kit_runtime::Shutdown;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
    #[error(transparent)]
    Cluster(#[from] ClusterError),
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
        _: &application::ports::SecretOwner<'_>,
        _: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), application::ports::SecretStoreError> {
        Err(self.0.clone())
    }
    async fn exists(
        &self,
        _: &api::common::SecretTarget,
        _: &application::ports::SecretOwner<'_>,
    ) -> Result<bool, application::ports::SecretStoreError> {
        Err(self.0.clone())
    }
    async fn delete(
        &self,
        _: &api::common::SecretTarget,
        _: &application::ports::SecretOwner<'_>,
    ) -> Result<(), application::ports::SecretStoreError> {
        Err(self.0.clone())
    }
}

/// ±20%: CRs created or restarted together don't stay in lockstep.
fn jittered(secs: u64) -> Duration {
    let spread = secs / 5;
    let secs = if spread == 0 {
        secs
    } else {
        secs - spread + rand::rng().random_range(0..=2 * spread)
    };
    Duration::from_secs(secs.max(1))
}

/// Hard errors (kube API, finalizer, cleanup) retry on the short cadence.
pub fn error_policy<K>(_obj: Arc<K>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    let after = jittered(30);
    tracing::warn!(error = %err, retry_in = after.as_secs(), "reconcile error");
    Action::requeue(after)
}

/// Failures only a spec, annotation or policy change can clear — each of
/// which triggers a reconcile on its own: no point retrying them often.
fn needs_a_change(reason: ReasonCode) -> bool {
    matches!(
        reason,
        ReasonCode::InvalidSpec
            | ReasonCode::DisruptiveUpdateRefused
            | ReasonCode::NamespaceNotAllowed
            | ReasonCode::CrossNamespaceReference
            | ReasonCode::ForgejoObjectAlreadyExists
            | ReasonCode::UnsupportedForgejoVersion
    )
}

/// 300 s steady-state drift check after a success (and after a failure
/// only a change can clear); 30 s after other failures, often a
/// dependency that isn't ready yet. Jittered, except for an explicit due
/// time (a token expiring).
pub fn requeue_after(outcome: &Outcome) -> Action {
    let base = if outcome.ready.is_ok() || needs_a_change(outcome.reason()) {
        300
    } else {
        30
    };
    match outcome.due_in {
        Some(due) if due < base => Action::requeue(Duration::from_secs(due)),
        _ => Action::requeue(jittered(base)),
    }
}

/// Whether the CR carries `forgejo.weebo.io/force-orphan: "true"`.
pub fn force_orphan(meta: &kube::api::ObjectMeta) -> bool {
    meta.annotations
        .as_ref()
        .and_then(|a| a.get(api::FORCE_ORPHAN_ANNOTATION))
        .is_some_and(|v| v == "true")
}

/// Runs a finalizer `cleanup` — unless the CR is force-orphaned — and
/// reports a failed one as a Warning Event on the CR: a CR stuck in
/// Terminating says why.
pub async fn finalize<K>(
    obj: &K,
    ctx: &Ctx,
    cleanup: impl std::future::Future<Output = Result<Action, Error>>,
) -> Result<Action, Error>
where
    K: kube::Resource<DynamicType = ()>,
{
    if force_orphan(obj.meta()) {
        tracing::warn!(
            kind = %K::kind(&()),
            name = %kube::ResourceExt::name_any(obj),
            "force-orphaned: releasing the finalizer without cleanup"
        );
        return Ok(Action::await_change());
    }
    let result = cleanup.await;
    if let Err(err) = &result {
        let event = kube::runtime::events::Event {
            type_: kube::runtime::events::EventType::Warning,
            reason: "CleanupFailed".to_string(),
            note: Some(
                format!(
                    "{err}; it is retried — annotate with {}=\"true\" to release the CR \
                     without cleanup",
                    api::FORCE_ORPHAN_ANNOTATION
                )
                .chars()
                .take(1000)
                .collect(),
            ),
            action: "Delete".to_string(),
            secondary: None,
        };
        if let Err(e) = ctx.recorder.publish(&event, &obj.object_ref(&())).await {
            tracing::warn!(error = %e, "failed to publish event");
        }
    }
    result
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
