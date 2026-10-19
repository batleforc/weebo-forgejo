//! One `kube::runtime::Controller` per CRD. Each controller resolves the
//! gateway and the `*Ref` fields (through the `ReferenceReader` port and
//! `application::use_cases::refs`), hands a plain input to its
//! `application::use_cases::reconcile_*`, and publishes the resulting
//! `Outcome` through [`status::publish`].

pub mod deploy_key;
pub mod instance;
pub mod local_instance;
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

use api::common::InstanceRef;
use application::ports::{
    BoundInstance, ClusterError, GatewayFactory, InstanceDirectory, PolicySource, ReferenceReader,
    SecretStoreFactory,
};
use application::use_cases::{Failure, Outcome, admission, instance_failure};
use domain::error::ReasonCode;
use kube::Client;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;
use weebo_kit_runtime::events;
use weebo_kit_runtime::scope::KindScope;
use weebo_kit_runtime::shared::SharedWatches;
use weebo_kit_runtime::{Health, WatchScope};

pub use api::FINALIZER;
use api::namespace_policy::NamespaceRule;

pub use api::KEY_OWNER_ANNOTATION;

/// Shared by every controller. Concrete adapters are built and injected
/// once in `operator::main` (or by a test) — no controller names
/// `ForgejoHttpGateway`/`K8sSecretStore` directly. `client` only serves
/// the CRs' own lifecycle (finalizers, status, annotations, events).
pub struct Ctx {
    pub client: Client,
    pub gateways: Arc<dyn GatewayFactory>,
    pub secrets: Arc<dyn SecretStoreFactory>,
    /// Which instance a CR lives on (the kit's `Instances`, on the watch
    /// scope).
    pub instances: Arc<dyn InstanceDirectory>,
    /// What the `*Ref` fields point at.
    pub refs: Arc<dyn ReferenceReader>,
    /// The `ForgejoNamespacePolicy` rules, re-checked before any Forgejo call.
    pub policies: Arc<dyn PolicySource<NamespaceRule>>,
    pub recorder: Recorder,
    pub shutdown: Shutdown,
    /// Liveness: controllers report their watch errors here.
    pub health: Arc<Health>,
    /// The binary's shared watches ([`spawn_watches`]): one per kind for
    /// every controller (`SharedWatches::default()`: each controller
    /// watches on its own). A controller watching a referenced kind goes
    /// through them too (`weebo_kit_runtime::shared::WatchesIn`).
    pub watches: SharedWatches,
    /// What the controllers watch (`WEEBO_WATCH_NAMESPACE`,
    /// `WEEBO_WATCH_LABEL_SELECTOR`, `WEEBO_WATCH_CLUSTER_KINDS`): every
    /// watch goes through it.
    pub scope: WatchScope,
}

/// `scope` without its label selector: its namespace only.
pub fn unselected(scope: &WatchScope) -> WatchScope {
    match scope.watched_namespace() {
        Some(ns) => WatchScope::namespace(ns),
        None => WatchScope::cluster(),
    }
}

/// One watch per kind for every controller (as its primary kind or as a
/// referenced one) and the claim and policy reads (their stores): without
/// it, `ForgejoNamespacePolicy` was listed and watched nine times,
/// `ForgejoUser` seven, `ForgejoRepository` five. Spawned before the lease
/// is campaigned for: a standby keeps them warm.
///
/// The CRs on `scope`; the policies without its label selector, and only
/// when it watches cluster-scoped kinds: the policy checks read every
/// policy, whichever release selects it, so a change to any of them
/// re-checks the CRs. Neither the instances (their own reflectors, without
/// the label selector) nor `ForgejoNamespacePolicy` as a primary kind
/// (its controller is on the watch scope) go through them.
pub fn spawn_watches(client: &Client, scope: &WatchScope, health: &Arc<Health>) -> SharedWatches {
    fn on<K>(
        watches: &mut SharedWatches,
        client: &Client,
        scope: &WatchScope,
        health: &Arc<Health>,
        name: &'static str,
    ) where
        K: kube::Resource<DynamicType = ()>
            + Clone
            + std::fmt::Debug
            + serde::de::DeserializeOwned
            + Send
            + Sync
            + 'static,
        K::Scope: KindScope,
    {
        watches.spawn(scope.api::<K>(client.clone()), scope, health, name);
    }
    let mut w = SharedWatches::default();
    let (c, s, h) = (client, scope, health);
    if scope.cluster_kinds() {
        let all = unselected(scope);
        on::<api::ForgejoNamespacePolicy>(&mut w, c, &all, h, "ForgejoNamespacePolicy watch");
    }
    on::<api::ForgejoUser>(&mut w, c, s, h, "ForgejoUser watch");
    on::<api::ForgejoOrganization>(&mut w, c, s, h, "ForgejoOrganization watch");
    on::<api::ForgejoTeam>(&mut w, c, s, h, "ForgejoTeam watch");
    on::<api::ForgejoRepository>(&mut w, c, s, h, "ForgejoRepository watch");
    on::<api::ForgejoUserKey>(&mut w, c, s, h, "ForgejoUserKey watch");
    on::<api::ForgejoWebhook>(&mut w, c, s, h, "ForgejoWebhook watch");
    on::<api::ForgejoDeployKey>(&mut w, c, s, h, "ForgejoDeployKey watch");
    on::<api::ForgejoOAuth2Application>(&mut w, c, s, h, "ForgejoOAuth2Application watch");
    on::<api::ForgejoAccessToken>(&mut w, c, s, h, "ForgejoAccessToken watch");
    w
}

/// The controller of `K`: on the binary's shared watch of its kind when
/// there is one, else on its own (the kit's `controller`) — through the
/// watch scope either way.
pub fn primary<K>(ctx: &Ctx, client: &Client) -> Controller<K>
where
    K: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + 'static,
    K::Scope: KindScope,
{
    ctx.watches
        .controller(ctx.scope.api::<K>(client.clone()), &ctx.scope)
}

/// The kinds with an `instanceRef`.
pub trait HasInstanceRef: kube::Resource<DynamicType = ()> + status::HasStatus {
    fn instance_ref(&self) -> Option<&InstanceRef>;
}

macro_rules! impl_has_instance_ref {
    ($($kind:ty),+) => {$(
        impl HasInstanceRef for $kind {
            fn instance_ref(&self) -> Option<&InstanceRef> {
                self.spec.instance_ref.as_ref()
            }
        }
    )+};
}
impl_has_instance_ref!(
    api::ForgejoUser,
    api::ForgejoOrganization,
    api::ForgejoTeam,
    api::ForgejoRepository,
    api::ForgejoWebhook,
    api::ForgejoDeployKey,
    api::ForgejoUserKey,
    api::ForgejoOAuth2Application,
    api::ForgejoAccessToken
);

/// The instance `obj` lives on: its `instanceRef` resolved (the kit's
/// rules), and never another one than its status recorded — the ids in
/// its status belong to the instance they were created on. (Not a CRD
/// immutability rule: such a rule couldn't read the CRs written when
/// `instanceRef` was a string, and would refuse their migration.)
pub async fn instance_of<K: HasInstanceRef>(ctx: &Ctx, obj: &K) -> Result<BoundInstance, Failure> {
    let recorded = obj.forgejo_status().and_then(|s| s.instance.as_ref());
    let resolved = ctx
        .instances
        .resolve(
            obj.meta().namespace.as_deref(),
            obj.instance_ref(),
            recorded,
        )
        .await
        .map_err(instance_failure)?;
    match recorded {
        Some(recorded) if *recorded != resolved => Err(Failure::new(
            ReasonCode::InstanceBindingChanged,
            format!(
                "spec.instanceRef now designates {resolved}, not the {recorded} this CR is bound \
                 to: a bound CR never moves; restore instanceRef, or delete the CR \
                 (deletionPolicy: Orphan keeps the Forgejo object) and create it again"
            ),
        )),
        _ => Ok(resolved),
    }
}

/// Where the user, organization and team refs of a CR of `namespace`,
/// bound to `instance`, are followed from: `gateway` checks `remoteName`s
/// (`None`: a finalizer cleanup, which takes them as they are).
pub fn referrer<'a>(
    ctx: &'a Ctx,
    namespace: &'a str,
    instance: &'a BoundInstance,
    gateway: Option<&'a dyn application::ports::ForgejoGateway>,
) -> application::use_cases::refs::Referrer<'a> {
    application::use_cases::refs::Referrer {
        reader: ctx.refs.as_ref(),
        namespace,
        instance,
        cross_namespace: ctx.scope.cross_namespace_refs(),
        gateway,
    }
}

/// The unique claim (D8): before creating or adopting the Forgejo object
/// `forgejo_name` of `kind` on `instance`'s server, no other CR — any
/// namespace, any instance of the same server — may own it already.
/// `me`: the CR's own `Kind/namespace/name`.
pub async fn claimed_elsewhere(
    ctx: &Ctx,
    kind: application::ports::RefKind,
    forgejo_name: &str,
    instance: &BoundInstance,
    me: &str,
) -> Result<Option<Failure>, Error> {
    let others: Vec<String> = ctx
        .refs
        .claimants(kind, forgejo_name, instance)
        .await?
        .into_iter()
        .filter(|id| id != me)
        .collect();
    Ok(others.first().map(|other| {
        Failure::new(
            ReasonCode::RemoteObjectClaimed,
            format!(
                "{} {forgejo_name:?} on this server is already owned by {other}: reference it \
                 with remoteName, or rename it",
                kind.as_str()
            ),
        )
    }))
}

/// The instance a finalizer cleans up on: the one recorded in the status,
/// not whatever the ref designates now — else the ref resolved.
pub async fn cleanup_instance<K: HasInstanceRef>(
    ctx: &Ctx,
    obj: &K,
) -> Result<BoundInstance, Failure> {
    match obj.forgejo_status().and_then(|s| s.instance.clone()) {
        Some(bound) => Ok(bound),
        None => instance_of(ctx, obj).await,
    }
}

/// The kit's controller skeleton: predicate-filtered watch, bounded
/// concurrency (`WEEBO_RECONCILE_CONCURRENCY`), result stream drained into
/// the liveness.
pub use weebo_kit_runtime::controller::{DEFAULT_CONCURRENCY, controller, drive};

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
    /// Anything the finalizer helper reports: the reconcile's own error
    /// (`ApplyFailed`/`CleanupFailed`) or adding/removing the finalizer.
    #[error("{0}")]
    Finalizer(Box<kube::runtime::finalizer::Error<Error>>),
    /// A finalizer cleanup that couldn't complete: the CR stays until it
    /// can (it is retried by `error_policy`).
    #[error(
        "cleanup failed: {}; it is retried — annotate with {}=\"true\" to release the CR without cleanup",
        .0.message,
        api::FORCE_ORPHAN_ANNOTATION
    )]
    Cleanup(application::use_cases::Failure),
}

/// The site-admin rule on what Forgejo says
/// (`admission::enforce_remote_admins`): `logins`, the users whose
/// credentials a `kind` CR mints, against the policies — for a CR whose
/// instance they govern only.
pub async fn remote_admins(
    ctx: &Ctx,
    instance: &BoundInstance,
    gateway: &dyn application::ports::ForgejoGateway,
    namespace: &str,
    kind: api::namespace_policy::NamespacedKind,
    logins: &[String],
) -> Result<Result<(), Failure>, Error> {
    if !instance.governed_by_policy() {
        return Ok(Ok(()));
    }
    let policies = ctx.policies.as_ref();
    let check = admission::enforce_remote_admins(policies, gateway, namespace, kind, logins);
    Ok(check.await?)
}

/// `false` only when Forgejo says `login` is a site admin the namespace
/// isn't allowed to hold `kind` credentials of — what was issued for it
/// is then revoked. An empty login (the operator's admin account, checked
/// on the CR), an error or an instance the policies don't govern: `true`,
/// nothing is revoked on a doubt.
pub async fn admin_allowed(
    ctx: &Ctx,
    instance: &BoundInstance,
    gateway: &dyn application::ports::ForgejoGateway,
    namespace: &str,
    kind: api::namespace_policy::NamespacedKind,
    login: &str,
) -> Result<bool, Error> {
    if login.is_empty() {
        return Ok(true);
    }
    let logins = [login.to_string()];
    let verdict = remote_admins(ctx, instance, gateway, namespace, kind, &logins).await?;
    Ok(!matches!(verdict, Err(f) if f.reason == domain::error::ReasonCode::NamespaceNotAllowed))
}

/// [`admin_allowed`] for what was issued to `stored_login` (as of
/// `stored_id`, `status.ownerId`): checked under the account's login now
/// (`owner_login_now`), since `get_user` ignores Forgejo's rename
/// redirects and the old login of a renamed account reads as no user — not
/// an admin. A deleted account (its objects went with it) or an error:
/// `true`, nothing is revoked on a doubt.
pub async fn owner_admin_allowed(
    ctx: &Ctx,
    instance: &BoundInstance,
    gateway: &dyn application::ports::ForgejoGateway,
    namespace: &str,
    kind: api::namespace_policy::NamespacedKind,
    stored_login: &str,
    stored_id: Option<i64>,
) -> Result<bool, Error> {
    match application::use_cases::owner_login_now(gateway, stored_login, stored_id).await {
        Ok(Some(login)) => admin_allowed(ctx, instance, gateway, namespace, kind, &login).await,
        Ok(None) | Err(_) => Ok(true),
    }
}

/// The gateway and secret store of a CR's instance, for kinds that emit
/// secrets.
pub async fn backends(
    ctx: &Ctx,
    instance: &BoundInstance,
) -> Result<
    (
        Arc<dyn application::ports::ForgejoGateway>,
        Arc<dyn application::ports::SecretStore>,
    ),
    application::use_cases::Failure,
> {
    let gateway = ctx
        .gateways
        .gateway_for(instance)
        .await
        .map_err(|e| Failure::new(e.reason(), e.to_string()))?;
    let secrets = ctx
        .secrets
        .store_for(instance)
        .await
        .map_err(|e| Failure::new(ReasonCode::SecretTargetFailed, e.to_string()))?;
    Ok((gateway, secrets))
}

/// The gateway for a finalizer cleanup. A resolution failure is handed to
/// the cleanup use-case rather than returned: it only matters if the
/// cleanup has to call Forgejo (`application::use_cases::CleanupGateway`).
pub async fn cleanup_gateway(
    ctx: &Ctx,
    instance: &Result<BoundInstance, Failure>,
) -> Result<Arc<dyn application::ports::ForgejoGateway>, Failure> {
    let instance = instance.as_ref().map_err(Clone::clone)?;
    ctx.gateways
        .gateway_for(instance)
        .await
        .map_err(|e| Failure::new(e.reason(), e.to_string()))
}

/// The secret store for a finalizer cleanup. Like [`cleanup_gateway`], a
/// resolution failure only surfaces if the cleanup has secrets to delete.
pub async fn cleanup_secrets(
    ctx: &Ctx,
    instance: &Result<BoundInstance, Failure>,
) -> Arc<dyn application::ports::SecretStore> {
    let instance = match instance {
        Ok(instance) => instance,
        Err(f) => {
            let e = application::ports::SecretStoreError(f.message.clone());
            return Arc::new(UnresolvedSecretStore(e));
        }
    };
    match ctx.secrets.store_for(instance).await {
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

impl Error {
    /// The reason code of the Event announcing this error, and whether it
    /// happened reconciling or cleaning up (the Event's `action`).
    pub fn reason(&self) -> (ReasonCode, &'static str) {
        use kube::runtime::finalizer::Error as Finalizer;
        match self {
            Error::Kube(_) | Error::Cluster(_) => {
                (ReasonCode::KubernetesApiError, events::RECONCILE)
            }
            Error::Cleanup(failure) => (failure.reason, events::CLEANUP),
            Error::Finalizer(err) => match err.as_ref() {
                Finalizer::ApplyFailed(inner) => inner.reason(),
                Finalizer::CleanupFailed(inner) => (inner.reason().0, events::CLEANUP),
                _ => (ReasonCode::KubernetesApiError, events::RECONCILE),
            },
        }
    }
}

/// Hard errors (kube API, finalizer, cleanup) retry on the short cadence,
/// each announced by a `Warning` Event on its CR (the kit folds repeats
/// into one series): a CR stuck in Terminating says why.
pub fn error_policy<K>(obj: Arc<K>, err: &Error, ctx: Arc<Ctx>) -> Action
where
    K: kube::Resource<DynamicType = ()>,
{
    let (reason, action) = err.reason();
    weebo_kit_runtime::controller::retry_after_error(
        &ctx.recorder,
        obj.object_ref(&()),
        reason,
        action,
        err,
    )
}

/// Failures only a spec, annotation or policy change can clear — each of
/// which triggers a reconcile on its own: no point retrying them often.
fn needs_a_change(reason: ReasonCode) -> bool {
    matches!(
        reason,
        ReasonCode::InvalidSpec
            | ReasonCode::InstanceNotAllowed
            | ReasonCode::InstanceBindingChanged
            | ReasonCode::DisruptiveUpdateRefused
            | ReasonCode::NamespaceNotAllowed
            | ReasonCode::CrossNamespaceReference
            | ReasonCode::ForgejoObjectAlreadyExists
            | ReasonCode::UnsupportedForgejoVersion
            | ReasonCode::InvalidVaultPathGrants
    )
}

/// 300 s steady-state drift check after a success (and after a failure
/// only a change can clear); 30 s after other failures, often a
/// dependency that isn't ready yet. Jittered, except for an explicit due
/// time (a token expiring).
pub fn requeue_after(outcome: &Outcome) -> Action {
    weebo_kit_runtime::controller::requeue_after(
        outcome.ready.is_ok() || needs_a_change(outcome.reason()),
        outcome.due_in,
    )
}

/// Whether the CR carries `forgejo.weebo.io/force-orphan: "true"`.
pub fn force_orphan(meta: &kube::api::ObjectMeta) -> bool {
    api::ANNOTATIONS.force_orphan(meta)
}

/// Runs a finalizer `cleanup` — unless the CR is force-orphaned — and
/// announces the release with a `Normal` Event. A failed cleanup reaches
/// `error_policy`, which warns on the CR.
pub async fn finalize<K>(
    obj: &K,
    ctx: &Ctx,
    cleanup: impl std::future::Future<Output = Result<Action, Error>>,
) -> Result<Action, Error>
where
    K: kube::Resource<DynamicType = ()>,
{
    weebo_kit_runtime::controller::finalize(
        obj,
        &ctx.recorder,
        &api::ANNOTATIONS,
        ReasonCode::Released,
        async { cleanup.await.map(|_| ()) },
    )
    .await
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
    api::ANNOTATIONS.rotate_nonce(meta)
}

/// Whether the CR carries `forgejo.weebo.io/allow-disruptive-update: "true"`.
pub fn allows_disruptive_update(meta: &kube::api::ObjectMeta) -> bool {
    api::ANNOTATIONS.allows_disruptive_update(meta)
}

/// Whether the importer is still seeding this CR's status (see
/// `api::IMPORT_PENDING_ANNOTATION`). A deletion is always processed.
pub fn import_pending(meta: &kube::api::ObjectMeta) -> bool {
    api::ANNOTATIONS.import_pending(meta)
}
