//! [`KubeClusterReader`]: the [`ReferenceReader`] and [`PolicySource`]
//! ports over the Kubernetes API — the referenced CRs, `Secret` keys and
//! `ForgejoNamespacePolicy` objects the reconcilers and the admission
//! webhook decide on — on the operator's watch scope: an object outside
//! its label selector, or a namespaced one outside the namespace it is
//! limited to, doesn't exist for it.
//!
//! The policies, the instances and the claiming kinds are read from the
//! binary's live reflector stores when it wires them in
//! ([`KubeClusterReader::with_stores`]), from the API otherwise: a claim
//! check reads every CR of its kind and every instance, a policy check
//! every policy, on every reconcile — from the API, a sweep of N CRs is
//! N LISTs of each.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use api::common::{
    BoundInstance, IdentityRef, InstanceKind, InstanceRef, ManagementPolicy, SharedWith,
};
use api::namespace_policy::NamespaceRule;
use api::status::ForgejoStatus;
use api::{
    ForgejoInstance, ForgejoLocalInstance, ForgejoNamespacePolicy, ForgejoOrganization,
    ForgejoRepository, ForgejoTeam, ForgejoUser,
};
use application::ports::{
    ClusterError, ForgejoRef, PolicySource, RefKind, ReferenceReader, ReferencedCr, SecretKey,
};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::api::ListParams;
use kube::core::{Selector, SelectorExt};
use kube::runtime::reflector::{ObjectRef, Store};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;
use weebo_kit_adapters::instance::STORE_READY_TIMEOUT;
use weebo_kit_adapters::wait_synced;

/// The binary's live stores. The claiming kinds' are on the operator's
/// watch scope (its namespace and label selector, as the API reads); the
/// policies' and the instances' on its namespace only, without the label
/// selector — as the API reads them here: a policy or an instance another
/// release selects still counts.
#[derive(Clone, Default)]
pub struct ClusterStores {
    pub policies: Option<Store<ForgejoNamespacePolicy>>,
    pub instances: Option<Store<ForgejoInstance>>,
    pub local_instances: Option<Store<ForgejoLocalInstance>>,
    pub users: Option<Store<ForgejoUser>>,
    pub organizations: Option<Store<ForgejoOrganization>>,
    pub teams: Option<Store<ForgejoTeam>>,
    pub access_tokens: Option<Store<api::ForgejoAccessToken>>,
}

/// Picks a kind's store out of [`ClusterStores`] (none: always listed).
trait Stored: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + 'static {
    fn store(_stores: &ClusterStores) -> Option<&Store<Self>> {
        None
    }
}

macro_rules! stored {
    ($($kind:ty => $field:ident),+ $(,)?) => {$(
        impl Stored for $kind {
            fn store(stores: &ClusterStores) -> Option<&Store<Self>> {
                stores.$field.as_ref()
            }
        }
    )+};
}
stored!(
    ForgejoNamespacePolicy => policies,
    ForgejoInstance => instances,
    ForgejoLocalInstance => local_instances,
    ForgejoUser => users,
    ForgejoOrganization => organizations,
    ForgejoTeam => teams,
    api::ForgejoAccessToken => access_tokens,
);
impl Stored for ForgejoRepository {}
impl Stored for api::ForgejoUserKey {}
impl Stored for api::ForgejoWebhook {}
impl Stored for api::ForgejoDeployKey {}
impl Stored for api::ForgejoOAuth2Application {}

/// `store` once it has listed: `None` when there is none, its writer is
/// gone (shutdown) or it still hasn't listed after [`STORE_READY_TIMEOUT`]
/// — the caller then reads the API: a decision is never made on a store
/// that hasn't listed, and a watch that can't list doesn't hang every
/// reconcile.
async fn ready<K: Resource<DynamicType = ()> + Clone + 'static>(
    store: Option<&Store<K>>,
) -> Option<&Store<K>> {
    let store = store?;
    wait_synced(store, STORE_READY_TIMEOUT)
        .await
        .then_some(store)
}

pub struct KubeClusterReader {
    client: Client,
    /// The namespace the operator is limited to, `None`: the whole cluster.
    watched_namespace: Option<String>,
    selector: Option<Selector>,
    cluster_kinds: bool,
    stores: ClusterStores,
}

impl KubeClusterReader {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            watched_namespace: None,
            selector: None,
            cluster_kinds: true,
            stores: ClusterStores::default(),
        }
    }

    /// Reads the policies, the instances and the claiming kinds from these
    /// stores (once they listed) instead of the API.
    pub fn with_stores(mut self, stores: ClusterStores) -> Self {
        self.stores = stores;
        self
    }

    /// Every `K` of `api`: from its store once listed, else listed from
    /// the API. `selected`: through the label selector (the store's
    /// objects are filtered again, the API lists through it).
    async fn read<K: Stored>(
        &self,
        api: Api<K>,
        selected: bool,
    ) -> Result<Vec<Arc<K>>, ClusterError> {
        if let Some(store) = ready(K::store(&self.stores)).await {
            return Ok(store
                .state()
                .into_iter()
                .filter(|o| !selected || self.selects(o.as_ref()))
                .collect());
        }
        let params = if selected {
            self.params()
        } else {
            ListParams::default()
        };
        let list = api
            .list(&params)
            .await
            .map_err(|e| ClusterError(format!("listing {}: {e}", K::kind(&()))))?;
        Ok(list.items.into_iter().map(Arc::new).collect())
    }

    /// The operator's watch scope (`WatchScope`): the namespace it is
    /// limited to, its label selector, and whether it watches
    /// cluster-scoped kinds at all.
    pub fn with_scope(
        mut self,
        watched_namespace: Option<String>,
        selector: Option<Selector>,
        cluster_kinds: bool,
    ) -> Self {
        self.watched_namespace = watched_namespace;
        self.selector = selector;
        self.cluster_kinds = cluster_kinds;
        self
    }

    fn selects<K: Resource>(&self, obj: &K) -> bool {
        let Some(selector) = &self.selector else {
            return true;
        };
        let empty = Default::default();
        selector.matches(obj.meta().labels.as_ref().unwrap_or(&empty))
    }

    fn params(&self) -> ListParams {
        match &self.selector {
            Some(selector) => ListParams::default().labels_from(selector),
            None => ListParams::default(),
        }
    }
}

/// What [`read`] needs from each referenced kind.
struct View<'a> {
    status: Option<&'a ForgejoStatus>,
    spec_name: &'a str,
    shared_with: Option<&'a SharedWith>,
    admin: bool,
}

async fn read<K>(
    reader: &KubeClusterReader,
    api: Api<K>,
    name: &str,
    view: fn(&K) -> View<'_>,
) -> Result<Option<ReferencedCr>, ClusterError>
where
    K: kube::Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned,
{
    let Some(obj) = api
        .get_opt(name)
        .await
        .map_err(|e| ClusterError(format!("reading {} {name}: {e}", K::kind(&()))))?
        .filter(|o| reader.selects(o))
    else {
        return Ok(None);
    };
    let View {
        status,
        spec_name,
        shared_with,
        admin,
    } = view(&obj);
    // An unparsable id (hand-edited status) reads as "nothing owned yet".
    let forgejo = status.and_then(|s| {
        Some(ForgejoRef {
            id: s.forgejo_id.as_deref()?.parse().ok()?,
            name: s.forgejo_name.clone()?,
        })
    });
    let ready = status
        .and_then(|s| s.conditions.iter().find(|c| c.type_ == "Ready"))
        .map(|c| (c.status == "True", c.reason.clone()));
    Ok(Some(ReferencedCr {
        instance: status.and_then(|s| s.instance.clone()),
        forgejo,
        forgejo_name: status.and_then(|s| s.forgejo_name.clone()),
        ready,
        spec_name: Some(spec_name.to_string()),
        shared_with: shared_with.cloned(),
        organization: None,
        admin,
    }))
}

/// The server an instance URL designates, for the unique-claim check:
/// its web base, lowercased.
fn server(url: &str) -> String {
    api::instance::split_urls(url).1.to_ascii_lowercase()
}

impl KubeClusterReader {
    /// Whether `namespace` is within the watch scope.
    fn visible(&self, namespace: &str) -> bool {
        self.watched_namespace
            .as_deref()
            .is_none_or(|watched| watched == namespace)
    }

    /// The server each visible instance points at.
    async fn servers(&self) -> Result<Vec<(BoundInstance, String)>, ClusterError> {
        let mut servers = Vec::new();
        if let Some(api) = self.cluster_api::<ForgejoInstance>() {
            let list = self.read(api, false).await?;
            servers.extend(list.iter().map(|i| {
                let name = i.meta().name.clone().unwrap_or_default();
                (BoundInstance::cluster(name), server(&i.spec.url))
            }));
        }
        let list = self
            .read(self.namespaced_api::<ForgejoLocalInstance>(), false)
            .await?;
        servers.extend(list.iter().map(|i| {
            let meta = i.meta();
            let bound = BoundInstance::local(
                meta.namespace.clone().unwrap_or_default(),
                meta.name.clone().unwrap_or_default(),
            );
            (bound, server(&i.spec.url))
        }));
        Ok(servers)
    }

    /// The Forgejo name of a team's organization (`None` while unknown).
    async fn organization_name(
        &self,
        team_namespace: &str,
        r: &IdentityRef,
    ) -> Result<Option<String>, ClusterError> {
        let Some((namespace, name)) = r.target(team_namespace) else {
            return Ok(r.remote_name.clone());
        };
        if !self.visible(namespace) {
            return Ok(None);
        }
        let name_of = |o: &ForgejoOrganization| {
            o.status
                .as_ref()
                .and_then(|s| s.forgejo_name.clone())
                .unwrap_or_else(|| o.spec.name.clone())
        };
        // A miss in the store (outside the label selector) is read from
        // the API, as before the store.
        if let Some(store) = ready(self.stores.organizations.as_ref()).await
            && let Some(org) = store.get(&ObjectRef::new(name).within(namespace))
        {
            return Ok(Some(name_of(&org)));
        }
        let org = Api::<ForgejoOrganization>::namespaced(self.client.clone(), namespace)
            .get_opt(name)
            .await
            .map_err(|e| ClusterError(format!("reading ForgejoOrganization {name}: {e}")))?;
        Ok(org.as_ref().map(name_of))
    }
}

/// Whether a CR is bound to `instance`: recorded in its status, or — not
/// resolved yet — its `instanceRef` (or, without one, `default`) points at
/// it.
fn bound_to(
    instance: &BoundInstance,
    default: bool,
    namespace: Option<&str>,
    instance_ref: Option<&InstanceRef>,
    recorded: Option<&BoundInstance>,
) -> bool {
    if let Some(recorded) = recorded {
        return recorded == instance;
    }
    let Some(r) = instance_ref else {
        return default;
    };
    if r.name != instance.name || r.kind.is_some_and(|k| k != instance.kind) {
        return false;
    }
    match instance.kind {
        InstanceKind::Instance => r.namespace.is_none(),
        InstanceKind::LocalInstance => {
            r.namespace.as_deref().or(namespace) == instance.namespace.as_deref()
        }
    }
}

impl KubeClusterReader {
    /// Where a namespaced kind is listed: the namespace the operator is
    /// limited to, or the whole cluster.
    fn namespaced_api<K>(&self) -> Api<K>
    where
        K: kube::Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>,
    {
        match &self.watched_namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    /// A cluster-scoped kind, unless the operator watches none.
    fn cluster_api<K>(&self) -> Option<Api<K>>
    where
        K: kube::Resource<DynamicType = (), Scope = k8s_openapi::ClusterResourceScope>,
    {
        self.cluster_kinds.then(|| Api::all(self.client.clone()))
    }

    /// `Kind/[namespace/]name` of every `K` listed through `api` bound to
    /// `instance` (see [`bound_to`]). `view`: its `instanceRef` and status.
    async fn bound<K>(
        &self,
        api: Option<Api<K>>,
        instance: &BoundInstance,
        default: bool,
        view: fn(&K) -> (Option<&InstanceRef>, Option<&ForgejoStatus>),
    ) -> Result<Vec<String>, ClusterError>
    where
        K: Stored,
    {
        let Some(api) = api else {
            return Ok(Vec::new());
        };
        let list = self.read(api, true).await?;
        Ok(list
            .iter()
            .filter(|o| {
                let (instance_ref, status) = view(o);
                bound_to(
                    instance,
                    default,
                    o.meta().namespace.as_deref(),
                    instance_ref,
                    status.and_then(|s| s.instance.as_ref()),
                )
            })
            .map(|o| {
                let meta = o.meta();
                let name = meta.name.clone().unwrap_or_default();
                match &meta.namespace {
                    Some(ns) => format!("{}/{ns}/{name}", K::kind(&())),
                    None => format!("{}/{name}", K::kind(&())),
                }
            })
            .collect())
    }
}

/// `(instanceRef, status)` of a CR, for [`KubeClusterReader::bound`].
macro_rules! view {
    () => {
        |o| (o.spec.instance_ref.as_ref(), o.status.as_ref())
    };
}

#[async_trait::async_trait]
impl ReferenceReader for KubeClusterReader {
    async fn instance_dependents(
        &self,
        instance: &BoundInstance,
        default: bool,
    ) -> Result<Vec<String>, ClusterError> {
        use api::{
            ForgejoAccessToken, ForgejoDeployKey, ForgejoOAuth2Application, ForgejoUserKey,
            ForgejoWebhook,
        };
        let (i, d) = (instance, default);
        let mut all = Vec::new();
        all.extend(
            self.bound::<ForgejoUser>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoOrganization>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoTeam>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoUserKey>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoRepository>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoWebhook>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoDeployKey>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoOAuth2Application>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        all.extend(
            self.bound::<ForgejoAccessToken>(Some(self.namespaced_api()), i, d, view!())
                .await?,
        );
        Ok(all)
    }

    async fn referenced(
        &self,
        kind: RefKind,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ReferencedCr>, ClusterError> {
        if !self.visible(namespace) {
            return Ok(None);
        }
        let client = self.client.clone();
        match kind {
            RefKind::User => {
                let api = Api::<ForgejoUser>::namespaced(client, namespace);
                read(self, api, name, |o| View {
                    status: o.status.as_ref(),
                    spec_name: &o.spec.username,
                    shared_with: o.spec.shared_with.as_ref(),
                    // An observed account's flags aren't the CR's to say.
                    admin: o.spec.admin || o.spec.management_policy == ManagementPolicy::Observe,
                })
                .await
            }
            RefKind::Organization => {
                let api = Api::<ForgejoOrganization>::namespaced(client, namespace);
                read(self, api, name, |o| View {
                    status: o.status.as_ref(),
                    spec_name: &o.spec.name,
                    shared_with: o.spec.shared_with.as_ref(),
                    admin: false,
                })
                .await
            }
            RefKind::Team => {
                let api = Api::<ForgejoTeam>::namespaced(client.clone(), namespace);
                let Some(mut cr) = read(self, api, name, |o| View {
                    status: o.status.as_ref(),
                    spec_name: &o.spec.name,
                    shared_with: o.spec.shared_with.as_ref(),
                    admin: false,
                })
                .await?
                else {
                    return Ok(None);
                };
                let team = Api::<ForgejoTeam>::namespaced(client, namespace)
                    .get_opt(name)
                    .await
                    .map_err(|e| ClusterError(format!("reading ForgejoTeam {name}: {e}")))?;
                if let Some(team) = team {
                    cr.organization = self
                        .organization_name(namespace, &team.spec.organization_ref)
                        .await?;
                }
                Ok(Some(cr))
            }
            RefKind::Repository => {
                let api = Api::<ForgejoRepository>::namespaced(client, namespace);
                read(self, api, name, |o| View {
                    status: o.status.as_ref(),
                    spec_name: &o.spec.name,
                    shared_with: None,
                    admin: false,
                })
                .await
            }
        }
    }

    async fn namespace_labels(
        &self,
        namespace: &str,
    ) -> Result<Option<BTreeMap<String, String>>, ClusterError> {
        let found = Api::<Namespace>::all(self.client.clone())
            .get_opt(namespace)
            .await
            .map_err(|e| ClusterError(format!("reading namespace {namespace}: {e}")))?;
        Ok(found.map(|n| n.metadata.labels.unwrap_or_default()))
    }

    async fn claimants(
        &self,
        kind: RefKind,
        forgejo_name: &str,
        instance: &BoundInstance,
    ) -> Result<Vec<String>, ClusterError> {
        let servers = self.servers().await?;
        let server_of = |bound: Option<&BoundInstance>| {
            let bound = bound?;
            servers
                .iter()
                .find(|(b, _)| b == bound)
                .map(|(_, url)| url.clone())
        };
        let Some(target) = server_of(Some(instance)) else {
            return Ok(Vec::new());
        };
        let same = |name: Option<&String>, status: Option<&ForgejoStatus>| {
            name.is_some_and(|n| n.eq_ignore_ascii_case(forgejo_name))
                && server_of(status.and_then(|s| s.instance.as_ref())).as_ref() == Some(&target)
        };
        let id = |kind: &str, meta: &kube::api::ObjectMeta| {
            format!(
                "{kind}/{}/{}",
                meta.namespace.clone().unwrap_or_default(),
                meta.name.clone().unwrap_or_default()
            )
        };
        let mut claimed = Vec::new();
        match kind {
            RefKind::User => {
                for u in self
                    .read(self.namespaced_api::<ForgejoUser>(), true)
                    .await?
                {
                    // Observing an account doesn't own it.
                    let observed = u.spec.management_policy == ManagementPolicy::Observe;
                    let status = u.status.as_ref();
                    if !observed && same(status.and_then(|s| s.forgejo_name.as_ref()), status) {
                        claimed.push(id("ForgejoUser", &u.metadata));
                    }
                }
            }
            RefKind::Organization => {
                let orgs = self.read(self.namespaced_api::<ForgejoOrganization>(), true);
                for o in orgs.await? {
                    let status = o.status.as_ref();
                    if same(status.and_then(|s| s.forgejo_name.as_ref()), status) {
                        claimed.push(id("ForgejoOrganization", &o.metadata));
                    }
                }
            }
            RefKind::Team => {
                // `forgejo_name`: `organization/team`, a team's name being
                // unique within its organization only.
                for t in self
                    .read(self.namespaced_api::<ForgejoTeam>(), true)
                    .await?
                {
                    let status = t.status.as_ref();
                    let Some(team) = status.and_then(|s| s.forgejo_name.as_ref()) else {
                        continue;
                    };
                    let namespace = t.metadata.namespace.clone().unwrap_or_default();
                    let org = self
                        .organization_name(&namespace, &t.spec.organization_ref)
                        .await?;
                    let full = org.map(|org| format!("{org}/{team}"));
                    if same(full.as_ref(), status) {
                        claimed.push(id("ForgejoTeam", &t.metadata));
                    }
                }
            }
            RefKind::Repository => {}
        }
        Ok(claimed)
    }

    async fn token_claimants(
        &self,
        user: &str,
        token_name: &str,
        instance: &BoundInstance,
    ) -> Result<Vec<String>, ClusterError> {
        use application::use_cases::reconcile_token::{rotated_name, token_name as name_of};

        let servers = self.servers().await?;
        let server_of = |bound: Option<&BoundInstance>| {
            let bound = bound?;
            servers
                .iter()
                .find(|(b, _)| b == bound)
                .map(|(_, url)| url.clone())
        };
        let Some(target) = server_of(Some(instance)) else {
            return Ok(Vec::new());
        };
        let clash = |theirs: &str| {
            theirs == token_name
                || rotated_name(theirs) == token_name
                || theirs == rotated_name(token_name)
        };
        let tokens = self.read(self.namespaced_api::<api::ForgejoAccessToken>(), true);
        let mut claimed = Vec::new();
        for t in tokens.await? {
            let status = t.status.as_ref();
            let issued_for = status.and_then(|s| s.forgejo_name.as_deref());
            let on = server_of(status.and_then(|s| s.instance.as_ref()));
            let (ns, name) = (
                t.metadata.namespace.clone().unwrap_or_default(),
                t.metadata.name.clone().unwrap_or_default(),
            );
            if issued_for.is_some_and(|u| u.eq_ignore_ascii_case(user))
                && on.as_ref() == Some(&target)
                && clash(&name_of(&t.spec, &ns, &name))
            {
                claimed.push(format!("ForgejoAccessToken/{ns}/{name}"));
            }
        }
        Ok(claimed)
    }

    async fn secret_key(
        &self,
        namespace: &str,
        name: &str,
        key: &str,
    ) -> Result<SecretKey, ClusterError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let Some(secret) = api
            .get_opt(name)
            .await
            .map_err(|e| ClusterError(format!("reading secret {namespace}/{name}: {e}")))?
        else {
            return Ok(SecretKey::Missing);
        };
        let labelled = secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(api::CREDENTIAL_LABEL))
            .is_some_and(|v| v == "true");
        if !labelled {
            return Ok(SecretKey::NotLabelled);
        }
        Ok(secret
            .data
            .and_then(|mut data| data.remove(key))
            .map_or(SecretKey::Missing, |v| SecretKey::Value(v.0)))
    }
}

#[async_trait::async_trait]
impl PolicySource<NamespaceRule> for KubeClusterReader {
    async fn policies(&self) -> Result<Vec<Vec<NamespaceRule>>, ClusterError> {
        let api: Api<ForgejoNamespacePolicy> = Api::all(self.client.clone());
        Ok(self
            .read(api, false)
            .await?
            .iter()
            .map(|p| p.spec.rules.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use kube::runtime::reflector::store::Writer;
    use kube::runtime::{reflector, watcher};
    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const GROUP: &str = "/apis/forgejo.weebo.io/v1alpha1";

    fn manifest<K: DeserializeOwned>(kind: &str, meta: Value, spec: Value, status: Value) -> K {
        serde_json::from_value(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": kind,
            "metadata": meta, "spec": spec, "status": status,
        }))
        .unwrap()
    }

    fn main_instance() -> ForgejoInstance {
        manifest(
            "ForgejoInstance",
            json!({"name": "main"}),
            json!({"url": "https://git.example.com",
                   "tokenSecretRef": {"name": "t", "namespace": "default", "key": "token"}}),
            json!({}),
        )
    }

    /// `alice` in `team-a`, owning the account `alice` on `main`.
    fn alice() -> ForgejoUser {
        manifest(
            "ForgejoUser",
            json!({"name": "alice", "namespace": "team-a"}),
            json!({"username": "alice"}),
            json!({"forgejoName": "alice", "instance": {"kind": "Instance", "name": "main"}}),
        )
    }

    fn policy() -> ForgejoNamespacePolicy {
        manifest(
            "ForgejoNamespacePolicy",
            json!({"name": "deny-all"}),
            json!({"rules": []}),
            json!({}),
        )
    }

    /// A store fed `objects` (listed when `listed`), and its writer.
    fn store<K>(objects: Vec<K>, listed: bool) -> (Store<K>, Writer<K>)
    where
        K: Resource<DynamicType = ()> + Clone + 'static,
    {
        let (store, mut writer) = reflector::store::<K>();
        writer.apply_watcher_event(&watcher::Event::Init);
        for o in objects {
            writer.apply_watcher_event(&watcher::Event::InitApply(o));
        }
        if listed {
            writer.apply_watcher_event(&watcher::Event::InitDone);
        }
        (store, writer)
    }

    fn client(url: &str) -> Client {
        // Err: another test installed it first, which is as good.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        Client::try_from(kube::Config::new(url.parse().unwrap())).unwrap()
    }

    /// Nothing listens there: any API read fails.
    fn no_api() -> Client {
        client("http://127.0.0.1:9")
    }

    fn list(kind: &str, items: Vec<Value>) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": format!("{kind}List"),
            "metadata": {"resourceVersion": "1"}, "items": items,
        }))
    }

    fn instance_stores() -> ClusterStores {
        ClusterStores {
            instances: Some(store(vec![main_instance()], true).0),
            local_instances: Some(store(Vec::new(), true).0),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_claim_is_read_from_the_listed_stores_without_the_api() {
        let stores = ClusterStores {
            users: Some(store(vec![alice()], true).0),
            ..instance_stores()
        };
        let reader = KubeClusterReader::new(no_api()).with_stores(stores);
        let main = BoundInstance::cluster("main");
        let claimed = reader
            .claimants(RefKind::User, "ALICE", &main)
            .await
            .unwrap();
        assert_eq!(claimed, ["ForgejoUser/team-a/alice"]);
        let none = reader.claimants(RefKind::User, "bob", &main).await.unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn a_store_that_never_listed_is_not_trusted_empty() {
        // Its watch gone before listing (shutdown): the API decides, and
        // the claim is still seen.
        let (users, writer) = store::<ForgejoUser>(Vec::new(), false);
        drop(writer);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("{GROUP}/forgejousers")))
            .respond_with(list(
                "ForgejoUser",
                vec![serde_json::to_value(alice()).unwrap()],
            ))
            .expect(1)
            .mount(&server)
            .await;
        let stores = ClusterStores {
            users: Some(users),
            ..instance_stores()
        };
        let reader = KubeClusterReader::new(client(&server.uri())).with_stores(stores);
        let main = BoundInstance::cluster("main");
        let claimed = reader
            .claimants(RefKind::User, "alice", &main)
            .await
            .unwrap();
        assert_eq!(claimed, ["ForgejoUser/team-a/alice"]);
    }

    #[tokio::test]
    async fn a_read_waits_for_the_store_to_list() {
        let (users, mut writer) = store::<ForgejoUser>(Vec::new(), false);
        let stores = ClusterStores {
            users: Some(users),
            ..instance_stores()
        };
        let reader = KubeClusterReader::new(no_api()).with_stores(stores);
        let read = tokio::spawn(async move {
            let main = BoundInstance::cluster("main");
            reader.claimants(RefKind::User, "alice", &main).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!read.is_finished(), "decided on a store that hasn't listed");
        writer.apply_watcher_event(&watcher::Event::InitApply(alice()));
        writer.apply_watcher_event(&watcher::Event::InitDone);
        let claimed = read.await.unwrap().unwrap();
        assert_eq!(claimed, ["ForgejoUser/team-a/alice"]);
    }

    #[tokio::test]
    async fn every_read_waiting_for_a_store_is_answered_once_it_lists() {
        let (users, mut writer) = store::<ForgejoUser>(Vec::new(), false);
        let stores = ClusterStores {
            users: Some(users),
            ..instance_stores()
        };
        let reader = Arc::new(KubeClusterReader::new(no_api()).with_stores(stores));
        let reads: Vec<_> = (0..8)
            .map(|_| {
                let reader = reader.clone();
                tokio::spawn(async move {
                    let main = BoundInstance::cluster("main");
                    reader.claimants(RefKind::User, "alice", &main).await
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(100)).await;
        writer.apply_watcher_event(&watcher::Event::InitApply(alice()));
        writer.apply_watcher_event(&watcher::Event::InitDone);
        for read in reads {
            let claimed = tokio::time::timeout(Duration::from_secs(1), read)
                .await
                .expect("a waiting read was never woken")
                .unwrap()
                .unwrap();
            assert_eq!(claimed, ["ForgejoUser/team-a/alice"]);
        }
    }

    #[tokio::test]
    async fn the_policies_are_read_from_the_store_whatever_their_labels() {
        let stores = ClusterStores {
            policies: Some(store(vec![policy()], true).0),
            ..Default::default()
        };
        let selector: Selector = kube::core::Expression::Equal("shard".into(), "a".into()).into();
        let reader = KubeClusterReader::new(no_api())
            .with_scope(None, Some(selector), true)
            .with_stores(stores);
        // An existing policy, even with no rule, switches to default-deny.
        assert_eq!(reader.policies().await.unwrap(), vec![Vec::new()]);
    }

    #[tokio::test]
    async fn the_policies_are_listed_while_their_store_has_not() {
        let (policies, writer) = store::<ForgejoNamespacePolicy>(Vec::new(), false);
        drop(writer);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("{GROUP}/forgejonamespacepolicies")))
            .respond_with(list(
                "ForgejoNamespacePolicy",
                vec![serde_json::to_value(policy()).unwrap()],
            ))
            .expect(1)
            .mount(&server)
            .await;
        let stores = ClusterStores {
            policies: Some(policies),
            ..Default::default()
        };
        let reader = KubeClusterReader::new(client(&server.uri())).with_stores(stores);
        assert_eq!(reader.policies().await.unwrap(), vec![Vec::new()]);
    }

    #[tokio::test]
    async fn a_team_claim_reads_its_organization_from_the_store() {
        let org: ForgejoOrganization = manifest(
            "ForgejoOrganization",
            json!({"name": "platform", "namespace": "team-a"}),
            json!({"name": "platform"}),
            json!({"forgejoName": "Platform"}),
        );
        let team: ForgejoTeam = manifest(
            "ForgejoTeam",
            json!({"name": "devs", "namespace": "team-a"}),
            json!({"name": "devs", "organizationRef": {"name": "platform"}}),
            json!({"forgejoName": "devs", "instance": {"kind": "Instance", "name": "main"}}),
        );
        let stores = ClusterStores {
            organizations: Some(store(vec![org], true).0),
            teams: Some(store(vec![team], true).0),
            ..instance_stores()
        };
        let reader = KubeClusterReader::new(no_api()).with_stores(stores);
        let main = BoundInstance::cluster("main");
        let claimed = reader
            .claimants(RefKind::Team, "platform/devs", &main)
            .await
            .unwrap();
        assert_eq!(claimed, ["ForgejoTeam/team-a/devs"]);
    }

    #[test]
    fn a_cr_is_bound_by_its_status_else_by_its_ref() {
        let main = BoundInstance::cluster("main");
        let local = BoundInstance::local("team-a", "main");
        let by_name = InstanceRef::named("main");
        // Recorded: only the status counts.
        assert!(bound_to(&main, false, None, None, Some(&main)));
        assert!(!bound_to(&main, true, None, Some(&by_name), Some(&local)));
        // Not resolved yet: the ref, or the default.
        assert!(bound_to(&main, false, Some("team-a"), Some(&by_name), None));
        assert!(bound_to(
            &local,
            false,
            Some("team-a"),
            Some(&by_name),
            None
        ));
        assert!(!bound_to(
            &local,
            false,
            Some("team-b"),
            Some(&by_name),
            None
        ));
        let pinned = InstanceRef {
            kind: Some(InstanceKind::LocalInstance),
            ..by_name.clone()
        };
        assert!(!bound_to(&main, false, Some("team-a"), Some(&pinned), None));
        assert!(bound_to(&main, true, Some("team-a"), None, None));
        assert!(!bound_to(&main, false, Some("team-a"), None, None));
    }
}
