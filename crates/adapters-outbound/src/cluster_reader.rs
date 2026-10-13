//! [`KubeClusterReader`]: the [`ReferenceReader`] and [`PolicySource`]
//! ports over the Kubernetes API — the referenced CRs, `Secret` keys and
//! `ForgejoNamespacePolicy` objects the reconcilers and the admission
//! webhook decide on — on the operator's watch scope: an object outside
//! its label selector, or a namespaced one outside the namespace it is
//! limited to, doesn't exist for it.

use std::collections::BTreeMap;
use std::fmt::Debug;

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
    ClusterError, ForgejoRef, PolicySource, RefKind, ReferenceReader, ReferencedCr,
};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::ListParams;
use kube::core::{Selector, SelectorExt};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;

use weebo_kit_adapters::read_secret_key;

pub struct KubeClusterReader {
    client: Client,
    /// The namespace the operator is limited to, `None`: the whole cluster.
    watched_namespace: Option<String>,
    selector: Option<Selector>,
    cluster_kinds: bool,
}

impl KubeClusterReader {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            watched_namespace: None,
            selector: None,
            cluster_kinds: true,
        }
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
            let list = api
                .list(&ListParams::default())
                .await
                .map_err(|e| ClusterError(format!("listing ForgejoInstance: {e}")))?;
            servers.extend(list.items.iter().map(|i| {
                let name = i.meta().name.clone().unwrap_or_default();
                (BoundInstance::cluster(name), server(&i.spec.url))
            }));
        }
        let list = self
            .namespaced_api::<ForgejoLocalInstance>()
            .list(&ListParams::default())
            .await
            .map_err(|e| ClusterError(format!("listing ForgejoLocalInstance: {e}")))?;
        servers.extend(list.items.iter().map(|i| {
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
        let org = Api::<ForgejoOrganization>::namespaced(self.client.clone(), namespace)
            .get_opt(name)
            .await
            .map_err(|e| ClusterError(format!("reading ForgejoOrganization {name}: {e}")))?;
        Ok(org.map(|o| o.status.and_then(|s| s.forgejo_name).unwrap_or(o.spec.name)))
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
        K: kube::Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned,
    {
        let Some(api) = api else {
            return Ok(Vec::new());
        };
        let list = api
            .list(&self.params())
            .await
            .map_err(|e| ClusterError(format!("listing {}: {e}", K::kind(&()))))?;
        Ok(list
            .items
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
        let list_err = |kind: &str, e: kube::Error| ClusterError(format!("listing {kind}: {e}"));
        let mut claimed = Vec::new();
        match kind {
            RefKind::User => {
                let users = self
                    .namespaced_api::<ForgejoUser>()
                    .list(&self.params())
                    .await;
                for u in users.map_err(|e| list_err("ForgejoUser", e))?.items {
                    // Observing an account doesn't own it.
                    let observed = u.spec.management_policy == ManagementPolicy::Observe;
                    let status = u.status.as_ref();
                    if !observed && same(status.and_then(|s| s.forgejo_name.as_ref()), status) {
                        claimed.push(id("ForgejoUser", &u.metadata));
                    }
                }
            }
            RefKind::Organization => {
                let orgs = self
                    .namespaced_api::<ForgejoOrganization>()
                    .list(&self.params())
                    .await;
                for o in orgs.map_err(|e| list_err("ForgejoOrganization", e))?.items {
                    let status = o.status.as_ref();
                    if same(status.and_then(|s| s.forgejo_name.as_ref()), status) {
                        claimed.push(id("ForgejoOrganization", &o.metadata));
                    }
                }
            }
            RefKind::Team => {
                // `forgejo_name`: `organization/team`, a team's name being
                // unique within its organization only.
                let teams = self
                    .namespaced_api::<ForgejoTeam>()
                    .list(&self.params())
                    .await;
                for t in teams.map_err(|e| list_err("ForgejoTeam", e))?.items {
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
        let tokens = self
            .namespaced_api::<api::ForgejoAccessToken>()
            .list(&self.params())
            .await
            .map_err(|e| ClusterError(format!("listing ForgejoAccessToken: {e}")))?;
        let mut claimed = Vec::new();
        for t in tokens.items {
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
    ) -> Result<Option<Vec<u8>>, ClusterError> {
        let secret_ref = api::common::SecretKeyRef {
            namespace: namespace.to_string(),
            name: name.to_string(),
            key: key.to_string(),
        };
        read_secret_key(&self.client, &secret_ref)
            .await
            .map_err(ClusterError)
    }
}

#[async_trait::async_trait]
impl PolicySource<NamespaceRule> for KubeClusterReader {
    async fn policies(&self) -> Result<Vec<Vec<NamespaceRule>>, ClusterError> {
        let api: Api<ForgejoNamespacePolicy> = Api::all(self.client.clone());
        Ok(api
            .list(&Default::default())
            .await
            .map_err(|e| ClusterError(format!("listing ForgejoNamespacePolicy: {e}")))?
            .into_iter()
            .map(|p| p.spec.rules)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
