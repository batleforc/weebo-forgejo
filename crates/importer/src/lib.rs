//! Turning an [`Import`] into CRs ([`manifests`]) and applying them to a
//! cluster: the only adoption path (`.prompt/plan.md`, "Seul chemin
//! d'adoption"). Each CR is created paused, its `status.forgejoId`/
//! `forgejoName` seeded, then unpaused.

pub mod namespaced;

use std::collections::BTreeMap;
use std::fmt::Debug;

use adapters_outbound::{ForgejoInstances, KubeClusterReader};
use anyhow::Context;
use api::common::{InstanceRef, ManagementPolicy};
use api::status::ForgejoStatus;
use api::{
    ForgejoDeployKey, ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser,
    ForgejoWebhook,
};
use application::ports::{InstanceDirectory, RefKind, ReferenceReader};
use application::use_cases::import::{Existing, Import, Imported};
use kube::api::{Api, ListParams};
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use weebo_kit_adapters::{Adopter, Adoption};

const FIELD_MANAGER: &str = "weebo-forgejo-importer";

/// The CRs describing an instance, in dependency order.
#[derive(Debug, Default)]
pub struct Manifests {
    pub users: Vec<ForgejoUser>,
    pub organizations: Vec<ForgejoOrganization>,
    pub teams: Vec<ForgejoTeam>,
    pub repositories: Vec<ForgejoRepository>,
    pub webhooks: Vec<ForgejoWebhook>,
    pub deploy_keys: Vec<ForgejoDeployKey>,
}

/// The CRs of `import`, each with its `status.forgejoId`/`forgejoName`
/// seeded, all in `namespace`.
pub fn manifests(import: &Import, namespace: &str) -> Manifests {
    fn cr<K, S>(o: &Imported<S>, new: fn(&str, S) -> K, namespace: Option<&str>) -> K
    where
        K: Resource + Seeded,
        S: Clone,
    {
        let mut cr = new(&o.name, o.spec.clone());
        cr.meta_mut().namespace = namespace.map(str::to_string);
        *cr.status_mut() = Some(ForgejoStatus {
            forgejo_id: Some(o.forgejo.id.to_string()),
            forgejo_name: Some(o.forgejo.name.clone()),
            ..Default::default()
        });
        cr
    }
    let ns = Some(namespace);
    Manifests {
        users: import
            .users
            .iter()
            .map(|o| cr(o, ForgejoUser::new, ns))
            .collect(),
        organizations: (import.organizations.iter())
            .map(|o| cr(o, ForgejoOrganization::new, ns))
            .collect(),
        teams: import
            .teams
            .iter()
            .map(|o| cr(o, ForgejoTeam::new, ns))
            .collect(),
        repositories: (import.repositories.iter())
            .map(|o| cr(o, ForgejoRepository::new, ns))
            .collect(),
        webhooks: (import.webhooks.iter())
            .map(|o| cr(o, ForgejoWebhook::new, ns))
            .collect(),
        deploy_keys: (import.deploy_keys.iter())
            .map(|k| {
                let mut cr = cr(&k.key, ForgejoDeployKey::new, ns);
                // Cleanup finds the key without the repository CR.
                cr.annotations_mut()
                    .insert(api::KEY_OWNER_ANNOTATION.to_string(), k.repository.clone());
                cr
            })
            .collect(),
    }
}

/// Runs `$body` with `$cr` bound to each CR of `$import`, in dependency
/// order (one generic closure can't take the six CR types).
macro_rules! for_each {
    ($import:expr, |$cr:ident| $body:expr) => {{
        let i = $import;
        for $cr in &i.users {
            $body;
        }
        for $cr in &i.organizations {
            $body;
        }
        for $cr in &i.teams {
            $body;
        }
        for $cr in &i.repositories {
            $body;
        }
        for $cr in &i.webhooks {
            $body;
        }
        for $cr in &i.deploy_keys {
            $body;
        }
    }};
}

/// Every CR as one multi-document YAML stream, `status` included (ignored
/// by `kubectl apply`, kept as a record of the adopted ids).
pub fn to_yaml(i: &Manifests) -> anyhow::Result<String> {
    let mut docs = Vec::new();
    for_each!(i, |cr| docs.push(serde_norway::to_string(cr)?));
    Ok(docs.iter().map(|d| format!("---\n{d}")).collect::<String>())
}

/// The CRs `--apply` would collide with, so the import names around them
/// (and an object adopted by an earlier run keeps its CR).
pub async fn existing(client: &Client, namespace: &str) -> anyhow::Result<Existing> {
    async fn owners<K>(api: Api<K>) -> anyhow::Result<BTreeMap<String, Option<String>>>
    where
        K: Resource<DynamicType = ()> + Seeded + Clone + Debug + DeserializeOwned,
    {
        let list = api
            .list(&ListParams::default())
            .await
            .with_context(|| format!("listing {}", K::plural(&())))?;
        Ok(list
            .into_iter()
            .map(|cr| {
                let id = cr.seeded().and_then(|s| s.forgejo_id.clone());
                (cr.name_any(), id)
            })
            .collect())
    }
    let api = || client.clone();
    Ok(Existing {
        users: owners::<ForgejoUser>(Api::namespaced(api(), namespace)).await?,
        organizations: owners::<ForgejoOrganization>(Api::namespaced(api(), namespace)).await?,
        teams: owners::<ForgejoTeam>(Api::namespaced(api(), namespace)).await?,
        repositories: owners::<ForgejoRepository>(Api::namespaced(client.clone(), namespace))
            .await?,
    })
}

/// What `--apply` did, per CR: adopted, skipped (already owning the same
/// Forgejo object, a re-run), failed (reported on stderr as they happen).
pub use weebo_kit_adapters::Summary;

/// The kit's adoption flow, as this importer.
const ADOPTER: Adopter = Adopter {
    field_manager: FIELD_MANAGER,
    annotations: api::ANNOTATIONS,
};

/// Adopts every CR in dependency order; a failure is reported and the rest
/// carry on. A CR already in the cluster that owns nothing yet is refused
/// (the operator may be creating its object right now), and so is a user,
/// organization or team another CR already owns on the same server
/// (`RemoteObjectClaimed`).
pub async fn apply_all(client: &Client, i: &Manifests) -> Summary {
    apply_all_with(client, i, false).await
}

/// [`apply_all`]; `force` also takes over CRs that own nothing yet.
pub async fn apply_all_with(client: &Client, i: &Manifests, force: bool) -> Summary {
    let mut summary = Summary::default();
    let claims = Claims::new(client, i);
    for_each!(i, |cr| {
        let result = match claims.check(cr).await {
            Ok(()) => adopt(client, cr, force).await,
            Err(e) => Err(e),
        };
        // The claim check fails with a `String`, not an `AdoptError`: a
        // failure is counted here rather than through `Summary::record`.
        match result {
            Ok(adoption) => summary.record(&Ok(adoption)),
            Err(e) => {
                eprintln!("error: {}: {e}", describe(cr));
                summary.failed = summary.failed.saturating_add(1);
            }
        }
    });
    summary
}

/// What `adopt` needs from each CR kind: its (shared) status type, its
/// `Api` handle, and — for the kinds owning a unique Forgejo object — the
/// claim it makes.
trait Seeded: Sized {
    fn seeded(&self) -> Option<&ForgejoStatus>;
    fn status_mut(&mut self) -> &mut Option<ForgejoStatus>;
    fn api(client: Client, namespace: Option<&str>) -> Api<Self>;
    /// The kind and Forgejo name this CR claims, given the Forgejo names
    /// of the organizations by CR name (a team is unique in its org only).
    fn claim(&self, _organizations: &BTreeMap<String, String>) -> Option<(RefKind, String)> {
        None
    }
    fn instance_ref(&self) -> Option<&InstanceRef> {
        None
    }
}

macro_rules! impl_seeded {
    ($($kind:ty),+) => {$(
        impl Seeded for $kind {
            fn seeded(&self) -> Option<&ForgejoStatus> {
                self.status.as_ref()
            }
            fn status_mut(&mut self) -> &mut Option<ForgejoStatus> {
                &mut self.status
            }
            fn api(client: Client, namespace: Option<&str>) -> Api<Self> {
                Api::namespaced(client, namespace.unwrap_or("default"))
            }
            fn claim(&self, organizations: &BTreeMap<String, String>) -> Option<(RefKind, String)> {
                claim_of(self, organizations)
            }
            fn instance_ref(&self) -> Option<&InstanceRef> {
                self.spec.instance_ref.as_ref()
            }
        }
    )+};
}
impl_seeded!(
    ForgejoUser,
    ForgejoOrganization,
    ForgejoTeam,
    ForgejoRepository,
    ForgejoWebhook,
    ForgejoDeployKey
);

/// What a CR claims, per kind (users, organizations, teams only).
trait Claiming {
    fn claimed(&self, _organizations: &BTreeMap<String, String>) -> Option<(RefKind, String)> {
        None
    }
}

fn claim_of<K: Claiming>(
    cr: &K,
    organizations: &BTreeMap<String, String>,
) -> Option<(RefKind, String)> {
    cr.claimed(organizations)
}

impl Claiming for ForgejoUser {
    fn claimed(&self, _: &BTreeMap<String, String>) -> Option<(RefKind, String)> {
        // Observing an account doesn't own it.
        let manages = self.spec.management_policy == ManagementPolicy::Manage;
        manages.then(|| (RefKind::User, self.spec.username.clone()))
    }
}

impl Claiming for ForgejoOrganization {
    fn claimed(&self, _: &BTreeMap<String, String>) -> Option<(RefKind, String)> {
        Some((RefKind::Organization, self.spec.name.clone()))
    }
}

impl Claiming for ForgejoTeam {
    fn claimed(&self, organizations: &BTreeMap<String, String>) -> Option<(RefKind, String)> {
        let org_cr = self.spec.organization_ref.name.as_ref()?;
        let org = organizations.get(org_cr)?;
        Some((RefKind::Team, format!("{org}/{}", self.spec.name)))
    }
}

impl Claiming for ForgejoRepository {}
impl Claiming for ForgejoWebhook {}
impl Claiming for ForgejoDeployKey {}

/// The unique claim (D8) at adoption: a user, organization or team another
/// CR already owns on the same server isn't adopted twice.
struct Claims {
    reader: KubeClusterReader,
    instances: ForgejoInstances,
    /// Organization CR name → its Forgejo name, for team claims.
    organizations: BTreeMap<String, String>,
}

impl Claims {
    fn new(client: &Client, i: &Manifests) -> Self {
        let organizations = i
            .organizations
            .iter()
            .map(|o| (o.name_any(), o.spec.name.clone()))
            .collect();
        Self {
            reader: KubeClusterReader::new(client.clone()),
            instances: ForgejoInstances::new(client.clone()),
            organizations,
        }
    }

    async fn check<K>(&self, cr: &K) -> Result<(), String>
    where
        K: Resource<DynamicType = ()> + Seeded,
    {
        let Some((kind, name)) = cr.claim(&self.organizations) else {
            return Ok(());
        };
        let namespace = cr.namespace();
        // No instance to resolve yet: no server to compare claims on.
        let Ok(instance) = self
            .instances
            .resolve(namespace.as_deref(), cr.instance_ref(), None)
            .await
        else {
            return Ok(());
        };
        let me = format!(
            "{}/{}/{}",
            K::kind(&()),
            namespace.unwrap_or_default(),
            cr.name_any()
        );
        let others: Vec<String> = self
            .reader
            .claimants(kind, &name, &instance)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|id| *id != me)
            .collect();
        match others.first() {
            None => Ok(()),
            Some(other) => Err(format!(
                "RemoteObjectClaimed: {} {name:?} on this server is already owned by {other}",
                kind.as_str()
            )),
        }
    }
}

fn describe<K: Resource<DynamicType = ()>>(cr: &K) -> String {
    match cr.namespace() {
        Some(ns) => format!("{} {ns}/{}", K::kind(&()), cr.name_any()),
        None => format!("{} {}", K::kind(&()), cr.name_any()),
    }
}

/// Creates (or takes over) the CR paused, seeds its status, then unpauses
/// it (the kit's [`Adopter`]) — the operator never sees it without its
/// `forgejoId`, so it can't create a duplicate (webhooks have no name to
/// collide on).
async fn adopt<K>(client: &Client, cr: &K, force: bool) -> Result<Adoption, String>
where
    K: Resource<DynamicType = ()> + Seeded + Clone + Debug + Serialize + DeserializeOwned,
{
    let api = K::api(client.clone(), cr.namespace().as_deref());
    let seed = cr.seeded().ok_or("CR without a seeded status")?;
    let id = seed.forgejo_id.clone().unwrap_or_default();
    ADOPTER
        .adopt(
            &api,
            cr,
            &id,
            json!({ "forgejoId": seed.forgejo_id, "forgejoName": seed.forgejo_name }),
            |existing: &K| existing.seeded().and_then(|s| s.forgejo_id.clone()),
            force,
        )
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use api::keys::ForgejoDeployKeySpec;
    use api::organization::ForgejoOrganizationSpec;
    use application::ports::ForgejoRef;
    use application::use_cases::import::ImportedKey;

    use super::*;

    fn imported<S>(name: &str, spec: S, id: i64, forgejo_name: &str) -> Imported<S> {
        Imported {
            name: name.into(),
            spec,
            forgejo: ForgejoRef {
                id,
                name: forgejo_name.into(),
            },
        }
    }

    #[test]
    fn manifests_seed_the_status_and_place_namespaced_crs() {
        let import = Import {
            organizations: vec![imported(
                "weebo",
                serde_json::from_value::<ForgejoOrganizationSpec>(json!({"name": "weebo"}))
                    .unwrap(),
                9,
                "weebo",
            )],
            deploy_keys: vec![ImportedKey {
                key: imported(
                    "weebo-app-key-3",
                    serde_json::from_value::<ForgejoDeployKeySpec>(json!({
                        "repositoryRef": {"name": "weebo-app"},
                        "key": {"publicKey": "ssh-ed25519 AAAA"},
                    }))
                    .unwrap(),
                    3,
                    "ci",
                ),
                repository: "weebo/app".into(),
            }],
            ..Default::default()
        };
        let crs = manifests(&import, "forgejo");

        let org = &crs.organizations[0];
        assert_eq!(org.name_any(), "weebo");
        assert_eq!(org.namespace().as_deref(), Some("forgejo"));
        let status = org.status.as_ref().unwrap();
        assert_eq!(status.forgejo_id.as_deref(), Some("9"));
        assert_eq!(status.forgejo_name.as_deref(), Some("weebo"));

        let key = &crs.deploy_keys[0];
        assert_eq!(key.namespace().as_deref(), Some("forgejo"));
        assert_eq!(key.annotations()[api::KEY_OWNER_ANNOTATION], "weebo/app");
        assert_eq!(
            key.status.as_ref().unwrap().forgejo_id.as_deref(),
            Some("3")
        );
    }
}
