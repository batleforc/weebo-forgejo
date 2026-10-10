//! Turning an [`Import`] into CRs ([`manifests`]) and applying them to a
//! cluster: the only adoption path (`.prompt/plan.md`, "Seul chemin
//! d'adoption"). Each CR is created paused, its `status.forgejoId`/
//! `forgejoName` seeded, then unpaused.

use std::collections::BTreeMap;
use std::fmt::Debug;

use anyhow::Context;
use api::status::ForgejoStatus;
use api::{
    ForgejoDeployKey, ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser,
    ForgejoWebhook,
};
use application::use_cases::import::{Existing, Import, Imported};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

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
/// seeded; the namespaced ones (repositories, webhooks, deploy keys) in
/// `namespace`.
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
            .map(|o| cr(o, ForgejoUser::new, None))
            .collect(),
        organizations: (import.organizations.iter())
            .map(|o| cr(o, ForgejoOrganization::new, None))
            .collect(),
        teams: import
            .teams
            .iter()
            .map(|o| cr(o, ForgejoTeam::new, None))
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
    Ok(Existing {
        users: owners::<ForgejoUser>(Api::all(client.clone())).await?,
        organizations: owners::<ForgejoOrganization>(Api::all(client.clone())).await?,
        teams: owners::<ForgejoTeam>(Api::all(client.clone())).await?,
        repositories: owners::<ForgejoRepository>(Api::namespaced(client.clone(), namespace))
            .await?,
    })
}

/// What `--apply` did, per CR.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub adopted: usize,
    /// Already owning the same Forgejo object (a re-run).
    pub skipped: usize,
    /// Reported on stderr as they happen.
    pub failed: usize,
}

/// Adopts every CR in dependency order; a failure is reported and the rest
/// carry on. A CR already in the cluster that owns nothing yet is refused
/// (the operator may be creating its object right now).
pub async fn apply_all(client: &Client, i: &Manifests) -> Summary {
    apply_all_with(client, i, false).await
}

/// [`apply_all`]; `force` also takes over CRs that own nothing yet.
pub async fn apply_all_with(client: &Client, i: &Manifests, force: bool) -> Summary {
    let mut summary = Summary::default();
    for_each!(i, |cr| match adopt(client, cr, force).await {
        Ok(true) => summary.adopted += 1,
        Ok(false) => summary.skipped += 1,
        Err(e) => {
            summary.failed += 1;
            eprintln!("error: {}: {e:#}", describe(cr));
        }
    });
    summary
}

/// What `adopt` needs from each CR kind: its (shared) status type, and an
/// `Api` handle of the right scope.
trait Seeded: Sized {
    fn seeded(&self) -> Option<&ForgejoStatus>;
    fn status_mut(&mut self) -> &mut Option<ForgejoStatus>;
    fn api(client: Client, namespace: Option<&str>) -> Api<Self>;
}

macro_rules! impl_seeded {
    ($ctor:ident: $($kind:ty),+) => {$(
        impl Seeded for $kind {
            fn seeded(&self) -> Option<&ForgejoStatus> {
                self.status.as_ref()
            }
            fn status_mut(&mut self) -> &mut Option<ForgejoStatus> {
                &mut self.status
            }
            fn api(client: Client, namespace: Option<&str>) -> Api<Self> {
                impl_seeded!(@$ctor client, namespace)
            }
        }
    )+};
    (@cluster $client:ident, $ns:ident) => {{
        let _ = $ns;
        Api::all($client)
    }};
    (@namespaced $client:ident, $ns:ident) => {
        Api::namespaced($client, $ns.unwrap_or("default"))
    };
}
impl_seeded!(cluster: ForgejoUser, ForgejoOrganization, ForgejoTeam);
impl_seeded!(namespaced: ForgejoRepository, ForgejoWebhook, ForgejoDeployKey);

fn describe<K: Resource<DynamicType = ()>>(cr: &K) -> String {
    match cr.namespace() {
        Some(ns) => format!("{} {ns}/{}", K::kind(&()), cr.name_any()),
        None => format!("{} {}", K::kind(&()), cr.name_any()),
    }
}

/// Creates (or takes over) the CR paused, seeds its status, then unpauses
/// it — the operator never sees it without its `forgejoId`, so it can't
/// create a duplicate (webhooks have no name to collide on). `Ok(false)`:
/// the CR already owns this object (still paused from a run that failed
/// after seeding: unpaused now). A CR owning another one is an error.
async fn adopt<K>(client: &Client, cr: &K, force: bool) -> anyhow::Result<bool>
where
    K: Resource<DynamicType = ()> + Seeded + Clone + Debug + Serialize + DeserializeOwned,
{
    let api = K::api(client.clone(), cr.namespace().as_deref());
    let name = cr.name_any();
    let seed = cr.seeded().context("CR without a seeded status")?;
    let id = seed.forgejo_id.as_deref();

    if let Some(existing) = api.get_opt(&name).await? {
        match existing.seeded().and_then(|s| s.forgejo_id.as_deref()) {
            Some(owned) if Some(owned) == id => {
                // A run that seeded the status but failed to unpause: finish it.
                if existing
                    .annotations()
                    .contains_key(api::IMPORT_PENDING_ANNOTATION)
                {
                    unpause(&api, &name).await?;
                }
                return Ok(false);
            }
            Some(owned) => anyhow::bail!(
                "already owns Forgejo id {owned}, not {}",
                id.unwrap_or_default()
            ),
            // Paused by an earlier run of ours: safe to finish.
            None if existing
                .annotations()
                .contains_key(api::IMPORT_PENDING_ANNOTATION) => {}
            None if force => {}
            None => anyhow::bail!(
                "exists but owns nothing yet — the operator may be creating its object \
                 right now; delete it, or re-run with --force to take it over"
            ),
        }
    }

    let mut body = serde_json::to_value(cr)?;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("status");
    }
    body["metadata"]["annotations"][api::IMPORT_PENDING_ANNOTATION] = json!("true");
    api.patch(
        &name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&body),
    )
    .await
    .context("creating the CR")?;

    api.patch_status(
        &name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "status": {
            "forgejoId": seed.forgejo_id,
            "forgejoName": seed.forgejo_name,
        }})),
    )
    .await
    .context("seeding status (the CR stays paused until a re-run succeeds)")?;

    unpause(&api, &name).await?;
    Ok(true)
}

async fn unpause<K>(api: &Api<K>, name: &str) -> anyhow::Result<()>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned,
{
    api.patch(
        name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "metadata": { "annotations": {
            api::IMPORT_PENDING_ANNOTATION: null,
        }}})),
    )
    .await
    .context("removing the import-pending annotation")?;
    Ok(())
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
        assert_eq!(org.namespace(), None, "cluster-scoped");
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
