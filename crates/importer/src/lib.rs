//! Applying an [`Import`] to a cluster: the only adoption path
//! (`.prompt/plan.md`, "Seul chemin d'adoption"). Each CR is created
//! paused, its `status.forgejoId`/`forgejoName` seeded, then unpaused.

use std::fmt::Debug;

use anyhow::Context;
use api::status::ForgejoStatus;
use application::use_cases::import::Import;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

const FIELD_MANAGER: &str = "weebo-forgejo-importer";

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
pub fn to_yaml(i: &Import) -> anyhow::Result<String> {
    let mut docs = Vec::new();
    for_each!(i, |cr| docs.push(serde_norway::to_string(cr)?));
    Ok(docs.iter().map(|d| format!("---\n{d}")).collect::<String>())
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
/// carry on.
pub async fn apply_all(client: &Client, i: &Import) -> Summary {
    let mut summary = Summary::default();
    for_each!(i, |cr| match adopt(client, cr).await {
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
    fn api(client: Client, namespace: Option<&str>) -> Api<Self>;
}

macro_rules! impl_seeded {
    ($ctor:ident: $($kind:ty),+) => {$(
        impl Seeded for $kind {
            fn seeded(&self) -> Option<&ForgejoStatus> {
                self.status.as_ref()
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
impl_seeded!(cluster: api::ForgejoUser, api::ForgejoOrganization, api::ForgejoTeam);
impl_seeded!(namespaced: api::ForgejoRepository, api::ForgejoWebhook, api::ForgejoDeployKey);

fn describe<K: Resource<DynamicType = ()>>(cr: &K) -> String {
    match cr.namespace() {
        Some(ns) => format!("{} {ns}/{}", K::kind(&()), cr.name_any()),
        None => format!("{} {}", K::kind(&()), cr.name_any()),
    }
}

/// Creates (or takes over) the CR paused, seeds its status, then unpauses
/// it — the operator never sees it without its `forgejoId`, so it can't
/// create a duplicate (webhooks have no name to collide on). `Ok(false)`:
/// the CR already owns this object. A CR owning another one is an error.
async fn adopt<K>(client: &Client, cr: &K) -> anyhow::Result<bool>
where
    K: Resource<DynamicType = ()> + Seeded + Clone + Debug + Serialize + DeserializeOwned,
{
    let api = K::api(client.clone(), cr.namespace().as_deref());
    let name = cr.name_any();
    let seed = cr.seeded().context("CR without a seeded status")?;
    let id = seed.forgejo_id.as_deref();

    if let Some(existing) = api.get_opt(&name).await? {
        match existing.seeded().and_then(|s| s.forgejo_id.as_deref()) {
            Some(owned) if Some(owned) == id => return Ok(false),
            Some(owned) => anyhow::bail!(
                "already owns Forgejo id {owned}, not {}",
                id.unwrap_or_default()
            ),
            None => {}
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

    api.patch(
        &name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "metadata": { "annotations": {
            api::IMPORT_PENDING_ANNOTATION: null,
        }}})),
    )
    .await
    .context("removing the import-pending annotation")?;
    Ok(true)
}
