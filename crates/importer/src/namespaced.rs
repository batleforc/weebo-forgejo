//! `migrate-to-namespaced`: moves the CRs of the kinds that used to be
//! cluster-scoped (`ForgejoUser`, `ForgejoOrganization`, `ForgejoTeam`,
//! `ForgejoUserKey`) into namespaces — the plan is
//! `application::use_cases::namespaced_migration`'s, this carries it out.
//!
//! A CRD's scope can't change in place: the old CRD must go, and with it
//! every CR of its kind. Order (the operator **stopped**: no finalizer must
//! run, nothing is touched in Forgejo):
//!
//! 1. read the cluster-scoped CRs and the namespaced ones referencing them,
//!    plan, write the plan and the new manifests to `out`;
//! 2. remove the finalizers of the old CRs, delete them, then their CRDs;
//! 3. wait for the new (namespaced) CRDs, applied out of band (`kubectl
//!    apply -f crds.yaml`, or the chart with `crds.install`);
//! 4. recreate each CR in its namespace, paused, its status seeded (the
//!    kit's `Adopter`), then released;
//! 5. rewrite the references of the namespaced CRs, and the owner recorded
//!    on the Kubernetes `Secret`s the moved CRs emitted.
//!
//! A run that stopped after step 2 resumes from the plan saved in `out`.

use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use api::{
    ForgejoAccessToken, ForgejoOAuth2Application, ForgejoOrganization, ForgejoRepository,
    ForgejoTeam, ForgejoUser, ForgejoUserKey, ForgejoWebhook,
};
use application::use_cases::namespaced_migration::{
    MOVED, Move, Plan, REFERRING, Rewrite, Targets, plan,
};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams};
use kube::{Client, CustomResourceExt, Resource};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use weebo_kit_adapters::Adopter;

const FIELD_MANAGER: &str = "weebo-forgejo-migrate";
const PLAN_FILE: &str = "plan.json";

pub struct Options {
    pub targets: Targets,
    /// Where the plan and the rewritten manifests go.
    pub out: PathBuf,
    /// Only plan and write: touch nothing.
    pub dry_run: bool,
    /// The release enables `references.crossNamespace`: required when the
    /// plan makes references cross namespaces.
    pub allow_cross_namespace: bool,
    /// How long to wait for each step (the new CRDs especially).
    pub wait: Duration,
}

/// The CRD of a moved kind.
fn crd_name(kind: &str) -> String {
    match kind {
        "ForgejoUser" => ForgejoUser::crd_name(),
        "ForgejoOrganization" => ForgejoOrganization::crd_name(),
        "ForgejoTeam" => ForgejoTeam::crd_name(),
        _ => ForgejoUserKey::crd_name(),
    }
    .to_string()
}

fn resource(kind: &str) -> ApiResource {
    match kind {
        "ForgejoUser" => ApiResource::erase::<ForgejoUser>(&()),
        "ForgejoOrganization" => ApiResource::erase::<ForgejoOrganization>(&()),
        "ForgejoTeam" => ApiResource::erase::<ForgejoTeam>(&()),
        "ForgejoUserKey" => ApiResource::erase::<ForgejoUserKey>(&()),
        "ForgejoRepository" => ApiResource::erase::<ForgejoRepository>(&()),
        "ForgejoWebhook" => ApiResource::erase::<ForgejoWebhook>(&()),
        "ForgejoOAuth2Application" => ApiResource::erase::<ForgejoOAuth2Application>(&()),
        _ => ApiResource::erase::<ForgejoAccessToken>(&()),
    }
}

/// What the run did.
#[derive(Debug, Default)]
pub struct Report {
    pub plan: Plan,
    /// Whether it went past planning.
    pub applied: bool,
}

/// Runs the migration (see the module doc). With `dry_run`, stops after
/// writing the plan.
pub async fn migrate(client: &Client, options: &Options) -> anyhow::Result<Report> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let mut cluster_scoped = Vec::new();
    for kind in MOVED {
        let crd = crds.get_opt(&crd_name(kind)).await?;
        if crd.is_some_and(|c| c.spec.scope == "Cluster") {
            cluster_scoped.push(kind);
        }
    }
    let saved = options.out.join(PLAN_FILE);
    let plan = if cluster_scoped.is_empty() {
        // Nothing cluster-scoped any more: resume a run that deleted the
        // old CRDs, or there's nothing to do.
        if !saved.exists() {
            eprintln!("no cluster-scoped kind left: nothing to migrate");
            return Ok(Report::default());
        }
        eprintln!("resuming from {}", saved.display());
        read_plan(&saved)?
    } else {
        let mut old = Vec::new();
        for kind in &cluster_scoped {
            old.extend(list(client, kind).await?);
        }
        let mut namespaced = Vec::new();
        for kind in REFERRING {
            namespaced.extend(list(client, kind).await?);
        }
        let plan = plan(&old, &namespaced, &options.targets)?;
        write_plan(&options.out, &plan)?;
        plan
    };
    for warning in &plan.warnings {
        eprintln!("warning: {warning}");
    }
    eprintln!(
        "{} CR(s) to move, {} CR(s) whose references change; plan in {}",
        plan.moves.len(),
        plan.rewrites.len(),
        options.out.display()
    );
    if plan.cross_namespace && !options.allow_cross_namespace {
        bail!(
            "the migration makes references cross namespaces: enable references.crossNamespace \
             on the release, then rerun with --allow-cross-namespace"
        );
    }
    if options.dry_run {
        return Ok(Report {
            plan,
            applied: false,
        });
    }

    for kind in &cluster_scoped {
        delete_old(client, kind).await?;
    }
    for kind in &cluster_scoped {
        let name = crd_name(kind);
        crds.delete(&name, &DeleteParams::default()).await?;
        // Gone — or already replaced by the namespaced one.
        wait(options.wait, &format!("CRD {name} to go"), || async {
            let crd = crds.get_opt(&name).await?;
            Ok(crd.is_none_or(|c| c.spec.scope == "Namespaced"))
        })
        .await?;
    }
    let kinds: Vec<&str> = plan.moves.iter().map(|m| m.kind.as_str()).collect();
    for kind in MOVED.iter().filter(|k| kinds.contains(k)) {
        let name = crd_name(kind);
        eprintln!("waiting for the namespaced CRD {name}: apply the new CRDs now");
        wait(options.wait, &format!("namespaced CRD {name}"), || async {
            Ok(crds.get_opt(&name).await?.is_some_and(|c| {
                let established = c.status.and_then(|s| s.conditions).is_some_and(|cs| {
                    cs.iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
                });
                c.spec.scope == "Namespaced" && established
            }))
        })
        .await?;
    }
    for m in &plan.moves {
        recreate(client, m, options.wait)
            .await
            .with_context(|| format!("recreating {}/{}/{}", m.kind, m.namespace, m.name))?;
    }
    for r in &plan.rewrites {
        rewrite(client, r)
            .await
            .with_context(|| format!("rewriting {}/{}/{}", r.kind, r.namespace, r.name))?;
    }
    rename_owners(client, &plan.owner_renames).await?;
    Ok(Report {
        plan,
        applied: true,
    })
}

/// Every CR of `kind`, as JSON.
async fn list(client: &Client, kind: &str) -> anyhow::Result<Vec<Value>> {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource(kind));
    let items = api
        .list(&ListParams::default())
        .await
        .with_context(|| format!("listing {kind}"))?
        .items;
    items
        .into_iter()
        .map(|o| serde_json::to_value(o).map_err(Into::into))
        .collect()
}

/// Removes the finalizers of every (cluster-scoped) CR of `kind`, then
/// deletes it: the operator is stopped, nothing happens in Forgejo.
async fn delete_old(client: &Client, kind: &str) -> anyhow::Result<()> {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource(kind));
    for o in api.list(&ListParams::default()).await?.items {
        let name = o.metadata.name.clone().unwrap_or_default();
        let unfinalized = json!({"metadata": {"finalizers": null}});
        api.patch(&name, &PatchParams::default(), &Patch::Merge(&unfinalized))
            .await?;
        api.delete(&name, &DeleteParams::default()).await?;
    }
    Ok(())
}

const ADOPTER: Adopter = Adopter {
    field_manager: FIELD_MANAGER,
    annotations: api::ANNOTATIONS,
};

async fn recreate(client: &Client, m: &Move, timeout: Duration) -> anyhow::Result<()> {
    match m.kind.as_str() {
        "ForgejoUser" => recreate_as::<ForgejoUser>(client, m, timeout).await,
        "ForgejoOrganization" => recreate_as::<ForgejoOrganization>(client, m, timeout).await,
        "ForgejoTeam" => recreate_as::<ForgejoTeam>(client, m, timeout).await,
        _ => recreate_as::<ForgejoUserKey>(client, m, timeout).await,
    }
}

/// Creates the CR in its namespace — paused and seeded when it owned a
/// Forgejo object. A CR already there (a resumed run) is left as it is.
async fn recreate_as<K>(client: &Client, m: &Move, timeout: Duration) -> anyhow::Result<()>
where
    K: Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + Debug
        + Serialize
        + DeserializeOwned,
{
    let api: Api<K> = Api::namespaced(client.clone(), &m.namespace);
    let cr: K = serde_json::from_value(m.manifest.clone())
        .with_context(|| format!("{} {} doesn't match the new CRD", m.kind, m.name))?;
    let Some(seed) = &m.seed else {
        if api.get_opt(&m.name).await?.is_none() {
            // The apiserver may still be warming the new CRD's schema.
            wait(timeout, &format!("creating {}", m.name), || async {
                Ok(api.create(&Default::default(), &cr).await.is_ok())
            })
            .await?;
        }
        return Ok(());
    };
    let bound_to = |existing: &K| {
        let value = serde_json::to_value(existing).ok()?;
        value
            .pointer("/status/forgejoId")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    ADOPTER
        .adopt(&api, &cr, &m.forgejo_id(), seed.clone(), bound_to, false)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(())
}

async fn rewrite(client: &Client, r: &Rewrite) -> anyhow::Result<()> {
    let api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), &r.namespace, &resource(&r.kind));
    let patch = json!({ "spec": r.spec });
    api.patch(
        &r.name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

/// The owner annotation of the `Secret`s the moved CRs emitted (their id
/// now carries their namespace). Vault values keep their old owner until
/// the operator next writes them: the moved CR carries it in its
/// `previous-owner` annotation, the operator takes them back and records
/// the new id.
async fn rename_owners(client: &Client, renames: &[(String, String)]) -> anyhow::Result<()> {
    if renames.is_empty() {
        return Ok(());
    }
    let secrets: Api<Secret> = Api::all(client.clone());
    for s in secrets.list(&ListParams::default()).await?.items {
        let Some(owner) = s
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(api::SECRET_OWNER_ANNOTATION))
        else {
            continue;
        };
        let Some((_, new)) = renames.iter().find(|(old, _)| old == owner) else {
            continue;
        };
        let (Some(ns), Some(name)) = (&s.metadata.namespace, &s.metadata.name) else {
            continue;
        };
        let patch = json!({"metadata": {"annotations": {api::SECRET_OWNER_ANNOTATION: new}}});
        Api::<Secret>::namespaced(client.clone(), ns)
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
    }
    Ok(())
}

async fn wait<F, Fut>(timeout: Duration, what: &str, mut done: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .with_context(|| format!("waiting {timeout:?} for {what}: too long"))?;
    loop {
        if done().await? {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// `out/plan.json` (to resume) and `out/<Kind>-<namespace>-<name>.yaml`,
/// the new manifests for GitOps (status left out).
fn write_plan(out: &Path, plan: &Plan) -> anyhow::Result<()> {
    std::fs::create_dir_all(out)?;
    let moves: Vec<Value> = plan
        .moves
        .iter()
        .map(|m| {
            json!({"kind": m.kind, "name": m.name, "namespace": m.namespace,
                   "manifest": m.manifest, "seed": m.seed})
        })
        .collect();
    let rewrites: Vec<Value> = plan
        .rewrites
        .iter()
        .map(|r| json!({"kind": r.kind, "name": r.name, "namespace": r.namespace, "spec": r.spec}))
        .collect();
    let saved = json!({"moves": moves, "rewrites": rewrites,
                       "ownerRenames": plan.owner_renames, "crossNamespace": plan.cross_namespace});
    std::fs::write(out.join(PLAN_FILE), serde_json::to_string_pretty(&saved)?)?;
    for m in &plan.moves {
        let file = out.join(format!("{}-{}-{}.yaml", m.kind, m.namespace, m.name));
        std::fs::write(file, serde_norway::to_string(&m.manifest)?)?;
    }
    for r in &plan.rewrites {
        let file = out.join(format!(
            "{}-{}-{}.spec-patch.yaml",
            r.kind, r.namespace, r.name
        ));
        std::fs::write(file, serde_norway::to_string(&json!({"spec": r.spec}))?)?;
    }
    Ok(())
}

/// `plan.json` as `write_plan` writes it: every field required, so a
/// truncated or hand-edited plan fails to load instead of resuming with
/// blanks.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedPlan {
    moves: Vec<SavedMove>,
    rewrites: Vec<SavedRewrite>,
    owner_renames: Vec<(String, String)>,
    cross_namespace: bool,
}

#[derive(Deserialize)]
struct SavedMove {
    kind: String,
    name: String,
    namespace: String,
    manifest: Value,
    seed: Option<Value>,
}

#[derive(Deserialize)]
struct SavedRewrite {
    kind: String,
    name: String,
    namespace: String,
    spec: Value,
}

fn read_plan(path: &Path) -> anyhow::Result<Plan> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let saved: SavedPlan =
        serde_json::from_str(&text).with_context(|| format!("parsing {path:?}"))?;
    let moves = saved
        .moves
        .into_iter()
        .map(|m| Move {
            kind: m.kind,
            name: m.name,
            namespace: m.namespace,
            manifest: m.manifest,
            seed: m.seed,
        })
        .collect();
    let rewrites = saved
        .rewrites
        .into_iter()
        .map(|r| Rewrite {
            kind: r.kind,
            name: r.name,
            namespace: r.namespace,
            spec: r.spec,
        })
        .collect();
    Ok(Plan {
        moves,
        rewrites,
        cross_namespace: saved.cross_namespace,
        owner_renames: saved.owner_renames,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_plan_reads_back() {
        let dir = std::env::temp_dir().join(format!("fj-plan-{}", std::process::id()));
        let plan = Plan {
            moves: vec![Move {
                kind: "ForgejoUser".into(),
                name: "alice".into(),
                namespace: "team-a".into(),
                manifest: json!({"kind": "ForgejoUser", "spec": {"username": "alice"}}),
                seed: Some(json!({"forgejoId": "3"})),
            }],
            rewrites: vec![Rewrite {
                kind: "ForgejoRepository".into(),
                name: "app".into(),
                namespace: "team-b".into(),
                spec: json!({"userRef": {"name": "alice", "namespace": "team-a"}}),
            }],
            cross_namespace: true,
            owner_renames: vec![(
                "ForgejoUser/alice".into(),
                "ForgejoUser/team-a/alice".into(),
            )],
            warnings: vec![],
        };
        write_plan(&dir, &plan).unwrap();
        assert_eq!(read_plan(&dir.join(PLAN_FILE)).unwrap(), plan);
        assert!(dir.join("ForgejoUser-team-a-alice.yaml").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_plan_missing_a_field_is_refused() {
        let dir = std::env::temp_dir().join(format!("plan-missing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(PLAN_FILE);
        std::fs::write(
            &path,
            r#"{"moves": [{"kind": "ForgejoUser", "name": "alice"}], "rewrites": [],
                "ownerRenames": [], "crossNamespace": false}"#,
        )
        .unwrap();
        assert!(read_plan(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
