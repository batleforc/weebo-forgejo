//! Integration test of `migrate-to-namespaced` (`importer::namespaced`): a
//! cluster-scoped `ForgejoUser` and `ForgejoOrganization` (their CRDs
//! installed as the old releases did, cluster-scoped) and a
//! `ForgejoRepository` referencing them are moved into namespaces — CRs
//! recreated with their binding to Forgejo, references and sharing
//! rewritten, the owner of the user's emitted `Secret` renamed.

use std::path::Path;
use std::time::Duration;

use api::common::IdentityRef;
use api::{ForgejoOrganization, ForgejoRepository, ForgejoUser};
use application::use_cases::namespaced_migration::Targets;
use importer::namespaced::{Options, migrate};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams, PostParams};
use kube::{Client, CustomResourceExt};
use serde_json::{Value, json};
use testkit::envtest::EnvTestCluster;

const TIMEOUT: Duration = Duration::from_secs(60);

async fn eventually<T, E: std::fmt::Debug, F: Future<Output = Result<Option<T>, E>>>(
    what: &str,
    mut attempt: impl FnMut() -> F,
) -> T {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        match attempt().await {
            Ok(Some(v)) => return v,
            Err(e) if tokio::time::Instant::now() > deadline => panic!("{what}: {e:?}"),
            Ok(None) if tokio::time::Instant::now() > deadline => panic!("{what}: timed out"),
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// `deploy/crd/<file>`: the CRD as this release generates it (namespaced).
fn current_crd(file: &str) -> CustomResourceDefinition {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/crd")
        .join(file);
    serde_norway::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Replaces CRD `name` by `crd` (a scope can't change in place: delete,
/// wait, create, wait until established).
async fn install(
    crds: &Api<CustomResourceDefinition>,
    name: &str,
    mut crd: CustomResourceDefinition,
) {
    if crds.get_opt(name).await.unwrap().is_some() {
        crds.delete(name, &DeleteParams::default()).await.unwrap();
        eventually(&format!("{name} gone"), || async {
            Ok::<_, kube::Error>(crds.get_opt(name).await?.is_none().then_some(()))
        })
        .await;
    }
    crd.metadata.resource_version = None;
    crd.metadata.uid = None;
    crd.status = None;
    crds.create(&PostParams::default(), &crd).await.unwrap();
    eventually(&format!("{name} established"), || async {
        let crd = crds.get(name).await?;
        let established = crd.status.and_then(|s| s.conditions).is_some_and(|cs| {
            cs.iter()
                .any(|c| c.type_ == "Established" && c.status == "True")
        });
        Ok::<_, kube::Error>(established.then_some(()))
    })
    .await;
}

/// Creates `manifest` through `api`, retrying while the schema warms up,
/// then seeds its status.
async fn create(api: &Api<DynamicObject>, manifest: Value, status: Option<Value>) {
    let obj: DynamicObject = serde_json::from_value(manifest).unwrap();
    let name = obj.metadata.name.clone().unwrap();
    eventually(&format!("creating {name}"), || async {
        Ok::<_, kube::Error>(api.create(&PostParams::default(), &obj).await.ok())
    })
    .await;
    if let Some(status) = status {
        api.patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(json!({"status": status})),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn cluster_scoped_identities_move_into_namespaces() {
    let cluster = EnvTestCluster::start().await;
    let client: Client = cluster.client();
    let pp = PostParams::default();
    for ns in ["team-a", "ids", "team-b"] {
        let ns: Namespace = serde_json::from_value(json!({"metadata": {"name": ns}})).unwrap();
        Api::<Namespace>::all(client.clone())
            .create(&pp, &ns)
            .await
            .unwrap();
    }

    // The old, cluster-scoped CRDs.
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for (name, file) in [
        (ForgejoUser::crd_name(), "forgejouser.yaml"),
        (ForgejoOrganization::crd_name(), "forgejoorganization.yaml"),
    ] {
        let mut crd = current_crd(file);
        crd.spec.scope = "Cluster".into();
        install(&crds, name, crd).await;
    }
    let users = ApiResource::erase::<ForgejoUser>(&());
    let orgs = ApiResource::erase::<ForgejoOrganization>(&());
    let repos = ApiResource::erase::<ForgejoRepository>(&());
    create(
        &Api::all_with(client.clone(), &users),
        json!({"apiVersion": users.api_version, "kind": users.kind,
               "metadata": {"name": "alice", "finalizers": ["forgejo.weebo.io/finalizer"]},
               "spec": {"username": "alice", "email": "alice@example.com"}}),
        Some(json!({"forgejoId": "3", "forgejoName": "alice"})),
    )
    .await;
    create(
        &Api::all_with(client.clone(), &orgs),
        json!({"apiVersion": orgs.api_version, "kind": orgs.kind,
               "metadata": {"name": "weebo"},
               "spec": {"name": "weebo", "ownerRef": {"name": "alice"}}}),
        Some(json!({"forgejoId": "9", "forgejoName": "weebo"})),
    )
    .await;
    create(
        &Api::namespaced_with(client.clone(), "team-b", &repos),
        json!({"apiVersion": repos.api_version, "kind": repos.kind,
               "metadata": {"name": "app", "namespace": "team-b"},
               "spec": {"name": "app", "organizationRef": {"name": "weebo"}}}),
        None,
    )
    .await;
    // A password Secret the user emitted, owned under its old id.
    let secret: Secret = serde_json::from_value(json!({
        "metadata": {"name": "alice-forgejo", "namespace": "team-a",
                     "annotations": {api::SECRET_OWNER_ANNOTATION: "ForgejoUser/alice"}},
    }))
    .unwrap();
    Api::<Secret>::namespaced(client.clone(), "team-a")
        .create(&pp, &secret)
        .await
        .unwrap();

    let out = std::env::temp_dir().join(format!("fj-migrate-{}", std::process::id()));
    let options = |dry_run, allow_cross_namespace| Options {
        targets: Targets {
            mapping: [("ForgejoUser/alice".to_string(), "team-a".to_string())].into(),
            default_namespace: Some("ids".into()),
        },
        out: out.clone(),
        dry_run,
        allow_cross_namespace,
        wait: TIMEOUT,
    };

    // A dry run plans and touches nothing; cross-namespace references need
    // the release's consent.
    let dry = migrate(&client, &options(true, true)).await.unwrap();
    assert!(!dry.applied && dry.plan.cross_namespace);
    assert_eq!(dry.plan.moves.len(), 2);
    assert!(out.join("ForgejoUser-team-a-alice.yaml").exists());
    assert!(migrate(&client, &options(false, false)).await.is_err());
    assert!(
        crds.get_opt(ForgejoUser::crd_name())
            .await
            .unwrap()
            .is_some()
    );

    // The new CRDs are applied out of band once the old ones are gone.
    let reinstall = tokio::spawn({
        let crds = crds.clone();
        async move {
            for (name, file) in [
                (ForgejoUser::crd_name(), "forgejouser.yaml"),
                (ForgejoOrganization::crd_name(), "forgejoorganization.yaml"),
            ] {
                eventually(&format!("{name} deleted by the migration"), || async {
                    let crd = crds.get_opt(name).await?;
                    Ok::<_, kube::Error>(crd.is_none().then_some(()))
                })
                .await;
                install(&crds, name, current_crd(file)).await;
            }
        }
    });
    let report = migrate(&client, &options(false, true)).await.unwrap();
    reinstall.await.unwrap();
    assert!(report.applied);

    let alice = Api::<ForgejoUser>::namespaced(client.clone(), "team-a")
        .get("alice")
        .await
        .unwrap();
    let status = alice.status.unwrap();
    assert_eq!(status.forgejo_id.as_deref(), Some("3"));
    assert_eq!(
        alice.spec.shared_with.unwrap().namespaces,
        vec!["ids".to_string()],
        "its organization (in ids) references it"
    );
    assert!(
        !api::ANNOTATIONS.import_pending(&alice.metadata),
        "released after seeding"
    );
    let weebo = Api::<ForgejoOrganization>::namespaced(client.clone(), "ids")
        .get("weebo")
        .await
        .unwrap();
    assert_eq!(weebo.status.unwrap().forgejo_name.as_deref(), Some("weebo"));
    assert_eq!(
        weebo.spec.owner_ref,
        Some(IdentityRef {
            namespace: Some("team-a".into()),
            ..IdentityRef::named("alice")
        })
    );
    assert_eq!(
        weebo.spec.shared_with.unwrap().namespaces,
        vec!["team-b".to_string()]
    );
    let app = Api::<ForgejoRepository>::namespaced(client.clone(), "team-b")
        .get("app")
        .await
        .unwrap();
    assert_eq!(
        app.spec.organization_ref,
        Some(IdentityRef {
            namespace: Some("ids".into()),
            ..IdentityRef::named("weebo")
        })
    );
    let secret = Api::<Secret>::namespaced(client.clone(), "team-a")
        .get("alice-forgejo")
        .await
        .unwrap();
    assert_eq!(
        secret.metadata.annotations.unwrap()[api::SECRET_OWNER_ANNOTATION],
        "ForgejoUser/team-a/alice"
    );
    std::fs::remove_dir_all(out).unwrap();
}
