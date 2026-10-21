//! Integration test: CRs written when `spec.instanceRef` was a bare name
//! are rewritten as `{name: …}` by the kit's migration (the operator's
//! `migrate-instance-ref` command) once the new CRDs are applied — the
//! immutability rule on `instanceRef` included.
#![expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test helpers fail the test on purpose"
)]

use std::time::Duration;

use api::common::InstanceRef;
use api::{ForgejoRepository, ForgejoUser};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ApiResource, DynamicObject, PostParams};
use kube::{Client, CustomResourceExt};
use serde_json::{Value, json};
use testkit::envtest::EnvTestCluster;
use weebo_kit_adapters::migrate::migrate_instance_refs;

const TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(250);

/// Retries `attempt` until it succeeds: a CRD's new schema reaches the
/// apiserver's handlers asynchronously.
async fn eventually<T, E: std::fmt::Debug, F: std::future::Future<Output = Result<T, E>>>(
    what: &str,
    mut attempt: impl FnMut() -> F,
) -> T {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        match attempt().await {
            Ok(v) => return v,
            Err(e) if tokio::time::Instant::now() > deadline => panic!("{what}: {e:?}"),
            Err(_) => tokio::time::sleep(POLL).await,
        }
    }
}

/// Replaces the versions of CRD `name`.
async fn set_versions(crds: &Api<CustomResourceDefinition>, name: &str, versions: Value) {
    let mut crd = serde_json::to_value(crds.get(name).await.unwrap()).unwrap();
    crd["spec"]["versions"] = versions;
    let crd: CustomResourceDefinition = serde_json::from_value(crd).unwrap();
    crds.replace(name, &PostParams::default(), &crd)
        .await
        .unwrap();
}

/// The CRD as it was: `instanceRef` a bare string, its immutability rule on
/// strings.
fn legacy(versions: &Value) -> Value {
    let mut old = versions.clone();
    let schema = &mut old[0]["schema"]["openAPIV3Schema"];
    schema["properties"]["spec"]["properties"]["instanceRef"] = json!({"type": "string"});
    let rules = schema["x-kubernetes-validations"].as_array_mut().unwrap();
    rules.retain(|r| !r["rule"].as_str().unwrap().contains("instanceRef"));
    rules.push(json!({
        "rule": "(has(self.spec.instanceRef) ? self.spec.instanceRef : '') == (has(oldSelf.spec.instanceRef) ? oldSelf.spec.instanceRef : '')",
        "message": "spec.instanceRef is immutable",
    }));
    old
}

#[tokio::test]
async fn bare_name_instance_refs_are_rewritten_as_objects() {
    let cluster = EnvTestCluster::start().await;
    let client: Client = cluster.client();
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let pp = PostParams::default();
    let mut current = Vec::new();
    for name in [ForgejoUser::crd_name(), ForgejoRepository::crd_name()] {
        let crd = serde_json::to_value(crds.get(name).await.unwrap()).unwrap();
        let versions = crd["spec"]["versions"].clone();
        set_versions(&crds, name, legacy(&versions)).await;
        current.push((name, versions));
    }
    let users = ApiResource::erase::<ForgejoUser>(&());
    let repos = ApiResource::erase::<ForgejoRepository>(&());
    let legacy_user: DynamicObject = serde_json::from_value(json!({
        "apiVersion": users.api_version, "kind": users.kind,
        "metadata": {"name": "alice", "namespace": "default"},
        "spec": {"instanceRef": "main", "username": "alice", "email": "alice@example.com"}
    }))
    .unwrap();
    let legacy_repo: DynamicObject = serde_json::from_value(json!({
        "apiVersion": repos.api_version, "kind": repos.kind,
        "metadata": {"name": "app", "namespace": "default"},
        "spec": {"instanceRef": "main", "organizationRef": {"name": "weebo"}, "name": "app"}
    }))
    .unwrap();
    let user_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), "default", &users);
    let repo_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), "default", &repos);
    eventually("creating a legacy user", || {
        user_api.create(&pp, &legacy_user)
    })
    .await;
    eventually("creating a legacy repository", || {
        repo_api.create(&pp, &legacy_repo)
    })
    .await;

    // The new CRDs, then the migration.
    for (name, versions) in current {
        set_versions(&crds, name, versions).await;
    }
    let kinds = [users, repos];
    let dry = migrate_instance_refs(&client, &kinds, "test", true)
        .await
        .unwrap();
    assert_eq!(dry.migrated.len(), 2, "{dry:?}");
    eventually("migrating", || {
        migrate_instance_refs(&client, &kinds, "test", false)
    })
    .await;

    let main = Some(InstanceRef::named("main"));
    let user_api: Api<ForgejoUser> = Api::namespaced(client.clone(), "default");
    let user = eventually("reading the user", || user_api.get("alice")).await;
    assert_eq!(user.spec.instance_ref, main);
    let repo_api: Api<ForgejoRepository> = Api::namespaced(client.clone(), "default");
    let repo = eventually("reading the repository", || repo_api.get("app")).await;
    assert_eq!(repo.spec.instance_ref, main);
    // Replayable: nothing left to do.
    let again = migrate_instance_refs(&client, &kinds, "test", false)
        .await
        .unwrap();
    assert!(again.migrated.is_empty());
}
