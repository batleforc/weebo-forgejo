//! Layer-3: references to users, organizations and teams now that they are
//! namespaced — across namespaces (enabled for the operator *and* shared by
//! the target), by Forgejo name (`remoteName`), and the unique claim of a
//! Forgejo object by one CR across namespaces.
#![expect(clippy::unwrap_used, reason = "test helpers fail the test on purpose")]

mod support;

use adapters_inbound::controller;
use api::{ForgejoInstance, ForgejoOrganization, ForgejoRepository};
use k8s_openapi::api::core::v1::Namespace;
use kube::Client;
use kube::api::{Api, Patch, PatchParams, PostParams};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use support::{condition, harness, harness_with, wait_for};
use weebo_kit_runtime::WatchScope;

fn manifest<K: DeserializeOwned>(kind: &str, name: &str, ns: Option<&str>, spec: Value) -> K {
    serde_json::from_value(json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": kind,
        "metadata": {"name": name, "namespace": ns}, "spec": spec,
    }))
    .unwrap()
}

async fn namespaces(client: &Client, names: &[&str]) {
    let api: Api<Namespace> = Api::all(client.clone());
    for name in names {
        let ns: Namespace = serde_json::from_value(json!({"metadata": {"name": name}})).unwrap();
        api.create(&PostParams::default(), &ns).await.unwrap();
    }
}

/// The `ForgejoInstance` the harness resolves every CR to (no
/// `instanceRef`): its URL is the server the unique claim compares.
async fn default_instance(client: &Client) {
    let instance: ForgejoInstance = manifest(
        "ForgejoInstance",
        "default",
        None,
        json!({"url": "https://git.example.com",
               "tokenSecretRef": {"name": "t", "namespace": "default", "key": "token"}}),
    );
    Api::<ForgejoInstance>::all(client.clone())
        .create(&PostParams::default(), &instance)
        .await
        .unwrap();
}

fn ready(status: Option<&api::ForgejoStatus>) -> Option<(String, String)> {
    condition(status, "Ready")
}

async fn organization(client: &Client, ns: &str, name: &str, forgejo_name: &str) {
    let org: ForgejoOrganization = manifest(
        "ForgejoOrganization",
        name,
        Some(ns),
        json!({"name": forgejo_name}),
    );
    Api::<ForgejoOrganization>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &org)
        .await
        .unwrap();
}

async fn repository(client: &Client, ns: &str, name: &str, owner: Value) {
    let mut spec = json!({"name": name});
    spec.as_object_mut()
        .unwrap()
        .extend(owner.as_object().unwrap().clone());
    let repo: ForgejoRepository = manifest("ForgejoRepository", name, Some(ns), spec);
    Api::<ForgejoRepository>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &repo)
        .await
        .unwrap();
}

#[tokio::test]
async fn another_namespace_is_refused_while_the_operator_doesnt_allow_it() {
    let h = harness().await;
    namespaces(&h.client, &["ids", "team-b"]).await;
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));
    tokio::spawn(controller::repository::run(h.client.clone(), h.ctx.clone()));
    organization(&h.client, "ids", "weebo", "weebo").await;
    let orgs: Api<ForgejoOrganization> = Api::namespaced(h.client.clone(), "ids");
    // Shared, but the release doesn't enable cross-namespace references.
    orgs.patch(
        "weebo",
        &PatchParams::default(),
        &Patch::Merge(json!({"spec": {"sharedWith": {"namespaces": ["team-b"]}}})),
    )
    .await
    .unwrap();
    repository(
        &h.client,
        "team-b",
        "app",
        json!({"organizationRef": {"name": "weebo", "namespace": "ids"}}),
    )
    .await;
    let repos: Api<ForgejoRepository> = Api::namespaced(h.client.clone(), "team-b");
    let refused = wait_for(&repos, "app", |r| ready(r.status.as_ref())).await;
    assert_eq!(refused, ("False".into(), "ReferenceNotAllowed".into()));
}

#[tokio::test]
async fn another_namespace_needs_the_target_to_share_itself() {
    let h = harness_with(WatchScope::cluster().with_cross_namespace_refs()).await;
    namespaces(&h.client, &["ids", "team-b"]).await;
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));
    tokio::spawn(controller::repository::run(h.client.clone(), h.ctx.clone()));
    organization(&h.client, "ids", "weebo", "weebo").await;
    let orgs: Api<ForgejoOrganization> = Api::namespaced(h.client.clone(), "ids");
    wait_for(&orgs, "weebo", |o| {
        ready(o.status.as_ref()).filter(|(s, _)| s == "True")
    })
    .await;
    repository(
        &h.client,
        "team-b",
        "app",
        json!({"organizationRef": {"name": "weebo", "namespace": "ids"}}),
    )
    .await;
    let repos: Api<ForgejoRepository> = Api::namespaced(h.client.clone(), "team-b");
    let refused = wait_for(&repos, "app", |r| ready(r.status.as_ref())).await;
    assert_eq!(refused, ("False".into(), "ReferenceNotAllowed".into()));

    // Shared with team-b: the organization's change re-triggers the
    // repository, which is created in it.
    orgs.patch(
        "weebo",
        &PatchParams::default(),
        &Patch::Merge(json!({"spec": {"sharedWith": {"namespaces": ["team-b"]}}})),
    )
    .await
    .unwrap();
    let created = wait_for(&repos, "app", |r| {
        let status = r.status.as_ref()?;
        (ready(Some(status))?.0 == "True").then(|| status.forgejo_name.clone())?
    })
    .await;
    assert_eq!(created, "weebo/app");
}

#[tokio::test]
async fn a_remote_name_is_used_as_is_and_never_managed() {
    let h = harness().await;
    h.forgejo.insert_user("ops");
    tokio::spawn(controller::repository::run(h.client.clone(), h.ctx.clone()));
    repository(
        &h.client,
        "default",
        "dots",
        json!({"userRef": {"remoteName": "ops"}}),
    )
    .await;
    repository(
        &h.client,
        "default",
        "ghost",
        json!({"userRef": {"remoteName": "ghost"}}),
    )
    .await;
    let repos: Api<ForgejoRepository> = Api::namespaced(h.client.clone(), "default");
    let created = wait_for(&repos, "dots", |r| {
        let status = r.status.as_ref()?;
        (ready(Some(status))?.0 == "True").then(|| status.forgejo_name.clone())?
    })
    .await;
    assert_eq!(created, "ops/dots");
    let missing = wait_for(&repos, "ghost", |r| ready(r.status.as_ref())).await;
    assert_eq!(missing, ("False".into(), "ReferenceNotFound".into()));
    assert!(
        h.forgejo
            .calls()
            .iter()
            .all(|c| !c.contains("user") || c.starts_with("get_user")),
        "a remote user is only read: {:?}",
        h.forgejo.calls()
    );
}

#[tokio::test]
async fn a_forgejo_object_is_owned_by_one_cr_across_namespaces() {
    let h = harness().await;
    namespaces(&h.client, &["team-a", "team-b"]).await;
    default_instance(&h.client).await;
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));
    organization(&h.client, "team-a", "weebo", "weebo").await;
    let first: Api<ForgejoOrganization> = Api::namespaced(h.client.clone(), "team-a");
    wait_for(&first, "weebo", |o| {
        ready(o.status.as_ref()).filter(|(s, _)| s == "True")
    })
    .await;
    h.forgejo.clear_calls();

    // Same server, same name, another namespace: refused, nothing called.
    organization(&h.client, "team-b", "platform", "weebo").await;
    let second: Api<ForgejoOrganization> = Api::namespaced(h.client.clone(), "team-b");
    let claimed = wait_for(&second, "platform", |o| ready(o.status.as_ref())).await;
    assert_eq!(claimed, ("False".into(), "RemoteObjectClaimed".into()));
    assert!(
        h.forgejo
            .calls()
            .iter()
            .all(|c| !c.starts_with("create_organization")),
        "{:?}",
        h.forgejo.calls()
    );
}
