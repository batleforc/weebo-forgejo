//! Layer-3: the admission webhook router answering real `AdmissionReview`s
//! against real `ForgejoNamespacePolicy` objects in a real apiserver, and
//! the Vault paths of `secretTargets` against a real `ForgejoInstance`.

mod support;

use std::sync::Arc;

use adapters_inbound::webhook::{WebhookState, router};
use adapters_outbound::{ForgejoInstanceVaults, ForgejoInstances, KubeClusterReader};
use api::{ForgejoInstance, ForgejoNamespacePolicy};
use axum::body::Body;
use http_body_util::BodyExt;
use kube::api::{Api, PostParams};
use serde_json::{Value, json};
use support::harness;
use tower::ServiceExt;

fn review(namespace: &str, kind: &str, spec: Value) -> Value {
    json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "11111111-1111-1111-1111-111111111111",
            "namespace": namespace,
            "kind": {"group": "forgejo.weebo.io", "version": "v1alpha1", "kind": kind},
            "resource": {"group": "forgejo.weebo.io", "version": "v1alpha1", "resource": "x"},
            "operation": "CREATE",
            "userInfo": {},
            "object": {
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": kind,
                "metadata": {"name": "x", "namespace": namespace},
                "spec": spec,
            },
        }
    })
}

async fn admit(client: &kube::Client, body: Value) -> (bool, String) {
    admit_on(client, body, false).await
}

/// `with_instances`: the CR's instance is resolved (and its Vault paths
/// checked), from the API.
async fn admit_on(client: &kube::Client, body: Value, with_instances: bool) -> (bool, String) {
    let cluster = Arc::new(KubeClusterReader::new(client.clone()));
    let instances = Arc::new(ForgejoInstances::new(client.clone()));
    let app = router(
        WebhookState {
            policies: cluster.clone(),
            refs: cluster,
            instances: with_instances.then(|| instances.clone() as _),
            vaults: with_instances.then(|| Arc::new(ForgejoInstanceVaults(instances)) as _),
        },
        Default::default(),
        weebo_kit_runtime::WatchScope::cluster(),
    );
    let request = axum::http::Request::post("/validate")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let review: Value = serde_json::from_slice(&bytes).unwrap();
    let r = &review["response"];
    (
        r["allowed"].as_bool().unwrap(),
        r["status"]["message"].as_str().unwrap_or("").to_string(),
    )
}

#[tokio::test]
async fn webhook_enforces_the_live_policies() {
    let h = harness().await;
    let token = |user: &str| json!({"userRef": {"name": user}, "scopes": ["read:user"]});
    let repo = |org: &str| json!({"organizationRef": {"name": org}, "name": "app"});

    // No policy at all: everything goes.
    assert!(
        admit(
            &h.client,
            review("team-a", "ForgejoAccessToken", token("admin-bot"))
        )
        .await
        .0
    );

    let policies: Api<ForgejoNamespacePolicy> = Api::all(h.client.clone());
    policies
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoNamespacePolicy",
                "metadata": {"name": "teams"},
                "spec": {"rules": [
                    {"namespaces": ["team-*"], "allowedKinds": ["ForgejoRepository"],
                     "allowedOrganizations": ["weebo"]},
                    {"namespaces": ["team-a"], "allowedKinds": ["ForgejoAccessToken"],
                     "allowedUsers": ["ci-bot"]},
                ]},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        admit(
            &h.client,
            review("team-b", "ForgejoRepository", repo("weebo"))
        )
        .await
        .0
    );
    let (allowed, message) = admit(
        &h.client,
        review("team-b", "ForgejoRepository", repo("other")),
    )
    .await;
    assert!(!allowed);
    assert!(message.contains("organizations [\"other\"]"), "{message}");

    assert!(
        admit(
            &h.client,
            review("team-a", "ForgejoAccessToken", token("ci-bot"))
        )
        .await
        .0
    );
    assert!(
        !admit(
            &h.client,
            review("team-a", "ForgejoAccessToken", token("admin-bot"))
        )
        .await
        .0
    );
    assert!(
        !admit(
            &h.client,
            review("ops", "ForgejoAccessToken", token("ci-bot"))
        )
        .await
        .0
    );
}

#[tokio::test]
async fn vault_paths_outside_the_subtree_need_a_grant() {
    let h = harness().await;
    let app = |path: &str| {
        json!({"redirectUris": ["https://argocd.example.com/auth/callback"],
               "secretTargets": [{"backend": "vault", "name": "argocd", "path": path}]})
    };
    // The admin's credentials (no ownerRef) need an Allow rule naming it.
    Api::<ForgejoNamespacePolicy>::all(h.client.clone())
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoNamespacePolicy",
                "metadata": {"name": "apps"},
                "spec": {"rules": [{"namespaces": ["ci", "team-a"],
                                    "allowedKinds": ["ForgejoOAuth2Application"],
                                    "allowedUsers": ["@instance-admin"]}]},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    // No instance yet: left to the reconcile.
    let (allowed, message) = admit_on(
        &h.client,
        review("ci", "ForgejoOAuth2Application", app("argocd/auth")),
        true,
    )
    .await;
    assert!(allowed, "{message}");

    let instances: Api<ForgejoInstance> = Api::all(h.client.clone());
    let instance = |grants: Value| -> ForgejoInstance {
        serde_json::from_value(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoInstance",
            "metadata": {"name": "main"},
            "spec": {"url": "https://git.example.com",
                     "tokenSecretRef": {"name": "t", "namespace": "default", "key": "token"},
                     "secretStore": {"vault": {
                         "address": "https://vault:8200", "mount": "secret",
                         "kubernetesAuthRole": "forgejo", "pathGrants": grants}}},
        }))
        .unwrap()
    };
    // The schema refuses a whole-mount grant.
    let err = instances
        .create(
            &PostParams::default(),
            &instance(json!([{"namespaces": ["ci"], "paths": ["+/*"]}])),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("literal segment"), "{err}");
    // And a cluster-scoped grant: every emitting kind is namespaced.
    let err = instances
        .create(
            &PostParams::default(),
            &instance(json!([{"clusterScoped": true, "paths": ["shared/*"]}])),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("clusterScoped grants never apply"),
        "{err}"
    );
    instances
        .create(
            &PostParams::default(),
            &instance(json!([{"namespaces": ["ci"], "paths": ["argocd/auth"]}])),
        )
        .await
        .unwrap();

    let (allowed, message) = admit_on(
        &h.client,
        review("team-a", "ForgejoOAuth2Application", app("argocd/auth")),
        true,
    )
    .await;
    assert!(!allowed);
    assert!(message.contains("no pathGrants entry"), "{message}");
    for (namespace, path) in [
        ("ci", "argocd/auth"),
        ("team-a", "weebo-forgejo/team-a/app"),
    ] {
        let (allowed, message) = admit_on(
            &h.client,
            review(namespace, "ForgejoOAuth2Application", app(path)),
            true,
        )
        .await;
        assert!(allowed, "{namespace} {path}: {message}");
    }
}
