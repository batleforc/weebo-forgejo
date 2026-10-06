//! Layer-3: the admission webhook router answering real `AdmissionReview`s
//! against real `ForgejoNamespacePolicy` objects in a real apiserver.

mod support;

use adapters_inbound::webhook::{WebhookState, router};
use api::ForgejoNamespacePolicy;
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
    let app = router(WebhookState {
        client: client.clone(),
    });
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
