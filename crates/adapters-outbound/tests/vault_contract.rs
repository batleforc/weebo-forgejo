//! Layer-2: the Vault KV v2 store against scripted HTTP — Kubernetes-auth
//! login, idempotent writes (no new KV version for identical data),
//! existence checks and hard deletes, routed through `RoutingSecretStore`'s
//! `vault` backend.

use std::collections::BTreeMap;

use adapters_outbound::secret_vault::VaultSecretStore;
use api::instance::VaultSecretStoreSpec;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn spec(server: &MockServer) -> VaultSecretStoreSpec {
    VaultSecretStoreSpec {
        address: server.uri(),
        mount: "secret".into(),
        path_prefix: "weebo-forgejo".into(),
        kubernetes_auth_role: "weebo-forgejo".into(),
        kubernetes_auth_mount: "kubernetes".into(),
        ca_secret_ref: None,
    }
}

/// Vault wraps every response in this envelope (`vaultrs` requires the
/// top-level fields).
fn envelope(data: serde_json::Value, auth: serde_json::Value) -> serde_json::Value {
    json!({
        "request_id": "r", "lease_id": "", "lease_duration": 0, "renewable": false,
        "data": data, "auth": auth, "wrap_info": null, "warnings": null,
    })
}

async fn login(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .and(body_partial_json(
            json!({"role": "weebo-forgejo", "jwt": "sa-jwt"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            serde_json::Value::Null,
            json!({
                "client_token": "vault-token",
                "accessor": "a",
                "policies": [],
                "token_policies": [],
                "metadata": {},
                "lease_duration": 3600,
                "renewable": true,
                "entity_id": "",
                "token_type": "service",
                "orphan": true,
            }),
        )))
        .mount(server)
        .await;
}

fn kv_response(data: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(envelope(
        json!({
            "data": data,
            "metadata": {
                "created_time": "2026-10-06T00:00:00Z",
                "custom_metadata": null,
                "deletion_time": "",
                "destroyed": false,
                "version": 1
            }
        }),
        serde_json::Value::Null,
    ))
}

#[tokio::test]
async fn logs_in_and_caches_for_most_of_the_lease() {
    let server = MockServer::start().await;
    login(&server).await;
    let store = VaultSecretStore::new(&spec(&server), "sa-jwt\n", None)
        .await
        .unwrap();
    assert_eq!(
        store.cache_ttl(),
        Some(std::time::Duration::from_secs(2880))
    );
    assert_eq!(
        store.default_path("team-a", "app"),
        "weebo-forgejo/team-a/app"
    );
}

#[tokio::test]
async fn identical_data_is_not_rewritten() {
    let server = MockServer::start().await;
    login(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/weebo-forgejo/team-a/app"))
        .respond_with(kv_response(json!({"FORGEJO_TOKEN": "t"})))
        .mount(&server)
        .await;
    // A write would be a new KV version: it must not happen.
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/weebo-forgejo/team-a/app"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let store = VaultSecretStore::new(&spec(&server), "sa-jwt", None)
        .await
        .unwrap();
    let data = BTreeMap::from([("FORGEJO_TOKEN".to_string(), "t".to_string())]);
    store
        .write_path("weebo-forgejo/team-a/app", &data)
        .await
        .unwrap();
}

#[tokio::test]
async fn new_data_is_written_with_the_vault_token() {
    let server = MockServer::start().await;
    login(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/custom/path"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"errors": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/custom/path"))
        .and(wiremock::matchers::header("X-Vault-Token", "vault-token"))
        .and(body_partial_json(json!({"data": {"FORGEJO_TOKEN": "t2"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(
            json!({"created_time": "2026-10-06T00:00:00Z", "custom_metadata": null,
                   "deletion_time": "", "destroyed": false, "version": 2}),
            serde_json::Value::Null,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let store = VaultSecretStore::new(&spec(&server), "sa-jwt", None)
        .await
        .unwrap();
    assert_eq!(store.read_path("custom/path").await.unwrap(), None);
    let data = BTreeMap::from([("FORGEJO_TOKEN".to_string(), "t2".to_string())]);
    store.write_path("custom/path", &data).await.unwrap();
}

#[tokio::test]
async fn delete_removes_every_version_and_is_idempotent() {
    let server = MockServer::start().await;
    login(&server).await;
    Mock::given(method("DELETE"))
        .and(path("/v1/secret/metadata/gone"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"errors": []})))
        .mount(&server)
        .await;
    let store = VaultSecretStore::new(&spec(&server), "sa-jwt", None)
        .await
        .unwrap();
    store.delete_path("gone").await.unwrap();
}

#[tokio::test]
async fn an_expired_token_relogs_in_once() {
    let server = MockServer::start().await;
    login(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/p"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/p"))
        .respond_with(kv_response(json!({"k": "v"})))
        .mount(&server)
        .await;
    let store = VaultSecretStore::new(&spec(&server), "sa-jwt", None)
        .await
        .unwrap();
    let read = store.read_path("p").await.unwrap().unwrap();
    assert_eq!(read["k"], "v");
    let logins = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/v1/auth/kubernetes/login")
        .count();
    assert_eq!(logins, 2);
}
