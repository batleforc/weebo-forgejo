//! Layer-4: access tokens, OAuth2 applications and the Vault secret store,
//! end to end — every controller on envtest against the live Forgejo
//! (`task test:live-forgejo`), and for Vault a real `vault server -dev`
//! whose Kubernetes auth validates envtest-issued ServiceAccount tokens.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test helpers fail the test on purpose"
)]

mod support;

use std::time::Duration;

use api::{ForgejoAccessToken, ForgejoOAuth2Application, ForgejoRepository, ForgejoUser};
use application::ports::ForgejoGateway;
use k8s_openapi::api::core::v1::{Namespace, Secret, ServiceAccount};
use k8s_openapi::api::rbac::v1::ClusterRoleBinding;
use kube::api::{Api, Patch, PatchParams, PostParams};
use serde_json::json;
use support::live::{Live, NS, Options, failed_with, live, live_with, ready, ready_id};
use support::{wait_for, wait_for_absence};

const ROTATE: &str = "forgejo.weebo.io/rotate-secret";
const DISRUPTIVE: &str = "forgejo.weebo.io/allow-disruptive-update";

/// A bot `ForgejoUser` (deleted with its CR); returns its Forgejo login.
async fn bot(l: &Live, cr_name: &str) -> String {
    let login = l.name(cr_name);
    let users: Api<ForgejoUser> = l.api();
    l.create(
        &users,
        json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
            "metadata": {"name": cr_name},
            "spec": {"username": login, "email": format!("{login}@weebo.local"), "bot": true,
                     "deletionPolicy": "Delete"},
        }),
    )
    .await;
    wait_for(&users, cr_name, |u| ready(u.status.as_ref())).await;
    login
}

async fn token_cr(l: &Live, name: &str, spec: serde_json::Value) {
    let tokens: Api<ForgejoAccessToken> = l.api();
    l.create(
        &tokens,
        json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
            "metadata": {"name": name}, "spec": spec,
        }),
    )
    .await;
}

/// HTTP status of `GET /api/v1{path}` with `token`.
async fn status_with(l: &Live, token: &str, path: &str) -> u16 {
    reqwest::Client::new()
        .get(format!("{}/api/v1{path}", l.url))
        .header("Authorization", format!("token {token}"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn annotate<K>(api: &Api<K>, name: &str, key: &str, value: &str)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    api.patch(
        name,
        &PatchParams::default(),
        &Patch::Merge(json!({"metadata": {"annotations": {key: value}}})),
    )
    .await
    .unwrap();
}

async fn patch_spec<K>(api: &Api<K>, name: &str, spec: serde_json::Value)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    api.patch(
        name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "spec": spec })),
    )
    .await
    .unwrap();
}

/// The current Forgejo id of a CR once it is `Ready` with an id other than
/// `not`.
async fn new_id<K>(
    api: &Api<K>,
    name: &str,
    not: i64,
    status: fn(&K) -> Option<&api::ForgejoStatus>,
) -> i64
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    wait_for(api, name, |k| ready_id(status(k)).filter(|id| *id != not)).await
}

fn token_status(t: &ForgejoAccessToken) -> Option<&api::ForgejoStatus> {
    t.status.as_ref()
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn token_rotation_nonce_revokes_the_old_value() {
    let l = live().await;
    bot(&l, "bot").await;
    token_cr(
        &l,
        "ci",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:user"]}),
    )
    .await;
    let tokens: Api<ForgejoAccessToken> = l.api();
    let first_id = wait_for(&tokens, "ci", |t| ready_id(token_status(t))).await;
    let first = l.secret_value("ci", "FORGEJO_TOKEN").await.unwrap();
    assert_eq!(status_with(&l, &first, "/user").await, 200);

    annotate(&tokens, "ci", ROTATE, "r1").await;
    wait_for(&tokens, "ci", |t| {
        (t.status.as_ref()?.last_rotation.as_deref() == Some("r1")).then_some(())
    })
    .await;
    let second_id = new_id(&tokens, "ci", first_id, token_status).await;
    assert_ne!(second_id, first_id);
    let second = l.secret_value("ci", "FORGEJO_TOKEN").await.unwrap();
    assert_ne!(second, first);
    assert_eq!(
        status_with(&l, &first, "/user").await,
        401,
        "old token revoked"
    );
    assert_eq!(status_with(&l, &second, "/user").await, 200);

    // Steady state: the same nonce never rotates again.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(l.secret_value("ci", "FORGEJO_TOKEN").await.unwrap(), second);

    tokens.delete("ci", &Default::default()).await.unwrap();
    wait_for_absence(&tokens, "ci").await;
    assert_eq!(status_with(&l, &second, "/user").await, 401);
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn token_rotation_period_reissues_an_expired_token() {
    let l = live().await;
    bot(&l, "bot").await;
    token_cr(
        &l,
        "ci",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:user"], "rotationPeriod": "3s"}),
    )
    .await;
    let tokens: Api<ForgejoAccessToken> = l.api();
    let first_id = wait_for(&tokens, "ci", |t| ready_id(token_status(t))).await;
    let first = l.secret_value("ci", "FORGEJO_TOKEN").await.unwrap();

    // No event needed: the controller requeues for the moment the token
    // expires (Outcome::due_in), not at the 300 s steady-state requeue.
    new_id(&tokens, "ci", first_id, token_status).await;
    let second = l.secret_value("ci", "FORGEJO_TOKEN").await.unwrap();
    assert_ne!(second, first);
    assert_eq!(status_with(&l, &first, "/user").await, 401);
    assert_eq!(status_with(&l, &second, "/user").await, 200);
    tokens.delete("ci", &Default::default()).await.unwrap();
    wait_for_absence(&tokens, "ci").await;
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn token_scope_change_needs_the_disruptive_annotation() {
    let l = live().await;
    let login = bot(&l, "bot").await;
    token_cr(
        &l,
        "ci",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:user"]}),
    )
    .await;
    let tokens: Api<ForgejoAccessToken> = l.api();
    let first_id = wait_for(&tokens, "ci", |t| ready_id(token_status(t))).await;
    let first = l.secret_value("ci", "FORGEJO_TOKEN").await.unwrap();

    patch_spec(
        &tokens,
        "ci",
        json!({"scopes": ["read:user", "read:repository"]}),
    )
    .await;
    wait_for(&tokens, "ci", |t| {
        failed_with(token_status(t), "DisruptiveUpdateRefused")
    })
    .await;
    assert_eq!(
        status_with(&l, &first, "/user").await,
        200,
        "a refused change keeps the current token"
    );

    annotate(&tokens, "ci", DISRUPTIVE, "true").await;
    let second_id = new_id(&tokens, "ci", first_id, token_status).await;
    let remote = l.fj.list_access_tokens(&login).await.unwrap();
    let issued = remote.iter().find(|t| t.id == second_id).unwrap();
    let mut scopes = issued.scopes.clone();
    scopes.sort();
    assert_eq!(scopes, vec!["read:repository", "read:user"]);
    assert!(remote.iter().all(|t| t.id != first_id), "old token revoked");
    tokens.delete("ci", &Default::default()).await.unwrap();
    wait_for_absence(&tokens, "ci").await;
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn repository_limited_token_reads_only_its_repository() {
    let l = live().await;
    let login = bot(&l, "bot").await;
    let repos: Api<ForgejoRepository> = l.api();
    for name in ["app", "other"] {
        l.create(
            &repos,
            json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoRepository",
                "metadata": {"name": name},
                "spec": {"userRef": {"name": "bot"}, "name": name, "private": true,
                         "init": {"readme": "Default"}, "deletionPolicy": "Delete"},
            }),
        )
        .await;
        wait_for(&repos, name, |r| ready(r.status.as_ref())).await;
    }

    token_cr(
        &l,
        "app-only",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:repository"],
               "repositoryRefs": [{"name": "app"}]}),
    )
    .await;
    // Forgejo only allows repository scopes on such a token: caught early.
    token_cr(
        &l,
        "bad",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:repository", "read:user"],
               "repositoryRefs": [{"name": "app"}]}),
    )
    .await;
    let tokens: Api<ForgejoAccessToken> = l.api();
    let id = wait_for(&tokens, "app-only", |t| ready_id(token_status(t))).await;
    wait_for(&tokens, "bad", |t| {
        failed_with(token_status(t), "InvalidSpec")
    })
    .await;
    assert!(l.secret_value("bad", "FORGEJO_TOKEN").await.is_none());

    let remote = l.fj.list_access_tokens(&login).await.unwrap();
    let issued = remote.iter().find(|t| t.id == id).unwrap();
    assert_eq!(issued.repositories, vec![format!("{login}/app")]);
    let token = l.secret_value("app-only", "FORGEJO_TOKEN").await.unwrap();
    assert_eq!(
        status_with(&l, &token, &format!("/repos/{login}/app")).await,
        200
    );
    assert_ne!(
        status_with(&l, &token, &format!("/repos/{login}/other")).await,
        200,
        "the token must not reach a repository it isn't limited to"
    );

    for name in ["app-only", "bad"] {
        tokens.delete(name, &Default::default()).await.unwrap();
        wait_for_absence(&tokens, name).await;
    }
    for name in ["app", "other"] {
        repos.delete(name, &Default::default()).await.unwrap();
        wait_for_absence(&repos, name).await;
    }
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn token_fans_out_and_is_reissued_when_a_target_is_lost() {
    let l = live().await;
    bot(&l, "bot").await;
    let namespaces: Api<Namespace> = l.cluster_api();
    l.create(&namespaces, json!({"metadata": {"name": "other"}}))
        .await;
    // A namespaced CR never writes into another namespace.
    token_cr(
        &l,
        "escape",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:user"],
               "secretTargets": [{"name": "stolen", "namespace": "other"}]}),
    )
    .await;
    let tokens: Api<ForgejoAccessToken> = l.api();
    wait_for(&tokens, "escape", |t| {
        let ready = token_status(t)?
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")?;
        (ready.reason == "CrossNamespaceReference").then_some(())
    })
    .await;
    let elsewhere: Api<Secret> = Api::namespaced(l.client.clone(), "other");
    assert!(elsewhere.get_opt("stolen").await.unwrap().is_none());

    token_cr(
        &l,
        "ci",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:user"],
               "secretTargets": [{"name": "ci-a"}, {"name": "ci-b"}]}),
    )
    .await;
    let first_id = wait_for(&tokens, "ci", |t| ready_id(token_status(t))).await;
    let other: Api<Secret> = l.api();
    let read_other = || async {
        let s = other.get_opt("ci-b").await.unwrap()?;
        Some(String::from_utf8(s.data?.get("FORGEJO_TOKEN")?.0.clone()).unwrap())
    };
    let a = l.secret_value("ci-a", "FORGEJO_TOKEN").await.unwrap();
    assert_eq!(read_other().await.as_deref(), Some(a.as_str()));
    assert!(
        l.secret_value("ci", "FORGEJO_TOKEN").await.is_none(),
        "no implicit target"
    );

    // A token can't be read back: losing one target means a new token
    // for every target.
    other.delete("ci-b", &Default::default()).await.unwrap();
    tokens
        .patch(
            "ci",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"labels": {"poke": "1"}}})),
        )
        .await
        .unwrap();
    new_id(&tokens, "ci", first_id, token_status).await;
    let mut renewed = None;
    for _ in 0..50 {
        if let Some(v) = read_other().await {
            renewed = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let renewed = renewed.expect("the lost target was rewritten");
    assert_ne!(renewed, a);
    assert_eq!(
        l.secret_value("ci-a", "FORGEJO_TOKEN").await.unwrap(),
        renewed
    );
    assert_eq!(status_with(&l, &a, "/user").await, 401);

    tokens.delete("ci", &Default::default()).await.unwrap();
    wait_for_absence(&tokens, "ci").await;
    assert!(read_other().await.is_none(), "targets deleted with the CR");
    assert!(l.secret_value("ci-a", "FORGEJO_TOKEN").await.is_none());
}

fn app_status(a: &ForgejoOAuth2Application) -> Option<&api::ForgejoStatus> {
    a.status.as_ref()
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn oauth2_app_targets_updates_and_owner_move() {
    let l = live().await;
    let first_owner = bot(&l, "sso-a").await;
    let second_owner = bot(&l, "sso-b").await;
    let apps: Api<ForgejoOAuth2Application> = l.api();
    l.create(
        &apps,
        json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOAuth2Application",
            "metadata": {"name": "grafana"},
            "spec": {"ownerRef": {"name": "sso-a"},
                     "redirectUris": ["https://grafana.example.com/login"],
                     "secretTargets": [{"name": "grafana-sso"}]},
        }),
    )
    .await;
    let id = wait_for(&apps, "grafana", |a| ready_id(app_status(a))).await;
    assert!(
        l.secret_value("grafana", "FORGEJO_CLIENT_ID")
            .await
            .is_none(),
        "explicit target only"
    );
    let client_id = l
        .secret_value("grafana-sso", "FORGEJO_CLIENT_ID")
        .await
        .unwrap();
    let secret = l
        .secret_value("grafana-sso", "FORGEJO_CLIENT_SECRET")
        .await
        .unwrap();
    let remote =
        l.fj.get_oauth2_app(Some(&first_owner), id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(remote.client_id, client_id);
    assert!(remote.confidential_client);

    // A real change updates the app in place; Forgejo regenerates the
    // client secret on every update, so the new one is emitted.
    patch_spec(
        &apps,
        "grafana",
        json!({"redirectUris": ["https://grafana.example.com/login", "https://g2.example.com/login"],
               "confidentialClient": false}),
    )
    .await;
    let mut changed = None;
    for _ in 0..150 {
        let r =
            l.fj.get_oauth2_app(Some(&first_owner), id)
                .await
                .unwrap()
                .unwrap();
        if r.redirect_uris.len() == 2 && !r.confidential_client {
            changed = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let changed = changed.expect("the app was updated");
    assert_eq!(changed.id, id, "updated in place");
    assert_eq!(changed.client_id, client_id);
    wait_for(&apps, "grafana", |a| ready(app_status(a))).await;
    let mut regenerated = None;
    for _ in 0..50 {
        let v = l
            .secret_value("grafana-sso", "FORGEJO_CLIENT_SECRET")
            .await
            .unwrap();
        if v != secret {
            regenerated = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        regenerated.is_some(),
        "the regenerated client secret is emitted"
    );

    // Moving the app to another owner recreates it: refused until allowed.
    patch_spec(&apps, "grafana", json!({"ownerRef": {"name": "sso-b"}})).await;
    wait_for(&apps, "grafana", |a| {
        failed_with(app_status(a), "DisruptiveUpdateRefused")
    })
    .await;
    assert!(
        l.fj.get_oauth2_app(Some(&first_owner), id)
            .await
            .unwrap()
            .is_some()
    );
    annotate(&apps, "grafana", DISRUPTIVE, "true").await;
    let moved = new_id(&apps, "grafana", id, app_status).await;
    assert!(
        l.fj.get_oauth2_app(Some(&first_owner), id)
            .await
            .unwrap()
            .is_none()
    );
    let remote =
        l.fj.get_oauth2_app(Some(&second_owner), moved)
            .await
            .unwrap()
            .unwrap();
    assert_ne!(remote.client_id, client_id, "a new client id");
    let mut emitted = None;
    for _ in 0..50 {
        let v = l
            .secret_value("grafana-sso", "FORGEJO_CLIENT_ID")
            .await
            .unwrap();
        if v == remote.client_id {
            emitted = Some(v);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(emitted.is_some(), "the new client id is emitted");

    apps.delete("grafana", &Default::default()).await.unwrap();
    wait_for_absence(&apps, "grafana").await;
    assert!(
        l.fj.get_oauth2_app(Some(&second_owner), moved)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        l.secret_value("grafana-sso", "FORGEJO_CLIENT_ID")
            .await
            .is_none()
    );
}

// ── Real Vault ────────────────────────────────────────────────────────────────

/// `vault server -dev` (from mise) on a free port, killed on drop.
struct VaultDev {
    child: std::process::Child,
    addr: String,
}

impl Drop for VaultDev {
    fn drop(&mut self) {
        // Err: it already exited, nothing left to stop or reap.
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

const ROOT: &str = "root";

fn vault_log() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("weebo-forgejo-vault-{}.log", std::process::id()))
}

async fn vault_dev() -> VaultDev {
    // The free port is released before vault binds it: should another
    // process take it in between, vault exits, and we retry on a new one.
    for _ in 0..5 {
        if let Some(vault) = try_vault_dev().await {
            return vault;
        }
    }
    panic!("vault server -dev did not come up, see {:?}", vault_log());
}

/// `None` when vault exited before answering (its port was taken).
async fn try_vault_dev() -> Option<VaultDev> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // From mise.toml: `mise install`, then run under `mise exec` (tasks do).
    let child = std::process::Command::new("vault")
        .args([
            "server",
            "-dev",
            &format!("-dev-listen-address=127.0.0.1:{port}"),
            &format!("-dev-root-token-id={ROOT}"),
        ])
        // Vault only tells clients "permission denied": the reason (e.g. a
        // failed TokenReview) is in its own log.
        .arg("-log-level=debug")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(vault_log()).unwrap())
        .spawn()
        .expect("spawning `vault server -dev`: is vault on PATH (mise install)?");
    let mut vault = VaultDev {
        child,
        addr: format!("http://127.0.0.1:{port}"),
    };
    for _ in 0..100 {
        if vault.child.try_wait().unwrap().is_some() {
            return None;
        }
        let up = reqwest::Client::new()
            .get(format!("{}/v1/sys/health", vault.addr))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        // Still running: the answer came from our vault, not a squatter.
        if up && vault.child.try_wait().unwrap().is_none() {
            return Some(vault);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("vault server -dev did not come up, see {:?}", vault_log());
}

impl VaultDev {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> reqwest::Response {
        let mut req = reqwest::Client::new()
            .request(method, format!("{}/v1/{path}", self.addr))
            .header("X-Vault-Token", ROOT);
        if let Some(b) = body {
            req = req.json(&b);
        }
        req.send().await.unwrap()
    }

    async fn post(&self, path: &str, body: serde_json::Value) {
        let resp = self.call(reqwest::Method::POST, path, Some(body)).await;
        let status = resp.status();
        assert!(
            status.is_success(),
            "vault {path}: {status} {}",
            resp.text().await.unwrap()
        );
    }

    /// `(data, current version)` of a KV v2 secret under `secret/`.
    async fn kv(&self, path: &str) -> Option<(serde_json::Value, u64)> {
        let resp = self
            .call(reqwest::Method::GET, &format!("secret/data/{path}"), None)
            .await;
        if resp.status() == 404 {
            return None;
        }
        let body: serde_json::Value = resp.json().await.unwrap();
        Some((
            body["data"]["data"].clone(),
            body["data"]["metadata"]["version"].as_u64().unwrap(),
        ))
    }
}

/// A token for `sa` (created in the test namespace) through the
/// TokenRequest API — for `audience`, or the apiserver's own when `None`.
async fn sa_token(l: &Live, sa: &str, audience: Option<&str>) -> String {
    let sas: Api<ServiceAccount> = l.api();
    l.create(&sas, json!({"metadata": {"name": sa}})).await;
    let mut spec = json!({"expirationSeconds": 3600});
    if let Some(audience) = audience {
        spec["audiences"] = json!([audience]);
    }
    let request: k8s_openapi::api::authentication::v1::TokenRequest =
        serde_json::from_value(json!({ "spec": spec })).unwrap();
    sas.create_token_request(sa, &PostParams::default(), &request)
        .await
        .unwrap_or_else(|e| panic!("envtest refused a TokenRequest for {sa}: {e}"))
        .status
        .and_then(|s| s.token)
        .expect("TokenRequest issued no token")
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
#[expect(unsafe_code, reason = "set_var is unsafe since edition 2024")]
async fn vault_secret_store_end_to_end() {
    use base64::Engine;

    let vault = vault_dev().await;
    let jwt_file =
        std::env::temp_dir().join(format!("weebo-forgejo-vault-jwt-{}", std::process::id()));
    // SAFETY: set before any controller runs; the only reader is the
    // secret store factory, and no other test here configures Vault.
    unsafe { std::env::set_var("VAULT_KUBERNETES_JWT_PATH", &jwt_file) };

    let l = live_with(Options {
        secret_store: json!({
            "backend": "vault",
            "vault": {"address": vault.addr, "mount": "secret",
                      "kubernetesAuthRole": "weebo-forgejo"},
        }),
    })
    .await;

    // Vault's Kubernetes auth reviews tokens against envtest's apiserver,
    // as a ServiceAccount allowed to (system:auth-delegator).
    let kubeconfig = l.cluster.kubeconfig();
    let cluster = &kubeconfig.clusters[0].cluster.as_ref().unwrap();
    let ca_pem = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(cluster.certificate_authority_data.as_ref().unwrap())
            .unwrap(),
    )
    .unwrap();
    // The reviewer token authenticates Vault's TokenReview calls to the
    // apiserver: it must carry the apiserver's own audience.
    let reviewer = sa_token(&l, "vault-reviewer", None).await;
    let bindings: Api<ClusterRoleBinding> = l.cluster_api();
    l.create(
        &bindings,
        json!({
            "metadata": {"name": "vault-reviewer"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                        "name": "system:auth-delegator"},
            "subjects": [{"kind": "ServiceAccount", "name": "vault-reviewer", "namespace": NS}],
        }),
    )
    .await;
    vault
        .post("sys/auth/kubernetes", json!({"type": "kubernetes"}))
        .await;
    vault
        .post(
            "auth/kubernetes/config",
            json!({"kubernetes_host": cluster.server, "kubernetes_ca_cert": ca_pem,
                   "token_reviewer_jwt": reviewer, "disable_local_ca_jwt": true}),
        )
        .await;
    vault
        .post(
            "sys/policies/acl/weebo-forgejo",
            json!({"policy": "path \"secret/data/*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\"] }\n\
                              path \"secret/metadata/*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"] }"}),
        )
        .await;
    vault
        .post(
            "auth/kubernetes/role/weebo-forgejo",
            json!({"bound_service_account_names": ["operator"],
                   "bound_service_account_namespaces": [NS],
                   "audience": "vault", "token_policies": ["weebo-forgejo"], "ttl": "1h"}),
        )
        .await;
    // The operator's own ServiceAccount token, where it reads it.
    let operator_jwt = sa_token(&l, "operator", Some("vault")).await;
    // What Vault will ask envtest, asked first as admin: a failure here is
    // envtest's, not Vault's.
    let reviews: Api<k8s_openapi::api::authentication::v1::TokenReview> = l.cluster_api();
    let review = reviews
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "spec": {"token": operator_jwt, "audiences": ["vault"]}
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        review.status.as_ref().and_then(|s| s.authenticated),
        Some(true),
        "envtest must validate the operator token for Vault: {:?}",
        review.status
    );
    std::fs::write(&jwt_file, operator_jwt).unwrap();

    bot(&l, "bot").await;
    // No secretTargets: the implicit target uses the instance's default
    // backend — Vault, at <pathPrefix>/<namespace>/<name>.
    token_cr(
        &l,
        "ci",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:user"]}),
    )
    .await;
    // Explicit fan-out to a Kubernetes Secret and a Vault path.
    token_cr(
        &l,
        "fan",
        json!({"userRef": {"name": "bot"}, "scopes": ["read:user"],
               "secretTargets": [{"backend": "kubernetes", "name": "fan-k8s"},
                                 {"backend": "vault", "name": "fan", "path": "weebo-forgejo/default/ci/fan"}]}),
    )
    .await;
    let tokens: Api<ForgejoAccessToken> = l.api();
    wait_for(&tokens, "ci", |t| ready(token_status(t))).await;
    wait_for(&tokens, "fan", |t| ready(token_status(t))).await;

    let (data, version) = vault
        .kv(&format!("weebo-forgejo/{NS}/ci"))
        .await
        .expect("written to Vault");
    assert_eq!(version, 1);
    let token = data["FORGEJO_TOKEN"].as_str().unwrap().to_string();
    assert_eq!(
        status_with(&l, &token, "/user").await,
        200,
        "the Vault copy is the live token"
    );
    assert!(
        l.secret_value("ci", "FORGEJO_TOKEN").await.is_none(),
        "nothing in Kubernetes"
    );

    let (fan, _) = vault
        .kv("weebo-forgejo/default/ci/fan")
        .await
        .expect("explicit Vault target");
    assert_eq!(
        l.secret_value("fan-k8s", "FORGEJO_TOKEN").await.as_deref(),
        fan["FORGEJO_TOKEN"].as_str(),
        "the same value fanned out to both backends"
    );

    // Steady state writes no new version; a rotation writes one.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        vault.kv(&format!("weebo-forgejo/{NS}/ci")).await.unwrap().1,
        1
    );
    annotate(&tokens, "ci", ROTATE, "v2").await;
    wait_for(&tokens, "ci", |t| {
        (t.status.as_ref()?.last_rotation.as_deref() == Some("v2")).then_some(())
    })
    .await;
    let (rotated, version) = vault.kv(&format!("weebo-forgejo/{NS}/ci")).await.unwrap();
    assert_eq!(version, 2);
    assert_ne!(rotated["FORGEJO_TOKEN"].as_str().unwrap(), token);

    // A lost Vault secret is noticed and reissued like a Kubernetes one.
    let resp = vault
        .call(
            reqwest::Method::DELETE,
            "secret/metadata/weebo-forgejo/default/ci/fan",
            None,
        )
        .await;
    assert!(resp.status().is_success());
    tokens
        .patch(
            "fan",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"labels": {"poke": "1"}}})),
        )
        .await
        .unwrap();
    let mut restored = None;
    for _ in 0..150 {
        if let Some(v) = vault.kv("weebo-forgejo/default/ci/fan").await {
            restored = Some(v.0);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let restored = restored.expect("the lost Vault target was rewritten");
    assert_ne!(restored["FORGEJO_TOKEN"], fan["FORGEJO_TOKEN"]);

    // Deleting the CRs removes every Vault version.
    for name in ["ci", "fan"] {
        tokens.delete(name, &Default::default()).await.unwrap();
        wait_for_absence(&tokens, name).await;
    }
    assert!(vault.kv(&format!("weebo-forgejo/{NS}/ci")).await.is_none());
    assert!(vault.kv("weebo-forgejo/default/ci/fan").await.is_none());
    assert!(l.secret_value("fan-k8s", "FORGEJO_TOKEN").await.is_none());
    // Err: a temp file left behind, harmless.
    std::fs::remove_file(&jwt_file).ok();
}
