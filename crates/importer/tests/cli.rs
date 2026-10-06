//! The real `weebo-forgejo-importer` binary against a scripted Forgejo
//! (wiremock): YAML on stdout, `--apply` into envtest through `KUBECONFIG`,
//! and a non-zero exit when Forgejo can't be read.

use std::process::{Command, Output};

use api::{ForgejoOrganization, ForgejoUser};
use kube::api::Api;
use serde_json::json;
use testkit::envtest::EnvTestCluster;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// One observed user and one organization without teams or repositories.
async fn forgejo() -> MockServer {
    let server = MockServer::start().await;
    let ok = |body: serde_json::Value| ResponseTemplate::new(200).set_body_json(body);
    for (p, body) in [
        (
            "/api/v1/admin/users",
            json!([{"id": 7, "login": "Alice_X", "email": "a@x.local", "visibility": "public",
                    "active": true}]),
        ),
        (
            "/api/v1/admin/orgs",
            json!([{"id": 9, "name": "weebo", "username": "weebo", "visibility": "private"}]),
        ),
        ("/api/v1/orgs/weebo/teams", json!([])),
        ("/api/v1/orgs/weebo/repos", json!([])),
        ("/api/v1/orgs/weebo/hooks", json!([])),
        ("/api/v1/users/Alice_X/repos", json!([])),
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ok(body))
            .mount(&server)
            .await;
    }
    server
}

fn importer(url: &str, extra: &[&str], kubeconfig: Option<&std::path::Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_weebo-forgejo-importer"));
    cmd.args(["--url", url, "--namespace", "forgejo"])
        .args(extra)
        .env("FORGEJO_TOKEN", "t0ken");
    if let Some(k) = kubeconfig {
        cmd.env("KUBECONFIG", k);
    }
    cmd.output().expect("importer runs")
}

#[tokio::test]
async fn prints_every_cr_with_its_seeded_status() {
    let server = forgejo().await;
    let out = importer(&server.uri(), &[], None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let yaml = String::from_utf8(out.stdout).unwrap();
    assert!(yaml.contains("kind: ForgejoUser"), "{yaml}");
    assert!(yaml.contains("name: alice-x"), "{yaml}");
    assert!(yaml.contains("managementPolicy: Observe"), "{yaml}");
    assert!(yaml.contains("kind: ForgejoOrganization"), "{yaml}");
    assert!(yaml.contains("forgejoId: '9'"), "{yaml}");
}

#[tokio::test]
async fn applies_into_the_cluster_and_is_idempotent() {
    let server = forgejo().await;
    let cluster = EnvTestCluster::start().await;
    let kubeconfig = std::env::temp_dir().join(format!("importer-cli-{}.yaml", std::process::id()));
    cluster.write_kubeconfig(&kubeconfig);

    let first = importer(
        &server.uri(),
        &["--apply", "--manage-users"],
        Some(&kubeconfig),
    );
    let stderr = String::from_utf8_lossy(&first.stderr);
    assert!(first.status.success(), "{stderr}");
    assert!(
        stderr.contains("2 adopted, 0 already adopted, 0 failed"),
        "{stderr}"
    );

    let users: Api<ForgejoUser> = Api::all(cluster.client());
    let alice = users.get("alice-x").await.unwrap();
    assert!(
        alice.spec.bot,
        "a managed local user never gets its password reset"
    );
    assert_eq!(alice.status.unwrap().forgejo_id.as_deref(), Some("7"));
    let orgs: Api<ForgejoOrganization> = Api::all(cluster.client());
    let weebo = orgs.get("weebo").await.unwrap();
    assert!(
        !weebo
            .metadata
            .annotations
            .unwrap_or_default()
            .contains_key(api::IMPORT_PENDING_ANNOTATION),
        "the pause annotation is removed once the status is seeded"
    );

    let again = importer(&server.uri(), &["--apply"], Some(&kubeconfig));
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(again.status.success(), "{stderr}");
    assert!(
        stderr.contains("0 adopted, 2 already adopted, 0 failed"),
        "{stderr}"
    );
    std::fs::remove_file(&kubeconfig).unwrap();
}

#[tokio::test]
async fn fails_when_forgejo_cannot_be_read() {
    let server = MockServer::start().await; // every route 404s
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let out = importer(&server.uri(), &[], None);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("reading Forgejo"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
