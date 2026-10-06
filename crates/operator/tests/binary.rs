//! The real `operator` binary on envtest, against a scripted Forgejo: it
//! serves the admission webhook over TLS on every replica, takes the
//! leader lease, reconciles, and exits as soon as the lease is lost.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use api::ForgejoInstance;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, Patch, PatchParams, PostParams};
use serde_json::json;
use testkit::envtest::EnvTestCluster;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LEASE: &str = "weebo-forgejo-operator-leader";

/// Kills the operator if the test fails before it exits on its own.
struct Operator(Child);

impl Drop for Operator {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn eventually<F, Fut>(what: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while !check().await {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn binary_serves_the_webhook_leads_reconciles_and_exits_on_lease_loss() {
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let dir = std::env::temp_dir().join(format!("operator-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kubeconfig = dir.join("kubeconfig.yaml");
    cluster.write_kubeconfig(&kubeconfig);

    let cert =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    let (cert_file, key_file) = (dir.join("tls.crt"), dir.join("tls.key"));
    std::fs::write(&cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&key_file, cert.signing_key.serialize_pem()).unwrap();

    let forgejo = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "16.0.5"})))
        .mount(&forgejo)
        .await;

    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), "default");
    secrets
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "metadata": {"name": "forgejo-admin"}, "stringData": {"token": "t0ken"},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let instances: Api<ForgejoInstance> = Api::all(client.clone());
    instances
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoInstance",
                "metadata": {"name": "main"},
                "spec": {"url": forgejo.uri(),
                         "tokenSecretRef": {"name": "forgejo-admin", "namespace": "default",
                                            "key": "token"}},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    let port = free_port();
    let mut op = Operator(
        Command::new(env!("CARGO_BIN_EXE_operator"))
            .env("KUBECONFIG", &kubeconfig)
            .env("POD_NAMESPACE", "default")
            .env("HOSTNAME", "operator-under-test")
            .env("WEBHOOK_TLS_CERT_FILE", &cert_file)
            .env("WEBHOOK_TLS_KEY_FILE", &key_file)
            .env("WEBHOOK_PORT", port.to_string())
            // Exercises the OTLP branch; nothing listens, exports just fail.
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("operator starts"),
    );

    // The webhook answers over TLS with the mounted certificate.
    let https = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let healthz = format!("https://127.0.0.1:{port}/healthz");
    eventually("the webhook /healthz", Duration::from_secs(30), || {
        let req = https.get(&healthz).send();
        async move { req.await.is_ok_and(|r| r.status().is_success()) }
    })
    .await;

    // It leads, and reconciles.
    let leases: Api<Lease> = Api::namespaced(client.clone(), "default");
    eventually("the leader lease", Duration::from_secs(30), || {
        let get = leases.get_opt(LEASE);
        async move {
            get.await
                .ok()
                .flatten()
                .and_then(|l| l.spec?.holder_identity)
                .as_deref()
                == Some("operator-under-test")
        }
    })
    .await;
    eventually("ForgejoInstance Ready", Duration::from_secs(30), || {
        let get = instances.get("main");
        async move {
            get.await.ok().and_then(|i| i.status).is_some_and(|s| {
                s.conditions
                    .iter()
                    .any(|c| c.type_ == "Ready" && c.status == "True")
            })
        }
    })
    .await;

    // Losing the lease ends the process (exit 1): a deposed leader must
    // never keep reconciling.
    leases
        .patch(
            LEASE,
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {
                "holderIdentity": "someone-else",
                "renewTime": MicroTime(Timestamp::now()),
            }})),
        )
        .await
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = op.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the operator kept running after losing the lease"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(status.code(), Some(1));
    std::fs::remove_dir_all(&dir).unwrap();
}
