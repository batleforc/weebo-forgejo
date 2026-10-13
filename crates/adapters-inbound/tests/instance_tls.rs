//! Layer-3: `ForgejoInstance.spec.tls` end to end — the instance controller
//! with the real `ForgejoGatewayFactory` against an HTTPS stand-in for
//! Forgejo whose certificate no public root trusts.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{ForgejoGatewayFactory, ForgejoSecretStoreFactory, KubeClusterReader};
use api::{ForgejoInstance, ForgejoLocalInstance};
use axum::Json;
use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde_json::json;
use support::{condition, wait_for};
use testkit::envtest::EnvTestCluster;

/// `GET /api/v1/version` and `/api/v1/user` (a site admin) over TLS with a fresh self-signed certificate;
/// returns the URL and the certificate's PEM.
async fn https_forgejo() -> (String, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let pem = cert.cert.pem();
    let tls = RustlsConfig::from_pem(pem.clone().into(), cert.signing_key.serialize_pem().into())
        .await
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = axum::Router::new()
        .route(
            "/api/v1/version",
            get(|| async { Json(json!({"version": "16.0.5"})) }),
        )
        .route(
            "/api/v1/user",
            get(|| async { Json(json!({"id": 1, "login": "root", "is_admin": true})) }),
        );
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    (format!("https://{addr}"), pem)
}

/// The controllers' context, with the real gateway factory.
fn ctx(client: &kube::Client) -> Arc<Ctx> {
    let client = client.clone();
    let instances = Arc::new(adapters_outbound::ForgejoInstances::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(ForgejoGatewayFactory::new(
            client.clone(),
            instances.clone(),
        )),
        secrets: Arc::new(ForgejoSecretStoreFactory::new(
            client.clone(),
            instances.clone(),
        )),
        instances,
        refs: Arc::new(KubeClusterReader::new(client.clone())),
        policies: Arc::new(KubeClusterReader::new(client.clone())),
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: "weebo-forgejo-test".into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: Default::default(),
        scope: weebo_kit_runtime::WatchScope::cluster(),
    })
}

#[tokio::test]
async fn tls_options_decide_whether_the_instance_is_trusted() {
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    tokio::spawn(controller::instance::run(client.clone(), ctx(&client)));
    let (url, ca) = https_forgejo().await;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");
    for (name, data) in [
        ("forgejo-admin", json!({"token": "t0ken"})),
        ("forgejo-ca", json!({"ca.crt": ca})),
        ("not-a-ca", json!({"ca.crt": "-----BEGIN NOTHING-----"})),
    ] {
        secrets
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({"metadata": {"name": name}, "stringData": data}))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let instances: Api<ForgejoInstance> = Api::all(client.clone());
    let cases = [
        ("untrusted", json!({}), "False", "InstanceUnreachable"),
        (
            "with-ca",
            json!({"caSecretRef": {"name": "forgejo-ca", "namespace": "default", "key": "ca.crt"}}),
            "True",
            "Reconciled",
        ),
        (
            "insecure",
            json!({"insecureSkipVerify": true}),
            "True",
            "Reconciled",
        ),
        (
            "bad-ca",
            json!({"caSecretRef": {"name": "not-a-ca", "namespace": "default", "key": "ca.crt"}}),
            "False",
            "InvalidSpec",
        ),
        (
            "missing-ca-key",
            json!({"caSecretRef": {"name": "forgejo-ca", "namespace": "default", "key": "nope"}}),
            "False",
            "InvalidSpec",
        ),
    ];
    for (name, tls, _, _) in &cases {
        instances
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({
                    "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoInstance",
                    "metadata": {"name": name},
                    "spec": {"url": url, "tls": tls,
                             "tokenSecretRef": {"name": "forgejo-admin", "namespace": "default",
                                                "key": "token"}},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
    }
    for (name, _, status, reason) in cases {
        let got = wait_for(&instances, name, |i| condition(i.status.as_ref(), "Ready")).await;
        assert_eq!(
            got,
            (status.to_string(), reason.to_string()),
            "instance {name}"
        );
    }
}

/// A `ForgejoLocalInstance` is created by a namespace's users: its token
/// `Secret` is only read once the namespace labelled it for that use.
#[tokio::test]
async fn a_local_instance_only_uses_a_labelled_token_secret() {
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    tokio::spawn(controller::local_instance::run(
        client.clone(),
        ctx(&client),
    ));
    let (url, ca) = https_forgejo().await;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");
    for (name, labels) in [
        ("unlabelled", json!({})),
        (
            "labelled",
            json!({"forgejo.weebo.io/instance-token": "true"}),
        ),
    ] {
        secrets
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({
                    "metadata": {"name": name, "labels": labels},
                    "stringData": {"token": "t0ken"},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
    }
    secrets
        .create(
            &PostParams::default(),
            &serde_json::from_value(
                json!({"metadata": {"name": "forgejo-ca"}, "stringData": {"ca.crt": ca}}),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let locals: Api<ForgejoLocalInstance> = Api::namespaced(client.clone(), "default");
    let cases = [
        ("unlabelled", "False", "TokenSecretNotAllowed"),
        ("labelled", "True", "Reconciled"),
    ];
    for (secret, _, _) in &cases {
        locals
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({
                    "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoLocalInstance",
                    "metadata": {"name": secret},
                    "spec": {"url": url,
                             "tls": {"caSecretRef": {"name": "forgejo-ca", "key": "ca.crt"}},
                             "tokenSecretRef": {"name": secret, "key": "token"}},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
    }
    for (name, status, reason) in cases {
        let got = wait_for(&locals, name, |i| condition(i.status.as_ref(), "Ready")).await;
        assert_eq!(
            got,
            (status.to_string(), reason.to_string()),
            "local instance {name}"
        );
    }
}
