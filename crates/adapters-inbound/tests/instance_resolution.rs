//! Layer-3 integration test of `spec.instanceRef` against a real apiserver,
//! with the real instance resolution (the kit's `Instances`): a
//! `ForgejoRepository` bound to a `ForgejoLocalInstance` of its namespace is
//! not governed by `ForgejoNamespacePolicy` (its namespace's own token
//! bounds it) and records its instance in `status.instance`; one bound to a
//! cluster `ForgejoInstance` still is.

mod support;

use std::sync::Arc;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{ForgejoInstances, KubeClusterReader, kubernetes_secret_store};
use api::common::BoundInstance;
use api::{ForgejoInstance, ForgejoLocalInstance, ForgejoNamespacePolicy, ForgejoRepository};
use application::test_support::FakeForgejo;
use kube::api::{Api, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use support::{condition, wait_for};
use testkit::envtest::EnvTestCluster;
use testkit::static_gateway_factory::StaticGatewayFactory;
use testkit::static_secret_store_factory::StaticSecretStoreFactory;

const NS: &str = "default";

fn manifest<K: DeserializeOwned>(kind: &str, name: &str, ns: Option<&str>, spec: Value) -> K {
    serde_json::from_value(json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": kind,
        "metadata": {"name": name, "namespace": ns}, "spec": spec,
    }))
    .unwrap()
}

fn repository(name: &str, instance_ref: Value) -> ForgejoRepository {
    manifest(
        "ForgejoRepository",
        name,
        Some(NS),
        json!({"instanceRef": instance_ref, "organizationRef": {"name": "weebo"}, "name": name}),
    )
}

#[tokio::test]
async fn a_local_instance_binds_its_crs_outside_the_namespace_policy() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let reader = Arc::new(KubeClusterReader::new(client.clone()));
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(Arc::new(FakeForgejo::default()))),
        secrets: Arc::new(StaticSecretStoreFactory::new(Arc::new(
            kubernetes_secret_store(client.clone()),
        ))),
        instances: Arc::new(ForgejoInstances::new(client.clone())),
        refs: reader.clone(),
        policies: reader,
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
        watches: Default::default(),
    });

    let pp = PostParams::default();
    // A policy that allows no ForgejoRepository in `default`.
    let policy: ForgejoNamespacePolicy = manifest(
        "ForgejoNamespacePolicy",
        "tokens-only",
        None,
        json!({"rules": [{"namespaces": [NS], "allowedKinds": ["ForgejoAccessToken"], "effect": "Allow"}]}),
    );
    Api::<ForgejoNamespacePolicy>::all(client.clone())
        .create(&pp, &policy)
        .await
        .unwrap();
    let instance: ForgejoInstance = manifest(
        "ForgejoInstance",
        "main",
        None,
        json!({"url": "https://git.example.com",
               "tokenSecretRef": {"name": "t", "namespace": NS, "key": "token"}}),
    );
    Api::<ForgejoInstance>::all(client.clone())
        .create(&pp, &instance)
        .await
        .unwrap();
    let local: ForgejoLocalInstance = manifest(
        "ForgejoLocalInstance",
        "own",
        Some(NS),
        json!({"url": "https://git.example.com", "tokenSecretRef": {"name": "t", "key": "token"}}),
    );
    Api::<ForgejoLocalInstance>::namespaced(client.clone(), NS)
        .create(&pp, &local)
        .await
        .unwrap();

    tokio::spawn(controller::repository::run(client.clone(), ctx));
    let repos: Api<ForgejoRepository> = Api::namespaced(client.clone(), NS);
    repos
        .create(&pp, &repository("on-local", json!({"name": "own"})))
        .await
        .unwrap();
    repos
        .create(
            &pp,
            &repository("on-cluster", json!({"name": "main", "kind": "Instance"})),
        )
        .await
        .unwrap();

    // Bound to the local instance, past the policy: it stops at its missing
    // organization.
    let (bound, reason) = wait_for(&repos, "on-local", |r| {
        let status = r.status.as_ref()?;
        Some((
            status.instance.clone()?,
            condition(Some(status), "Ready")?.1,
        ))
    })
    .await;
    assert_eq!(bound, BoundInstance::local(NS, "own"));
    assert_eq!(reason, "ReferenceNotFound");

    // Bound to the cluster instance: the policy still refuses it.
    let (bound, reason) = wait_for(&repos, "on-cluster", |r| {
        let status = r.status.as_ref()?;
        Some((
            status.instance.clone()?,
            condition(Some(status), "Ready")?.1,
        ))
    })
    .await;
    assert_eq!(bound, BoundInstance::cluster("main"));
    assert_eq!(reason, "NamespaceNotAllowed");

    // A bound CR never moves: re-pointing it is refused, nothing is done.
    let mut moved = repos.get("on-local").await.unwrap();
    moved.spec.instance_ref = Some(api::common::InstanceRef::named("main"));
    repos.replace("on-local", &pp, &moved).await.unwrap();
    let reason = wait_for(&repos, "on-local", |r| {
        let reason = condition(r.status.as_ref(), "Ready")?.1;
        (reason == "InstanceBindingChanged").then_some(reason)
    })
    .await;
    assert_eq!(reason, "InstanceBindingChanged");
    let kept = repos.get("on-local").await.unwrap();
    assert_eq!(
        kept.status.unwrap().instance,
        Some(BoundInstance::local(NS, "own"))
    );
}
