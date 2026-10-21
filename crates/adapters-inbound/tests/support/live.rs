//! Layer-4 harness: every controller wired like `operator::main` — the real
//! `ForgejoGatewayFactory`/`ForgejoSecretStoreFactory` resolving a real
//! `ForgejoInstance` and its token `Secret` — against envtest and the live
//! Forgejo named by `FORGEJO_URL`/`FORGEJO_TOKEN` (`task test:live-forgejo`).
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test helpers fail the test on purpose"
)]
// Not an expect: each test binary uses a different part of this harness.
#![allow(dead_code, reason = "shared by test binaries that each use part of it")]

use std::sync::Arc;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    ForgejoGatewayFactory, ForgejoHttpGateway, ForgejoSecretStoreFactory, KubeClusterReader,
};
use api::ForgejoInstance;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde_json::json;
use testkit::envtest::EnvTestCluster;

use super::{condition, wait_for};

pub const NS: &str = "default";

pub struct Live {
    pub cluster: EnvTestCluster,
    pub client: kube::Client,
    pub url: String,
    pub token: String,
    /// Per-run suffix for Forgejo-side names, so reruns never collide.
    pub run: String,
    /// An independent gateway to read back what the operator did.
    pub fj: ForgejoHttpGateway,
}

impl Live {
    pub fn api<K>(&self) -> Api<K>
    where
        K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope>,
        K::DynamicType: Default,
    {
        Api::namespaced(self.client.clone(), NS)
    }

    pub fn cluster_api<K>(&self) -> Api<K>
    where
        K: kube::Resource<Scope = k8s_openapi::ClusterResourceScope>,
        K::DynamicType: Default,
    {
        Api::all(self.client.clone())
    }

    /// A Forgejo-side name unique to this run.
    pub fn name(&self, base: &str) -> String {
        format!("e2e-{base}-{}", self.run)
    }

    /// Creates any object from a manifest-shaped JSON value.
    pub async fn create<K>(&self, api: &Api<K>, manifest: serde_json::Value) -> K
    where
        K: kube::Resource
            + Clone
            + serde::de::DeserializeOwned
            + serde::Serialize
            + std::fmt::Debug,
    {
        api.create(&PostParams::default(), &cr(manifest))
            .await
            .unwrap_or_else(|e| panic!("create failed: {e}"))
    }

    /// A `Secret` with one key in the test namespace, labelled for the CRs
    /// that hand it to Forgejo (`forgejo.weebo.io/credential`).
    pub async fn secret(&self, name: &str, key: &str, value: &str) {
        let secrets: Api<Secret> = self.api();
        self.create(
            &secrets,
            json!({"metadata": {"name": name,
                                "labels": {"forgejo.weebo.io/credential": "true"}},
                   "stringData": {key: value}}),
        )
        .await;
    }

    /// A key of a `Secret` in the test namespace, if both exist.
    pub async fn secret_value(&self, name: &str, key: &str) -> Option<String> {
        let secrets: Api<Secret> = self.api();
        let secret = secrets.get_opt(name).await.unwrap()?;
        let bytes = secret.data?.get(key)?.0.clone();
        Some(String::from_utf8(bytes).unwrap())
    }
}

/// Deserializes a manifest-shaped JSON value into a CR (or any object).
pub fn cr<K: serde::de::DeserializeOwned>(value: serde_json::Value) -> K {
    serde_json::from_value(value).expect("manifest must match the type")
}

pub fn ready(s: Option<&api::ForgejoStatus>) -> Option<()> {
    (condition(s, "Ready")?.0 == "True").then_some(())
}

pub fn ready_id(s: Option<&api::ForgejoStatus>) -> Option<i64> {
    ready(s)?;
    s?.forgejo_id.as_ref()?.parse().ok()
}

/// `Some(())` once `Ready` is `False` with `reason`.
pub fn failed_with(s: Option<&api::ForgejoStatus>, reason: &str) -> Option<()> {
    let (status, r) = condition(s, "Ready")?;
    (status == "False" && r == reason).then_some(())
}

/// Id of the OAuth2 authentication source external users log in through
/// (`FORGEJO_SOURCE_ID`); the CI bootstrap always creates one.
pub fn source_id() -> Option<i64> {
    std::env::var("FORGEJO_SOURCE_ID").ok()?.parse().ok()
}

/// What the instance's `spec.secretStore` should be.
#[derive(Default)]
pub struct Options {
    pub secret_store: serde_json::Value,
}

pub async fn live() -> Live {
    live_with(Options::default()).await
}

pub async fn live_with(options: Options) -> Live {
    let url = std::env::var("FORGEJO_URL").expect("FORGEJO_URL");
    let token = std::env::var("FORGEJO_TOKEN").expect("FORGEJO_TOKEN");
    let run = format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 100_000_000
    );
    // Err: another test set the subscriber first, which is as good.
    tracing_subscriber::fmt().with_test_writer().try_init().ok();
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let instances = Arc::new(adapters_outbound::ForgejoInstances::new(client.clone()));
    let ctx = Arc::new(Ctx {
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
                controller: "weebo-forgejo-live-test".into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: Default::default(),
        scope: weebo_kit_runtime::WatchScope::cluster(),
        watches: Default::default(),
    });
    tokio::spawn(controller::instance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::user::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::organization::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::team::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::repository::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::webhook::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::deploy_key::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::user_key::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::oauth2::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::token::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::namespace_policy::run(
        client.clone(),
        ctx.clone(),
    ));

    let (api_base, web) = api::instance::split_urls(&url);
    let live = Live {
        cluster,
        client: client.clone(),
        url: url.clone(),
        token: token.clone(),
        run,
        fj: ForgejoHttpGateway::new(api_base, web, token.clone(), reqwest::Client::new()),
    };
    live.secret("forgejo-admin", "token", &token).await;

    let instances: Api<ForgejoInstance> = live.cluster_api();
    let mut spec = json!({
        "url": url,
        "tokenSecretRef": {"name": "forgejo-admin", "namespace": NS, "key": "token"},
    });
    if !options.secret_store.is_null() {
        spec["secretStore"] = options.secret_store;
    }
    live.create(
        &instances,
        json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoInstance",
            "metadata": {"name": "main"}, "spec": spec,
        }),
    )
    .await;
    wait_for(&instances, "main", |i| ready(i.status.as_ref())).await;
    live
}
