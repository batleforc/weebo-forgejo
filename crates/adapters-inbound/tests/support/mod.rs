//! Shared setup for the layer-3 controller tests: a real apiserver
//! (`testkit::envtest`), the controller under test, the in-memory
//! `FakeForgejo` behind a `StaticGatewayFactory`, and the real
//! `K8sSecretStore` writing into the test apiserver.
#![allow(dead_code)]

pub mod live;

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{Ctx, Shutdown};
use adapters_outbound::{KubeClusterReader, kubernetes_secret_store};
use application::test_support::FakeForgejo;
use kube::Client;
use kube::runtime::events::{Recorder, Reporter};
use testkit::envtest::EnvTestCluster;
use testkit::static_gateway_factory::StaticGatewayFactory;
use testkit::static_secret_store_factory::StaticSecretStoreFactory;

pub struct Harness {
    // Keeps the control plane alive for the test's duration.
    pub cluster: EnvTestCluster,
    pub client: Client,
    pub forgejo: Arc<FakeForgejo>,
    pub ctx: Arc<Ctx>,
}

pub async fn harness() -> Harness {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let forgejo = Arc::new(FakeForgejo::default());
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(forgejo.clone())),
        secrets: Arc::new(StaticSecretStoreFactory::new(Arc::new(
            kubernetes_secret_store(client.clone()),
        ))),
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
    });
    Harness {
        cluster,
        client,
        forgejo,
        ctx,
    }
}

// Generous: live tests wait on a real Forgejo (clones, migrations).
const TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

pub async fn wait_for<K, T, F>(api: &kube::Api<K>, name: &str, extract: F) -> T
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
    F: FnMut(&K) -> Option<T>,
{
    testkit::polling::wait_for(api, name, TIMEOUT, POLL_INTERVAL, extract).await
}

pub async fn wait_for_absence<K>(api: &kube::Api<K>, name: &str)
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    testkit::polling::wait_for_absence(api, name, TIMEOUT, POLL_INTERVAL).await
}

/// `(status, reason)` of the `type` condition, once present.
pub fn condition(status: Option<&api::ForgejoStatus>, type_: &str) -> Option<(String, String)> {
    let c = status?.conditions.iter().find(|c| c.type_ == type_)?;
    Some((c.status.clone(), c.reason.clone()))
}
