//! Shared setup for the layer-3 controller tests: a real apiserver
//! (`testkit::envtest`), the controller under test, the in-memory
//! `FakeForgejo` behind a `StaticGatewayFactory`, and the real
//! `K8sSecretStore` writing into the test apiserver.
#![allow(dead_code)]

pub mod live;

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::shared::{SharedWatch, Watches};
use adapters_inbound::controller::{Ctx, Shutdown};
use adapters_outbound::cluster_reader::ClusterStores;
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
    harness_with(weebo_kit_runtime::WatchScope::cluster()).await
}

/// [`harness`] with the controllers on `scope` (e.g. cross-namespace
/// references enabled).
pub async fn harness_with(scope: weebo_kit_runtime::WatchScope) -> Harness {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let forgejo = Arc::new(FakeForgejo::default());
    // As the binary: the controllers on shared watches, the claim and
    // policy reads on their stores (the instances read from the API).
    let health: Arc<weebo_kit_runtime::Health> = Default::default();
    let watches = Watches::spawn(&client, &scope, &health);
    let stores = ClusterStores {
        policies: watches.policies.as_ref().map(SharedWatch::store),
        users: watches.users.as_ref().map(SharedWatch::store),
        organizations: watches.organizations.as_ref().map(SharedWatch::store),
        teams: watches.teams.as_ref().map(SharedWatch::store),
        access_tokens: watches.access_tokens.as_ref().map(SharedWatch::store),
        ..Default::default()
    };
    let reader = Arc::new(KubeClusterReader::new(client.clone()).with_stores(stores));
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(forgejo.clone())),
        instances: Arc::new(StaticGatewayFactory::new(forgejo.clone())),
        secrets: Arc::new(StaticSecretStoreFactory::new(Arc::new(
            kubernetes_secret_store(client.clone()),
        ))),
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
        health,
        scope,
        watches,
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

/// Waits for a Kubernetes Event of `reason` on the object `name` in
/// `namespace` (`default` for a cluster-scoped CR), and returns its type
/// (`Warning`/`Normal`).
pub async fn wait_for_event(
    client: &kube::Client,
    namespace: &str,
    name: &str,
    reason: &str,
) -> String {
    use k8s_openapi::api::core::v1::Event;
    let events: kube::Api<Event> = kube::Api::namespaced(client.clone(), namespace);
    let params = kube::api::ListParams::default().fields(&format!("involvedObject.name={name}"));
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let found = events
                .list(&params)
                .await
                .expect("events must be listable")
                .items
                .into_iter()
                .find(|e| e.reason.as_deref() == Some(reason));
            if let Some(event) = found {
                return event.type_.unwrap_or_default();
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {reason} Event on {namespace}/{name} within {TIMEOUT:?}"))
}
