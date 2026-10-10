use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_inbound::webhook::{self, WebhookState};
use adapters_outbound::{ForgejoGatewayFactory, ForgejoSecretStoreFactory, KubeClusterReader};
use api::ForgejoInstance;
use futures::StreamExt;
use kube::Client;
use kube::api::Api;
use kube::runtime::events::{Recorder, Reporter};
use kube::runtime::{WatchStreamExt, reflector, watcher};
use weebo_kit_runtime::{Health, leader, telemetry, webhook_server};

/// Default `LEASE_NAME`: what every release used before it became
/// configurable — keep it across upgrades, or old and new pods would each
/// hold "their" lease during the rollout.
const DEFAULT_LEASE_NAME: &str = "weebo-forgejo-operator-leader";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = telemetry::init("weebo-forgejo-operator")?;
    let result = run(&telemetry).await;
    if let Err(err) = &result {
        tracing::error!(error = %err, "operator failed");
    }
    telemetry.shutdown();
    result
}

async fn run(telemetry: &telemetry::Telemetry) -> anyhow::Result<()> {
    // `ring` and `aws-lc-rs` can both end up linked transitively; rustls
    // refuses to pick a default provider when more than one is present.
    let _ = rustls::crypto::ring::default_provider().install_default();

    telemetry.serve_metrics().await?;
    register_leader_gauge();

    let client = Client::try_default().await?;

    // The binary is PID 1 in its container: without a handler, SIGTERM
    // would be ignored and every rollout would wait for the SIGKILL.
    let shutdown = Shutdown::on_termination()?;
    let health = Arc::new(Health::default());

    // Every gateway resolution needs the ForgejoInstance list; one shared
    // reflector serves it from memory instead of a LIST per reconcile.
    // Watch errors back off exponentially instead of spinning.
    let (instances, writer) = reflector::store::<ForgejoInstance>();
    let instance_reflector = reflector::reflector(
        writer,
        watcher(
            Api::<ForgejoInstance>::all(client.clone()),
            watcher::Config::default(),
        )
        .default_backoff(),
    );
    tokio::spawn({
        let health = health.clone();
        async move {
            instance_reflector
                .for_each(|event| {
                    match event {
                        Ok(_) => health.ok("ForgejoInstance reflector"),
                        Err(err) => {
                            tracing::warn!(error = %err, "ForgejoInstance reflector watch error");
                            health.failed("ForgejoInstance reflector", err.to_string());
                        }
                    }
                    futures::future::ready(())
                })
                .await;
        }
    });

    let holder_id = std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let cluster = Arc::new(KubeClusterReader::new(client.clone()));
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(ForgejoGatewayFactory::new(
            client.clone(),
            Some(instances.clone()),
        )),
        secrets: Arc::new(ForgejoSecretStoreFactory::new(
            client.clone(),
            Some(instances),
        )),
        refs: cluster.clone(),
        policies: cluster,
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: "weebo-forgejo-operator".into(),
                instance: Some(holder_id.clone()),
            },
        ),
        shutdown: shutdown.clone(),
        health: health.clone(),
    });

    let webhook_cluster = Arc::new(KubeClusterReader::new(client.clone()));
    // The webhook serves on every replica, before and regardless of
    // leadership: with failurePolicy: Fail, a leader-only webhook would turn
    // every failover into an outage for the namespaced kinds. On shutdown
    // it keeps answering while endpoints drain.
    let webhook = webhook_server::spawn(
        webhook::router(
            WebhookState {
                policies: webhook_cluster.clone(),
                refs: webhook_cluster,
            },
            health.clone(),
        ),
        health,
        shutdown.clone(),
    )
    .await?;

    let leadership = tokio::select! {
        leadership = leader::acquire_leadership(&client, holder_id, DEFAULT_LEASE_NAME) => leadership,
        () = shutdown.wait() => {
            webhook.stopped().await;
            return Ok(());
        }
    };

    tracing::info!("starting controllers");
    tokio::join!(
        controller::instance::run(client.clone(), ctx.clone()),
        controller::user::run(client.clone(), ctx.clone()),
        controller::organization::run(client.clone(), ctx.clone()),
        controller::team::run(client.clone(), ctx.clone()),
        controller::repository::run(client.clone(), ctx.clone()),
        controller::webhook::run(client.clone(), ctx.clone()),
        controller::deploy_key::run(client.clone(), ctx.clone()),
        controller::user_key::run(client.clone(), ctx.clone()),
        controller::oauth2::run(client.clone(), ctx.clone()),
        controller::token::run(client.clone(), ctx.clone()),
        controller::namespace_policy::run(client, ctx),
    );
    // Every controller returns once the shutdown signal arrived and its
    // in-flight reconciles finished: hand the lease over right away
    // instead of making the next leader wait out the TTL.
    leadership.release().await;
    // Bounded: the drain started with the signal, long before.
    let _ = tokio::time::timeout(Duration::from_secs(30), webhook.stopped()).await;
    Ok(())
}

/// `weebo_forgejo_leader`: 1 on the replica holding the lease.
fn register_leader_gauge() {
    // The callback is registered with the meter provider and lives as long
    // as it does: the handle itself can go.
    let _ = opentelemetry::global::meter("weebo-forgejo-operator")
        .u64_observable_gauge("weebo_forgejo_leader")
        .with_description("1 when this replica holds the leader lease")
        .with_callback(|observer| observer.observe(u64::from(leader::is_leader()), &[]))
        .build();
}
