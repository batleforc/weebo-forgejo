use std::sync::Arc;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_inbound::webhook::{self, WebhookState};
use adapters_outbound::{ForgejoGatewayFactory, ForgejoSecretStoreFactory, KubeClusterReader};
use api::ForgejoInstance;
use futures::StreamExt;
use kube::Client;
use kube::api::Api;
use kube::runtime::events::{Recorder, Reporter};
use kube::runtime::{reflector, watcher};
use weebo_kit_runtime::{leader, telemetry, webhook_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init("weebo-forgejo-operator")?;

    // `ring` and `aws-lc-rs` can both end up linked transitively; rustls
    // refuses to pick a default provider when more than one is present.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client = Client::try_default().await?;

    // The binary is PID 1 in its container: without a handler, SIGTERM
    // would be ignored and every rollout would wait for the SIGKILL.
    let shutdown = Shutdown::on_termination()?;

    // Every gateway resolution needs the ForgejoInstance list; one shared
    // reflector serves it from memory instead of a LIST per reconcile.
    let (instances, writer) = reflector::store::<ForgejoInstance>();
    let instance_reflector = reflector::reflector(
        writer,
        watcher(
            Api::<ForgejoInstance>::all(client.clone()),
            watcher::Config::default(),
        ),
    );
    tokio::spawn(async move {
        instance_reflector
            .for_each(|event| async move {
                if let Err(err) = event {
                    tracing::warn!(error = %err, "ForgejoInstance reflector watch error");
                }
            })
            .await;
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
    });

    // The webhook serves on every replica, before and regardless of
    // leadership: with failurePolicy: Fail, a leader-only webhook would turn
    // every failover into an outage for the namespaced kinds.
    webhook_server::spawn(webhook::router(WebhookState {
        policies: Arc::new(KubeClusterReader::new(client.clone())),
    }))
    .await?;

    let leadership = tokio::select! {
        leadership = leader::acquire_leadership(&client, holder_id, "weebo-forgejo-operator-leader") => leadership,
        () = shutdown.wait() => return Ok(()),
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
    Ok(())
}
