mod telemetry;

use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;
use std::path::Path;

use adapters_inbound::controller::{self, Ctx};
use adapters_inbound::webhook::{self, WebhookState};
use adapters_outbound::{ForgejoGatewayFactory, ForgejoSecretStoreFactory};
use api::ForgejoInstance;
use axum_server::tls_rustls::RustlsConfig;
use futures::StreamExt;
use kube::Client;
use kube::api::Api;
use kube::runtime::events::{Recorder, Reporter};
use kube::runtime::{reflector, watcher};
use operator::leader;

/// 3:1 ttl:renew — survives a couple of missed renewals (GC pause, apiserver
/// hiccup) without losing leadership spuriously.
const LEASE_TTL: Duration = Duration::from_secs(15);
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(5);

/// cert-manager rotates the webhook certificate in place; re-reading it on
/// a fixed interval picks rotations up without a restart.
const TLS_RELOAD_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init()?;

    // `ring` and `aws-lc-rs` can both end up linked transitively; rustls
    // refuses to pick a default provider when more than one is present.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client = Client::try_default().await?;

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
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: "weebo-forgejo-operator".into(),
                instance: Some(holder_id.clone()),
            },
        ),
    });

    // The webhook serves on every replica, before and regardless of
    // leadership: with failurePolicy: Fail, a leader-only webhook would turn
    // every failover into an outage for the namespaced kinds.
    spawn_webhook(client.clone()).await?;

    acquire_leadership(&client, holder_id).await;

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
    Ok(())
}

/// Blocks until this replica holds the lease, then keeps renewing it in the
/// background and exits the process the moment it's lost.
async fn acquire_leadership(client: &Client, holder_id: String) {
    let namespace = std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "default".to_string());
    let lease_name =
        std::env::var("LEASE_NAME").unwrap_or_else(|_| "weebo-forgejo-operator-leader".to_string());
    let lease = leader::lease(
        client.clone(),
        &namespace,
        &lease_name,
        holder_id,
        LEASE_TTL,
    );

    tracing::info!("waiting for the leader lease");
    leader::acquire(&lease, LEASE_RENEW_INTERVAL).await;
    tracing::info!("acquired the leader lease");

    tokio::spawn(async move {
        let why = leader::hold(&lease, LEASE_RENEW_INTERVAL).await;
        tracing::error!("{why}, exiting");
        std::process::exit(1);
    });
}

/// Serves `/validate` over TLS when the certificate is mounted
/// (`WEBHOOK_TLS_CERT_FILE`/`WEBHOOK_TLS_KEY_FILE`, cert-manager in the Helm
/// chart). Without it — local runs — the webhook is skipped with a warning:
/// reconcilers re-check the allow-list on their own anyway.
async fn spawn_webhook(client: Client) -> anyhow::Result<()> {
    let cert = std::env::var("WEBHOOK_TLS_CERT_FILE")
        .unwrap_or_else(|_| "/etc/webhook/certs/tls.crt".to_string());
    let key = std::env::var("WEBHOOK_TLS_KEY_FILE")
        .unwrap_or_else(|_| "/etc/webhook/certs/tls.key".to_string());
    if !Path::new(&cert).exists() {
        tracing::warn!(%cert, "no webhook certificate, admission webhook disabled");
        return Ok(());
    }
    let port: u16 = std::env::var("WEBHOOK_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8443);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let tls = RustlsConfig::from_pem_file(&cert, &key).await?;

    tokio::spawn({
        let tls = tls.clone();
        async move {
            let mut interval = tokio::time::interval(TLS_RELOAD_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(err) = tls.reload_from_pem_file(&cert, &key).await {
                    tracing::error!(error = %err, "webhook certificate reload failed, keeping the previous one");
                }
            }
        }
    });

    let app = webhook::router(WebhookState { client });
    tracing::info!(%addr, "admission webhook listening");
    tokio::spawn(async move {
        if let Err(err) = axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service())
            .await
        {
            tracing::error!(error = %err, "admission webhook stopped");
            std::process::exit(1);
        }
    });
    Ok(())
}
