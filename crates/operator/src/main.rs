use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_inbound::webhook::{self, WebhookState};
use adapters_outbound::{
    ForgejoGatewayFactory, ForgejoInstanceVaults, ForgejoInstances, ForgejoSecretStoreFactory,
    KubeClusterReader,
};
use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoInstance, ForgejoLocalInstance,
    ForgejoOAuth2Application, ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser,
    ForgejoUserKey, ForgejoWebhook,
};
use application::ports::InstanceDirectory;
use futures::StreamExt;
use kube::api::{Api, ApiResource};
use kube::runtime::events::{Recorder, Reporter};
use kube::runtime::reflector::Store;
use kube::runtime::{WatchStreamExt, reflector, watcher};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use weebo_kit_runtime::{Health, WatchScope, leader, telemetry, webhook_server};

/// Default `LEASE_NAME`: what every release used before it became
/// configurable — keep it across upgrades, or old and new pods would each
/// hold "their" lease during the rollout.
const DEFAULT_LEASE_NAME: &str = "weebo-forgejo-operator-leader";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = telemetry::init("weebo-forgejo-operator")?;
    let result = match std::env::args().nth(1).as_deref() {
        Some("migrate-instance-ref") => migrate_instance_ref().await,
        Some("migrate-to-namespaced") => migrate_to_namespaced().await,
        Some(other) => Err(anyhow::anyhow!("unknown command {other:?}")),
        None => run(&telemetry).await,
    };
    if let Err(err) = &result {
        tracing::error!(error = %err, "operator failed");
    }
    telemetry.shutdown();
    result
}

/// `migrate-instance-ref [--dry-run]`: rewrites the CRs written when
/// `spec.instanceRef` was a bare name (`main` → `{name: main}`). Offline:
/// operator stopped, new CRDs applied, then this, then the operator.
async fn migrate_instance_ref() -> anyhow::Result<()> {
    let dry_run = std::env::args().any(|a| a == "--dry-run");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::try_default().await?;
    let kinds = [
        ApiResource::erase::<ForgejoUser>(&()),
        ApiResource::erase::<ForgejoOrganization>(&()),
        ApiResource::erase::<ForgejoTeam>(&()),
        ApiResource::erase::<ForgejoRepository>(&()),
        ApiResource::erase::<ForgejoWebhook>(&()),
        ApiResource::erase::<ForgejoDeployKey>(&()),
        ApiResource::erase::<ForgejoUserKey>(&()),
        ApiResource::erase::<ForgejoOAuth2Application>(&()),
        ApiResource::erase::<ForgejoAccessToken>(&()),
    ];
    let migration = weebo_kit_adapters::migrate::migrate_instance_refs(
        &client,
        &kinds,
        "weebo-forgejo-operator",
        dry_run,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e))?;
    let verb = if dry_run { "to migrate" } else { "migrated" };
    for id in &migration.migrated {
        println!("{verb}: {id}");
    }
    println!(
        "{} {verb}, {} unchanged",
        migration.migrated.len(),
        migration.unchanged
    );
    Ok(())
}

/// `migrate-to-namespaced --out <dir> [--mapping <file>] [--default-namespace
/// <ns>] [--allow-cross-namespace] [--dry-run | --yes] [--wait <seconds>]`:
/// moves the ForgejoUser/Organization/Team/UserKey CRs of the cluster-scoped
/// CRDs into namespaces (`importer::namespaced`). Offline: the operator
/// must be stopped.
async fn migrate_to_namespaced() -> anyhow::Result<()> {
    use application::use_cases::namespaced_migration::{Targets, parse_mapping};
    let args: Vec<String> = std::env::args().skip(2).collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let out = value("--out").ok_or_else(|| anyhow::anyhow!("--out <dir> is required"))?;
    let mapping = match value("--mapping") {
        Some(path) => parse_mapping(&std::fs::read_to_string(&path)?)
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?,
        None => Default::default(),
    };
    let (dry_run, yes) = (has("--dry-run"), has("--yes"));
    if !dry_run && !yes {
        anyhow::bail!(
            "this deletes the cluster-scoped CRs and CRDs (never the Forgejo objects): stop the \
             operator first, check the plan with --dry-run, then rerun with --yes"
        );
    }
    let options = importer::namespaced::Options {
        targets: Targets {
            mapping,
            default_namespace: value("--default-namespace"),
        },
        out: out.into(),
        dry_run,
        allow_cross_namespace: has("--allow-cross-namespace"),
        wait: Duration::from_secs(value("--wait").map_or(Ok(600), |w| w.parse())?),
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::try_default().await?;
    let report = importer::namespaced::migrate(&client, &options).await?;
    if report.applied {
        println!(
            "{} CR(s) moved, {} rewritten: start the operator",
            report.plan.moves.len(),
            report.plan.rewrites.len()
        );
    }
    Ok(())
}

/// A reflector on `api`, its watch errors reported to `health`: the store
/// serves every read from memory, and watch errors back off exponentially
/// instead of spinning.
fn spawn_reflector<K>(
    api: Api<K>,
    scope: &WatchScope,
    health: Arc<Health>,
    name: &'static str,
) -> Store<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Send + Sync + 'static,
{
    let (store, writer) = reflector::store::<K>();
    let stream = reflector::reflector(
        writer,
        watcher(api, scope.watcher_config()).default_backoff(),
    );
    tokio::spawn(async move {
        stream
            .for_each(|event| {
                match event {
                    Ok(_) => health.ok(name),
                    Err(err) => {
                        tracing::warn!(error = %err, "{name} watch error");
                        health.failed(name, err.to_string());
                    }
                }
                futures::future::ready(())
            })
            .await;
    });
    store
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

    // The whole cluster, or one namespace (with or without the
    // cluster-scoped kinds) and/or a label selector (the chart's
    // `watch.*`): an invalid value stops the start here, as does a kind
    // the scope can't watch.
    let scope = WatchScope::from_env()?;
    scope.ensure::<ForgejoLocalInstance>()?;
    scope.ensure::<ForgejoRepository>()?;
    if scope.cluster_kinds() {
        scope.ensure::<ForgejoInstance>()?;
    }
    tracing::info!(
        namespace = ?scope.watched_namespace(),
        selector = ?scope.selector(),
        cluster_kinds = scope.cluster_kinds(),
        "watch scope"
    );

    // Every resolution reads the instances: one shared reflector per kind
    // serves them from memory instead of a LIST per reconcile (no
    // ForgejoInstance without cluster-scoped kinds).
    let cluster_store = scope.cluster_kinds().then(|| {
        spawn_reflector(
            scope.api::<ForgejoInstance>(client.clone()),
            &scope,
            health.clone(),
            "ForgejoInstance reflector",
        )
    });
    let local_store = spawn_reflector(
        scope.api::<ForgejoLocalInstance>(client.clone()),
        &scope,
        health.clone(),
        "ForgejoLocalInstance reflector",
    );
    let instances = Arc::new(
        ForgejoInstances::new(client.clone())
            .with_scope(
                scope.watched_namespace().map(String::from),
                scope.selector().cloned(),
                scope.cluster_kinds(),
            )
            .with_stores(cluster_store, Some(local_store)),
    );
    let directory: Arc<dyn InstanceDirectory> = instances.clone();
    let reader = || {
        KubeClusterReader::new(client.clone()).with_scope(
            scope.watched_namespace().map(String::from),
            scope.selector().cloned(),
            scope.cluster_kinds(),
        )
    };

    let holder_id = std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let cluster = Arc::new(reader());
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
        instances: directory.clone(),
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
        scope: scope.clone(),
    });

    let webhook_cluster = Arc::new(reader());
    // The webhook serves on every replica, before and regardless of
    // leadership: with failurePolicy: Fail, a leader-only webhook would turn
    // every failover into an outage for the namespaced kinds. On shutdown
    // it keeps answering while endpoints drain.
    let webhook = webhook_server::spawn(
        webhook::router(
            WebhookState {
                policies: webhook_cluster.clone(),
                refs: webhook_cluster,
                instances: Some(directory),
                vaults: Some(Arc::new(ForgejoInstanceVaults(instances))),
            },
            health.clone(),
            scope.clone(),
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
    // Without cluster-scoped kinds (full namespaced), only the namespaced
    // ones.
    let cluster_kinds = async {
        if ctx.scope.cluster_kinds() {
            tokio::join!(
                controller::instance::run(client.clone(), ctx.clone()),
                controller::namespace_policy::run(client.clone(), ctx.clone()),
            );
        }
    };
    tokio::join!(
        cluster_kinds,
        controller::local_instance::run(client.clone(), ctx.clone()),
        controller::user::run(client.clone(), ctx.clone()),
        controller::organization::run(client.clone(), ctx.clone()),
        controller::team::run(client.clone(), ctx.clone()),
        controller::user_key::run(client.clone(), ctx.clone()),
        controller::repository::run(client.clone(), ctx.clone()),
        controller::webhook::run(client.clone(), ctx.clone()),
        controller::deploy_key::run(client.clone(), ctx.clone()),
        controller::oauth2::run(client.clone(), ctx.clone()),
        controller::token::run(client.clone(), ctx.clone()),
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
