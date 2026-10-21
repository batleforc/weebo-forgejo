use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_inbound::webhook::{self, WebhookState};
use adapters_outbound::cluster_reader::ClusterStores;
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
use kube::Client;
use kube::api::ApiResource;
use kube::runtime::events::{Recorder, Reporter};
use weebo_kit_runtime::shared::{LISTED_TIMEOUT, SharedWatch};
use weebo_kit_runtime::store::spawn_reflector;
use weebo_kit_runtime::{Health, WatchScope, leader, telemetry, webhook_server};

/// Default `LEASE_NAME`: what every release used before it became
/// configurable — keep it across upgrades, or old and new pods would each
/// hold "their" lease during the rollout.
const DEFAULT_LEASE_NAME: &str = "weebo-forgejo-operator-leader";

/// The kit's runtime: `WEEBO_WORKER_THREADS` workers (4 by default), not
/// tokio's one per core (`weebo_kit_runtime::runtime`).
fn main() -> anyhow::Result<()> {
    weebo_kit_runtime::runtime::build()?.block_on(operator())
}

async fn operator() -> anyhow::Result<()> {
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
    // Err: a provider is already installed, which is as good.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
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
            .and_then(|i| args.get(i.saturating_add(1)))
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
    // Err: a provider is already installed, which is as good.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
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

async fn run(telemetry: &telemetry::Telemetry) -> anyhow::Result<()> {
    // `ring` and `aws-lc-rs` can both end up linked transitively; rustls
    // refuses to pick a default provider when more than one is present.
    // Err: a provider is already installed, which is as good.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    telemetry.serve_metrics().await?;
    // `weebo_forgejo_leader`: 1 on the replica holding the lease.
    leader::register_leader_gauge("weebo-forgejo-operator", "weebo_forgejo");

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

    // Every resolution reads the instances, every claim check the
    // instances and every CR of its kind, every admission and policy check
    // the policies: reflectors serve them from memory instead of a LIST
    // per reconcile, and one shared watch per kind feeds every controller
    // watching it (instead of a watch, and a LIST, per controller). All
    // started before campaigning for the lease: a standby keeps them warm,
    // and the controllers start from stores that already listed. The
    // instances and the policies are watched without the label selector —
    // one another release selects still counts for the claim and policy
    // checks; `ForgejoInstances` applies the selector to what it resolves.
    let watches = controller::spawn_watches(&client, &scope, &health);
    // Not shared watches: `wait_listed` doesn't wait for them before the
    // lease, as before (the instance controllers keep their own watches).
    let unselected = scope.without_selector();
    let cluster_store = scope.cluster_kinds().then(|| {
        spawn_reflector(
            unselected.api::<ForgejoInstance>(client.clone()),
            &unselected,
            health.clone(),
            "ForgejoInstance reflector",
        )
    });
    let local_store = spawn_reflector(
        unselected.api::<ForgejoLocalInstance>(client.clone()),
        &unselected,
        health.clone(),
        "ForgejoLocalInstance reflector",
    );
    let stores = ClusterStores {
        policies: watches
            .get_in(&scope.without_selector())
            .map(SharedWatch::store),
        instances: cluster_store.clone(),
        local_instances: Some(local_store.clone()),
        users: watches.get().map(SharedWatch::store),
        organizations: watches.get().map(SharedWatch::store),
        teams: watches.get().map(SharedWatch::store),
        access_tokens: watches.get().map(SharedWatch::store),
    };
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
        KubeClusterReader::new(client.clone())
            .with_scope(
                scope.watched_namespace().map(String::from),
                scope.selector().cloned(),
                scope.cluster_kinds(),
            )
            .with_stores(stores.clone())
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
        watches,
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

    // Campaign once the shared watches listed: the controllers then start
    // from full stores, their LISTs done before the lease, not in the
    // first idle minute. Bounded: a watch that can't list is reported by
    // /livez, not waited for.
    let campaign = async {
        ctx.watches.wait_listed(LISTED_TIMEOUT).await;
        leader::acquire_leadership(&client, holder_id, DEFAULT_LEASE_NAME).await
    };
    let leadership = tokio::select! {
        leadership = campaign => leadership,
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
    if tokio::time::timeout(Duration::from_secs(30), webhook.stopped())
        .await
        .is_err()
    {
        tracing::warn!("the webhook server was still draining after 30 s: exiting anyway");
    }
    Ok(())
}
