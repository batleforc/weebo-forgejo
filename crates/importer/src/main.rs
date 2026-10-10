//! `weebo-forgejo-importer`: the only adoption path (`.prompt/plan.md`,
//! "Seul chemin d'adoption"). Reads a live Forgejo and prints the CRs
//! describing it, or with `--apply` creates them and seeds their
//! `status.forgejoId`/`forgejoName` so the operator adopts the objects
//! instead of colliding with them.

use adapters_outbound::forgejo_http::ForgejoHttpGateway;
use anyhow::Context;
use application::use_cases::import::{Existing, ImportOptions, import};
use clap::Parser;
use importer::{apply_all_with, existing, manifests, to_yaml};
use kube::Client;

#[derive(Parser, Debug)]
#[command(
    name = "weebo-forgejo-importer",
    version,
    about = "Import an existing Forgejo's objects as weebo-forgejo CRs"
)]
struct Args {
    /// Forgejo base URL (same form as `ForgejoInstance.spec.url`).
    #[arg(long, env = "FORGEJO_URL")]
    url: String,
    /// Site-administrator API token (read access is enough).
    #[arg(long, env = "FORGEJO_TOKEN", hide_env_values = true)]
    token: String,
    /// Namespace of the namespaced CRs (repositories, webhooks, deploy keys).
    #[arg(long, short, default_value = "default")]
    namespace: String,
    /// `ForgejoInstance` written as `spec.instanceRef` (default: none, the
    /// cluster's only instance).
    #[arg(long)]
    instance_ref: Option<String>,
    /// Only import these organizations/users (repeatable). Default: all.
    #[arg(long = "owner")]
    owners: Vec<String>,
    /// Import users as `managementPolicy: Manage` (local ones as `bot: true`,
    /// so their password is never reset) instead of `Observe`.
    #[arg(long)]
    manage_users: bool,
    /// Import teams as `membersPolicy: External` (members synced by
    /// Forgejo itself, e.g. OIDC group sync) instead of `Managed`.
    #[arg(long)]
    external_teams: bool,
    /// Create the CRs in the current kube context and seed their status,
    /// instead of printing them.
    #[arg(long)]
    apply: bool,
    /// With `--apply`: also take over CRs that exist but own nothing yet.
    #[arg(long, requires = "apply")]
    force: bool,
    /// PEM bundle trusted on top of the system roots (a Forgejo behind a
    /// private CA).
    #[arg(long, env = "FORGEJO_CA_FILE")]
    ca_file: Option<std::path::PathBuf>,
    /// Skip TLS verification (testing only).
    #[arg(long)]
    insecure_skip_verify: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();

    let (api_base, web_url) = api::instance::split_urls(&args.url);
    let mut http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
    if let Some(path) = &args.ca_file {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parsing {}", path.display()))?;
        anyhow::ensure!(
            !certs.is_empty(),
            "{} holds no PEM certificate",
            path.display()
        );
        for cert in certs {
            http = http.add_root_certificate(cert);
        }
    }
    if args.insecure_skip_verify {
        eprintln!("warning: TLS verification disabled");
        http = http.danger_accept_invalid_certs(true);
    }
    let gateway = ForgejoHttpGateway::new(
        api_base,
        web_url,
        args.token.trim().to_string(),
        http.build()?,
    );
    // With `--apply`, the CRs already there: names stay those of earlier
    // runs and avoid the ones owned by other objects.
    let (client, existing) = if args.apply {
        let client = Client::try_default()
            .await
            .context("connecting to Kubernetes")?;
        let existing = existing(&client, &args.namespace).await?;
        (Some(client), existing)
    } else {
        (None, Existing::default())
    };
    let options = ImportOptions {
        instance_ref: args.instance_ref,
        owners: args.owners,
        manage_users: args.manage_users,
        external_teams: args.external_teams,
        existing,
    };
    let imported = import(&gateway, &options)
        .await
        .context("reading Forgejo")?;
    for warning in &imported.warnings {
        eprintln!("warning: {warning}");
    }
    let crs = manifests(&imported, &args.namespace);

    if let Some(client) = client {
        let s = apply_all_with(&client, &crs, args.force).await;
        eprintln!(
            "{} adopted, {} already adopted, {} failed",
            s.adopted, s.skipped, s.failed
        );
        anyhow::ensure!(s.failed == 0, "{} CR(s) could not be imported", s.failed);
        Ok(())
    } else {
        print!("{}", to_yaml(&crs)?);
        Ok(())
    }
}
