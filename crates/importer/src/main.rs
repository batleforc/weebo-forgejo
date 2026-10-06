//! `weebo-forgejo-importer`: the only adoption path (`.prompt/plan.md`,
//! "Seul chemin d'adoption"). Reads a live Forgejo and prints the CRs
//! describing it, or with `--apply` creates them and seeds their
//! `status.forgejoId`/`forgejoName` so the operator adopts the objects
//! instead of colliding with them.

use adapters_outbound::forgejo_http::ForgejoHttpGateway;
use anyhow::Context;
use application::use_cases::import::{ImportOptions, import};
use clap::Parser;
use importer::{apply_all, to_yaml};
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
    /// Create the CRs in the current kube context and seed their status,
    /// instead of printing them.
    #[arg(long)]
    apply: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();

    let (api_base, web_url) = api::instance::split_urls(&args.url);
    let gateway = ForgejoHttpGateway::new(
        api_base,
        web_url,
        args.token.trim().to_string(),
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?,
    );
    let options = ImportOptions {
        instance_ref: args.instance_ref,
        namespace: args.namespace,
        owners: args.owners,
        manage_users: args.manage_users,
    };
    let imported = import(&gateway, &options)
        .await
        .context("reading Forgejo")?;
    for warning in &imported.warnings {
        eprintln!("warning: {warning}");
    }

    if args.apply {
        let client = Client::try_default()
            .await
            .context("connecting to Kubernetes")?;
        let s = apply_all(&client, &imported).await;
        eprintln!(
            "{} adopted, {} already adopted, {} failed",
            s.adopted, s.skipped, s.failed
        );
        anyhow::ensure!(s.failed == 0, "{} CR(s) could not be imported", s.failed);
        Ok(())
    } else {
        print!("{}", to_yaml(&imported)?);
        Ok(())
    }
}
