//! Emits `deploy/crd/*.yaml`, one file per CRD kind, via
//! `CustomResourceExt::crd()`. Invoked directly by `task recu` — see
//! `.prompt/plan.md`, "Architecture hexagonale".

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use kube::CustomResourceExt;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "deploy/crd")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out)?;

    write_crd(&args.out, "forgejoinstance", api::ForgejoInstance::crd())?;
    write_crd(
        &args.out,
        "forgejolocalinstance",
        api::ForgejoLocalInstance::crd(),
    )?;
    write_crd(&args.out, "forgejouser", api::ForgejoUser::crd())?;
    write_crd(
        &args.out,
        "forgejoorganization",
        api::ForgejoOrganization::crd(),
    )?;
    write_crd(&args.out, "forgejoteam", api::ForgejoTeam::crd())?;
    write_crd(
        &args.out,
        "forgejorepository",
        api::ForgejoRepository::crd(),
    )?;
    write_crd(&args.out, "forgejowebhook", api::ForgejoWebhook::crd())?;
    write_crd(&args.out, "forgejodeploykey", api::ForgejoDeployKey::crd())?;
    write_crd(&args.out, "forgejouserkey", api::ForgejoUserKey::crd())?;
    write_crd(
        &args.out,
        "forgejooauth2application",
        api::ForgejoOAuth2Application::crd(),
    )?;
    write_crd(
        &args.out,
        "forgejoaccesstoken",
        api::ForgejoAccessToken::crd(),
    )?;

    write_crd(
        &args.out,
        "forgejonamespacepolicy",
        api::ForgejoNamespacePolicy::crd(),
    )?;

    println!("wrote CRDs to {}", args.out.display());
    Ok(())
}

fn write_crd(out: &Path, name: &str, crd: impl serde::Serialize) -> anyhow::Result<()> {
    let yaml = serde_norway::to_string(&crd)?;
    fs::write(out.join(format!("{name}.yaml")), yaml)?;
    Ok(())
}
