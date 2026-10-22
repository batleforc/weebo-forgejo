//! Emits `deploy/crd/*.yaml`, one file per CRD kind, via
//! `CustomResourceExt::crd()`, and `deploy/crd/links.json`, the reference
//! fields and produced Secrets of each kind (`weebo_kit_api::links`) for
//! the docs' CRD IDE, with the schematic kinds the IDE draws: the kit's
//! shared ones and this operator's `GitRemote` (`schematic.rs`). Invoked
//! directly by `task recu` — see
//! `.prompt/plan.md`, "Architecture hexagonale".

mod schematic;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::CustomResourceExt;
use schemars::JsonSchema;
use weebo_kit_api::links::{self, GroupKind, KindLinks, Roles};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "deploy/crd")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out)?;
    let roles = Roles {
        instance: group_kind(&api::ForgejoInstance::crd()),
        local_instance: group_kind(&api::ForgejoLocalInstance::crd()),
    };
    let mut kinds = BTreeMap::new();
    let out = &args.out;
    write::<api::ForgejoInstance>(out, &roles, &mut kinds)?;
    write::<api::ForgejoLocalInstance>(out, &roles, &mut kinds)?;
    write::<api::ForgejoUser>(out, &roles, &mut kinds)?;
    write::<api::ForgejoOrganization>(out, &roles, &mut kinds)?;
    write::<api::ForgejoTeam>(out, &roles, &mut kinds)?;
    write::<api::ForgejoRepository>(out, &roles, &mut kinds)?;
    write::<api::ForgejoWebhook>(out, &roles, &mut kinds)?;
    write::<api::ForgejoDeployKey>(out, &roles, &mut kinds)?;
    write::<api::ForgejoUserKey>(out, &roles, &mut kinds)?;
    write::<api::ForgejoOAuth2Application>(out, &roles, &mut kinds)?;
    write::<api::ForgejoAccessToken>(out, &roles, &mut kinds)?;
    write::<api::ForgejoNamespacePolicy>(out, &roles, &mut kinds)?;
    let mut drawn = weebo_kit_api::schematic::shared(&roles)?;
    drawn.extend(schematic::own(&roles)?);
    let links = serde_json::json!({ "version": 1, "kinds": kinds, "schematic": drawn });
    fs::write(
        out.join("links.json"),
        serde_json::to_string_pretty(&links)? + "\n",
    )?;

    println!("wrote CRDs and links.json to {}", out.display());
    Ok(())
}

fn write<K: CustomResourceExt + JsonSchema>(
    out: &Path,
    roles: &Roles,
    kinds: &mut BTreeMap<String, KindLinks>,
) -> anyhow::Result<()> {
    let crd = K::crd();
    let kind = crd.spec.names.kind.clone();
    fs::write(
        out.join(format!("{}.yaml", kind.to_lowercase())),
        serde_norway::to_string(&crd)?,
    )?;
    kinds.insert(kind, links::of::<K>(roles)?);
    Ok(())
}

fn group_kind(crd: &CustomResourceDefinition) -> GroupKind {
    GroupKind::new(&crd.spec.group, &crd.spec.names.kind)
}
