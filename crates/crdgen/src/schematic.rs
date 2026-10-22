//! This operator's schematic kinds, drawn by the docs' CRD IDE and never
//! applied. Their doc comments are the IDE's descriptions.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use weebo_kit_api::links::{LinkError, Roles, Schematic, Scope, schematic};

/// The group of this operator's schematic kinds.
pub const GROUP: &str = "schematic.forgejo.weebo.io";

/// A Git repository outside the instance that a repository is migrated or
/// mirrored from, named by its clone URL (`spec.migrate.cloneAddr`).
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitRemoteSpec {
    /// The forge it lives on: `github`, `gitlab`, `gitea`, `forgejo`…
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Whether cloning it needs credentials.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authenticated: bool,
    /// Free text, for the drawing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

pub fn own(roles: &Roles) -> Result<BTreeMap<String, Schematic>, LinkError> {
    Ok(BTreeMap::from([(
        "GitRemote".to_string(),
        schematic::<GitRemoteSpec>(GROUP, Scope::Cluster, roles)?,
    )]))
}
