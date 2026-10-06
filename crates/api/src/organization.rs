use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DeletionPolicy, ObjectRef, Visibility};
use crate::status::ForgejoStatus;

/// A Forgejo organization.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoOrganization",
    plural = "forgejoorganizations",
    shortname = "fjorg",
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Name","type":"string","jsonPath":".spec.name"}"#,
    printcolumn = r#"{"name":"ID","type":"string","jsonPath":".status.forgejoId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoOrganizationSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    /// Organization name (its URL slug). Changing it renames in place.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub visibility: Visibility,
    /// Let repository admins change which teams can access their repo.
    #[serde(default)]
    pub repo_admin_change_team_access: bool,
    /// `ForgejoUser` that becomes the organization's first owner. Only read
    /// at creation; without it the operator's admin account owns it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<ObjectRef>,
    /// Defaults to `Orphan`: deleting the CR never deletes the
    /// organization (Forgejo also refuses while it still owns repos).
    #[serde(default = "DeletionPolicy::orphan")]
    pub deletion_policy: DeletionPolicy,
}
