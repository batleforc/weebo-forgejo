use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DeletionPolicy, ObjectRef};
use crate::status::ForgejoStatus;

/// A team inside a `ForgejoOrganization`, with its members. Repositories
/// grant themselves access to it through `ForgejoRepository.spec.teamRefs`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoTeam",
    validation = kube::core::Rule::new("(has(self.spec.instanceRef) ? self.spec.instanceRef : '') == (has(oldSelf.spec.instanceRef) ? oldSelf.spec.instanceRef : '')").message("spec.instanceRef is immutable: ids in status belong to the instance they were created on").reason(kube::core::Reason::FieldValueForbidden),
    validation = kube::core::Rule::new("!has(self.spec.membersPolicy) || self.spec.membersPolicy != 'External' || !has(self.spec.memberRefs) || size(self.spec.memberRefs) == 0").message("spec.memberRefs must be empty when membersPolicy is External"),
    plural = "forgejoteams",
    shortname = "fjteam",
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Organization","type":"string","jsonPath":".spec.organizationRef.name"}"#,
    printcolumn = r#"{"name":"Name","type":"string","jsonPath":".spec.name"}"#,
    printcolumn = r#"{"name":"ID","type":"string","jsonPath":".status.forgejoId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoTeamSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    /// `ForgejoOrganization` the team belongs to. A team can't move between
    /// organizations: changing this deletes and recreates it, which needs
    /// the `forgejo.weebo.io/allow-disruptive-update: "true"` annotation.
    pub organization_ref: ObjectRef,
    /// Team name, unique within the organization. `Owners` is reserved.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub permission: TeamPermission,
    /// Per-unit access (`repo.code`, `repo.issues`, `repo.pulls`,
    /// `repo.releases`, `repo.wiki`, `repo.packages`, `repo.actions`, ...)
    /// to `none`, `read`, `write` or `admin`. Empty means every repository
    /// unit at `permission` (Forgejo refuses a team without units). Ignored
    /// by Forgejo when `permission` is `admin`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub units_map: BTreeMap<String, String>,
    /// Grant access to every repository of the organization, current and
    /// future.
    #[serde(default)]
    pub includes_all_repositories: bool,
    #[serde(default)]
    pub can_create_org_repo: bool,
    /// Who decides the team's members. `Managed` (the default):
    /// `memberRefs` is authoritative. `External`: the operator never adds
    /// or removes members, leaving them to Forgejo's OIDC group sync
    /// (`group-team-map` / `dyn-group-maps` on the authentication source);
    /// `memberRefs` must then be empty.
    #[serde(default)]
    pub members_policy: MembersPolicy,
    /// `ForgejoUser`s in the team. The member list is authoritative:
    /// anyone else is removed. A member whose user doesn't exist in Forgejo
    /// yet (e.g. an observed OIDC user who never logged in) is reported as
    /// `MemberPending` while the others are synced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_refs: Vec<ObjectRef>,
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TeamPermission {
    #[default]
    Read,
    Write,
    Admin,
}

/// Who owns a team's member list.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum MembersPolicy {
    /// `memberRefs` is authoritative: listed users are added, anyone else
    /// is removed.
    #[default]
    Managed,
    /// Members come from outside the operator — typically Forgejo's OIDC
    /// group sync, which runs at each sign-in. The operator still owns the
    /// team itself (name, permission, units, repositories).
    External,
}
