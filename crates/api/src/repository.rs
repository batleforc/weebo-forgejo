use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DeletionPolicy, IdentityRef, InstanceRef, ObjectRef};
use crate::status::ForgejoStatus;

/// A Forgejo repository, owned by a `ForgejoOrganization` or a
/// `ForgejoUser`. Created empty (optionally initialized), from a template
/// repository, or by migrating/mirroring a remote.
///
/// Set exactly one of `organizationRef`/`userRef`, at most one of
/// `init`/`fromTemplate`/`migrate`, and exactly one of
/// `fromTemplate.repositoryRef`/`fromTemplate.repository`; anything else
/// reports `InvalidSpec`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoRepository",
    validation = kube::core::Rule::new("has(self.spec.organizationRef) != has(self.spec.userRef)").message("set exactly one of spec.organizationRef and spec.userRef"),
    validation = kube::core::Rule::new("(has(self.spec.init) ? 1 : 0) + (has(self.spec.fromTemplate) ? 1 : 0) + (has(self.spec.migrate) ? 1 : 0) <= 1").message("set at most one of spec.init, spec.fromTemplate and spec.migrate"),
    validation = kube::core::Rule::new("!has(self.spec.fromTemplate) || has(self.spec.fromTemplate.repositoryRef) != has(self.spec.fromTemplate.repository)").message("set exactly one of spec.fromTemplate.repositoryRef and spec.fromTemplate.repository"),
    validation = kube::core::Rule::new("!has(self.spec.fromTemplate) || !has(self.spec.fromTemplate.repository) || self.spec.fromTemplate.repository.matches('^[^/]+/[^/]+$')").message("spec.fromTemplate.repository must be owner/name"),
    validation = kube::core::Rule::new("!has(self.spec.userRef) || !has(self.spec.teamRefs) || size(self.spec.teamRefs) == 0").message("spec.teamRefs only applies to organization-owned repositories"),
    plural = "forgejorepositories",
    shortname = "fjrepo",
    namespaced,
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Repository","type":"string","jsonPath":".status.forgejoName"}"#,
    printcolumn = r#"{"name":"ID","type":"string","jsonPath":".status.forgejoId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoRepositorySpec {
    /// The `ForgejoInstance` or `ForgejoLocalInstance` this object lives
    /// on. Unset: the cluster's only `ForgejoInstance`, else the only
    /// `ForgejoLocalInstance` of this namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<InstanceRef>,
    /// Owning organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-weebo-link" = { "to": [{ "group": "forgejo.weebo.io", "kind": "ForgejoOrganization" }] }))]
    pub organization_ref: Option<IdentityRef>,
    /// Owning user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-weebo-link" = { "to": [{ "group": "forgejo.weebo.io", "kind": "ForgejoUser" }] }))]
    pub user_ref: Option<IdentityRef>,
    /// Repository name. Changing it renames in place (Forgejo keeps a
    /// redirect from the old name). Changing the owner transfers the
    /// repository, which needs the
    /// `forgejo.weebo.io/allow-disruptive-update: "true"` annotation.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(default)]
    pub private: bool,
    /// Mark the repository as a template others can be generated from.
    #[serde(default)]
    pub is_template: bool,
    /// Archived repositories are read-only; their settings, branch
    /// protections and teams are left alone until unarchived.
    #[serde(default)]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    /// Repository units to enable or disable. Unset = Forgejo's default.
    #[serde(default)]
    pub units: RepositoryUnits,
    /// Creation-time initialization of an empty repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<RepositoryInit>,
    /// Generate the repository from a template repository: a
    /// `ForgejoRepository` in the same namespace, or any Forgejo template
    /// by name (gated by the namespace policy's `allowedTemplates`).
    /// Creation-time only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_template: Option<TemplateSource>,
    /// Migrate (or pull-mirror) a remote repository. Creation-time only,
    /// except `mirrorInterval`, which stays in sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrate: Option<MigrateSource>,
    /// Branch protection rules. Unset: the repository's rules are left
    /// alone (those copied from a template, or set in Forgejo). Set:
    /// authoritative — a rule not listed here is deleted, and `[]` deletes
    /// them all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_protections: Option<Vec<BranchProtection>>,
    /// `ForgejoTeam`s granted access (organization-owned repositories only;
    /// the teams must belong to the owning organization). Authoritative,
    /// except for the `Owners` team and teams with
    /// `includesAllRepositories`, which Forgejo always grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(extend("x-weebo-link" = { "to": [{ "group": "forgejo.weebo.io", "kind": "ForgejoTeam" }] }))]
    pub team_refs: Vec<IdentityRef>,
    /// Defaults to `Orphan`: deleting the CR never deletes git history.
    #[serde(default = "DeletionPolicy::orphan")]
    pub deletion_policy: DeletionPolicy,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryUnits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issues: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wiki: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_requests: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projects: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packages: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryInit {
    /// Create an initial commit (README, and the files below).
    #[serde(default = "default_true")]
    pub auto_init: bool,
    /// `.gitignore` template names, comma-separated (e.g. `Rust,Node`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitignores: Option<String>,
    /// License template name (e.g. `MIT`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// README template name (`Default`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readme: Option<String>,
    /// `sha1` (default) or `sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_format: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSource {
    /// Template `ForgejoRepository` in the same namespace (must have
    /// `isTemplate: true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-weebo-link" = { "to": [{ "group": "forgejo.weebo.io", "kind": "ForgejoRepository" }] }))]
    pub repository_ref: Option<ObjectRef>,
    /// Template repository by its Forgejo name, `owner/name` (e.g.
    /// `batlehub/weebo-base`) — one shared by every namespace, managed by a
    /// CR elsewhere or not at all. It must be marked as a template in
    /// Forgejo. A `ForgejoNamespacePolicy` restricts which ones a namespace
    /// may use with `allowedTemplates`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default = "default_true")]
    pub git_content: bool,
    #[serde(default)]
    pub topics: bool,
    #[serde(default)]
    pub labels: bool,
    #[serde(default)]
    pub webhooks: bool,
    /// Copy the template's branch protections. Leave `branchProtections`
    /// unset to keep them: when set, it is authoritative and a copied rule
    /// it doesn't list is deleted right after.
    #[serde(default)]
    pub protected_branches: bool,
    #[serde(default)]
    pub git_hooks: bool,
    #[serde(default)]
    pub avatar: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MigrateSource {
    /// URL to clone from.
    // Drawn by the docs' CRD IDE (crdgen's GitRemote).
    #[schemars(extend("x-weebo-produces" = { "kind": { "group": "schematic.forgejo.weebo.io", "kind": "GitRemote" }, "name": ["."] }))]
    pub clone_addr: String,
    /// `git` (default), `github`, `gitea`, `gitlab`, `gogs`, `onedev`,
    /// `gitbucket`, `codebase`, `forgejo` or `pagure`. Non-`git` services
    /// can also bring issues, PRs, releases... (flags below).
    #[serde(default = "default_service")]
    pub service: String,
    /// Keep the repository as a pull mirror of `cloneAddr`.
    #[serde(default)]
    pub mirror: bool,
    /// Pull-mirror sync interval, a Go duration (`8h`, `30m`). Kept in sync
    /// after creation; `0` disables periodic sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_interval: Option<String>,
    #[serde(default)]
    pub lfs: bool,
    #[serde(default)]
    pub wiki: bool,
    #[serde(default)]
    pub issues: bool,
    #[serde(default)]
    pub pull_requests: bool,
    #[serde(default)]
    pub releases: bool,
    #[serde(default)]
    pub labels: bool,
    #[serde(default)]
    pub milestones: bool,
    /// Credentials for the remote, from a `Secret` in this namespace.
    /// The `Secret` must carry the label `forgejo.weebo.io/credential: "true"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_secret_ref: Option<MigrateAuth>,
}

fn default_service() -> String {
    "git".to_string()
}

/// Keys of one `Secret` (same namespace) holding the remote's credentials:
/// a username/password pair, a token, or both.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MigrateAuth {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_key: Option<String>,
}

/// One branch protection rule. Allow-lists name Forgejo users and teams
/// directly (not CRs); each `enable*Whitelist` switch is derived from
/// whether its lists are non-empty.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BranchProtection {
    /// Branch name or glob (`main`, `release/*`).
    pub rule_name: String,
    /// Allow pushing at all; with push allow-lists, only those may push.
    #[serde(default)]
    pub enable_push: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub push_whitelist_usernames: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub push_whitelist_teams: Vec<String>,
    #[serde(default)]
    pub push_whitelist_deploy_keys: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merge_whitelist_usernames: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merge_whitelist_teams: Vec<String>,
    #[serde(default)]
    pub required_approvals: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals_whitelist_usernames: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals_whitelist_teams: Vec<String>,
    /// Required status checks; enables the check when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_check_contexts: Vec<String>,
    #[serde(default)]
    pub block_on_rejected_reviews: bool,
    #[serde(default)]
    pub block_on_official_review_requests: bool,
    #[serde(default)]
    pub block_on_outdated_branch: bool,
    #[serde(default)]
    pub dismiss_stale_approvals: bool,
    #[serde(default)]
    pub ignore_stale_approvals: bool,
    #[serde(default)]
    pub require_signed_commits: bool,
    #[serde(default)]
    pub apply_to_admins: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_file_patterns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unprotected_file_patterns: Option<String>,
}
