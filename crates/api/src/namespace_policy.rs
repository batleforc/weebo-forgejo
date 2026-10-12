use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::status::ForgejoStatus;

/// Namespace allow-list for the namespaced kinds, enforced by the
/// admission webhook (CREATE/UPDATE) and re-checked by every reconciler.
/// It governs the CRs bound to a `ForgejoInstance` (shared by every
/// namespace); a CR bound to a `ForgejoLocalInstance` is bounded by its
/// namespace's own token instead.
///
/// While no `ForgejoNamespacePolicy` exists, everything is allowed. As soon
/// as one exists, a namespaced CR is only accepted if some `Allow` rule
/// matches its namespace and kind and covers the organizations, users and
/// templates it references — and no `Deny` rule matches. Rules of every
/// policy are pooled; deny always wins.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoNamespacePolicy",
    plural = "forgejonamespacepolicies",
    shortname = "fjnp",
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoNamespacePolicySpec {
    pub rules: Vec<NamespaceRule>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceRule {
    /// Namespace names, `*` for all, or a prefix glob like `team-*`.
    pub namespaces: Vec<String>,
    pub allowed_kinds: Vec<NamespacedKind>,
    /// Organizations (Forgejo names) the namespace may manage or reference —
    /// a `ForgejoOrganization`'s own name, the owner of its repositories
    /// and teams, the target of its org webhooks — whether through a CR or
    /// a `remoteName`. Unset: any. On a `Deny` rule: only deny requests
    /// referencing one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_organizations: Option<Vec<String>>,
    /// Users (Forgejo logins) the namespace may manage or reference — a
    /// `ForgejoUser`'s own login, the owner of a repository, organization
    /// or OAuth2 application, a team member, the holder of an access token
    /// or SSH key — whether through a CR or a `remoteName`. Unset: any.
    /// Restricting this is what stops a namespace from minting tokens for
    /// a privileged account. On a `Deny` rule: only deny requests
    /// referencing one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_users: Option<Vec<String>>,
    /// Template repositories (Forgejo `owner/name`, `*`, or a prefix glob
    /// like `batlehub/*`) the namespace may generate repositories from by
    /// name (`fromTemplate.repository`). Unset: any. A template referenced
    /// as a same-namespace CR (`fromTemplate.repositoryRef`) isn't
    /// governed by this list. On a `Deny` rule: only deny requests
    /// referencing one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_templates: Option<Vec<String>>,
    #[serde(default)]
    pub effect: Effect,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
pub enum NamespacedKind {
    ForgejoUser,
    ForgejoUserKey,
    ForgejoOrganization,
    ForgejoTeam,
    ForgejoRepository,
    ForgejoWebhook,
    ForgejoDeployKey,
    ForgejoOAuth2Application,
    ForgejoAccessToken,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum Effect {
    #[default]
    Allow,
    Deny,
}
