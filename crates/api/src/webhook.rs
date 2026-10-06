use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DeletionPolicy, LocalSecretKeyRef, ObjectRef};
use crate::status::ForgejoStatus;

/// A webhook on a `ForgejoRepository` (same namespace) or a
/// `ForgejoOrganization` — exactly one of the two refs.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoWebhook",
    plural = "forgejowebhooks",
    shortname = "fjhook",
    namespaced,
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Target","type":"string","jsonPath":".status.forgejoName"}"#,
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoWebhookSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_ref: Option<ObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_ref: Option<ObjectRef>,
    /// `forgejo` (default), `gitea`, `gogs`, `slack`, `discord`,
    /// `dingtalk`, `telegram`, `msteams`, `feishu`, `wechatwork` or
    /// `packagist`. Changing it recreates the hook.
    #[serde(default = "default_type", rename = "type")]
    pub type_: String,
    /// Payload URL.
    pub url: String,
    /// `json` (default) or `form`.
    #[serde(default = "default_content_type")]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// Trigger events (`push`, `pull_request`, `issues`, `release`,
    /// `create`, `delete`, ...).
    #[serde(default = "default_events")]
    pub events: Vec<String>,
    /// Glob limiting push/branch events, e.g. `main` or `{main,release/*}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_filter: Option<String>,
    #[serde(default = "default_true")]
    pub active: bool,
    /// HMAC secret signing the payloads. Write-only in Forgejo: a change of
    /// the Secret's value is detected through `status.appliedSecretHash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<LocalSecretKeyRef>,
    /// Value sent as the `Authorization` header (write-only as well).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_header_secret_ref: Option<LocalSecretKeyRef>,
    /// Type-specific settings (e.g. `username`/`channel` for Slack).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_config: BTreeMap<String, String>,
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}

fn default_type() -> String {
    "forgejo".to_string()
}

fn default_content_type() -> String {
    "json".to_string()
}

fn default_events() -> Vec<String> {
    vec!["push".to_string()]
}

fn default_true() -> bool {
    true
}
