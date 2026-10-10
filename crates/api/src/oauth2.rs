use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DeletionPolicy, ObjectRef, SecretTarget};
use crate::status::ForgejoStatus;

/// An OAuth2 application registered in Forgejo, for apps that use Forgejo
/// as their identity provider. Its credentials (`FORGEJO_CLIENT_ID`,
/// `FORGEJO_CLIENT_SECRET`, `FORGEJO_URL` — the OIDC issuer) are written to
/// `secretTargets`.
///
/// Forgejo regenerates the client secret on every update and never returns
/// it again, so the application is only updated when the spec actually
/// differs, when a target lost the secret, or on a new
/// `forgejo.weebo.io/rotate-secret` nonce.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoOAuth2Application",
    validation = kube::core::Rule::new("(has(self.spec.instanceRef) ? self.spec.instanceRef : '') == (has(oldSelf.spec.instanceRef) ? oldSelf.spec.instanceRef : '')").message("spec.instanceRef is immutable: ids in status belong to the instance they were created on").reason(kube::core::Reason::FieldValueForbidden),
    plural = "forgejooauth2applications",
    shortname = "fjoauth",
    namespaced,
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Owner","type":"string","jsonPath":".status.forgejoName"}"#,
    printcolumn = r#"{"name":"ID","type":"string","jsonPath":".status.forgejoId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoOAuth2ApplicationSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    /// `ForgejoUser` owning the application (typically a `bot`) — the
    /// operator acts as that user through Forgejo's `Sudo` header. Unset:
    /// the operator's admin account. Changing it recreates the application
    /// (new client id), which needs the
    /// `forgejo.weebo.io/allow-disruptive-update: "true"` annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<ObjectRef>,
    /// Display name. Defaults to the CR name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
    /// Confidential clients authenticate with their secret; public clients
    /// (SPAs, CLIs) use PKCE only.
    #[serde(default = "default_true")]
    pub confidential_client: bool,
    /// Defaults to one target named after the CR, in its namespace, on the
    /// instance's default `secretStore` backend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_targets: Vec<SecretTarget>,
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}

fn default_true() -> bool {
    true
}
