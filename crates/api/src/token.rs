use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DeletionPolicy, ObjectRef, SecretTarget};
use crate::status::ForgejoStatus;

/// An access token of a `ForgejoUser` (typically a bot), issued through the
/// admin API (Forgejo v16+) and written to `secretTargets` as
/// `FORGEJO_TOKEN`, `FORGEJO_USERNAME` and `FORGEJO_URL`.
///
/// Token values can't be read back: a lost target, a new
/// `forgejo.weebo.io/rotate-secret` nonce or an elapsed `rotationPeriod`
/// issues a new token (the old one is revoked first, as names are unique).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoAccessToken",
    plural = "forgejoaccesstokens",
    shortname = "fjtoken",
    namespaced,
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"User","type":"string","jsonPath":".spec.userRef.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoAccessTokenSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    /// `ForgejoUser` the token belongs to.
    pub user_ref: ObjectRef,
    /// Token name, unique per user. Defaults to `<namespace>-<cr name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `all`, or `read:`/`write:` + `activitypub`, `admin`, `issue`,
    /// `misc`, `notification`, `organization`, `package`, `repository`,
    /// `user`. Changing scopes issues a new token, which needs the
    /// `forgejo.weebo.io/allow-disruptive-update: "true"` annotation.
    pub scopes: Vec<String>,
    /// Restrict the token to these `ForgejoRepository`s (same namespace).
    /// Same disruptive-update rule as `scopes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repository_refs: Vec<ObjectRef>,
    /// Issue a new token once the current one is this old — a Go duration
    /// such as `720h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_period: Option<String>,
    /// Defaults to one target named after the CR, in its namespace, on the
    /// instance's default `secretStore` backend.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_targets: Vec<SecretTarget>,
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}
