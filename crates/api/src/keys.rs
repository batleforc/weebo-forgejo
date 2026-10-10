use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{DeletionPolicy, ObjectRef, SecretTarget};
use crate::status::ForgejoStatus;

/// An SSH deploy key on a `ForgejoRepository` (same namespace). Without
/// `publicKey`, the operator generates an ed25519 pair and writes the
/// private half to `secretTargets` (`ssh-privatekey`, `ssh-publickey` — the
/// `kubernetes.io/ssh-auth` key names). Keys are immutable in Forgejo: any
/// change recreates the key.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoDeployKey",
    validation = kube::core::Rule::new("(has(self.spec.instanceRef) ? self.spec.instanceRef : '') == (has(oldSelf.spec.instanceRef) ? oldSelf.spec.instanceRef : '')").message("spec.instanceRef is immutable: ids in status belong to the instance they were created on").reason(kube::core::Reason::FieldValueForbidden),
    validation = kube::core::Rule::new("has(self.spec.publicKey) || (has(self.spec.secretTargets) && size(self.spec.secretTargets) > 0)").message("a generated key (no spec.publicKey) needs spec.secretTargets"),
    plural = "forgejodeploykeys",
    shortname = "fjdkey",
    namespaced,
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Repository","type":"string","jsonPath":".spec.repositoryRef.name"}"#,
    printcolumn = r#"{"name":"ReadOnly","type":"boolean","jsonPath":".spec.readOnly"}"#,
    printcolumn = r#"{"name":"ID","type":"string","jsonPath":".status.forgejoId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoDeployKeySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    pub repository_ref: ObjectRef,
    /// Defaults to the CR name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default = "default_true")]
    pub read_only: bool,
    #[serde(flatten)]
    pub key: KeySource,
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}

/// An SSH public key of a `ForgejoUser` — typically a bot's. Same key
/// handling as `ForgejoDeployKey`; generated keys need `secretTargets` with
/// an explicit namespace (this CR is cluster-scoped).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoUserKey",
    validation = kube::core::Rule::new("(has(self.spec.instanceRef) ? self.spec.instanceRef : '') == (has(oldSelf.spec.instanceRef) ? oldSelf.spec.instanceRef : '')").message("spec.instanceRef is immutable: ids in status belong to the instance they were created on").reason(kube::core::Reason::FieldValueForbidden),
    validation = kube::core::Rule::new("has(self.spec.publicKey) || (has(self.spec.secretTargets) && size(self.spec.secretTargets) > 0)").message("a generated key (no spec.publicKey) needs spec.secretTargets"),
    plural = "forgejouserkeys",
    shortname = "fjukey",
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"User","type":"string","jsonPath":".spec.userRef.name"}"#,
    printcolumn = r#"{"name":"ID","type":"string","jsonPath":".status.forgejoId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoUserKeySpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<String>,
    pub user_ref: ObjectRef,
    /// Defaults to the CR name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(flatten)]
    pub key: KeySource,
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}

/// Where the public key comes from.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeySource {
    /// An OpenSSH public key (`ssh-ed25519 AAAA... comment`). Unset: the
    /// operator generates an ed25519 pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Destinations of a generated private key. Required when `publicKey`
    /// is unset; a target that disappears (or a new
    /// `forgejo.weebo.io/rotate-secret` nonce) generates a fresh pair.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_targets: Vec<SecretTarget>,
}

fn default_true() -> bool {
    true
}
