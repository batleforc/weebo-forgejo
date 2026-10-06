//! Field types shared across CRDs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A key inside a Kubernetes `Secret` in an explicit namespace — used by
/// cluster-scoped CRDs, which have no namespace of their own to default to.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretKeyRef {
    pub name: String,
    pub namespace: String,
    pub key: String,
}

/// Reference to another CR of this operator, by `metadata.name`. Always a
/// CR, never a raw Forgejo name (see `.prompt/plan.md`, "Références"): a
/// cluster-scoped target is looked up cluster-wide, a namespaced one in the
/// referencing CR's own namespace only.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectRef {
    pub name: String,
}

/// What happens to the Forgejo object when its CR is deleted.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
pub enum DeletionPolicy {
    /// Delete the Forgejo object.
    Delete,
    /// Leave the Forgejo object in place, only drop the CR.
    Orphan,
}

impl DeletionPolicy {
    /// Default for kinds whose deletion destroys git history or commit
    /// attribution (repositories, organizations, users).
    pub fn orphan() -> Self {
        DeletionPolicy::Orphan
    }

    /// Default for every other kind.
    pub fn delete() -> Self {
        DeletionPolicy::Delete
    }
}

/// Whether the operator owns the Forgejo object or only looks it up.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum ManagementPolicy {
    /// Create, update and (per `deletionPolicy`) delete the object.
    #[default]
    Manage,
    /// Never create, modify or delete it — only resolve it by name and
    /// publish its id, so other CRs can reference it. For users Forgejo
    /// auto-creates on their first OIDC login.
    Observe,
}

/// Visibility of a Forgejo user or organization.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    #[default]
    Public,
    /// Visible to signed-in users only.
    Limited,
    Private,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Limited => "limited",
            Visibility::Private => "private",
        }
    }
}

/// Where an emitted secret (generated password or key, OAuth2 credentials,
/// access token) is written. A CR may list several targets — the same
/// value is fanned out to each.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretTarget {
    /// `kubernetes` (default) or `vault`. A Vault target reuses the
    /// connection (address, mount, auth) of the `ForgejoInstance`'s
    /// `secretStore.vault`, which must then be set.
    #[serde(default)]
    pub backend: crate::instance::SecretStoreBackend,
    /// Kubernetes: the `Secret` name. Vault: names the default path
    /// `<pathPrefix>/<namespace>/<name>` when `path` is unset.
    pub name: String,
    /// Kubernetes `Secret` namespace (Vault: the namespace segment of the
    /// default path). Defaults to the CR's own namespace; required on
    /// cluster-scoped CRs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Vault only: explicit KV v2 path under the instance's mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// A key of a `Secret` in the referencing CR's own namespace.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalSecretKeyRef {
    pub name: String,
    pub key: String,
}
