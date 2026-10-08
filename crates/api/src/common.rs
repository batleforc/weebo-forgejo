//! Field types shared across CRDs. Those every weebo operator shares
//! (secret refs and targets, CR refs) come from the kit.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use weebo_kit_api::{LocalSecretKeyRef, ObjectRef, SecretKeyRef, SecretTarget};

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
