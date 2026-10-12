//! Field types shared across CRDs. Those every weebo operator shares
//! (secret refs and targets, CR refs) come from the kit.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use weebo_kit_api::{
    BoundInstance, InstanceKind, InstanceRef, LocalSecretKeyRef, ObjectRef, SecretKeyRef,
    SecretTarget, SharedWith,
};

/// A user, organization or team: a CR (`name`) — of this object's
/// namespace, or of `namespace` when cross-namespace references are
/// enabled for the operator and the target lists this namespace in its
/// `sharedWith` — or an object that exists in Forgejo but no CR manages
/// (`remoteName`, its Forgejo name). The operator never creates, changes
/// nor deletes a `remoteName` object.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.name) != has(self.remoteName)", "message": "set exactly one of name and remoteName"},
    {"rule": "!has(self.namespace) || has(self.name)", "message": "namespace only applies with name"}
]))]
pub struct IdentityRef {
    /// `metadata.name` of the CR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Namespace of the CR; defaults to this object's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Forgejo name of an object no CR manages (a user's login, an
    /// organization's or team's name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_name: Option<String>,
}

impl IdentityRef {
    /// A CR of the referencing object's namespace.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }

    /// An object no CR manages, by its Forgejo name.
    pub fn remote(name: impl Into<String>) -> Self {
        Self {
            remote_name: Some(name.into()),
            ..Self::default()
        }
    }

    /// The CR it designates, `(namespace, name)`, from an object of
    /// `namespace`; `None` for a `remoteName`.
    pub fn target<'a>(&'a self, namespace: &'a str) -> Option<(&'a str, &'a str)> {
        let name = self.name.as_deref()?;
        Some((self.namespace.as_deref().unwrap_or(namespace), name))
    }

    /// Whether it designates the CR `name` of `target_namespace`, from an
    /// object of `namespace`.
    pub fn points_at(
        &self,
        namespace: Option<&str>,
        target_namespace: Option<&str>,
        name: &str,
    ) -> bool {
        self.target(namespace.unwrap_or_default())
            .is_some_and(|(ns, n)| n == name && Some(ns) == target_namespace)
    }
}

impl std::fmt::Display for IdentityRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.name, &self.namespace, &self.remote_name) {
            (Some(name), Some(ns), _) => write!(f, "{ns}/{name}"),
            (Some(name), None, _) => write!(f, "{name}"),
            (None, _, Some(remote)) => write!(f, "remote {remote:?}"),
            (None, _, None) => write!(f, "<empty>"),
        }
    }
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
