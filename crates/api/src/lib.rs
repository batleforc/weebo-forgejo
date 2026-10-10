pub mod common;
pub mod instance;
pub mod keys;
pub mod namespace_policy;
pub mod oauth2;
pub mod organization;
pub mod repository;
pub mod status;
pub mod team;
pub mod token;
pub mod user;
pub mod webhook;

pub use instance::ForgejoInstance;
pub use keys::{ForgejoDeployKey, ForgejoUserKey};
pub use namespace_policy::ForgejoNamespacePolicy;
pub use oauth2::ForgejoOAuth2Application;
pub use organization::ForgejoOrganization;
pub use repository::ForgejoRepository;
pub use status::ForgejoStatus;
pub use team::ForgejoTeam;
pub use token::ForgejoAccessToken;
pub use user::ForgejoUser;
pub use webhook::ForgejoWebhook;

/// API group shared by every CRD of this operator.
pub const GROUP: &str = "forgejo.weebo.io";
/// Finalizer set on every CR whose deletion has a Forgejo-side effect.
pub const FINALIZER: &str = "forgejo.weebo.io/finalizer";
/// Authorizes a delete-and-recreate the reconciler would otherwise refuse
/// (`ReasonCode::DisruptiveUpdateRefused`). See `.prompt/plan.md`,
/// "Politique de mutation".
pub const ALLOW_DISRUPTIVE_UPDATE_ANNOTATION: &str = "forgejo.weebo.io/allow-disruptive-update";
/// A nonce; changing it forces a secret rotation (OAuth2 client secret,
/// access token, local user password).
pub const ROTATE_SECRET_ANNOTATION: &str = "forgejo.weebo.io/rotate-secret";
/// Set by the importer while it creates a CR and seeds its status: the
/// controllers leave the CR alone until it's removed, so they never try to
/// create the object the CR is about to adopt.
pub const IMPORT_PENDING_ANNOTATION: &str = "forgejo.weebo.io/import-pending";
/// Set on `ForgejoDeployKey`/`ForgejoUserKey` (by the operator, or the
/// importer): the Forgejo-side owner (`owner/repo` or login) the key was
/// created on. Forgejo only addresses a key through its owner, and the
/// owner's CR may be gone by the time the key's finalizer runs (a
/// namespace deletion, an `Orphan` repository or user).
pub const KEY_OWNER_ANNOTATION: &str = "forgejo.weebo.io/key-owner";

/// On every `Secret` the operator emits: the emitting CR, as
/// `<Kind>/<namespace>/<name>` (`<Kind>/<name>` when cluster-scoped). A
/// `Secret` without it (and without the `managed-by` label) or naming
/// another CR is never overwritten nor deleted.
pub const SECRET_OWNER_ANNOTATION: &str = "forgejo.weebo.io/owner";

/// `"true"` on a CR being deleted: release its finalizer without touching
/// Forgejo or the emitted secrets — the escape hatch when cleanup can't
/// succeed (its `ForgejoInstance` or token already gone). Everything the
/// CR owned is left behind, as with `deletionPolicy: Orphan`.
pub const FORCE_ORPHAN_ANNOTATION: &str = "forgejo.weebo.io/force-orphan";
