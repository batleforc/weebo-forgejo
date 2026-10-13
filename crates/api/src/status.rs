//! The status shared by every CRD's `#[kube(status = "ForgejoStatus")]`
//! (its conditions are the kit's). See `.prompt/plan.md`,
//! "Modèle de status commun".

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use weebo_kit_api::{BoundInstance, Condition};

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// The Forgejo-side identifier. Presence means this CR actually
    /// owns/created the corresponding Forgejo object — set once on first
    /// successful create (or seeded by the importer), never inferred by
    /// name-matching. For `managementPolicy: Observe` users it is the id
    /// of the observed user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgejo_id: Option<String>,
    /// Current Forgejo-side name the API addresses the object by (user
    /// login, organization or team name). Kept so a rename in `spec` knows
    /// the old name to rename *from*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgejo_name: Option<String>,
    /// Value of the `forgejo.weebo.io/rotate-secret` annotation the last
    /// secret was issued for, so the same nonce never rotates twice. Only
    /// used by kinds that emit a secret (a `rotationPeriod` renewal shows
    /// as a new `forgejoId` instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotation: Option<String>,
    /// SHA-256 of the write-only inputs last sent to Forgejo (webhook
    /// secret and authorization header), so a changed `Secret` value is
    /// re-applied even though Forgejo never returns it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_secret_hash: Option<String>,
    /// A secret (token, client secret, password) was issued in Forgejo but
    /// not written to every target: the targets may hold a revoked value,
    /// so the next reconcile issues a new one instead of trusting them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_pending: Option<bool>,
    /// A `ForgejoUser`'s generated password was handed out to its
    /// `secretTargets`: turning it into a bot (or an external account) then
    /// replaces the password, so the one handed out stops working. Never
    /// set on an adopted account: its password isn't the operator's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_emitted: Option<bool>,
    /// Forgejo id of the account owning the object (an access token's
    /// user, an OAuth2 application's owner), so a renamed owner isn't
    /// mistaken for a different one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// The instance this object was resolved to and stays bound to: a
    /// `spec.instanceRef` by name only never silently moves to another
    /// instance created later under that name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<BoundInstance>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
