//! Kubernetes-side mirror of `domain::status`. Shared by every CRD's
//! `#[kube(status = "ForgejoStatus")]`. See `.prompt/plan.md`,
//! "Modèle de status commun".

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    /// `"True"`, `"False"`, or `"Unknown"`.
    pub status: String,
    /// One of `domain::error::ReasonCode`'s `as_str()` values — never a
    /// hand-written string.
    pub reason: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<Time>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

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
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
