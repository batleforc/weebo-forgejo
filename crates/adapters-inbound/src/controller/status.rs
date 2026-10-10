//! `Outcome` → `status` translation, shared by every controller: one merge
//! patch on the status subresource (`observedGeneration`, `forgejoId`,
//! `forgejoName`, conditions) and a Kubernetes `Event` whenever `Ready`
//! changes. Only `ReasonCode`s ever reach a condition or an Event.

use std::fmt::Debug;
use std::time::Duration;

use api::status::{Condition, ForgejoStatus};
use application::ports::ForgejoRef;
use application::use_cases::Outcome;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::events::Recorder;
use kube::{Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub const FIELD_MANAGER: &str = "weebo-forgejo-operator";

/// The `status` of every CRD here is a `ForgejoStatus`; this gives the
/// shared helpers access to it without a trait per field.
pub trait HasStatus {
    fn forgejo_status(&self) -> Option<&ForgejoStatus>;
}

macro_rules! impl_has_status {
    ($($kind:ty),+) => {$(
        impl HasStatus for $kind {
            fn forgejo_status(&self) -> Option<&ForgejoStatus> {
                self.status.as_ref()
            }
        }
    )+};
}
impl_has_status!(
    api::ForgejoInstance,
    api::ForgejoUser,
    api::ForgejoOrganization,
    api::ForgejoTeam,
    api::ForgejoRepository,
    api::ForgejoWebhook,
    api::ForgejoDeployKey,
    api::ForgejoUserKey,
    api::ForgejoOAuth2Application,
    api::ForgejoAccessToken,
    api::ForgejoNamespacePolicy
);

/// `status.forgejoId`/`forgejoName` as a port-level ref. An unparsable id
/// (hand-edited status) reads as "nothing owned yet".
pub fn current_ref<K: HasStatus>(obj: &K) -> Option<ForgejoRef> {
    let status = obj.forgejo_status()?;
    Some(ForgejoRef {
        id: status.forgejo_id.as_deref()?.parse().ok()?,
        name: status.forgejo_name.clone()?,
    })
}

/// `status.secretPending`: a secret was issued but not written everywhere.
pub fn secret_pending(status: &Option<ForgejoStatus>) -> bool {
    status.as_ref().and_then(|s| s.secret_pending) == Some(true)
}

/// `status.ownerId`, the Forgejo id of the owning account.
pub fn owner_id(status: &Option<ForgejoStatus>) -> Option<i64> {
    status.as_ref()?.owner_id.as_deref()?.parse().ok()
}

/// Whether `spec` changed since the last reconcile that reached the end.
pub fn spec_changed<K: HasStatus + Resource>(obj: &K) -> bool {
    let observed = obj.forgejo_status().and_then(|s| s.observed_generation);
    observed != obj.meta().generation
}

pub fn ready_condition(status: Option<&ForgejoStatus>) -> Option<&Condition> {
    weebo_kit_api::status::ready(&status?.conditions)
}

/// Builds the full condition list (the kit's: `Ready` first, then one
/// condition per advisory; `lastTransitionTime` only moves on a flip).
pub fn conditions(
    previous: &[Condition],
    outcome: &Outcome,
    generation: Option<i64>,
    now: &Time,
) -> Vec<Condition> {
    weebo_kit_runtime::conditions::conditions(
        previous,
        &outcome.ready,
        &outcome.advisories,
        generation,
        now,
    )
}

/// Extra attempts of a failed status patch.
const STATUS_RETRIES: u32 = 3;

/// Worth retrying: the apiserver unreachable, overloaded or timing out —
/// not a patch it refuses.
fn transient(err: &kube::Error) -> bool {
    match err {
        kube::Error::Api(e) => e.code == 429 || e.code >= 500,
        _ => true,
    }
}

/// Patches the outcome onto `obj` (freshly read from the API server) and
/// emits an Event if `Ready`'s status or reason changed. `observedGeneration`
/// only advances on success. A failed outcome
/// without a `forgejo` ref keeps whatever id the status already had.
pub async fn publish<K>(
    api: &Api<K>,
    recorder: &Recorder,
    obj: &K,
    outcome: &Outcome,
) -> Result<(), kube::Error>
where
    K: Resource<DynamicType = ()> + HasStatus + Clone + Debug + DeserializeOwned + Serialize,
{
    let previous = obj
        .forgejo_status()
        .map(|s| s.conditions.as_slice())
        .unwrap_or_default();
    let generation = obj.meta().generation;
    let now = Time(Timestamp::now());
    let conds = conditions(previous, outcome, generation, &now);

    let mut status = serde_json::json!({ "conditions": conds });
    // Only a reconcile that reached the end has observed this generation:
    // `spec_changed` must keep re-sending a change that failed to apply.
    if outcome.ready.is_ok() {
        status["observedGeneration"] = generation.into();
    }
    if let Some(r) = &outcome.forgejo {
        status["forgejoId"] = r.id.to_string().into();
        status["forgejoName"] = r.name.clone().into();
        // The account `forgejo` belongs to, always alongside it: `null`
        // (the admin account, or a kind without an owner) drops a stale id.
        status["ownerId"] = outcome
            .owner_id
            .map_or(serde_json::Value::Null, |id| id.to_string().into());
    }
    if let Some(hash) = &outcome.secret_hash {
        status["appliedSecretHash"] = hash.clone().into();
    }
    if let Some(rotation) = &outcome.last_rotation {
        status["lastRotation"] = rotation.clone().into();
    }
    // `null` drops the field from the status (merge patch).
    if let Some(pending) = outcome.secret_pending {
        status["secretPending"] = if pending {
            true.into()
        } else {
            serde_json::Value::Null
        };
    }
    let patch = Patch::Merge(serde_json::json!({ "status": status }));
    // Retried in place: a lost patch after a create would leave the new
    // Forgejo object untracked, and the next reconcile would create it again
    // (or collide with it).
    let mut attempt = 0;
    loop {
        match api
            .patch_status(&obj.name_any(), &PatchParams::apply(FIELD_MANAGER), &patch)
            .await
        {
            Ok(_) => break,
            Err(err) if attempt < STATUS_RETRIES && transient(&err) => {
                attempt += 1;
                tracing::warn!(error = %err, attempt, "status patch failed, retrying");
                tokio::time::sleep(Duration::from_millis(250 * 2u64.pow(attempt))).await;
            }
            Err(err) => {
                if let Some(r) = &outcome.forgejo {
                    tracing::error!(
                        error = %err,
                        forgejo_id = r.id,
                        forgejo_name = %r.name,
                        "status patch failed: the Forgejo object above is not recorded on the CR"
                    );
                }
                return Err(err);
            }
        }
    }

    weebo_kit_runtime::conditions::announce_ready_change(
        recorder,
        &obj.object_ref(&()),
        previous,
        &conds,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use application::use_cases::{Advisory, Failure};
    use domain::error::ReasonCode;

    use super::*;

    fn at(secs: i64) -> Time {
        Time(Timestamp::from_second(secs).unwrap())
    }

    #[test]
    fn transition_time_only_moves_when_status_flips() {
        let ok = Outcome::synced(None, "fine");
        let first = conditions(&[], &ok, Some(1), &at(10));
        assert_eq!(first[0].last_transition_time, Some(at(10)));

        let again = conditions(&first, &ok, Some(2), &at(20));
        assert_eq!(again[0].last_transition_time, Some(at(10)));
        assert_eq!(again[0].observed_generation, Some(2));

        let failed = Outcome::failed(None, Failure::new(ReasonCode::InstanceUnreachable, "x"));
        let flipped = conditions(&again, &failed, Some(2), &at(30));
        assert_eq!(flipped[0].last_transition_time, Some(at(30)));
        assert_eq!(flipped[0].reason, "InstanceUnreachable");
    }

    #[test]
    fn advisories_become_their_own_conditions() {
        let mut ok = Outcome::synced(None, "fine");
        ok.advisories.push(Advisory {
            reason: ReasonCode::MemberPending,
            message: "carol".into(),
        });
        let conds = conditions(&[], &ok, None, &at(1));
        assert_eq!(conds.len(), 2);
        assert_eq!(conds[1].type_, "MemberPending");
        assert_eq!(conds[1].status, "True");
    }
}
