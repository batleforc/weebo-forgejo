//! `Outcome` → `status` translation, shared by every controller: one merge
//! patch on the status subresource (`observedGeneration`, `forgejoId`,
//! `forgejoName`, the resolved `instance`, conditions), then Kubernetes Events: a `Warning` for every
//! failed reconcile, a `Normal` for every condition change, when the CR
//! gets bound to a Forgejo object, and when fields of that object were put
//! back after a drift (`DriftCorrected`, naming them). Only `ReasonCode`s
//! ever reach a condition or an Event.

use std::fmt::Debug;

use api::status::{Condition, ForgejoStatus};
use application::ports::ForgejoRef;
use application::use_cases::Outcome;
use domain::error::ReasonCode;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::Resource;
use kube::api::Api;
use kube::runtime::events::Recorder;
use serde::Serialize;
use serde::de::DeserializeOwned;
use weebo_kit_runtime::events;
use weebo_kit_runtime::status::StatusUpdate;

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
    api::ForgejoLocalInstance,
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

/// `status.passwordEmitted`: a user's generated password was handed out.
pub fn password_emitted(status: &Option<ForgejoStatus>) -> bool {
    status.as_ref().and_then(|s| s.password_emitted) == Some(true)
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

/// Patches the outcome onto `obj` (freshly read from the API server) and
/// emits its Events (see the module doc). `observedGeneration`
/// only advances on success. A failed outcome
/// without a `forgejo` ref keeps whatever id the status already had,
/// unless it `released` it.
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
    let mut fields = serde_json::Map::new();
    if let Some(r) = &outcome.forgejo {
        fields.insert("forgejoId".into(), r.id.to_string().into());
        fields.insert("forgejoName".into(), r.name.clone().into());
        // The account `forgejo` belongs to, always alongside it: `null`
        // (the admin account, or a kind without an owner) drops a stale id.
        fields.insert(
            "ownerId".into(),
            outcome
                .owner_id
                .map_or(serde_json::Value::Null, |id| id.to_string().into()),
        );
    }
    if outcome.forgejo.is_none() && outcome.released {
        for field in ["forgejoId", "forgejoName", "ownerId"] {
            fields.insert(field.into(), serde_json::Value::Null);
        }
    }
    if let Some(instance) = &outcome.instance {
        let instance = serde_json::to_value(instance).expect("a BoundInstance serializes");
        fields.insert("instance".into(), instance);
    }
    if let Some(hash) = &outcome.secret_hash {
        fields.insert("appliedSecretHash".into(), hash.clone().into());
    }
    if let Some(rotation) = &outcome.last_rotation {
        fields.insert("lastRotation".into(), rotation.clone().into());
    }
    // `null` drops the field from the status (merge patch).
    if let Some(pending) = outcome.secret_pending {
        fields.insert(
            "secretPending".into(),
            if pending {
                true.into()
            } else {
                serde_json::Value::Null
            },
        );
    }
    if let Some(emitted) = outcome.password_emitted {
        let value = if emitted {
            true.into()
        } else {
            serde_json::Value::Null
        };
        fields.insert("passwordEmitted".into(), value);
    }
    let published = weebo_kit_runtime::status::publish(
        api,
        recorder,
        FIELD_MANAGER,
        obj,
        previous,
        StatusUpdate {
            ready: &outcome.ready,
            advisories: &outcome.advisories,
            fields,
        },
    )
    .await;
    if let Err(err) = &published
        && let Some(r) = &outcome.forgejo
    {
        tracing::error!(
            error = %err,
            forgejo_id = r.id,
            forgejo_name = %r.name,
            "status patch failed: the Forgejo object above is not recorded on the CR"
        );
    }
    published?;

    // The kit announced the conditions (a `Warning` on every failed
    // reconcile, a `Normal` for every change); one more when the CR gets
    // bound to a Forgejo object.
    let object = obj.object_ref(&());
    if let Some(r) = &outcome.forgejo
        && current_ref(obj).is_none()
    {
        events::announce_change(
            recorder,
            &object,
            ReasonCode::Bound,
            events::RECONCILE,
            &format!("bound to Forgejo object {:?} (id {})", r.name, r.id),
        )
        .await;
    }
    // `obj` was read before the reconcile: a spec change being applied is
    // not a drift, only a Forgejo object that moved on its own is.
    if !spec_changed(obj)
        && let Some(note) = drift_note(outcome)
    {
        events::announce_change(
            recorder,
            &object,
            ReasonCode::DriftCorrected,
            events::RECONCILE,
            &note,
        )
        .await;
    }
    Ok(())
}

/// The note of a `DriftCorrected` Event (the kit's, plus what else the
/// correction did); `None` when no field drifted.
pub fn drift_note(outcome: &Outcome) -> Option<String> {
    if outcome.drift.is_empty() {
        return None;
    }
    let note = events::drift_note(&outcome.drift);
    Some(match outcome.drift_effect {
        Some(effect) => format!("{note}; {effect}"),
        None => note,
    })
}

#[cfg(test)]
mod tests {
    use application::use_cases::{Advisory, Failure};
    use domain::error::ReasonCode;
    use k8s_openapi::jiff::Timestamp;

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
    fn a_drift_note_names_the_fields_and_what_else_happened() {
        let synced = Outcome::synced(None, "fine");
        assert_eq!(drift_note(&synced), None);
        let mut drift = application::use_cases::Drift::default();
        drift.note("redirect_uris", true);
        let mut corrected = synced.corrected(drift);
        assert_eq!(
            drift_note(&corrected).as_deref(),
            Some("drift corrected on the remote object: redirect_uris")
        );
        corrected.drift_effect = Some("the client secret was rotated by Forgejo");
        assert_eq!(
            drift_note(&corrected).as_deref(),
            Some(
                "drift corrected on the remote object: redirect_uris; the client secret was \
                 rotated by Forgejo"
            )
        );
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
