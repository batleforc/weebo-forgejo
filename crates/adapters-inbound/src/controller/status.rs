//! `Outcome` → `status` translation, shared by every controller: one merge
//! patch on the status subresource (`observedGeneration`, `forgejoId`,
//! `forgejoName`, conditions) and a Kubernetes `Event` whenever `Ready`
//! changes. Only `ReasonCode`s ever reach a condition or an Event.

use std::fmt::Debug;

use api::status::{Condition, ForgejoStatus};
use application::ports::ForgejoRef;
use application::use_cases::Outcome;
use domain::error::ReasonCode;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::events::{Event, EventType, Recorder};
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

/// Whether `spec` changed since the last reconcile that reached the end.
pub fn spec_changed<K: HasStatus + Resource>(obj: &K) -> bool {
    let observed = obj.forgejo_status().and_then(|s| s.observed_generation);
    observed != obj.meta().generation
}

pub fn ready_condition(status: Option<&ForgejoStatus>) -> Option<&Condition> {
    status?.conditions.iter().find(|c| c.type_ == "Ready")
}

/// Builds the full condition list: `Ready` first, then one condition per
/// advisory (its `type` is the reason's name). `lastTransitionTime` only
/// moves when a condition's status flips.
pub fn conditions(
    previous: &[Condition],
    outcome: &Outcome,
    generation: Option<i64>,
    now: &Time,
) -> Vec<Condition> {
    let condition = |type_: &str, status: &str, reason: ReasonCode, message: &str| {
        let prev = previous.iter().find(|c| c.type_ == type_);
        let last_transition_time = match prev {
            Some(p) if p.status == status => p.last_transition_time.clone(),
            _ => Some(now.clone()),
        };
        Condition {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: reason.as_str().to_string(),
            message: message.to_string(),
            last_transition_time,
            observed_generation: generation,
        }
    };

    let mut out = vec![match &outcome.ready {
        Ok(message) => condition("Ready", "True", ReasonCode::Reconciled, message),
        Err(f) => condition("Ready", "False", f.reason, &f.message),
    }];
    for advisory in &outcome.advisories {
        out.push(condition(
            advisory.reason.as_str(),
            "True",
            advisory.reason,
            &advisory.message,
        ));
    }
    out
}

/// Patches the outcome onto `obj` (freshly read from the API server) and
/// emits an Event if `Ready`'s status or reason changed. A failed outcome
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
    let previous = obj.forgejo_status();
    let generation = obj.meta().generation;
    let now = Time(Timestamp::now());
    let conds = conditions(
        previous
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default(),
        outcome,
        generation,
        &now,
    );

    let mut status = serde_json::json!({
        "observedGeneration": generation,
        "conditions": conds,
    });
    if let Some(r) = &outcome.forgejo {
        status["forgejoId"] = r.id.to_string().into();
        status["forgejoName"] = r.name.clone().into();
    }
    if let Some(hash) = &outcome.secret_hash {
        status["appliedSecretHash"] = hash.clone().into();
    }
    if let Some(rotation) = &outcome.last_rotation {
        status["lastRotation"] = rotation.clone().into();
    }
    api.patch_status(
        &obj.name_any(),
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;

    let before = ready_condition(previous).map(|c| (c.status.as_str(), c.reason.as_str()));
    let after = (conds[0].status.as_str(), conds[0].reason.as_str());
    if before != Some(after) {
        let event = Event {
            type_: if outcome.ready.is_ok() {
                EventType::Normal
            } else {
                EventType::Warning
            },
            reason: conds[0].reason.clone(),
            // Events cap the note at 1 KiB.
            note: Some(conds[0].message.chars().take(1000).collect()),
            action: "Reconcile".to_string(),
            secondary: None,
        };
        // An Event is a courtesy: failing to record one must not fail the
        // reconcile (and requeue a status patch that already succeeded).
        if let Err(err) = recorder.publish(&event, &obj.object_ref(&())).await {
            tracing::warn!(error = %err, "failed to publish event");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use application::use_cases::{Advisory, Failure};

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
