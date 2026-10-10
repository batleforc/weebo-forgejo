//! Writing a value that Forgejo shows only once (client secret, token) to
//! every target of a CR, and detecting a target that lost it — the kit's
//! helpers, with failures mapped to `SecretTargetFailed` (and target
//! namespace violations to `CrossNamespaceReference`/`InvalidSpec`).

use std::collections::BTreeMap;

use api::common::SecretTarget;
use domain::error::ReasonCode;

use crate::ports::{SecretOwner, SecretStore};
use crate::use_cases::Failure;

use weebo_kit_application::emit as kit;
pub use weebo_kit_application::emit::{TargetViolation, rotation_requested, targets};

fn failed(e: crate::ports::SecretStoreError) -> Failure {
    Failure::new(ReasonCode::SecretTargetFailed, e.to_string())
}

/// A namespaced CR's targets stay in its namespace; a cluster-scoped CR's
/// targets name one. Checked before any Forgejo call, by the reconcilers
/// and the admission webhook alike.
pub fn check_targets(targets: &[SecretTarget], owner: &SecretOwner<'_>) -> Result<(), Failure> {
    kit::check_targets(targets, owner).map_err(|v| match v {
        TargetViolation::CrossNamespace { .. } => {
            Failure::new(ReasonCode::CrossNamespaceReference, v.to_string())
        }
        TargetViolation::MissingNamespace { .. } => {
            Failure::new(ReasonCode::InvalidSpec, v.to_string())
        }
    })
}

pub async fn any_missing(
    targets: &[SecretTarget],
    owner: &SecretOwner<'_>,
    store: &dyn SecretStore,
) -> Result<bool, Failure> {
    kit::any_missing(targets, owner, store)
        .await
        .map_err(failed)
}

pub async fn write_all(
    targets: &[SecretTarget],
    owner: &SecretOwner<'_>,
    data: &BTreeMap<String, String>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    kit::write_all(targets, owner, data, store)
        .await
        .map_err(failed)
}

pub async fn delete_all(
    targets: &[SecretTarget],
    owner: &SecretOwner<'_>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    kit::delete_all(targets, owner, store).await.map_err(failed)
}
