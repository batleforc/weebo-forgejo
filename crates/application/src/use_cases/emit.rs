//! Writing a value that Forgejo shows only once (client secret, token) to
//! every target of a CR, and detecting a target that lost it — the kit's
//! helpers, with failures mapped to `SecretTargetFailed`.

use std::collections::BTreeMap;

use api::common::SecretTarget;
use domain::error::ReasonCode;

use crate::ports::SecretStore;
use crate::use_cases::Failure;

use weebo_kit_application::emit as kit;
pub use weebo_kit_application::emit::{rotation_requested, targets};

fn failed(e: crate::ports::SecretStoreError) -> Failure {
    Failure::new(ReasonCode::SecretTargetFailed, e.to_string())
}

pub async fn any_missing(
    targets: &[SecretTarget],
    namespace: Option<&str>,
    store: &dyn SecretStore,
) -> Result<bool, Failure> {
    kit::any_missing(targets, namespace, store)
        .await
        .map_err(failed)
}

pub async fn write_all(
    targets: &[SecretTarget],
    namespace: Option<&str>,
    data: &BTreeMap<String, String>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    kit::write_all(targets, namespace, data, store)
        .await
        .map_err(failed)
}

pub async fn delete_all(
    targets: &[SecretTarget],
    namespace: Option<&str>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    kit::delete_all(targets, namespace, store)
        .await
        .map_err(failed)
}
