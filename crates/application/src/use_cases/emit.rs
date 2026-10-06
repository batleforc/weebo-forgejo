//! Writing a value that Forgejo shows only once (client secret, token) to
//! every target of a CR, and detecting a target that lost it.

use std::collections::BTreeMap;

use api::common::SecretTarget;
use domain::error::ReasonCode;

use crate::ports::SecretStore;
use crate::use_cases::Failure;

/// The CR's own targets, or the implicit one: named after the CR, in its
/// namespace, on the instance's default backend.
pub fn targets(
    explicit: &[SecretTarget],
    cr_name: &str,
    store: &dyn SecretStore,
) -> Vec<SecretTarget> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    vec![SecretTarget {
        backend: store.default_backend(),
        name: cr_name.to_string(),
        namespace: None,
        path: None,
    }]
}

pub async fn any_missing(
    targets: &[SecretTarget],
    namespace: Option<&str>,
    store: &dyn SecretStore,
) -> Result<bool, Failure> {
    for target in targets {
        let exists = store
            .exists(target, namespace)
            .await
            .map_err(|e| Failure::new(ReasonCode::SecretTargetFailed, e.to_string()))?;
        if !exists {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn write_all(
    targets: &[SecretTarget],
    namespace: Option<&str>,
    data: &BTreeMap<String, String>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    for target in targets {
        store
            .write(target, namespace, data)
            .await
            .map_err(|e| Failure::new(ReasonCode::SecretTargetFailed, e.to_string()))?;
    }
    Ok(())
}

pub async fn delete_all(
    targets: &[SecretTarget],
    namespace: Option<&str>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    for target in targets {
        store
            .delete(target, namespace)
            .await
            .map_err(|e| Failure::new(ReasonCode::SecretTargetFailed, e.to_string()))?;
    }
    Ok(())
}

/// A rotation was requested through a nonce the CR hasn't been rotated
/// for yet.
pub fn rotation_requested(nonce: &Option<String>, last_rotation: &Option<String>) -> bool {
    nonce.is_some() && nonce != last_rotation
}
