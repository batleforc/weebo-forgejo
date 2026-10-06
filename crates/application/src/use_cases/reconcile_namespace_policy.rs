use api::namespace_policy::ForgejoNamespacePolicySpec;
use domain::error::ReasonCode;

use crate::use_cases::{Failure, Outcome};

/// A policy has no Forgejo-side object: it's ready once its rules are
/// usable. An empty `namespaces`/`allowedKinds` list can never match, which
/// is almost certainly a mistake worth surfacing.
pub fn reconcile_namespace_policy(spec: &ForgejoNamespacePolicySpec) -> Outcome {
    for (i, rule) in spec.rules.iter().enumerate() {
        if rule.namespaces.is_empty() || rule.allowed_kinds.is_empty() {
            return Outcome::failed(
                None,
                Failure::new(
                    ReasonCode::InvalidSpec,
                    format!(
                        "spec.rules[{i}] has no namespaces or no allowedKinds and can never match"
                    ),
                ),
            );
        }
    }
    Outcome::synced(None, format!("{} rule(s) in force", spec.rules.len()))
}
