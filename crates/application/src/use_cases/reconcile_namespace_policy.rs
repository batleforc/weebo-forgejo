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

#[cfg(test)]
mod tests {
    use api::namespace_policy::{Effect, NamespaceRule, NamespacedKind};

    use super::*;

    fn rule(namespaces: &[&str], kinds: &[NamespacedKind]) -> NamespaceRule {
        NamespaceRule {
            namespaces: namespaces.iter().map(|n| n.to_string()).collect(),
            allowed_kinds: kinds.to_vec(),
            allowed_organizations: None,
            allowed_users: None,
            allowed_templates: None,
            effect: Effect::Allow,
        }
    }

    #[test]
    fn usable_rules_are_ready() {
        let spec = ForgejoNamespacePolicySpec {
            rules: vec![rule(&["team-*"], &[NamespacedKind::ForgejoRepository])],
        };
        let outcome = reconcile_namespace_policy(&spec);
        assert_eq!(outcome.ready, Ok("1 rule(s) in force".to_string()));
    }

    #[test]
    fn a_rule_that_can_never_match_is_invalid() {
        for bad in [
            rule(&[], &[NamespacedKind::ForgejoRepository]),
            rule(&["team-a"], &[]),
        ] {
            let spec = ForgejoNamespacePolicySpec {
                rules: vec![rule(&["x"], &[NamespacedKind::ForgejoWebhook]), bad],
            };
            let outcome = reconcile_namespace_policy(&spec);
            assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
            assert!(outcome.ready.unwrap_err().message.contains("rules[1]"));
        }
    }
}
