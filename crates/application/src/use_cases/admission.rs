//! The allow-list check shared by the admission webhook and every
//! namespaced reconciler — same rules, same `ReasonCode`
//! (`NamespaceNotAllowed`) whichever side refuses.

use api::namespace_policy::{Effect as ApiEffect, NamespaceRule, NamespacedKind};
use domain::allow_list::{self, Decision, Effect, Kind, Request, Rule};
use domain::error::ReasonCode;

use crate::use_cases::Failure;

pub fn kind_of(kind: NamespacedKind) -> Kind {
    match kind {
        NamespacedKind::ForgejoRepository => Kind::Repository,
        NamespacedKind::ForgejoWebhook => Kind::Webhook,
        NamespacedKind::ForgejoDeployKey => Kind::DeployKey,
        NamespacedKind::ForgejoOAuth2Application => Kind::OAuth2Application,
        NamespacedKind::ForgejoAccessToken => Kind::AccessToken,
    }
}

pub fn rule_of(rule: &NamespaceRule) -> Rule {
    Rule {
        namespaces: rule.namespaces.clone(),
        kinds: rule.allowed_kinds.iter().copied().map(kind_of).collect(),
        organizations: rule.allowed_organizations.clone(),
        users: rule.allowed_users.clone(),
        effect: match rule.effect {
            ApiEffect::Allow => Effect::Allow,
            ApiEffect::Deny => Effect::Deny,
        },
    }
}

/// `policies`: the `spec.rules` of every `ForgejoNamespacePolicy`, one
/// entry per policy (an existing policy with no rule still switches the
/// cluster to default-deny).
pub fn check(request: &Request<'_>, policies: &[Vec<NamespaceRule>]) -> Result<(), Failure> {
    let rules: Vec<Rule> = policies.iter().flatten().map(rule_of).collect();
    match allow_list::evaluate(request, &rules, !policies.is_empty()) {
        Decision::Allowed => Ok(()),
        Decision::Denied(why) => Err(Failure::new(ReasonCode::NamespaceNotAllowed, why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_rules_map_onto_the_domain() {
        let policies = vec![vec![NamespaceRule {
            namespaces: vec!["team-a".into()],
            allowed_kinds: vec![NamespacedKind::ForgejoAccessToken],
            allowed_organizations: None,
            allowed_users: Some(vec!["ci-bot".into()]),
            effect: ApiEffect::Allow,
        }]];
        let bot = vec!["ci-bot".to_string()];
        let admin = vec!["admin".to_string()];
        let ask = |users| Request {
            namespace: "team-a",
            kind: Kind::AccessToken,
            organizations: &[],
            users,
        };
        assert!(check(&ask(&bot), &policies).is_ok());
        let denied = check(&ask(&admin), &policies).unwrap_err();
        assert_eq!(denied.reason, ReasonCode::NamespaceNotAllowed);
        assert!(
            check(&ask(&admin), &[]).is_ok(),
            "no policy, no restriction"
        );
    }
}
