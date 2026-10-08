//! The allow-list check shared by the admission webhook and every
//! namespaced reconciler — same rules, same `ReasonCode`
//! (`NamespaceNotAllowed`) whichever side refuses: what each namespaced
//! kind references ([`Governed`]), and the decision against the policies
//! read through the [`PolicySource`] port.

use api::namespace_policy::{Effect as ApiEffect, NamespaceRule, NamespacedKind};
use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoOAuth2Application, ForgejoRepository,
    ForgejoWebhook,
};
use domain::allow_list::{self, Decision, Effect, Kind, Request, Rule};
use domain::error::ReasonCode;

use crate::ports::{ClusterError, PolicySource};
use crate::use_cases::Failure;

/// A namespaced kind governed by `ForgejoNamespacePolicy`.
pub trait Governed {
    const KIND: NamespacedKind;
    /// `(ForgejoOrganization names, ForgejoUser names)` this CR references.
    fn references(&self) -> (Vec<String>, Vec<String>);
}

fn names<'a>(refs: impl IntoIterator<Item = Option<&'a api::common::ObjectRef>>) -> Vec<String> {
    refs.into_iter().flatten().map(|r| r.name.clone()).collect()
}

impl Governed for ForgejoRepository {
    const KIND: NamespacedKind = NamespacedKind::ForgejoRepository;
    fn references(&self) -> (Vec<String>, Vec<String>) {
        (
            names([self.spec.organization_ref.as_ref()]),
            names([self.spec.user_ref.as_ref()]),
        )
    }
}

impl Governed for ForgejoWebhook {
    const KIND: NamespacedKind = NamespacedKind::ForgejoWebhook;
    fn references(&self) -> (Vec<String>, Vec<String>) {
        (names([self.spec.organization_ref.as_ref()]), vec![])
    }
}

impl Governed for ForgejoDeployKey {
    const KIND: NamespacedKind = NamespacedKind::ForgejoDeployKey;
    fn references(&self) -> (Vec<String>, Vec<String>) {
        // Only a same-namespace repository, itself governed.
        (vec![], vec![])
    }
}

impl Governed for ForgejoOAuth2Application {
    const KIND: NamespacedKind = NamespacedKind::ForgejoOAuth2Application;
    fn references(&self) -> (Vec<String>, Vec<String>) {
        // Without an owner the app belongs to the operator's admin account:
        // that is a user too, or `allowedUsers` would vacuously cover it.
        let owner = match &self.spec.owner_ref {
            Some(r) => r.name.clone(),
            None => allow_list::INSTANCE_ADMIN.to_string(),
        };
        (vec![], vec![owner])
    }
}

impl Governed for ForgejoAccessToken {
    const KIND: NamespacedKind = NamespacedKind::ForgejoAccessToken;
    fn references(&self) -> (Vec<String>, Vec<String>) {
        (vec![], names([Some(&self.spec.user_ref)]))
    }
}

/// Checks `obj` (in `namespace`) against the current policies.
pub async fn enforce<K: Governed>(
    policies: &dyn PolicySource,
    namespace: &str,
    obj: &K,
) -> Result<Result<(), Failure>, ClusterError> {
    let (organizations, users) = obj.references();
    let request = allow_list::request(namespace, kind_of(K::KIND), &organizations, &users);
    Ok(check(&request, &policies.policies().await?))
}

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
    allow_list::rule(
        rule.namespaces.clone(),
        rule.allowed_kinds.iter().copied().map(kind_of).collect(),
        rule.allowed_organizations.clone(),
        rule.allowed_users.clone(),
        match rule.effect {
            ApiEffect::Allow => Effect::Allow,
            ApiEffect::Deny => Effect::Deny,
        },
    )
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
        let ask = |users| allow_list::request("team-a", Kind::AccessToken, &[], users);
        assert!(check(&ask(&bot), &policies).is_ok());
        let denied = check(&ask(&admin), &policies).unwrap_err();
        assert_eq!(denied.reason, ReasonCode::NamespaceNotAllowed);
        assert!(
            check(&ask(&admin), &[]).is_ok(),
            "no policy, no restriction"
        );
    }

    fn app(owner: Option<&str>) -> ForgejoOAuth2Application {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOAuth2Application",
            "metadata": {"name": "app"},
            "spec": {
                "redirectUris": ["https://x/cb"],
                "ownerRef": owner.map(|n| serde_json::json!({"name": n})),
            },
        }))
        .unwrap()
    }

    fn decide(app: &ForgejoOAuth2Application, users: Option<&[&str]>) -> Decision {
        let (organizations, refs) = app.references();
        let rule = allow_list::rule(
            vec!["team-a".into()],
            vec![Kind::OAuth2Application],
            None,
            users.map(|u| u.iter().map(|s| s.to_string()).collect()),
            Effect::Allow,
        );
        let request = allow_list::request("team-a", Kind::OAuth2Application, &organizations, &refs);
        allow_list::evaluate(&request, &[rule], true)
    }

    #[test]
    fn an_app_without_owner_is_not_covered_by_a_restricted_allowed_users() {
        assert!(matches!(
            decide(&app(None), Some(&["sso-bot"])),
            Decision::Denied(_)
        ));
        assert_eq!(
            decide(&app(Some("sso-bot")), Some(&["sso-bot"])),
            Decision::Allowed
        );
        assert_eq!(
            decide(&app(None), Some(&[allow_list::INSTANCE_ADMIN])),
            Decision::Allowed
        );
        assert_eq!(decide(&app(None), None), Decision::Allowed);
    }

    #[tokio::test]
    async fn enforce_reads_the_policies_through_the_port() {
        let cluster = crate::test_support::FakeCluster::default();
        assert!(
            enforce(&cluster, "team-a", &app(None))
                .await
                .unwrap()
                .is_ok()
        );
        cluster.set_policies(vec![vec![]]);
        let denied = enforce(&cluster, "team-a", &app(None)).await.unwrap();
        assert_eq!(denied.unwrap_err().reason, ReasonCode::NamespaceNotAllowed);
        cluster.fail_with("apiserver down");
        assert!(enforce(&cluster, "team-a", &app(None)).await.is_err());
    }
}
