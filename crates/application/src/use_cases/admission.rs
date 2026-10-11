//! The admission checks shared by the admission webhook and every
//! namespaced reconciler — same rules, same `ReasonCode` whichever side
//! refuses:
//!
//! - `secretTargets` stay in the CR's namespace (`CrossNamespaceReference`);
//! - the allow-list: what each namespaced kind references ([`Governed`]),
//!   against the policies read through the [`PolicySource`] port
//!   (`NamespaceNotAllowed`);
//! - credentials of a site admin — a token or an OAuth2 application of a
//!   `ForgejoUser` with `admin: true`, or of the operator's own admin
//!   account — need an `Allow` rule naming that user in `allowedUsers`,
//!   even while no policy exists (`NamespaceNotAllowed`).

use api::namespace_policy::{Effect as ApiEffect, NamespaceRule, NamespacedKind};
use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoOAuth2Application, ForgejoRepository,
    ForgejoWebhook,
};
use domain::allow_list::{self, Decision, Effect, Kind, Request, Rule};
use domain::error::ReasonCode;

use api::common::SecretTarget;

use crate::ports::{ClusterError, PolicySource, RefKind, ReferenceReader, SecretOwner};
use crate::use_cases::{Failure, emit};

/// A namespaced kind governed by `ForgejoNamespacePolicy`.
pub trait Governed {
    const KIND: NamespacedKind;
    /// `(ForgejoOrganization names, ForgejoUser names)` this CR references.
    fn references(&self) -> (Vec<String>, Vec<String>);
    /// Where the CR writes the secrets it emits.
    fn secret_targets(&self) -> &[SecretTarget] {
        &[]
    }
    /// The users whose credentials the CR mints (`ForgejoUser` names, or
    /// [`allow_list::INSTANCE_ADMIN`]).
    fn credential_users(&self) -> Vec<String> {
        vec![]
    }
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
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.key.secret_targets
    }
}

impl Governed for ForgejoOAuth2Application {
    const KIND: NamespacedKind = NamespacedKind::ForgejoOAuth2Application;
    fn references(&self) -> (Vec<String>, Vec<String>) {
        // Without an owner the app belongs to the operator's admin account:
        // that is a user too, or `allowedUsers` would vacuously cover it.
        (vec![], self.credential_users())
    }
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.secret_targets
    }
    fn credential_users(&self) -> Vec<String> {
        vec![match &self.spec.owner_ref {
            Some(r) => r.name.clone(),
            None => allow_list::INSTANCE_ADMIN.to_string(),
        }]
    }
}

impl Governed for ForgejoAccessToken {
    const KIND: NamespacedKind = NamespacedKind::ForgejoAccessToken;
    fn references(&self) -> (Vec<String>, Vec<String>) {
        (vec![], self.credential_users())
    }
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.secret_targets
    }
    fn credential_users(&self) -> Vec<String> {
        names([Some(&self.spec.user_ref)])
    }
}

/// Every admission check of `obj` (in `namespace`), in order: its secret
/// targets, the allow-list, then the site-admin credentials rule.
pub async fn enforce<K: Governed>(
    policies: &dyn PolicySource<NamespaceRule>,
    refs: &dyn ReferenceReader,
    namespace: &str,
    obj: &K,
) -> Result<Result<(), Failure>, ClusterError> {
    let owner = SecretOwner::namespaced("", namespace, "");
    if let Err(f) = emit::check_targets(obj.secret_targets(), &owner) {
        return Ok(Err(f));
    }
    let (organizations, users) = obj.references();
    let request = allow_list::request(namespace, kind_of(K::KIND), &organizations, &users);
    let policies = policies.policies().await?;
    if let Err(f) = check(&request, &policies) {
        return Ok(Err(f));
    }
    let mut admins = Vec::new();
    for user in obj.credential_users() {
        if user == allow_list::INSTANCE_ADMIN
            || refs
                .referenced(RefKind::User, namespace, &user)
                .await?
                .is_some_and(|u| u.admin)
        {
            admins.push(user);
        }
    }
    Ok(check_admin_credentials(
        namespace,
        kind_of(K::KIND),
        &admins,
        &policies,
    ))
}

/// `admins`: the site-admin users whose credentials a CR mints. Each must
/// be named in the `allowedUsers` of an `Allow` rule covering the CR's
/// namespace and kind — a rule allowing any user doesn't count, and the
/// rule applies even while no policy exists: anyone allowed to create a
/// token in some namespace must not get a site-admin token by default.
pub fn check_admin_credentials(
    namespace: &str,
    kind: Kind,
    admins: &[String],
    policies: &[Vec<NamespaceRule>],
) -> Result<(), Failure> {
    if admins.is_empty() {
        return Ok(());
    }
    let explicit: Vec<Rule> = policies
        .iter()
        .flatten()
        .filter(|r| r.effect == ApiEffect::Deny || r.allowed_users.is_some())
        .map(rule_of)
        .collect();
    let request = allow_list::request(namespace, kind, &[], admins);
    match allow_list::evaluate(&request, &explicit, true) {
        Decision::Allowed => Ok(()),
        Decision::Denied(_) => Err(Failure::new(
            ReasonCode::NamespaceNotAllowed,
            format!(
                "credentials of site admin(s) {} need a ForgejoNamespacePolicy Allow rule \
                 for namespace {namespace:?} naming them in allowedUsers",
                admins.join(", ")
            ),
        )),
    }
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

    fn token(user: &str, targets: serde_json::Value) -> ForgejoAccessToken {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
            "metadata": {"name": "t", "namespace": "team-a"},
            "spec": {"userRef": {"name": user}, "scopes": ["read:user"], "secretTargets": targets},
        }))
        .unwrap()
    }

    fn allow_tokens(users: Option<Vec<String>>) -> Vec<Vec<NamespaceRule>> {
        vec![vec![NamespaceRule {
            namespaces: vec!["team-a".into()],
            allowed_kinds: vec![
                NamespacedKind::ForgejoAccessToken,
                NamespacedKind::ForgejoOAuth2Application,
            ],
            allowed_organizations: None,
            allowed_users: users,
            effect: ApiEffect::Allow,
        }]]
    }

    #[tokio::test]
    async fn enforce_reads_the_policies_through_the_port() {
        let cluster = crate::test_support::FakeCluster::default();
        let app = app(Some("sso-bot"));
        assert!(
            enforce(&cluster, &cluster, "team-a", &app)
                .await
                .unwrap()
                .is_ok()
        );
        cluster.set_policies(vec![vec![]]);
        let denied = enforce(&cluster, &cluster, "team-a", &app).await.unwrap();
        assert_eq!(denied.unwrap_err().reason, ReasonCode::NamespaceNotAllowed);
        cluster.fail_with("apiserver down");
        assert!(enforce(&cluster, &cluster, "team-a", &app).await.is_err());
    }

    #[tokio::test]
    async fn secret_targets_stay_in_the_namespace() {
        let cluster = crate::test_support::FakeCluster::default();
        let own = token(
            "ci-bot",
            serde_json::json!([{"name": "a", "namespace": "team-a"}]),
        );
        assert!(
            enforce(&cluster, &cluster, "team-a", &own)
                .await
                .unwrap()
                .is_ok()
        );
        let foreign = token(
            "ci-bot",
            serde_json::json!([{"name": "a", "namespace": "kube-system"}]),
        );
        let denied = enforce(&cluster, &cluster, "team-a", &foreign)
            .await
            .unwrap();
        assert_eq!(
            denied.unwrap_err().reason,
            ReasonCode::CrossNamespaceReference
        );
    }

    #[tokio::test]
    async fn site_admin_credentials_need_an_explicit_allow() {
        let cluster = crate::test_support::FakeCluster::default();
        cluster.put(
            RefKind::User,
            "",
            "root",
            crate::ports::ReferencedCr {
                admin: true,
                ..Default::default()
            },
        );
        let admin = token("root", serde_json::json!([]));
        // Even without any policy...
        assert!(
            enforce(&cluster, &cluster, "team-a", &admin)
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            enforce(&cluster, &cluster, "team-a", &app(None))
                .await
                .unwrap()
                .is_err()
        );
        // ...and with a rule allowing any user.
        cluster.set_policies(allow_tokens(None));
        assert!(
            enforce(&cluster, &cluster, "team-a", &admin)
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            enforce(
                &cluster,
                &cluster,
                "team-a",
                &token("ci-bot", serde_json::json!([]))
            )
            .await
            .unwrap()
            .is_ok()
        );
        // Named explicitly: allowed.
        cluster.set_policies(allow_tokens(Some(vec![
            "root".into(),
            allow_list::INSTANCE_ADMIN.into(),
        ])));
        assert!(
            enforce(&cluster, &cluster, "team-a", &admin)
                .await
                .unwrap()
                .is_ok()
        );
        assert!(
            enforce(&cluster, &cluster, "team-a", &app(None))
                .await
                .unwrap()
                .is_ok()
        );
    }
}
