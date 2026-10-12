//! The admission checks shared by the admission webhook and every
//! namespaced reconciler — same rules, same `ReasonCode` whichever side
//! refuses:
//!
//! - `secretTargets` stay in the CR's namespace (`CrossNamespaceReference`);
//! - the allow-list: what each namespaced kind manages or references
//!   ([`Governed`]) — users and organizations by their **Forgejo** names,
//!   whether referenced through a CR or a `remoteName` — against the
//!   policies read through the [`PolicySource`] port (`NamespaceNotAllowed`);
//! - credentials of a site admin — a token or an OAuth2 application of a
//!   `ForgejoUser` with `admin: true`, or of the operator's own admin
//!   account — need an `Allow` rule naming that user in `allowedUsers`,
//!   even while no policy exists (`NamespaceNotAllowed`).
//!
//! A CR bound to a `ForgejoLocalInstance` is not governed by the policies
//! (its namespace's own token bounds what it can do): only its secret
//! targets are checked.

use api::common::IdentityRef;
use api::namespace_policy::{Effect as ApiEffect, NamespaceRule, NamespacedKind};
use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoOAuth2Application, ForgejoOrganization,
    ForgejoRepository, ForgejoTeam, ForgejoUser, ForgejoUserKey, ForgejoWebhook,
};
use domain::allow_list::{self, Decision, Effect, Kind, Request, Rule};
use domain::error::ReasonCode;

use api::common::SecretTarget;

use crate::ports::{
    BoundInstance, ClusterError, PolicySource, RefKind, ReferenceReader, SecretOwner,
};
use crate::use_cases::refs::forgejo_name;
use crate::use_cases::{Failure, emit};

/// A user or organization a CR manages or references, as the policy sees
/// it: by its Forgejo name.
pub enum Named<'a> {
    /// The CR's own Forgejo name (a `ForgejoUser`'s login, a
    /// `ForgejoOrganization`'s name).
    Own(&'a str),
    /// A reference, resolved to the Forgejo name it stands for.
    Ref(&'a IdentityRef),
}

/// A user whose credentials a CR mints.
pub enum Credential<'a> {
    /// The operator's own admin account ([`allow_list::INSTANCE_ADMIN`]).
    InstanceAdmin,
    /// A referenced user: a site admin when its CR says `admin: true` — or
    /// whenever it's a `remoteName`, whose flags the policy can't read.
    User(&'a IdentityRef),
}

/// A namespaced kind governed by `ForgejoNamespacePolicy`.
pub trait Governed {
    const KIND: NamespacedKind;
    /// The organizations this CR manages or references.
    fn organizations(&self) -> Vec<Named<'_>> {
        vec![]
    }
    /// The users this CR manages or references.
    fn users(&self) -> Vec<Named<'_>> {
        vec![]
    }
    /// Template repositories (Forgejo `owner/name`) the CR generates from
    /// by name.
    fn templates(&self) -> Vec<String> {
        vec![]
    }
    /// Where the CR writes the secrets it emits.
    fn secret_targets(&self) -> &[SecretTarget] {
        &[]
    }
    /// The users whose credentials the CR mints.
    fn credential_users(&self) -> Vec<Credential<'_>> {
        vec![]
    }
}

fn refs<'a>(refs: impl IntoIterator<Item = Option<&'a IdentityRef>>) -> Vec<Named<'a>> {
    refs.into_iter().flatten().map(Named::Ref).collect()
}

impl Governed for ForgejoUser {
    const KIND: NamespacedKind = NamespacedKind::ForgejoUser;
    fn users(&self) -> Vec<Named<'_>> {
        vec![Named::Own(&self.spec.username)]
    }
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.secret_targets
    }
}

impl Governed for ForgejoUserKey {
    const KIND: NamespacedKind = NamespacedKind::ForgejoUserKey;
    fn users(&self) -> Vec<Named<'_>> {
        refs([Some(&self.spec.user_ref)])
    }
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.key.secret_targets
    }
    /// An SSH key pushes as its user: a site admin's needs an explicit rule.
    fn credential_users(&self) -> Vec<Credential<'_>> {
        vec![Credential::User(&self.spec.user_ref)]
    }
}

impl Governed for ForgejoOrganization {
    const KIND: NamespacedKind = NamespacedKind::ForgejoOrganization;
    fn organizations(&self) -> Vec<Named<'_>> {
        vec![Named::Own(&self.spec.name)]
    }
    fn users(&self) -> Vec<Named<'_>> {
        refs([self.spec.owner_ref.as_ref()])
    }
}

impl Governed for ForgejoTeam {
    const KIND: NamespacedKind = NamespacedKind::ForgejoTeam;
    fn organizations(&self) -> Vec<Named<'_>> {
        refs([Some(&self.spec.organization_ref)])
    }
    fn users(&self) -> Vec<Named<'_>> {
        refs(self.spec.member_refs.iter().map(Some))
    }
}

impl Governed for ForgejoRepository {
    const KIND: NamespacedKind = NamespacedKind::ForgejoRepository;
    fn organizations(&self) -> Vec<Named<'_>> {
        refs([self.spec.organization_ref.as_ref()])
    }
    fn users(&self) -> Vec<Named<'_>> {
        refs([self.spec.user_ref.as_ref()])
    }
    fn templates(&self) -> Vec<String> {
        let by_name = self.spec.from_template.as_ref();
        by_name
            .and_then(|t| t.repository.clone())
            .into_iter()
            .collect()
    }
}

impl Governed for ForgejoWebhook {
    const KIND: NamespacedKind = NamespacedKind::ForgejoWebhook;
    fn organizations(&self) -> Vec<Named<'_>> {
        refs([self.spec.organization_ref.as_ref()])
    }
}

impl Governed for ForgejoDeployKey {
    const KIND: NamespacedKind = NamespacedKind::ForgejoDeployKey;
    // Only a same-namespace repository, itself governed.
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.key.secret_targets
    }
}

impl Governed for ForgejoOAuth2Application {
    const KIND: NamespacedKind = NamespacedKind::ForgejoOAuth2Application;
    // Without an owner the app belongs to the operator's admin account:
    // that is a user too, or `allowedUsers` would vacuously cover it.
    fn users(&self) -> Vec<Named<'_>> {
        vec![match &self.spec.owner_ref {
            Some(r) => Named::Ref(r),
            None => Named::Own(allow_list::INSTANCE_ADMIN),
        }]
    }
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.secret_targets
    }
    fn credential_users(&self) -> Vec<Credential<'_>> {
        vec![match &self.spec.owner_ref {
            Some(r) => Credential::User(r),
            None => Credential::InstanceAdmin,
        }]
    }
}

impl Governed for ForgejoAccessToken {
    const KIND: NamespacedKind = NamespacedKind::ForgejoAccessToken;
    fn users(&self) -> Vec<Named<'_>> {
        refs([Some(&self.spec.user_ref)])
    }
    fn secret_targets(&self) -> &[SecretTarget] {
        &self.spec.secret_targets
    }
    fn credential_users(&self) -> Vec<Credential<'_>> {
        vec![Credential::User(&self.spec.user_ref)]
    }
}

/// The Forgejo names of `named`, as seen from `namespace`.
async fn names(
    reader: &dyn ReferenceReader,
    kind: RefKind,
    namespace: &str,
    named: Vec<Named<'_>>,
) -> Result<Vec<String>, ClusterError> {
    let mut names = Vec::with_capacity(named.len());
    for n in named {
        names.push(match n {
            Named::Own(name) => name.to_string(),
            Named::Ref(r) => forgejo_name(reader, kind, namespace, r).await?,
        });
    }
    Ok(names)
}

/// Every admission check of `obj` (in `namespace`), in order: its secret
/// targets, the allow-list, then the site-admin credentials rule — for a
/// CR whose instance isn't known (as if bound to a `ForgejoInstance`).
pub async fn enforce<K: Governed>(
    policies: &dyn PolicySource<NamespaceRule>,
    refs: &dyn ReferenceReader,
    namespace: &str,
    obj: &K,
) -> Result<Result<(), Failure>, ClusterError> {
    enforce_on(policies, refs, namespace, obj, None).await
}

/// [`enforce`] for a CR bound to `instance`: a `ForgejoLocalInstance`
/// skips the policies (secret targets only); `None` (not resolved) is
/// governed.
pub async fn enforce_on<K: Governed>(
    policies: &dyn PolicySource<NamespaceRule>,
    refs: &dyn ReferenceReader,
    namespace: &str,
    obj: &K,
    instance: Option<&BoundInstance>,
) -> Result<Result<(), Failure>, ClusterError> {
    let owner = SecretOwner::namespaced("", namespace, "");
    if let Err(f) = emit::check_targets(obj.secret_targets(), &owner) {
        return Ok(Err(f));
    }
    if instance.is_some_and(|i| !i.governed_by_policy()) {
        return Ok(Ok(()));
    }
    let organizations = names(refs, RefKind::Organization, namespace, obj.organizations()).await?;
    let users = names(refs, RefKind::User, namespace, obj.users()).await?;
    let templates = obj.templates();
    let request = allow_list::request(
        namespace,
        kind_of(K::KIND),
        &organizations,
        &users,
        &templates,
    );
    let policies = policies.policies().await?;
    if let Err(f) = check(&request, &policies) {
        return Ok(Err(f));
    }
    let mut admins = Vec::new();
    for user in obj.credential_users() {
        match user {
            Credential::InstanceAdmin => admins.push(allow_list::INSTANCE_ADMIN.to_string()),
            Credential::User(r) => {
                let admin = match r.target(namespace) {
                    Some((ns, name)) => refs
                        .referenced(RefKind::User, ns, name)
                        .await?
                        .is_some_and(|u| u.admin),
                    // A remote user's flags aren't known here: treated as
                    // a site admin, it needs an explicit rule.
                    None => true,
                };
                if admin {
                    admins.push(forgejo_name(refs, RefKind::User, namespace, r).await?);
                }
            }
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
    let request = allow_list::request(namespace, kind, &[], admins, &[]);
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
        NamespacedKind::ForgejoUser => Kind::User,
        NamespacedKind::ForgejoUserKey => Kind::UserKey,
        NamespacedKind::ForgejoOrganization => Kind::Organization,
        NamespacedKind::ForgejoTeam => Kind::Team,
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
        rule.allowed_templates.clone(),
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
            allowed_templates: None,
            effect: ApiEffect::Allow,
        }]];
        let bot = vec!["ci-bot".to_string()];
        let admin = vec!["admin".to_string()];
        let ask = |users| allow_list::request("team-a", Kind::AccessToken, &[], users, &[]);
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
        let organizations: Vec<String> = vec![];
        let refs: Vec<String> = app
            .users()
            .into_iter()
            .map(|n| match n {
                Named::Own(name) => name.to_string(),
                Named::Ref(r) => r.name.clone().unwrap(),
            })
            .collect();
        let rule = allow_list::rule(
            vec!["team-a".into()],
            vec![Kind::OAuth2Application],
            None,
            users.map(|u| u.iter().map(|s| s.to_string()).collect()),
            None,
            Effect::Allow,
        );
        let request = allow_list::request(
            "team-a",
            Kind::OAuth2Application,
            &organizations,
            &refs,
            &[],
        );
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
            allowed_templates: None,
            effect: ApiEffect::Allow,
        }]]
    }

    fn repository(template: serde_json::Value) -> ForgejoRepository {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoRepository",
            "metadata": {"name": "app", "namespace": "team-a"},
            "spec": {"organizationRef": {"name": "weebo"}, "name": "app", "fromTemplate": template},
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn templates_by_name_are_governed_by_allowed_templates() {
        let cluster = crate::test_support::FakeCluster::default();
        let shared = repository(serde_json::json!({"repository": "batlehub/weebo-base"}));
        let foreign = repository(serde_json::json!({"repository": "ops/secrets"}));
        let local = repository(serde_json::json!({"repositoryRef": {"name": "tpl"}}));
        let verdict = |repo: &ForgejoRepository| {
            let (cluster, repo) = (&cluster, repo.clone());
            async move { enforce(cluster, cluster, "team-a", &repo).await.unwrap() }
        };
        assert!(verdict(&foreign).await.is_ok(), "no policy, no restriction");

        cluster.set_policies(vec![vec![NamespaceRule {
            namespaces: vec!["team-*".into()],
            allowed_kinds: vec![NamespacedKind::ForgejoRepository],
            allowed_organizations: None,
            allowed_users: None,
            allowed_templates: Some(vec!["batlehub/*".into()]),
            effect: ApiEffect::Allow,
        }]]);
        assert!(verdict(&shared).await.is_ok());
        assert!(
            verdict(&local).await.is_ok(),
            "a same-namespace template CR isn't a template by name"
        );
        let denied = verdict(&foreign).await.unwrap_err();
        assert_eq!(denied.reason, ReasonCode::NamespaceNotAllowed);
        assert!(denied.message.contains("ops/secrets"), "{}", denied.message);
    }

    #[tokio::test]
    async fn a_cr_on_a_local_instance_skips_the_policies_not_its_targets() {
        let cluster = crate::test_support::FakeCluster::default();
        cluster.set_policies(vec![vec![NamespaceRule {
            namespaces: vec!["team-b".into()],
            allowed_kinds: vec![NamespacedKind::ForgejoRepository],
            allowed_organizations: None,
            allowed_users: None,
            allowed_templates: None,
            effect: ApiEffect::Allow,
        }]]);
        let repo = repository(serde_json::json!({"repository": "ops/secrets"}));
        let local = BoundInstance::local("team-a", "own");
        let cluster_instance = BoundInstance::cluster("main");
        let on = |instance| enforce_on(&cluster, &cluster, "team-a", &repo, instance);
        assert!(on(Some(&local)).await.unwrap().is_ok());
        let denied = on(Some(&cluster_instance)).await.unwrap().unwrap_err();
        assert_eq!(denied.reason, ReasonCode::NamespaceNotAllowed);
        assert!(on(None).await.unwrap().is_err());

        let elsewhere: ForgejoAccessToken = serde_json::from_value(serde_json::json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
            "metadata": {"name": "t", "namespace": "team-a"},
            "spec": {"userRef": {"name": "bot"}, "scopes": ["read:user"],
                     "secretTargets": [{"name": "t", "namespace": "team-b"}]},
        }))
        .unwrap();
        let targets = enforce_on(&cluster, &cluster, "team-a", &elsewhere, Some(&local));
        assert_eq!(
            targets.await.unwrap().unwrap_err().reason,
            ReasonCode::CrossNamespaceReference
        );
    }

    #[tokio::test]
    async fn the_policy_matches_forgejo_names_and_distrusts_remote_users() {
        let cluster = crate::test_support::FakeCluster::default();
        cluster.put(
            RefKind::User,
            "team-a",
            "bot",
            crate::ports::ReferencedCr {
                spec_name: Some("ci-bot".into()),
                ..Default::default()
            },
        );
        cluster.set_policies(allow_tokens(Some(vec!["ci-bot".into()])));
        let token = |user: serde_json::Value| -> ForgejoAccessToken {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
                "metadata": {"name": "t", "namespace": "team-a"},
                "spec": {"userRef": user, "scopes": ["read:user"]},
            }))
            .unwrap()
        };
        let by_cr = token(serde_json::json!({"name": "bot"}));
        assert!(
            enforce(&cluster, &cluster, "team-a", &by_cr)
                .await
                .unwrap()
                .is_ok()
        );
        // The CR name isn't what the rule lists: its Forgejo login is.
        cluster.set_policies(allow_tokens(Some(vec!["bot".into()])));
        assert!(
            enforce(&cluster, &cluster, "team-a", &by_cr)
                .await
                .unwrap()
                .is_err()
        );
        // A remote user is matched by its name, and treated as a site admin:
        // allowed by an explicit rule only.
        let remote = token(serde_json::json!({"remoteName": "ops"}));
        cluster.set_policies(vec![]);
        let denied = enforce(&cluster, &cluster, "team-a", &remote)
            .await
            .unwrap();
        assert_eq!(denied.unwrap_err().reason, ReasonCode::NamespaceNotAllowed);
        cluster.set_policies(allow_tokens(Some(vec!["ops".into()])));
        assert!(
            enforce(&cluster, &cluster, "team-a", &remote)
                .await
                .unwrap()
                .is_ok()
        );
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
            "team-a",
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
