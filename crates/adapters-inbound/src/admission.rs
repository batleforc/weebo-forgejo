//! The namespace allow-list, Kubernetes side: what each namespaced kind
//! references, and the policy lookup shared by the webhook and the
//! reconcilers (`application::use_cases::admission::check` decides).

use api::namespace_policy::NamespacedKind;
use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoNamespacePolicy, ForgejoOAuth2Application,
    ForgejoRepository, ForgejoWebhook,
};
use application::use_cases::Failure;
use application::use_cases::admission::{check, kind_of};
use domain::allow_list::Request;
use kube::{Api, Client};

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
            None => domain::allow_list::INSTANCE_ADMIN.to_string(),
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

/// Every policy's rules, one entry per policy.
pub async fn policies(
    client: &Client,
) -> Result<Vec<Vec<api::namespace_policy::NamespaceRule>>, kube::Error> {
    let api: Api<ForgejoNamespacePolicy> = Api::all(client.clone());
    Ok(api
        .list(&Default::default())
        .await?
        .into_iter()
        .map(|p| p.spec.rules)
        .collect())
}

/// Checks `obj` (in `namespace`) against the current policies.
pub async fn enforce<K: Governed>(
    client: &Client,
    namespace: &str,
    obj: &K,
) -> Result<Result<(), Failure>, kube::Error> {
    let (organizations, users) = obj.references();
    let request = Request {
        namespace,
        kind: kind_of(K::KIND),
        organizations: &organizations,
        users: &users,
    };
    Ok(check(&request, &policies(client).await?))
}

#[cfg(test)]
mod tests {
    use domain::allow_list::{Decision, Effect, Kind, Rule, evaluate};

    use super::*;

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
        let rule = Rule {
            namespaces: vec!["team-a".into()],
            kinds: vec![Kind::OAuth2Application],
            organizations: None,
            users: users.map(|u| u.iter().map(|s| s.to_string()).collect()),
            effect: Effect::Allow,
        };
        let request = Request {
            namespace: "team-a",
            kind: Kind::OAuth2Application,
            organizations: &organizations,
            users: &refs,
        };
        evaluate(&request, &[rule], true)
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
            decide(&app(None), Some(&[domain::allow_list::INSTANCE_ADMIN])),
            Decision::Allowed
        );
        assert_eq!(decide(&app(None), None), Decision::Allowed);
    }
}
