//! `ForgejoNamespacePolicy` rules — shared by the admission webhook and the
//! reconcilers' own re-check. The engine is the kit's
//! (`weebo_kit_domain::allow_list`); this module binds it to Forgejo's
//! kinds and to the two dimensions a request is scoped by: the
//! `ForgejoOrganization`s and `ForgejoUser`s it references. See
//! `.prompt/plan.md`, "Sécurité opérationnelle & déploiement".

use std::collections::BTreeMap;

pub use weebo_kit_domain::allow_list::{Decision, Effect};

/// Named in denial messages.
pub const POLICY_KIND: &str = "ForgejoNamespacePolicy";
/// Scope dimension: `ForgejoOrganization` CR names.
pub const ORGANIZATIONS: &str = "organizations";
/// Scope dimension: `ForgejoUser` CR names.
pub const USERS: &str = "users";

/// Namespaced kinds the allow-list governs (cluster-scoped kinds are
/// governed by cluster RBAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Repository,
    Webhook,
    DeployKey,
    OAuth2Application,
    AccessToken,
}

impl Kind {
    pub fn from_kind_name(kind: &str) -> Option<Self> {
        Some(match kind {
            "ForgejoRepository" => Kind::Repository,
            "ForgejoWebhook" => Kind::Webhook,
            "ForgejoDeployKey" => Kind::DeployKey,
            "ForgejoOAuth2Application" => Kind::OAuth2Application,
            "ForgejoAccessToken" => Kind::AccessToken,
            _ => return None,
        })
    }
}

/// Stands for the operator's own admin account among a request's users —
/// what an OAuth2 application without `ownerRef` is created under. Never a
/// valid `ForgejoUser` name, so a rule restricting `allowedUsers` covers it
/// only when it lists this value explicitly.
pub const INSTANCE_ADMIN: &str = "@instance-admin";

pub type Rule = weebo_kit_domain::allow_list::Rule<Kind>;
pub type Request<'a> = weebo_kit_domain::allow_list::Request<'a, Kind>;

/// A rule from its `ForgejoNamespacePolicy` fields (`None` = any).
pub fn rule(
    namespaces: Vec<String>,
    kinds: Vec<Kind>,
    organizations: Option<Vec<String>>,
    users: Option<Vec<String>>,
    effect: Effect,
) -> Rule {
    let scopes = [(ORGANIZATIONS, organizations), (USERS, users)]
        .into_iter()
        .filter_map(|(dimension, names)| Some((dimension.to_string(), names?)))
        .collect();
    Rule {
        namespaces,
        kinds,
        scopes,
        effect,
    }
}

/// What a namespaced CR in `namespace` asks for.
pub fn request<'a>(
    namespace: &'a str,
    kind: Kind,
    organizations: &'a [String],
    users: &'a [String],
) -> Request<'a> {
    Request {
        namespace,
        kind,
        references: BTreeMap::from([(ORGANIZATIONS, organizations), (USERS, users)]),
    }
}

/// See `weebo_kit_domain::allow_list::evaluate`: allow everything while no
/// `ForgejoNamespacePolicy` exists, default-deny as soon as one does; deny
/// always wins.
pub fn evaluate(request: &Request<'_>, rules: &[Rule], policies_exist: bool) -> Decision {
    weebo_kit_domain::allow_list::evaluate(POLICY_KIND, request, rules, policies_exist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn organizations_and_users_scope_the_rules() {
        let rules = [rule(
            s(&["team-*"]),
            vec![Kind::Repository, Kind::AccessToken],
            Some(s(&["weebo"])),
            Some(s(&["ci-bot"])),
            Effect::Allow,
        )];
        let weebo = s(&["weebo"]);
        let admin = s(&["admin-bot"]);
        assert_eq!(
            evaluate(
                &request("team-a", Kind::Repository, &weebo, &[]),
                &rules,
                true
            ),
            Decision::Allowed
        );
        let denied = evaluate(
            &request("team-a", Kind::AccessToken, &[], &admin),
            &rules,
            true,
        );
        assert_eq!(
            denied,
            Decision::Denied(
                "no ForgejoNamespacePolicy rule allows AccessToken in namespace \"team-a\" \
                 with users [\"admin-bot\"]"
                    .into()
            )
        );
    }

    #[test]
    fn unset_scopes_cover_anything() {
        let rules = [rule(
            s(&["*"]),
            vec![Kind::Webhook],
            None,
            None,
            Effect::Allow,
        )];
        let weebo = s(&["weebo"]);
        assert_eq!(
            evaluate(&request("x", Kind::Webhook, &weebo, &[]), &rules, true),
            Decision::Allowed
        );
    }

    #[test]
    fn kind_names_round_trip() {
        for k in [
            "ForgejoRepository",
            "ForgejoWebhook",
            "ForgejoDeployKey",
            "ForgejoOAuth2Application",
            "ForgejoAccessToken",
        ] {
            assert!(Kind::from_kind_name(k).is_some(), "{k}");
        }
        assert_eq!(Kind::from_kind_name("ForgejoTeam"), None);
    }
}
