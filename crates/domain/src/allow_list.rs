//! Pure evaluation of `ForgejoNamespacePolicy` rules — shared by the
//! admission webhook and the reconcilers' own re-check. See
//! `.prompt/plan.md`, "Sécurité opérationnelle & déploiement".

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Exact names, `*`, or a prefix glob such as `team-*`.
    pub namespaces: Vec<String>,
    pub kinds: Vec<Kind>,
    /// `ForgejoOrganization` CR names; `None` = any.
    pub organizations: Option<Vec<String>>,
    /// `ForgejoUser` CR names; `None` = any.
    pub users: Option<Vec<String>>,
    pub effect: Effect,
}

/// What a namespaced CR asks for: its namespace, kind, and the
/// cluster-scoped CRs it references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub namespace: &'a str,
    pub kind: Kind,
    pub organizations: &'a [String],
    pub users: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Human-readable why, for the webhook message / status condition.
    Denied(String),
}

/// Allow everything while no `ForgejoNamespacePolicy` exists at all;
/// default-deny as soon as one does (even with zero rules).
///
/// Then a request is allowed only if some `Allow` rule matches its
/// namespace and kind *and* covers every organization and user it
/// references, and no `Deny` rule matches. A `Deny` rule matches on
/// namespace and kind, narrowed by its `organizations`/`users` when set
/// (it then only denies requests referencing one of them). Deny always
/// wins, whatever the order.
pub fn evaluate(request: &Request<'_>, rules: &[Rule], policies_exist: bool) -> Decision {
    if !policies_exist {
        return Decision::Allowed;
    }
    let applies = |rule: &Rule| {
        rule.kinds.contains(&request.kind)
            && rule
                .namespaces
                .iter()
                .any(|pattern| namespace_matches(pattern, request.namespace))
    };

    for rule in rules
        .iter()
        .filter(|r| r.effect == Effect::Deny && applies(r))
    {
        let hits = |listed: &Option<Vec<String>>, asked: &[String]| {
            listed
                .as_ref()
                .is_none_or(|l| asked.iter().any(|a| l.contains(a)))
        };
        if hits(&rule.organizations, request.organizations) && hits(&rule.users, request.users) {
            return Decision::Denied(format!(
                "a Deny rule matches namespace {:?} for {:?}",
                request.namespace, request.kind
            ));
        }
    }

    let covers = |listed: &Option<Vec<String>>, asked: &[String]| {
        listed
            .as_ref()
            .is_none_or(|l| asked.iter().all(|a| l.contains(a)))
    };
    let allowed = rules.iter().any(|r| {
        r.effect == Effect::Allow
            && applies(r)
            && covers(&r.organizations, request.organizations)
            && covers(&r.users, request.users)
    });
    if allowed {
        return Decision::Allowed;
    }

    let mut why = format!(
        "no ForgejoNamespacePolicy rule allows {:?} in namespace {:?}",
        request.kind, request.namespace
    );
    if !request.organizations.is_empty() {
        why.push_str(&format!(" with organizations {:?}", request.organizations));
    }
    if !request.users.is_empty() {
        why.push_str(&format!(" with users {:?}", request.users));
    }
    Decision::Denied(why)
}

fn namespace_matches(pattern: &str, namespace: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => namespace.starts_with(prefix),
        None => pattern == namespace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(ns: &[&str], kinds: &[Kind], effect: Effect) -> Rule {
        Rule {
            namespaces: ns.iter().map(|s| s.to_string()).collect(),
            kinds: kinds.to_vec(),
            organizations: None,
            users: None,
            effect,
        }
    }

    fn req<'a>(ns: &'a str, kind: Kind, orgs: &'a [String], users: &'a [String]) -> Request<'a> {
        Request {
            namespace: ns,
            kind,
            organizations: orgs,
            users,
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn no_policy_allows_everything() {
        assert_eq!(
            evaluate(&req("a", Kind::Repository, &[], &[]), &[], false),
            Decision::Allowed
        );
    }

    #[test]
    fn an_existing_policy_switches_to_default_deny() {
        assert!(matches!(
            evaluate(&req("a", Kind::Repository, &[], &[]), &[], true),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn allow_matches_namespace_globs_and_kinds() {
        let rules = [rule(&["team-*"], &[Kind::Repository], Effect::Allow)];
        assert_eq!(
            evaluate(&req("team-a", Kind::Repository, &[], &[]), &rules, true),
            Decision::Allowed
        );
        assert!(matches!(
            evaluate(&req("ops", Kind::Repository, &[], &[]), &rules, true),
            Decision::Denied(_)
        ));
        assert!(matches!(
            evaluate(&req("team-a", Kind::AccessToken, &[], &[]), &rules, true),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn organizations_and_users_must_all_be_covered() {
        let mut r = rule(
            &["team-a"],
            &[Kind::Repository, Kind::AccessToken],
            Effect::Allow,
        );
        r.organizations = Some(s(&["weebo"]));
        r.users = Some(s(&["ci-bot"]));
        let rules = [r];
        let weebo = s(&["weebo"]);
        let other = s(&["other"]);
        let bot = s(&["ci-bot"]);
        let admin = s(&["admin-bot"]);
        assert_eq!(
            evaluate(&req("team-a", Kind::Repository, &weebo, &[]), &rules, true),
            Decision::Allowed
        );
        assert!(matches!(
            evaluate(&req("team-a", Kind::Repository, &other, &[]), &rules, true),
            Decision::Denied(_)
        ));
        assert_eq!(
            evaluate(&req("team-a", Kind::AccessToken, &[], &bot), &rules, true),
            Decision::Allowed
        );
        // The escalation the user list exists for: a token of another user.
        assert!(matches!(
            evaluate(&req("team-a", Kind::AccessToken, &[], &admin), &rules, true),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn deny_wins_and_can_be_narrowed() {
        let mut deny = rule(&["*"], &[Kind::AccessToken], Effect::Deny);
        deny.users = Some(s(&["admin-bot"]));
        let rules = [rule(&["*"], &[Kind::AccessToken], Effect::Allow), deny];
        let bot = s(&["ci-bot"]);
        let admin = s(&["admin-bot"]);
        assert_eq!(
            evaluate(&req("x", Kind::AccessToken, &[], &bot), &rules, true),
            Decision::Allowed
        );
        assert!(matches!(
            evaluate(&req("x", Kind::AccessToken, &[], &admin), &rules, true),
            Decision::Denied(_)
        ));
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
