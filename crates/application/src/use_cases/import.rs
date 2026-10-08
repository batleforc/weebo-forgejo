//! The importer (`.prompt/plan.md`, "Seul chemin d'adoption"): reads a live
//! Forgejo and describes it as CR names and specs, each paired with the
//! Forgejo object it must own — the `status.forgejoId`/`forgejoName` seed
//! that makes the reconcilers adopt the object instead of colliding with
//! it. Nothing here writes to Forgejo or Kubernetes, nor knows how a CR is
//! laid out: `crates/importer` turns an [`Import`] into manifests.
//!
//! Every imported CR is `deletionPolicy: Orphan`: these objects existed
//! before the operator, and deleting a generated manifest must not destroy
//! them. Write-only values Forgejo never returns (webhook secrets, local
//! passwords, private keys) stay where they are and out of the CRs.

use std::collections::{BTreeMap, BTreeSet};

use api::common::{DeletionPolicy, ManagementPolicy, ObjectRef, Visibility};
use api::keys::{ForgejoDeployKeySpec, KeySource};
use api::organization::ForgejoOrganizationSpec;
use api::repository::{BranchProtection, ForgejoRepositorySpec, MigrateSource, RepositoryUnits};
use api::team::{ForgejoTeamSpec, MembersPolicy, TeamPermission};
use api::user::ForgejoUserSpec;
use api::webhook::ForgejoWebhookSpec;

use crate::ports::{
    ForgejoInventory, ForgejoRef, GatewayError, HookTarget, ProtectionRule, RemoteHook,
    RemoteRepository, RemoteTeam, RemoteUser,
};

/// Name of the team Forgejo creates with every organization; it can't be
/// managed (nor removed from a repository).
const OWNERS_TEAM: &str = "Owners";

#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Written as `spec.instanceRef` (`None` = the cluster's only instance).
    pub instance_ref: Option<String>,
    /// Organizations and users to import, with their repositories. Empty =
    /// everything. Users other than these are only imported when a team or
    /// repository references them.
    pub owners: Vec<String>,
    /// Import users as `managementPolicy: Manage` instead of `Observe`. A
    /// local account becomes `bot: true` so its password is never reset
    /// (the operator can't know it).
    pub manage_users: bool,
    /// The CRs already in the cluster: an object adopted by an earlier run
    /// keeps its CR name, and a name owned by another object is never
    /// reused — so names don't depend on this run's `owners` selection.
    pub existing: Existing,
}

/// CRs already in the cluster, per kind: CR name → `status.forgejoId`
/// (`None` for a CR whose import was interrupted before seeding, which the
/// importer takes over). Repositories: those of the namespace the
/// namespaced CRs go to only.
#[derive(Debug, Clone, Default)]
pub struct Existing {
    pub users: BTreeMap<String, Option<String>>,
    pub organizations: BTreeMap<String, Option<String>>,
    pub teams: BTreeMap<String, Option<String>>,
    pub repositories: BTreeMap<String, Option<String>>,
}

/// One Forgejo object to adopt: the CR name it gets, its spec, and the
/// object that CR must own from the start.
#[derive(Debug, Clone)]
pub struct Imported<S> {
    pub name: String,
    pub spec: S,
    pub forgejo: ForgejoRef,
}

/// A deploy key, with the repository it lives on — recorded on the CR so
/// its cleanup finds the key even without the repository CR.
#[derive(Debug, Clone)]
pub struct ImportedKey {
    pub key: Imported<ForgejoDeployKeySpec>,
    /// `owner/name`.
    pub repository: String,
}

/// The objects describing an instance, in dependency order.
#[derive(Debug, Default)]
pub struct Import {
    pub users: Vec<Imported<ForgejoUserSpec>>,
    pub organizations: Vec<Imported<ForgejoOrganizationSpec>>,
    pub teams: Vec<Imported<ForgejoTeamSpec>>,
    pub repositories: Vec<Imported<ForgejoRepositorySpec>>,
    pub webhooks: Vec<Imported<ForgejoWebhookSpec>>,
    pub deploy_keys: Vec<ImportedKey>,
    /// What was left out, and why.
    pub warnings: Vec<String>,
}

pub async fn import(
    inventory: &dyn ForgejoInventory,
    options: &ImportOptions,
) -> Result<Import, GatewayError> {
    let wanted = |name: &str| {
        options.owners.is_empty() || options.owners.iter().any(|o| o.eq_ignore_ascii_case(name))
    };
    let mut out = Import::default();
    let all_users = inventory.list_users().await?;
    let mut user_names = Names::new(&options.existing.users);
    let mut users: BTreeMap<String, (String, RemoteUser)> = BTreeMap::new();
    for u in all_users {
        let name = user_names.claim(&u.login, u.id);
        users.insert(u.login.clone(), (name, u));
    }
    // Users to emit: everything, or what the selection references.
    let mut referenced: BTreeSet<String> = users
        .keys()
        .filter(|login| wanted(login))
        .cloned()
        .collect();

    let mut org_names = Names::new(&options.existing.organizations);
    let mut orgs = Vec::new();
    for org in inventory.list_organizations().await? {
        if !wanted(&org.name) {
            continue;
        }
        let name = org_names.claim(&org.name, org.id);
        let spec = ForgejoOrganizationSpec {
            instance_ref: options.instance_ref.clone(),
            name: org.name.clone(),
            full_name: non_empty(&org.full_name),
            description: non_empty(&org.description),
            website: non_empty(&org.website),
            location: non_empty(&org.location),
            email: non_empty(&org.email),
            visibility: visibility(&org.visibility),
            repo_admin_change_team_access: org.repo_admin_change_team_access,
            owner_ref: None,
            deletion_policy: DeletionPolicy::Orphan,
        };
        out.organizations
            .push(imported(name.clone(), spec, org.id, &org.name));
        orgs.push((name, org.name));
    }

    // Teams, keyed by (org, team name) for the repositories' `teamRefs`.
    let mut team_names = Names::new(&options.existing.teams);
    let mut teams: BTreeMap<(String, String), String> = BTreeMap::new();
    for (org_cr, org) in &orgs {
        for team in inventory.list_teams(org).await? {
            if team.name == OWNERS_TEAM {
                continue;
            }
            let Some(permission) = team_permission(&team.permission) else {
                out.warnings.push(format!(
                    "team {org}/{}: unsupported permission {:?}, skipped",
                    team.name, team.permission
                ));
                continue;
            };
            let mut member_refs = Vec::new();
            for login in inventory.list_team_members(team.id).await? {
                match users.get(&login) {
                    Some((name, _)) => {
                        referenced.insert(login);
                        member_refs.push(ObjectRef { name: name.clone() });
                    }
                    None => out.warnings.push(format!(
                        "team {org}/{}: unknown member {login:?}",
                        team.name
                    )),
                }
            }
            let name = team_names.claim(&format!("{org}-{}", team.name), team.id);
            let spec = team_spec(team.clone(), org_cr, permission, member_refs, options);
            out.teams
                .push(imported(name.clone(), spec, team.id, &team.name));
            teams.insert((org.clone(), team.name), name);
        }
    }

    // Repositories of the selected organizations, then of the selected
    // users (all of them without a selection).
    let mut owners: Vec<(Owner, String)> = orgs
        .iter()
        .map(|(cr, org)| (Owner::Organization(cr.clone()), org.clone()))
        .collect();
    for (login, (cr, _)) in &users {
        if wanted(login) {
            owners.push((Owner::User(cr.clone()), login.clone()));
        }
    }
    let mut repo_names = Names::new(&options.existing.repositories);
    let mut hook_owners: Vec<(HookOwner, HookTarget)> = orgs
        .iter()
        .map(|(cr, org)| {
            (
                HookOwner::Organization(cr.clone()),
                HookTarget::Organization(org.clone()),
            )
        })
        .collect();
    let mut repos = Vec::new();
    for (owner, login) in &owners {
        let is_org = matches!(owner, Owner::Organization(_));
        for repo in inventory.list_repositories(login, is_org).await? {
            if let Owner::User(_) = owner {
                referenced.insert(login.clone());
            }
            let name = repo_names.claim(&format!("{login}-{}", repo.name), repo.id);
            let full_name = repo.full_name();
            let protections = inventory.list_branch_protections(&full_name).await?;
            let team_refs = if is_org {
                let granted = inventory.list_repository_teams(&full_name).await?;
                repository_teams(login, &full_name, &granted, &teams, &mut out.warnings)
            } else {
                Vec::new()
            };
            let spec = repository_spec(&repo, owner, protections, team_refs, options);
            out.repositories
                .push(imported(name.clone(), spec, repo.id, &full_name));
            hook_owners.push((
                HookOwner::Repository(name.clone()),
                HookTarget::Repository {
                    owner: repo.owner.clone(),
                    name: repo.name.clone(),
                },
            ));
            repos.push((name, full_name));
        }
    }

    for (owner, target) in &hook_owners {
        for hook in inventory.list_hooks(target).await? {
            let Some(url) = hook.config.get("url").cloned() else {
                out.warnings
                    .push(format!("hook {} on {target}: no url, skipped", hook.id));
                continue;
            };
            let name = suffixed(owner.cr_name(), &format!("hook-{}", hook.id));
            let spec = webhook_spec(hook.clone(), url, owner, options);
            out.webhooks
                .push(imported(name, spec, hook.id, &target.to_string()));
        }
    }

    for (repo_cr, full_name) in &repos {
        for key in inventory.list_deploy_keys(full_name).await? {
            let spec = ForgejoDeployKeySpec {
                instance_ref: options.instance_ref.clone(),
                repository_ref: ObjectRef {
                    name: repo_cr.clone(),
                },
                title: Some(key.title.clone()),
                read_only: key.read_only,
                key: KeySource {
                    public_key: Some(key.key.clone()),
                    secret_targets: Vec::new(),
                },
                deletion_policy: DeletionPolicy::Orphan,
            };
            let name = suffixed(repo_cr, &format!("key-{}", key.id));
            out.deploy_keys.push(ImportedKey {
                key: imported(name, spec, key.id, &key.title),
                repository: full_name.clone(),
            });
        }
    }

    for (login, (name, user)) in &users {
        if referenced.contains(login) {
            let spec = user_spec(user, options);
            out.users
                .push(imported(name.clone(), spec, user.id, &user.login));
        }
    }
    Ok(out)
}

enum Owner {
    Organization(String),
    User(String),
}

enum HookOwner {
    Organization(String),
    Repository(String),
}

impl HookOwner {
    fn cr_name(&self) -> &str {
        match self {
            HookOwner::Organization(n) | HookOwner::Repository(n) => n,
        }
    }
}

fn user_spec(user: &RemoteUser, options: &ImportOptions) -> ForgejoUserSpec {
    let external = user.source_id != 0;
    let manage = options.manage_users;
    ForgejoUserSpec {
        instance_ref: options.instance_ref.clone(),
        username: user.login.clone(),
        management_policy: if manage {
            ManagementPolicy::Manage
        } else {
            ManagementPolicy::Observe
        },
        email: manage.then(|| user.email.clone()),
        full_name: non_empty(&user.full_name).filter(|_| manage),
        login_source_id: (manage && external).then_some(user.source_id),
        login_name: non_empty(&user.login_name).filter(|n| manage && external && *n != user.login),
        bot: manage && !external,
        prohibit_login: user.prohibit_login,
        must_change_password: None,
        admin: user.admin,
        restricted: user.restricted,
        visibility: visibility(&user.visibility),
        active: user.active,
        allow_create_organization: None,
        max_repo_creation: None,
        secret_targets: Vec::new(),
        deletion_policy: DeletionPolicy::Orphan,
    }
}

fn team_spec(
    team: RemoteTeam,
    org_cr: &str,
    permission: TeamPermission,
    member_refs: Vec<ObjectRef>,
    options: &ImportOptions,
) -> ForgejoTeamSpec {
    ForgejoTeamSpec {
        instance_ref: options.instance_ref.clone(),
        organization_ref: ObjectRef {
            name: org_cr.to_string(),
        },
        name: team.name,
        description: non_empty(&team.description),
        permission,
        units_map: team.units_map,
        includes_all_repositories: team.includes_all_repositories,
        can_create_org_repo: team.can_create_org_repo,
        members_policy: MembersPolicy::Managed,
        member_refs,
        deletion_policy: DeletionPolicy::Orphan,
    }
}

fn repository_spec(
    repo: &RemoteRepository,
    owner: &Owner,
    protections: Vec<ProtectionRule>,
    team_refs: Vec<ObjectRef>,
    options: &ImportOptions,
) -> ForgejoRepositorySpec {
    let (organization_ref, user_ref) = match owner {
        Owner::Organization(n) => (Some(ObjectRef { name: n.clone() }), None),
        Owner::User(n) => (None, Some(ObjectRef { name: n.clone() })),
    };
    ForgejoRepositorySpec {
        instance_ref: options.instance_ref.clone(),
        organization_ref,
        user_ref,
        name: repo.name.clone(),
        description: non_empty(&repo.description),
        website: non_empty(&repo.website),
        private: repo.private,
        is_template: repo.template,
        archived: repo.archived,
        default_branch: non_empty(&repo.default_branch),
        units: RepositoryUnits {
            issues: Some(repo.has_issues),
            wiki: Some(repo.has_wiki),
            pull_requests: Some(repo.has_pull_requests),
            projects: Some(repo.has_projects),
            releases: Some(repo.has_releases),
            packages: Some(repo.has_packages),
            actions: Some(repo.has_actions),
        },
        init: None,
        from_template: None,
        // Creation-time only, except the interval of a pull mirror, which
        // stays in sync.
        migrate: repo.mirror.then(|| MigrateSource {
            clone_addr: repo.original_url.clone(),
            service: "git".to_string(),
            mirror: true,
            mirror_interval: non_empty(&repo.mirror_interval),
            lfs: false,
            wiki: false,
            issues: false,
            pull_requests: false,
            releases: false,
            labels: false,
            milestones: false,
            auth_secret_ref: None,
        }),
        branch_protections: protections.into_iter().map(branch_protection).collect(),
        team_refs,
        deletion_policy: DeletionPolicy::Orphan,
    }
}

/// Teams granted explicitly: `Owners` and `includesAllRepositories` teams
/// have access anyway and are never listed in `teamRefs`.
fn repository_teams(
    org: &str,
    full_name: &str,
    granted: &[RemoteTeam],
    teams: &BTreeMap<(String, String), String>,
    warnings: &mut Vec<String>,
) -> Vec<ObjectRef> {
    granted
        .iter()
        .filter(|t| t.name != OWNERS_TEAM && !t.includes_all_repositories)
        .filter_map(|t| match teams.get(&(org.to_string(), t.name.clone())) {
            Some(name) => Some(ObjectRef { name: name.clone() }),
            None => {
                warnings.push(format!(
                    "repository {full_name}: team {:?} was not imported, left out of teamRefs",
                    t.name
                ));
                None
            }
        })
        .collect()
}

fn branch_protection(rule: ProtectionRule) -> BranchProtection {
    BranchProtection {
        rule_name: rule.rule_name,
        enable_push: rule.enable_push,
        push_whitelist_usernames: rule.push_whitelist_usernames,
        push_whitelist_teams: rule.push_whitelist_teams,
        push_whitelist_deploy_keys: rule.push_whitelist_deploy_keys,
        merge_whitelist_usernames: rule.merge_whitelist_usernames,
        merge_whitelist_teams: rule.merge_whitelist_teams,
        required_approvals: rule.required_approvals,
        approvals_whitelist_usernames: rule.approvals_whitelist_usernames,
        approvals_whitelist_teams: rule.approvals_whitelist_teams,
        status_check_contexts: rule.status_check_contexts,
        block_on_rejected_reviews: rule.block_on_rejected_reviews,
        block_on_official_review_requests: rule.block_on_official_review_requests,
        block_on_outdated_branch: rule.block_on_outdated_branch,
        dismiss_stale_approvals: rule.dismiss_stale_approvals,
        ignore_stale_approvals: rule.ignore_stale_approvals,
        require_signed_commits: rule.require_signed_commits,
        apply_to_admins: rule.apply_to_admins,
        protected_file_patterns: non_empty(&rule.protected_file_patterns),
        unprotected_file_patterns: non_empty(&rule.unprotected_file_patterns),
    }
}

/// No `secretRef`: Forgejo never returns the secret, and an edit without
/// one leaves it in place only as long as nothing else changes — add the
/// `secretRef` before changing the hook.
fn webhook_spec(
    hook: RemoteHook,
    url: String,
    owner: &HookOwner,
    options: &ImportOptions,
) -> ForgejoWebhookSpec {
    let (repository_ref, organization_ref) = match owner {
        HookOwner::Repository(n) => (Some(ObjectRef { name: n.clone() }), None),
        HookOwner::Organization(n) => (None, Some(ObjectRef { name: n.clone() })),
    };
    let mut config = hook.config;
    config.remove("url");
    config.remove("secret");
    let content_type = config
        .remove("content_type")
        .unwrap_or_else(|| "json".to_string());
    let http_method = config.remove("http_method").filter(|m| !m.is_empty());
    ForgejoWebhookSpec {
        instance_ref: options.instance_ref.clone(),
        repository_ref,
        organization_ref,
        type_: hook.type_,
        url,
        content_type,
        http_method,
        events: hook.events,
        branch_filter: non_empty(&hook.branch_filter),
        active: hook.active,
        secret_ref: None,
        authorization_header_secret_ref: None,
        extra_config: config,
        deletion_policy: DeletionPolicy::Orphan,
    }
}

fn imported<S>(name: String, spec: S, id: i64, forgejo_name: &str) -> Imported<S> {
    Imported {
        name,
        spec,
        forgejo: ForgejoRef {
            id,
            name: forgejo_name.to_string(),
        },
    }
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn visibility(s: &str) -> Visibility {
    match s {
        "limited" => Visibility::Limited,
        "private" => Visibility::Private,
        _ => Visibility::Public,
    }
}

fn team_permission(s: &str) -> Option<TeamPermission> {
    match s {
        "read" => Some(TeamPermission::Read),
        "write" => Some(TeamPermission::Write),
        "admin" => Some(TeamPermission::Admin),
        _ => None,
    }
}

/// Longest Kubernetes object name (RFC 1123 subdomain).
const MAX_NAME: usize = 253;

/// Kubernetes names (RFC 1123 subdomain) derived from Forgejo names,
/// unique per kind. An object already adopted in the cluster keeps its CR
/// name; otherwise a clash (`Foo_Bar` vs `foo-bar`, or a name a CR already
/// owns for another object) gets the id appended.
struct Names {
    taken: BTreeSet<String>,
    /// Forgejo id → name of the CR already owning it.
    adopted: BTreeMap<String, String>,
}

impl Names {
    fn new(existing: &BTreeMap<String, Option<String>>) -> Self {
        let mut names = Names {
            taken: BTreeSet::new(),
            adopted: BTreeMap::new(),
        };
        for (name, id) in existing {
            if let Some(id) = id {
                names.taken.insert(name.clone());
                names.adopted.insert(id.clone(), name.clone());
            }
        }
        names
    }

    fn claim(&mut self, forgejo_name: &str, id: i64) -> String {
        if let Some(name) = self.adopted.get(&id.to_string()) {
            return name.clone();
        }
        let base = dns_name(forgejo_name);
        let mut name = base.clone();
        let mut n = 1;
        while name.is_empty() || self.taken.contains(&name) {
            // The id is unique per kind, but `{base}-{id}` may still be some
            // other object's natural name: count until free.
            name = match n {
                1 => suffixed(&base, &id.to_string()),
                _ => suffixed(&base, &format!("{id}-{n}")),
            };
            n += 1;
        }
        self.taken.insert(name.clone());
        name
    }
}

/// `{base}-{suffix}`, `base` shortened so the whole stays a valid name —
/// the suffix carries the id that keeps it unique, so it's never cut.
fn suffixed(base: &str, suffix: &str) -> String {
    let room = MAX_NAME.saturating_sub(suffix.len() + 1);
    let base = base[..base.len().min(room)].trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
    if base.is_empty() {
        suffix.to_string()
    } else {
        format!("{base}-{suffix}")
    }
}

/// An RFC 1123 subdomain: lowercase alphanumerics and `-`, in labels that
/// start and end alphanumeric, joined by `.` (`weebo-.profile` →
/// `weebo.profile`). Names that were already valid are unchanged.
fn dns_name(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9' | '.' | '-') => c,
            _ => '-',
        })
        .collect();
    let joined = mapped
        .split('.')
        .map(|label| label.trim_matches('-'))
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    joined[..joined.len().min(MAX_NAME)]
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::ports::{
        DesiredHook, DesiredOrganization, DesiredRepository, DesiredTeam, DesiredUser,
        ForgejoGateway, RepositoryInitOptions,
    };
    use crate::test_support::FakeForgejo;

    async fn fixture() -> FakeForgejo {
        let f = FakeForgejo::default();
        for (login, source) in [("Alice_X", None), ("bob", Some(3))] {
            f.create_user(&DesiredUser {
                username: login.into(),
                email: format!("{login}@example.com"),
                source_id: source,
                login_name: source.map(|_| "bob-sub".to_string()),
                password: source.is_none().then(|| "pw".to_string()),
                visibility: "public",
                active: true,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        f.create_organization(
            None,
            &DesiredOrganization {
                name: "weebo".into(),
                description: Some("the org".into()),
                visibility: "limited",
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let dev = f
            .create_team(
                "weebo",
                &DesiredTeam {
                    name: "Dev".into(),
                    permission: "write",
                    units_map: BTreeMap::from([("repo.code".into(), "write".into())]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.add_team_member(dev.id, "Alice_X").await.unwrap();
        let app = DesiredRepository {
            name: "app".into(),
            private: true,
            ..Default::default()
        };
        f.create_repository("weebo", true, &app, &RepositoryInitOptions::default())
            .await
            .unwrap();
        f.add_repository_team("weebo/app", "Dev").await.unwrap();
        f.create_branch_protection(
            "weebo/app",
            &ProtectionRule {
                rule_name: "main".into(),
                required_approvals: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        f.create_hook(
            &HookTarget::Repository {
                owner: "weebo".into(),
                name: "app".into(),
            },
            &DesiredHook {
                type_: "forgejo".into(),
                config: BTreeMap::from([
                    ("url".into(), "https://ci.example.com/hook".into()),
                    ("content_type".into(), "json".into()),
                    ("secret".into(), "s3cr3t".into()),
                ]),
                events: vec!["push".into()],
                active: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        f.create_deploy_key("weebo/app", "ci", "ssh-ed25519 AAAA", true)
            .await
            .unwrap();
        f.create_repository(
            "bob",
            false,
            &DesiredRepository {
                name: "dots".into(),
                ..Default::default()
            },
            &RepositoryInitOptions::default(),
        )
        .await
        .unwrap();
        f
    }

    fn options() -> ImportOptions {
        ImportOptions::default()
    }

    #[tokio::test]
    async fn imports_everything_with_seeded_status() {
        let f = fixture().await;
        let out = import(&f, &options()).await.unwrap();

        let names = |v: Vec<String>| v.join(",");
        assert_eq!(
            names(out.users.iter().map(|u| u.name.clone()).collect()),
            "alice-x,bob"
        );
        assert!(
            out.users
                .iter()
                .all(|u| u.spec.management_policy == ManagementPolicy::Observe)
        );
        let org = &out.organizations[0];
        assert_eq!(org.spec.visibility, Visibility::Limited);
        assert_eq!(org.spec.deletion_policy, DeletionPolicy::Orphan);

        let team = &out.teams[0];
        assert_eq!(team.name, "weebo-dev");
        assert_eq!(team.spec.permission, TeamPermission::Write);
        assert_eq!(
            team.spec.member_refs,
            vec![ObjectRef {
                name: "alice-x".into()
            }]
        );

        let repo = out
            .repositories
            .iter()
            .find(|r| r.spec.name == "app")
            .unwrap();
        assert_eq!(
            repo.spec.organization_ref,
            Some(ObjectRef {
                name: "weebo".into()
            })
        );
        assert_eq!(
            repo.spec.team_refs,
            vec![ObjectRef {
                name: "weebo-dev".into()
            }]
        );
        assert_eq!(repo.spec.branch_protections[0].required_approvals, 1);
        assert_eq!(repo.forgejo.name, "weebo/app");

        let dots = out
            .repositories
            .iter()
            .find(|r| r.spec.name == "dots")
            .unwrap();
        assert_eq!(dots.spec.user_ref, Some(ObjectRef { name: "bob".into() }));

        let hook = &out.webhooks[0];
        assert_eq!(hook.spec.url, "https://ci.example.com/hook");
        assert_eq!(
            hook.spec.repository_ref,
            Some(ObjectRef {
                name: "weebo-app".into()
            })
        );
        assert!(hook.spec.extra_config.is_empty());
        assert_eq!(hook.forgejo.name, "repo:weebo/app");

        let key = &out.deploy_keys[0];
        assert_eq!(
            key.key.spec.key.public_key.as_deref(),
            Some("ssh-ed25519 AAAA")
        );
        assert!(key.key.spec.read_only);
        assert_eq!(
            key.repository, "weebo/app",
            "cleanup can find the key without the repository CR"
        );
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    }

    #[tokio::test]
    async fn owner_selection_keeps_only_referenced_users() {
        let f = fixture().await;
        let out = import(
            &f,
            &ImportOptions {
                owners: vec!["weebo".into()],
                ..options()
            },
        )
        .await
        .unwrap();
        // alice is a team member; bob owns nothing selected.
        assert_eq!(out.users.len(), 1);
        assert_eq!(out.users[0].spec.username, "Alice_X");
        assert_eq!(out.repositories.len(), 1);
    }

    #[tokio::test]
    async fn managed_users_never_get_a_password_reset() {
        let f = fixture().await;
        let out = import(
            &f,
            &ImportOptions {
                manage_users: true,
                ..options()
            },
        )
        .await
        .unwrap();
        let alice = &out.users[0].spec;
        assert_eq!(alice.management_policy, ManagementPolicy::Manage);
        assert!(alice.bot && !alice.emits_password());
        let bob = &out.users[1].spec;
        assert!(!bob.bot);
        assert_eq!(bob.login_source_id, Some(3));
        assert_eq!(bob.login_name.as_deref(), Some("bob-sub"));
    }

    /// The point of seeding: the reconcilers adopt the imported objects
    /// as they are — no create, no edit.
    #[tokio::test]
    async fn imported_objects_reconcile_without_writes() {
        use crate::use_cases::{reconcile_organization as org, reconcile_repository as repo};
        use crate::use_cases::{reconcile_team as team, reconcile_webhook as hook};

        let f = fixture().await;
        let out = import(&f, &options()).await.unwrap();
        f.clear_calls();

        let o = &out.organizations[0];
        let outcome = org::reconcile_organization(
            org::OrganizationInput {
                spec: &o.spec,
                current: Some(o.forgejo.clone()),
                owner: None,
            },
            &f,
        )
        .await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");

        let t = &out.teams[0];
        let outcome = team::reconcile_team(
            team::TeamInput {
                spec: &t.spec,
                current: Some(t.forgejo.clone()),
                organization: "weebo".into(),
                organization_id: None,
                members: vec![team::Member::Ready("Alice_X".into())],
                allow_disruptive_update: false,
            },
            &f,
        )
        .await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");

        let r = out
            .repositories
            .iter()
            .find(|r| r.spec.name == "app")
            .unwrap();
        let outcome = repo::reconcile_repository(
            repo::RepositoryInput {
                spec: &r.spec,
                current: Some(r.forgejo.clone()),
                owner: repo::Owner::Organization("weebo".into()),
                source: Err(crate::use_cases::Failure::new(
                    domain::error::ReasonCode::ReferenceNotReady,
                    "not needed",
                )),
                teams: vec!["Dev".into()],
                allow_disruptive_update: false,
            },
            &f,
        )
        .await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");

        let h = &out.webhooks[0];
        let outcome = hook::reconcile_webhook(
            hook::WebhookInput {
                spec: &h.spec,
                current: Some(h.forgejo.clone()),
                target: HookTarget::Repository {
                    owner: "weebo".into(),
                    name: "app".into(),
                },
                secret: None,
                authorization_header: None,
                applied_secret_hash: None,
            },
            &f,
        )
        .await;
        assert!(outcome.ready.is_ok(), "{outcome:?}");

        assert!(f.calls().is_empty(), "{:?}", f.calls());
    }

    /// Valid as a Kubernetes object name (RFC 1123 subdomain).
    fn is_subdomain(name: &str) -> bool {
        name.len() <= MAX_NAME
            && name.split('.').all(|label| {
                label.starts_with(|c: char| c.is_ascii_alphanumeric())
                    && label.ends_with(|c: char| c.is_ascii_alphanumeric())
                    && label
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
    }

    #[test]
    fn dns_names() {
        assert_eq!(dns_name("Alice_X"), "alice-x");
        assert_eq!(dns_name("_team.."), "team");
        let mut names = Names::new(&BTreeMap::new());
        assert_eq!(names.claim("Foo_Bar", 1), "foo-bar");
        assert_eq!(names.claim("foo-bar", 2), "foo-bar-2");
        assert_eq!(names.claim("___", 3), "3");
    }

    #[test]
    fn dns_names_are_valid_subdomains() {
        // Forgejo's profile README repository, and other dot/underscore mixes
        // that used to join into `-.` / `.-`.
        assert_eq!(dns_name("weebo-.profile"), "weebo.profile");
        assert_eq!(dns_name("foo._bar"), "foo.bar");
        assert_eq!(dns_name(".x"), "x");
        assert_eq!(dns_name("a..b"), "a.b");
        // Already valid names are unchanged.
        assert_eq!(dns_name("weebo-app.v2"), "weebo-app.v2");
        let long_dots = "x.".repeat(200);
        let long_accents = "é".repeat(300);
        for s in ["weebo-.profile", "-.-", "a_.b", &long_dots, &long_accents] {
            let name = dns_name(s);
            assert!(name.is_empty() || is_subdomain(&name), "{s:?} -> {name:?}");
        }
    }

    #[test]
    fn suffixed_names_keep_the_id() {
        let name = suffixed(&dns_name(&"a".repeat(300)), "hook-42");
        assert!(name.ends_with("-hook-42") && is_subdomain(&name), "{name}");
        // A cut landing right after a `.` never leaves `.-` behind.
        let dotted = format!("{}.b", "a".repeat(246));
        let name = suffixed(&dotted, "key-7");
        assert!(is_subdomain(&name), "{name}");
        assert_eq!(suffixed("", "key-7"), "key-7");
    }

    #[test]
    fn fallback_names_never_collide() {
        let mut names = Names::new(&BTreeMap::new());
        assert_eq!(names.claim("foo-bar", 1), "foo-bar");
        assert_eq!(names.claim("foo-bar-7", 2), "foo-bar-7");
        // `foo-bar-7` is already another object's natural name.
        assert_eq!(names.claim("foo_bar", 7), "foo-bar-7-2");
        // Two long names sharing their first 253 characters stay apart, the
        // id intact.
        let prefix = "t".repeat(260);
        let a = names.claim(&format!("{prefix}a"), 10);
        let b = names.claim(&format!("{prefix}b"), 11);
        assert_ne!(a, b);
        assert!(b.ends_with("-11") && is_subdomain(&b), "{b}");
    }

    #[test]
    fn existing_crs_keep_their_names() {
        let existing = BTreeMap::from([
            // Adopted by an earlier run (say `--owner a-b`) under the natural
            // name another object would get now.
            ("a-b-c".to_string(), Some("1".to_string())),
            // Adopted by an earlier run under a fallback name.
            ("x-y-5".to_string(), Some("5".to_string())),
            // An interrupted import, taken over by whoever claims it.
            ("pending".to_string(), None),
        ]);
        let mut names = Names::new(&existing);
        assert_eq!(names.claim("a-b-c", 2), "a-b-c-2");
        assert_eq!(names.claim("a-b-c", 1), "a-b-c");
        assert_eq!(names.claim("x_y", 5), "x-y-5");
        assert_eq!(names.claim("pending", 9), "pending");
    }

    #[tokio::test]
    async fn existing_crs_keep_their_names_across_runs() {
        let f = fixture().await;
        let first = import(&f, &options()).await.unwrap();
        let repo = &first.repositories[0];
        let natural = repo.name.clone();
        // The cluster holds the repository under another name, and its
        // natural name belongs to another object.
        let existing = Existing {
            repositories: BTreeMap::from([
                ("adopted".to_string(), Some(repo.forgejo.id.to_string())),
                (natural.clone(), Some("999999".to_string())),
            ]),
            ..Default::default()
        };
        let again = import(
            &f,
            &ImportOptions {
                existing,
                ..options()
            },
        )
        .await
        .unwrap();
        let same = again
            .repositories
            .iter()
            .find(|r| r.forgejo.id == repo.forgejo.id)
            .unwrap();
        assert_eq!(same.name, "adopted");
        assert!(again.repositories.iter().all(|r| r.name != natural));
    }
}
