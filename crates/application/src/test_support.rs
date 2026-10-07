//! In-memory doubles for the ports: a [`FakeForgejo`] that behaves like a
//! (tiny) real instance — ids, name collisions, renames, membership — and a
//! [`FakeSecretStore`]. Use-case tests assert on the resulting state and on
//! the recorded call log rather than scripting every response.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use api::common::SecretTarget;

use crate::ports::{
    DesiredHook, DesiredOAuth2App, DesiredOrganization, DesiredRepository, DesiredTeam,
    DesiredToken, DesiredUser, ForgejoGateway, ForgejoInventory, ForgejoRef, GatewayError,
    GenerateOptions, HookTarget, MigrateOptions, ProtectionRule, RemoteHook, RemoteKey,
    RemoteOAuth2App, RemoteOrganization, RemoteRepository, RemoteTeam, RemoteToken, RemoteUser,
    RepositoryInitOptions, SecretStore, SecretStoreError,
};
use crate::use_cases::reconcile_webhook::{forgejo_echoes, forgejo_events};

#[derive(Debug, Clone, Default)]
pub struct FakeUser {
    pub remote: RemoteUser,
    pub password: Option<String>,
    pub must_change_password: bool,
    pub allow_create_organization: Option<bool>,
    pub max_repo_creation: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct FakeOrg {
    pub remote: RemoteOrganization,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FakeTeam {
    pub remote: RemoteTeam,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FakeRepo {
    pub remote: RemoteRepository,
    pub protections: Vec<ProtectionRule>,
    /// Explicitly granted teams (not `includes_all_repositories` ones).
    pub teams: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FakeHook {
    pub target: String,
    pub remote: RemoteHook,
    pub secret: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FakeKey {
    /// `owner/name` or the user login.
    pub owner: String,
    pub remote: RemoteKey,
}

#[derive(Default)]
struct State {
    version: String,
    next_id: i64,
    users: BTreeMap<String, FakeUser>,
    orgs: BTreeMap<String, FakeOrg>,
    teams: BTreeMap<i64, FakeTeam>,
    repos: BTreeMap<i64, FakeRepo>,
    hooks: BTreeMap<i64, FakeHook>,
    keys: BTreeMap<i64, FakeKey>,
    /// id → (owner login, app, current client secret).
    oauth2_apps: BTreeMap<i64, (String, RemoteOAuth2App, String)>,
    /// id → (user login, token, value).
    tokens: BTreeMap<i64, (String, RemoteToken, String)>,
    /// Unix seconds stamped on new tokens.
    clock: i64,
    failures: VecDeque<GatewayError>,
    calls: Vec<String>,
}

pub struct FakeForgejo {
    state: Mutex<State>,
}

impl Default for FakeForgejo {
    fn default() -> Self {
        Self::with_version("16.0.5")
    }
}

impl FakeForgejo {
    pub fn with_version(version: &str) -> Self {
        Self {
            state: Mutex::new(State {
                version: version.to_string(),
                next_id: 1,
                ..Default::default()
            }),
        }
    }

    /// The next gateway call fails with `err` (queued, one per call).
    pub fn fail_next(&self, err: GatewayError) {
        self.state.lock().unwrap().failures.push_back(err);
    }

    /// Every mutating call so far, e.g. `"edit_user alice"`.
    pub fn calls(&self) -> Vec<String> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn clear_calls(&self) {
        self.state.lock().unwrap().calls.clear();
    }

    pub fn user(&self, login: &str) -> Option<FakeUser> {
        self.state.lock().unwrap().users.get(login).cloned()
    }

    pub fn org(&self, name: &str) -> Option<FakeOrg> {
        self.state.lock().unwrap().orgs.get(name).cloned()
    }

    pub fn team(&self, id: i64) -> Option<FakeTeam> {
        self.state.lock().unwrap().teams.get(&id).cloned()
    }

    pub fn repo(&self, id: i64) -> Option<RemoteRepository> {
        self.state
            .lock()
            .unwrap()
            .repos
            .get(&id)
            .map(|r| r.remote.clone())
    }

    pub fn protections(&self, id: i64) -> Vec<ProtectionRule> {
        self.state.lock().unwrap().repos[&id].protections.clone()
    }

    /// Every team with access, including `includes_all_repositories` ones.
    pub fn repo_teams(&self, id: i64) -> Vec<String> {
        let s = self.state.lock().unwrap();
        repo_teams(&s, id).into_iter().map(|t| t.name).collect()
    }

    /// `(type, config including the secret)`.
    pub fn hook(&self, id: i64) -> Option<(String, BTreeMap<String, String>)> {
        self.state.lock().unwrap().hooks.get(&id).map(|h| {
            let mut config = h.remote.config.clone();
            if let Some(secret) = &h.secret {
                config.insert("secret".into(), secret.clone());
            }
            (h.remote.type_.clone(), config)
        })
    }

    /// `(owner, app, current secret)`; the admin owns apps created without
    /// sudo.
    pub fn oauth2_app(&self, id: i64) -> Option<(String, RemoteOAuth2App, String)> {
        self.state.lock().unwrap().oauth2_apps.get(&id).cloned()
    }

    /// `(token, value)`.
    pub fn token(&self, id: i64) -> Option<(RemoteToken, String)> {
        self.state
            .lock()
            .unwrap()
            .tokens
            .get(&id)
            .map(|(_, t, v)| (t.clone(), v.clone()))
    }

    pub fn set_clock(&self, unix_seconds: i64) {
        self.state.lock().unwrap().clock = unix_seconds;
    }

    pub fn key(&self, id: i64) -> Option<RemoteKey> {
        self.state
            .lock()
            .unwrap()
            .keys
            .get(&id)
            .map(|k| k.remote.clone())
    }

    /// Deletes a key out of band.
    pub fn remove_key(&self, id: i64) {
        self.state.lock().unwrap().keys.remove(&id);
    }

    /// Seeds a user as if it existed before (e.g. created by OIDC login).
    pub fn insert_user(&self, login: &str) -> i64 {
        let mut s = self.state.lock().unwrap();
        let id = s.next_id;
        s.next_id += 1;
        s.users.insert(
            login.to_string(),
            FakeUser {
                remote: RemoteUser {
                    id,
                    login: login.to_string(),
                    active: true,
                    visibility: "public".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        id
    }

    pub fn insert_team_member(&self, team: i64, login: &str) {
        let mut s = self.state.lock().unwrap();
        s.teams
            .get_mut(&team)
            .unwrap()
            .members
            .push(login.to_string());
    }

    /// Simulates an out-of-band deletion in the Forgejo UI.
    /// Like Forgejo, takes the user's access tokens along.
    pub fn remove_user(&self, login: &str) {
        let mut s = self.state.lock().unwrap();
        s.users.remove(login);
        s.tokens.retain(|_, (owner, _, _)| owner != login);
    }

    fn begin(
        &self,
        call: Option<String>,
    ) -> Result<std::sync::MutexGuard<'_, State>, GatewayError> {
        let mut s = self.state.lock().unwrap();
        if let Some(err) = s.failures.pop_front() {
            return Err(err);
        }
        if let Some(call) = call {
            s.calls.push(call);
        }
        Ok(s)
    }
}

fn next_id(s: &mut State) -> i64 {
    let id = s.next_id;
    s.next_id += 1;
    id
}

fn repo_by_full_name<'a>(
    s: &'a mut State,
    full_name: &str,
) -> Result<&'a mut FakeRepo, GatewayError> {
    s.repos
        .values_mut()
        .find(|r| r.remote.full_name() == full_name)
        .ok_or_else(|| GatewayError::NotFound(full_name.to_string()))
}

fn repo_teams(s: &State, id: i64) -> Vec<RemoteTeam> {
    let Some(repo) = s.repos.get(&id) else {
        return vec![];
    };
    s.teams
        .values()
        .filter(|t| t.remote.organization == repo.remote.owner)
        .filter(|t| t.remote.includes_all_repositories || repo.teams.contains(&t.remote.name))
        .map(|t| t.remote.clone())
        .collect()
}

fn apply_repo_edit(r: &mut RemoteRepository, d: &DesiredRepository) {
    r.name = d.name.clone();
    if let Some(v) = &d.description {
        r.description = v.clone();
    }
    if let Some(v) = &d.website {
        r.website = v.clone();
    }
    r.private = d.private;
    r.template = d.template;
    if let Some(v) = &d.default_branch {
        r.default_branch = v.clone();
    }
    let flag = |field: &mut bool, v: Option<bool>| {
        if let Some(v) = v {
            *field = v;
        }
    };
    flag(&mut r.has_issues, d.has_issues);
    flag(&mut r.has_wiki, d.has_wiki);
    flag(&mut r.has_pull_requests, d.has_pull_requests);
    flag(&mut r.has_projects, d.has_projects);
    flag(&mut r.has_releases, d.has_releases);
    flag(&mut r.has_packages, d.has_packages);
    flag(&mut r.has_actions, d.has_actions);
    if r.mirror
        && let Some(i) = &d.mirror_interval
    {
        // Forgejo echoes Go's canonical duration form.
        let secs = crate::use_cases::reconcile_repository::go_duration_secs(i).unwrap_or(0);
        r.mirror_interval = format!("{}h{}m{}s", secs / 3600, secs % 3600 / 60, secs % 60);
    }
}

fn insert_repo(
    s: &mut State,
    owner: &str,
    repo: &DesiredRepository,
    mirror: Option<&str>,
) -> Result<ForgejoRef, GatewayError> {
    let full = format!("{owner}/{}", repo.name);
    if s.repos.values().any(|r| r.remote.full_name() == full) {
        return Err(GatewayError::AlreadyExists(full));
    }
    if !s.orgs.contains_key(owner) && !s.users.contains_key(owner) {
        return Err(GatewayError::NotFound(owner.to_string()));
    }
    let id = next_id(s);
    let mut remote = RemoteRepository {
        id,
        owner: owner.to_string(),
        default_branch: "main".into(),
        has_issues: true,
        has_wiki: true,
        has_pull_requests: true,
        has_projects: true,
        has_releases: true,
        has_packages: true,
        has_actions: false,
        mirror: mirror.is_some(),
        mirror_interval: String::new(),
        ..Default::default()
    };
    apply_repo_edit(&mut remote, repo);
    if let Some(interval) = mirror {
        apply_repo_edit(
            &mut remote,
            &DesiredRepository {
                mirror_interval: Some(interval.to_string()),
                ..repo.clone()
            },
        );
    }
    s.repos.insert(
        id,
        FakeRepo {
            remote,
            ..Default::default()
        },
    );
    Ok(ForgejoRef { id, name: full })
}

fn apply_user_edit(u: &mut FakeUser, d: &DesiredUser) {
    u.remote.email = d.email.clone();
    if let Some(n) = &d.full_name {
        u.remote.full_name = n.clone();
    }
    u.remote.admin = d.admin;
    u.remote.restricted = d.restricted;
    u.remote.visibility = d.visibility.to_string();
    u.remote.active = d.active;
    u.remote.prohibit_login = d.prohibit_login;
    u.remote.source_id = d.source_id.unwrap_or(0);
    u.remote.login_name = d.login_name.clone().unwrap_or_default();
    if d.password.is_some() {
        u.password = d.password.clone();
        u.must_change_password = d.must_change_password;
    }
    u.allow_create_organization = d.allow_create_organization;
    u.max_repo_creation = d.max_repo_creation;
}

fn apply_org_edit(o: &mut RemoteOrganization, d: &DesiredOrganization) {
    let set = |field: &mut String, v: &Option<String>| {
        if let Some(v) = v {
            *field = v.clone();
        }
    };
    set(&mut o.full_name, &d.full_name);
    set(&mut o.description, &d.description);
    set(&mut o.website, &d.website);
    set(&mut o.location, &d.location);
    set(&mut o.email, &d.email);
    o.visibility = d.visibility.to_string();
    o.repo_admin_change_team_access = d.repo_admin_change_team_access;
}

fn apply_team_edit(t: &mut RemoteTeam, d: &DesiredTeam) {
    t.name = d.name.clone();
    if let Some(desc) = &d.description {
        t.description = desc.clone();
    }
    t.permission = d.permission.to_string();
    t.units_map.extend(d.units_map.clone());
    t.includes_all_repositories = d.includes_all_repositories;
    t.can_create_org_repo = d.can_create_org_repo;
}

#[async_trait::async_trait]
impl ForgejoGateway for FakeForgejo {
    async fn server_version(&self) -> Result<String, GatewayError> {
        Ok(self.begin(None)?.version.clone())
    }

    fn web_url(&self) -> &str {
        "https://git.example.com"
    }

    async fn get_user(&self, username: &str) -> Result<Option<RemoteUser>, GatewayError> {
        Ok(self
            .begin(None)?
            .users
            .get(username)
            .map(|u| u.remote.clone()))
    }

    async fn user_login(&self, id: i64) -> Result<Option<String>, GatewayError> {
        Ok(self
            .begin(None)?
            .users
            .values()
            .find(|u| u.remote.id == id)
            .map(|u| u.remote.login.clone()))
    }

    async fn create_user(&self, user: &DesiredUser) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("create_user {}", user.username)))?;
        if s.users.contains_key(&user.username) || s.orgs.contains_key(&user.username) {
            return Err(GatewayError::AlreadyExists(format!(
                "user already exists [name: {}]",
                user.username
            )));
        }
        if user.source_id.is_none() && user.password.is_none() {
            return Err(GatewayError::Api(
                "password is required for local users".into(),
            ));
        }
        let id = s.next_id;
        s.next_id += 1;
        let mut u = FakeUser {
            remote: RemoteUser {
                id,
                login: user.username.clone(),
                active: true,
                ..Default::default()
            },
            ..Default::default()
        };
        // Only the creation fields: admin/active/prohibit_login need an edit.
        u.remote.email = user.email.clone();
        u.remote.full_name = user.full_name.clone().unwrap_or_default();
        u.remote.restricted = user.restricted;
        u.remote.visibility = user.visibility.to_string();
        u.remote.source_id = user.source_id.unwrap_or(0);
        u.remote.login_name = user.login_name.clone().unwrap_or_default();
        u.password = user.password.clone();
        u.must_change_password = user.must_change_password;
        s.users.insert(user.username.clone(), u);
        Ok(ForgejoRef {
            id,
            name: user.username.clone(),
        })
    }

    async fn edit_user(&self, username: &str, user: &DesiredUser) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("edit_user {username}")))?;
        let u = s
            .users
            .get_mut(username)
            .ok_or_else(|| GatewayError::NotFound(username.to_string()))?;
        apply_user_edit(u, user);
        Ok(())
    }

    async fn rename_user(&self, username: &str, new_username: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("rename_user {username} {new_username}")))?;
        if s.users.contains_key(new_username) {
            return Err(GatewayError::AlreadyExists(new_username.to_string()));
        }
        let mut u = s
            .users
            .remove(username)
            .ok_or_else(|| GatewayError::NotFound(username.to_string()))?;
        u.remote.login = new_username.to_string();
        s.users.insert(new_username.to_string(), u);
        // Tokens and applications hang off the user id: they follow.
        let st = &mut *s;
        let owners = st.tokens.values_mut().map(|(o, _, _)| o);
        for owner in owners.chain(st.oauth2_apps.values_mut().map(|(o, _, _)| o)) {
            if owner == username {
                *owner = new_username.to_string();
            }
        }
        Ok(())
    }

    async fn delete_user(&self, username: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_user {username}")))?;
        s.users
            .remove(username)
            .map(|_| ())
            .ok_or_else(|| GatewayError::NotFound(username.to_string()))
    }

    async fn get_organization(
        &self,
        name: &str,
    ) -> Result<Option<RemoteOrganization>, GatewayError> {
        Ok(self.begin(None)?.orgs.get(name).map(|o| o.remote.clone()))
    }

    async fn create_organization(
        &self,
        owner: Option<&str>,
        org: &DesiredOrganization,
    ) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("create_organization {}", org.name)))?;
        if s.orgs.contains_key(&org.name) || s.users.contains_key(&org.name) {
            return Err(GatewayError::AlreadyExists(org.name.clone()));
        }
        if let Some(owner) = owner
            && !s.users.contains_key(owner)
        {
            return Err(GatewayError::NotFound(owner.to_string()));
        }
        let id = s.next_id;
        s.next_id += 1;
        let mut remote = RemoteOrganization {
            id,
            name: org.name.clone(),
            ..Default::default()
        };
        apply_org_edit(&mut remote, org);
        s.orgs.insert(
            org.name.clone(),
            FakeOrg {
                remote,
                owner: owner.map(str::to_string),
            },
        );
        Ok(ForgejoRef {
            id,
            name: org.name.clone(),
        })
    }

    async fn edit_organization(
        &self,
        name: &str,
        org: &DesiredOrganization,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("edit_organization {name}")))?;
        let o = s
            .orgs
            .get_mut(name)
            .ok_or_else(|| GatewayError::NotFound(name.to_string()))?;
        apply_org_edit(&mut o.remote, org);
        Ok(())
    }

    async fn rename_organization(&self, name: &str, new_name: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("rename_organization {name} {new_name}")))?;
        let mut o = s
            .orgs
            .remove(name)
            .ok_or_else(|| GatewayError::NotFound(name.to_string()))?;
        o.remote.name = new_name.to_string();
        for t in s.teams.values_mut() {
            if t.remote.organization == name {
                t.remote.organization = new_name.to_string();
            }
        }
        s.orgs.insert(new_name.to_string(), o);
        Ok(())
    }

    async fn delete_organization(&self, name: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_organization {name}")))?;
        s.orgs
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| GatewayError::NotFound(name.to_string()))
    }

    async fn get_team(&self, id: i64) -> Result<Option<RemoteTeam>, GatewayError> {
        Ok(self.begin(None)?.teams.get(&id).map(|t| t.remote.clone()))
    }

    async fn create_team(&self, org: &str, team: &DesiredTeam) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("create_team {org}/{}", team.name)))?;
        if !s.orgs.contains_key(org) {
            return Err(GatewayError::NotFound(org.to_string()));
        }
        if s.teams
            .values()
            .any(|t| t.remote.organization == org && t.remote.name == team.name)
        {
            return Err(GatewayError::AlreadyExists(team.name.clone()));
        }
        let id = s.next_id;
        s.next_id += 1;
        let organization_id = Some(s.orgs[org].remote.id);
        let mut remote = RemoteTeam {
            id,
            organization: org.to_string(),
            organization_id,
            ..Default::default()
        };
        apply_team_edit(&mut remote, team);
        s.teams.insert(
            id,
            FakeTeam {
                remote,
                members: Vec::new(),
            },
        );
        Ok(ForgejoRef {
            id,
            name: team.name.clone(),
        })
    }

    async fn edit_team(&self, id: i64, team: &DesiredTeam) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("edit_team {id}")))?;
        let t = s
            .teams
            .get_mut(&id)
            .ok_or_else(|| GatewayError::NotFound(id.to_string()))?;
        apply_team_edit(&mut t.remote, team);
        Ok(())
    }

    async fn delete_team(&self, id: i64) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_team {id}")))?;
        s.teams
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| GatewayError::NotFound(id.to_string()))
    }

    async fn list_team_members(&self, id: i64) -> Result<Vec<String>, GatewayError> {
        let s = self.begin(None)?;
        s.teams
            .get(&id)
            .map(|t| t.members.clone())
            .ok_or_else(|| GatewayError::NotFound(id.to_string()))
    }

    async fn add_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("add_team_member {id} {username}")))?;
        if !s.users.contains_key(username) {
            return Err(GatewayError::NotFound(username.to_string()));
        }
        let t = s
            .teams
            .get_mut(&id)
            .ok_or_else(|| GatewayError::NotFound(id.to_string()))?;
        if !t.members.iter().any(|m| m == username) {
            t.members.push(username.to_string());
        }
        Ok(())
    }

    async fn remove_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("remove_team_member {id} {username}")))?;
        let t = s
            .teams
            .get_mut(&id)
            .ok_or_else(|| GatewayError::NotFound(id.to_string()))?;
        t.members.retain(|m| m != username);
        Ok(())
    }

    async fn get_repository(&self, id: i64) -> Result<Option<RemoteRepository>, GatewayError> {
        Ok(self.begin(None)?.repos.get(&id).map(|r| r.remote.clone()))
    }

    async fn create_repository(
        &self,
        owner: &str,
        _owner_is_org: bool,
        repo: &DesiredRepository,
        _init: &RepositoryInitOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("create_repository {owner}/{}", repo.name)))?;
        insert_repo(&mut s, owner, repo, None)
    }

    async fn generate_repository(
        &self,
        template: &str,
        owner: &str,
        repo: &DesiredRepository,
        _options: &GenerateOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!(
            "generate_repository {template} {owner}/{}",
            repo.name
        )))?;
        let is_template = repo_by_full_name(&mut s, template)?.remote.template;
        if !is_template {
            return Err(GatewayError::Api(format!("{template} is not a template")));
        }
        insert_repo(&mut s, owner, repo, None)
    }

    async fn migrate_repository(
        &self,
        owner: &str,
        repo: &DesiredRepository,
        options: &MigrateOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("migrate_repository {owner}/{}", repo.name)))?;
        let mirror = options.mirror.then(|| {
            options
                .mirror_interval
                .clone()
                .unwrap_or_else(|| "8h".into())
        });
        insert_repo(&mut s, owner, repo, mirror.as_deref())
    }

    async fn edit_repository(
        &self,
        full_name: &str,
        repo: &DesiredRepository,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("edit_repository {full_name}")))?;
        let r = repo_by_full_name(&mut s, full_name)?;
        if r.remote.archived {
            return Err(GatewayError::Api("423: repository is archived".into()));
        }
        apply_repo_edit(&mut r.remote, repo);
        Ok(())
    }

    async fn set_repository_archived(
        &self,
        full_name: &str,
        archived: bool,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!(
            "set_repository_archived {full_name} {archived}"
        )))?;
        repo_by_full_name(&mut s, full_name)?.remote.archived = archived;
        Ok(())
    }

    async fn transfer_repository(
        &self,
        full_name: &str,
        new_owner: &str,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("transfer_repository {full_name} {new_owner}")))?;
        if !s.orgs.contains_key(new_owner) && !s.users.contains_key(new_owner) {
            return Err(GatewayError::NotFound(new_owner.to_string()));
        }
        let r = repo_by_full_name(&mut s, full_name)?;
        r.remote.owner = new_owner.to_string();
        r.teams.clear();
        Ok(())
    }

    async fn delete_repository(&self, full_name: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_repository {full_name}")))?;
        let id = repo_by_full_name(&mut s, full_name)?.remote.id;
        s.repos.remove(&id);
        Ok(())
    }

    async fn list_branch_protections(
        &self,
        full_name: &str,
    ) -> Result<Vec<ProtectionRule>, GatewayError> {
        let mut s = self.begin(None)?;
        Ok(repo_by_full_name(&mut s, full_name)?.protections.clone())
    }

    async fn create_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!(
            "create_branch_protection {full_name} {}",
            rule.rule_name
        )))?;
        let r = repo_by_full_name(&mut s, full_name)?;
        if r.protections.iter().any(|p| p.rule_name == rule.rule_name) {
            return Err(GatewayError::AlreadyExists(rule.rule_name.clone()));
        }
        r.protections.push(as_stored(rule));
        Ok(())
    }

    async fn edit_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!(
            "edit_branch_protection {full_name} {}",
            rule.rule_name
        )))?;
        let r = repo_by_full_name(&mut s, full_name)?;
        let existing = r
            .protections
            .iter_mut()
            .find(|p| p.rule_name == rule.rule_name)
            .ok_or_else(|| GatewayError::NotFound(rule.rule_name.clone()))?;
        *existing = as_stored(rule);
        Ok(())
    }

    async fn delete_branch_protection(
        &self,
        full_name: &str,
        rule_name: &str,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!(
            "delete_branch_protection {full_name} {rule_name}"
        )))?;
        repo_by_full_name(&mut s, full_name)?
            .protections
            .retain(|p| p.rule_name != rule_name);
        Ok(())
    }

    async fn list_repository_teams(
        &self,
        full_name: &str,
    ) -> Result<Vec<RemoteTeam>, GatewayError> {
        let mut s = self.begin(None)?;
        let id = repo_by_full_name(&mut s, full_name)?.remote.id;
        Ok(repo_teams(&s, id))
    }

    async fn add_repository_team(&self, full_name: &str, team: &str) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("add_repository_team {full_name} {team}")))?;
        let owner = repo_by_full_name(&mut s, full_name)?.remote.owner.clone();
        if !s
            .teams
            .values()
            .any(|t| t.remote.organization == owner && t.remote.name == team)
        {
            return Err(GatewayError::NotFound(team.to_string()));
        }
        repo_by_full_name(&mut s, full_name)?
            .teams
            .push(team.to_string());
        Ok(())
    }

    async fn remove_repository_team(
        &self,
        full_name: &str,
        team: &str,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("remove_repository_team {full_name} {team}")))?;
        repo_by_full_name(&mut s, full_name)?
            .teams
            .retain(|t| t != team);
        Ok(())
    }

    async fn get_hook(
        &self,
        target: &HookTarget,
        id: i64,
    ) -> Result<Option<RemoteHook>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.hooks
            .get(&id)
            .filter(|h| h.target == target.to_string())
            .map(|h| h.remote.clone()))
    }

    async fn create_hook(
        &self,
        target: &HookTarget,
        hook: &DesiredHook,
    ) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("create_hook {target}")))?;
        let id = next_id(&mut s);
        // Like Forgejo: only echoed keys read back, events expanded.
        let secret = hook.config.get("secret").cloned();
        let config = hook
            .config
            .iter()
            .filter(|(k, _)| forgejo_echoes(&hook.type_, k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        s.hooks.insert(
            id,
            FakeHook {
                target: target.to_string(),
                remote: RemoteHook {
                    id,
                    type_: hook.type_.clone(),
                    config,
                    events: forgejo_events(&hook.events).into_iter().collect(),
                    branch_filter: hook.branch_filter.clone(),
                    active: hook.active,
                },
                secret,
            },
        );
        Ok(ForgejoRef {
            id,
            name: target.to_string(),
        })
    }

    async fn edit_hook(
        &self,
        target: &HookTarget,
        id: i64,
        hook: &DesiredHook,
    ) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("edit_hook {target} {id}")))?;
        let h = s
            .hooks
            .get_mut(&id)
            .filter(|h| h.target == target.to_string())
            .ok_or_else(|| GatewayError::NotFound(id.to_string()))?;
        // Like Forgejo: the secret and non-echoed keys are create-only.
        for (k, v) in &hook.config {
            if forgejo_echoes(&hook.type_, k) {
                h.remote.config.insert(k.clone(), v.clone());
            }
        }
        h.remote.events = forgejo_events(&hook.events).into_iter().collect();
        h.remote.branch_filter = hook.branch_filter.clone();
        h.remote.active = hook.active;
        Ok(())
    }

    async fn delete_hook(&self, target: &HookTarget, id: i64) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_hook {target} {id}")))?;
        match s.hooks.get(&id) {
            Some(h) if h.target == target.to_string() => {
                s.hooks.remove(&id);
                Ok(())
            }
            _ => Err(GatewayError::NotFound(id.to_string())),
        }
    }

    async fn get_deploy_key(
        &self,
        full_name: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.keys
            .get(&id)
            .filter(|k| k.owner == full_name)
            .map(|k| k.remote.clone()))
    }

    async fn create_deploy_key(
        &self,
        full_name: &str,
        title: &str,
        key: &str,
        read_only: bool,
    ) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("create_deploy_key {full_name} {title}")))?;
        insert_key(&mut s, full_name, title, key, read_only)
    }

    async fn delete_deploy_key(&self, full_name: &str, id: i64) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_deploy_key {full_name} {id}")))?;
        remove_key(&mut s, full_name, id)
    }

    async fn get_user_key(
        &self,
        username: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.keys
            .get(&id)
            .filter(|k| k.owner == username)
            .map(|k| k.remote.clone()))
    }

    async fn create_user_key(
        &self,
        username: &str,
        title: &str,
        key: &str,
    ) -> Result<ForgejoRef, GatewayError> {
        let mut s = self.begin(Some(format!("create_user_key {username} {title}")))?;
        insert_key(&mut s, username, title, key, false)
    }

    async fn delete_user_key(&self, username: &str, id: i64) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_user_key {username} {id}")))?;
        remove_key(&mut s, username, id)
    }

    async fn get_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
    ) -> Result<Option<RemoteOAuth2App>, GatewayError> {
        let owner = sudo.unwrap_or("admin");
        let s = self.begin(None)?;
        Ok(s.oauth2_apps
            .get(&id)
            .filter(|(o, _, _)| o == owner)
            .map(|(_, a, _)| a.clone()))
    }

    async fn create_oauth2_app(
        &self,
        sudo: Option<&str>,
        app: &DesiredOAuth2App,
    ) -> Result<(RemoteOAuth2App, String), GatewayError> {
        let owner = sudo.unwrap_or("admin").to_string();
        let mut s = self.begin(Some(format!("create_oauth2_app {owner} {}", app.name)))?;
        if owner != "admin" && !s.users.contains_key(&owner) {
            return Err(GatewayError::Api(format!("sudo: no user {owner}")));
        }
        let id = next_id(&mut s);
        let remote = RemoteOAuth2App {
            id,
            name: app.name.clone(),
            client_id: format!("client-{id}"),
            redirect_uris: app.redirect_uris.clone(),
            confidential_client: app.confidential_client,
        };
        let secret = format!("secret-{id}-0");
        s.oauth2_apps
            .insert(id, (owner, remote.clone(), secret.clone()));
        Ok((remote, secret))
    }

    async fn update_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
        app: &DesiredOAuth2App,
    ) -> Result<String, GatewayError> {
        let owner = sudo.unwrap_or("admin");
        let mut s = self.begin(Some(format!("update_oauth2_app {owner} {id}")))?;
        let calls = s.calls.len();
        let (_, remote, secret) = s
            .oauth2_apps
            .get_mut(&id)
            .filter(|(o, _, _)| o == owner)
            .ok_or_else(|| GatewayError::NotFound(id.to_string()))?;
        remote.name = app.name.clone();
        remote.redirect_uris = app.redirect_uris.clone();
        remote.confidential_client = app.confidential_client;
        // Like Forgejo: every update issues a new secret.
        *secret = format!("secret-{id}-{calls}");
        Ok(secret.clone())
    }

    async fn delete_oauth2_app(&self, sudo: Option<&str>, id: i64) -> Result<(), GatewayError> {
        let owner = sudo.unwrap_or("admin");
        let mut s = self.begin(Some(format!("delete_oauth2_app {owner} {id}")))?;
        match s.oauth2_apps.get(&id) {
            Some((o, _, _)) if o == owner => {
                s.oauth2_apps.remove(&id);
                Ok(())
            }
            _ => Err(GatewayError::NotFound(id.to_string())),
        }
    }

    async fn list_access_tokens(&self, username: &str) -> Result<Vec<RemoteToken>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.tokens
            .values()
            .filter(|(u, _, _)| u == username)
            .map(|(_, t, _)| t.clone())
            .collect())
    }

    async fn create_access_token(
        &self,
        username: &str,
        token: &DesiredToken,
    ) -> Result<(ForgejoRef, String), GatewayError> {
        let mut s = self.begin(Some(format!(
            "create_access_token {username} {}",
            token.name
        )))?;
        if !s.users.contains_key(username) {
            return Err(GatewayError::NotFound(username.to_string()));
        }
        if s.tokens
            .values()
            .any(|(u, t, _)| u == username && t.name == token.name)
        {
            return Err(GatewayError::AlreadyExists(token.name.clone()));
        }
        let id = next_id(&mut s);
        let value = format!("{id:040x}");
        let remote = RemoteToken {
            id,
            name: token.name.clone(),
            scopes: token.scopes.clone(),
            repositories: token.repositories.clone(),
            created_at: Some(s.clock),
        };
        s.tokens
            .insert(id, (username.to_string(), remote, value.clone()));
        Ok((
            ForgejoRef {
                id,
                name: token.name.clone(),
            },
            value,
        ))
    }

    async fn delete_access_token(&self, username: &str, id: i64) -> Result<(), GatewayError> {
        let mut s = self.begin(Some(format!("delete_access_token {username} {id}")))?;
        match s.tokens.get(&id) {
            Some((u, _, _)) if u == username => {
                s.tokens.remove(&id);
                Ok(())
            }
            _ => Err(GatewayError::NotFound(id.to_string())),
        }
    }
}

/// Like Forgejo: the push allow-list switches only stick while pushing is
/// enabled (the lists themselves are kept).
fn as_stored(rule: &ProtectionRule) -> ProtectionRule {
    let mut r = rule.clone();
    r.enable_push_whitelist &= r.enable_push;
    r.push_whitelist_deploy_keys &= r.enable_push_whitelist;
    r
}

fn insert_key(
    s: &mut State,
    owner: &str,
    title: &str,
    key: &str,
    read_only: bool,
) -> Result<ForgejoRef, GatewayError> {
    // Forgejo refuses the same key material twice.
    let material: Vec<&str> = key.split_whitespace().take(2).collect();
    if s.keys.values().any(|k| {
        k.owner == owner && k.remote.key.split_whitespace().take(2).collect::<Vec<_>>() == material
    }) {
        return Err(GatewayError::AlreadyExists("key already exists".into()));
    }
    let id = next_id(s);
    s.keys.insert(
        id,
        FakeKey {
            owner: owner.to_string(),
            remote: RemoteKey {
                id,
                title: title.to_string(),
                // Forgejo keeps algorithm + material, not the comment.
                key: material.join(" "),
                read_only,
            },
        },
    );
    Ok(ForgejoRef {
        id,
        name: title.to_string(),
    })
}

fn remove_key(s: &mut State, owner: &str, id: i64) -> Result<(), GatewayError> {
    match s.keys.get(&id) {
        Some(k) if k.owner == owner => {
            s.keys.remove(&id);
            Ok(())
        }
        _ => Err(GatewayError::NotFound(id.to_string())),
    }
}

#[async_trait::async_trait]
impl ForgejoInventory for FakeForgejo {
    async fn list_users(&self) -> Result<Vec<RemoteUser>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.users.values().map(|u| u.remote.clone()).collect())
    }

    async fn list_organizations(&self) -> Result<Vec<RemoteOrganization>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.orgs.values().map(|o| o.remote.clone()).collect())
    }

    async fn list_teams(&self, org: &str) -> Result<Vec<RemoteTeam>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.teams
            .values()
            .filter(|t| t.remote.organization == org)
            .map(|t| t.remote.clone())
            .collect())
    }

    async fn list_repositories(
        &self,
        owner: &str,
        _owner_is_org: bool,
    ) -> Result<Vec<RemoteRepository>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.repos
            .values()
            .filter(|r| r.remote.owner == owner)
            .map(|r| r.remote.clone())
            .collect())
    }

    async fn list_hooks(&self, target: &HookTarget) -> Result<Vec<RemoteHook>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.hooks
            .values()
            .filter(|h| h.target == target.to_string())
            .map(|h| h.remote.clone())
            .collect())
    }

    async fn list_deploy_keys(&self, full_name: &str) -> Result<Vec<RemoteKey>, GatewayError> {
        let s = self.begin(None)?;
        Ok(s.keys
            .values()
            .filter(|k| k.owner == full_name)
            .map(|k| k.remote.clone())
            .collect())
    }
}

/// Secrets keyed by `namespace/name`.
#[derive(Default)]
pub struct FakeSecretStore {
    secrets: Mutex<BTreeMap<String, BTreeMap<String, String>>>,
    fail_writes: Mutex<bool>,
}

impl FakeSecretStore {
    fn key(target: &SecretTarget, default_namespace: Option<&str>) -> String {
        let ns = target
            .namespace
            .as_deref()
            .or(default_namespace)
            .unwrap_or("<none>");
        format!("{ns}/{}", target.name)
    }

    pub fn get(&self, key: &str) -> Option<BTreeMap<String, String>> {
        self.secrets.lock().unwrap().get(key).cloned()
    }

    pub fn remove(&self, key: &str) {
        self.secrets.lock().unwrap().remove(key);
    }

    pub fn fail_writes(&self, fail: bool) {
        *self.fail_writes.lock().unwrap() = fail;
    }
}

#[async_trait::async_trait]
impl SecretStore for FakeSecretStore {
    fn default_backend(&self) -> api::instance::SecretStoreBackend {
        api::instance::SecretStoreBackend::Kubernetes
    }

    async fn write(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
        data: &BTreeMap<String, String>,
    ) -> Result<(), SecretStoreError> {
        if *self.fail_writes.lock().unwrap() {
            return Err(SecretStoreError("write refused".into()));
        }
        self.secrets
            .lock()
            .unwrap()
            .insert(Self::key(target, default_namespace), data.clone());
        Ok(())
    }

    async fn exists(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<bool, SecretStoreError> {
        Ok(self
            .secrets
            .lock()
            .unwrap()
            .contains_key(&Self::key(target, default_namespace)))
    }

    async fn delete(
        &self,
        target: &SecretTarget,
        default_namespace: Option<&str>,
    ) -> Result<(), SecretStoreError> {
        self.secrets
            .lock()
            .unwrap()
            .remove(&Self::key(target, default_namespace));
        Ok(())
    }
}
