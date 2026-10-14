//! Port traits. Adapters (`adapters-outbound`) implement them; use-cases in
//! this crate depend only on the traits — dependency injection happens in
//! `operator::main`. See `.prompt/plan.md`, "Architecture hexagonale".
//!
//! The gateway speaks in the port structs below, never in CRD types or the
//! generated client's models: use-cases build the *desired* shape from a
//! spec, the adapter returns the *remote* shape, and the diff between the
//! two (deciding whether a PATCH is needed at all) stays in this crate.

use std::collections::BTreeMap;
use std::sync::Arc;

use domain::error::ReasonCode;

/// Failure of a Forgejo API call, already classified into the stable
/// `ReasonCode` a reconciler surfaces for it.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GatewayError {
    /// The name is already taken by an object this CR doesn't own (409, or
    /// a 422 saying so, on create). Never resolved by adoption — see
    /// `.prompt/plan.md`, "Collision avec un objet existant".
    #[error("object already exists in Forgejo: {0}")]
    AlreadyExists(String),
    #[error("object not found in Forgejo: {0}")]
    NotFound(String),
    #[error("Forgejo unreachable: {0}")]
    Unreachable(String),
    #[error("Forgejo API error: {0}")]
    Api(String),
}

impl GatewayError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            GatewayError::AlreadyExists(_) => ReasonCode::ForgejoObjectAlreadyExists,
            GatewayError::NotFound(_) | GatewayError::Api(_) => ReasonCode::ForgejoApiError,
            GatewayError::Unreachable(_) => ReasonCode::InstanceUnreachable,
        }
    }
}

/// Identity of a Forgejo object: its numeric id (stable across renames)
/// and the name the API addresses it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgejoRef {
    pub id: i64,
    pub name: String,
}

// ── Users ─────────────────────────────────────────────────────────────────────

/// Everything `POST /admin/users` + `PATCH /admin/users/{u}` can set. Some
/// fields only exist on edit, so a create is always followed by an edit.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct DesiredUser {
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    /// `None` for an external (auth-source) account.
    pub password: Option<String>,
    pub must_change_password: bool,
    pub source_id: Option<i64>,
    pub login_name: Option<String>,
    pub admin: bool,
    pub restricted: bool,
    pub visibility: &'static str,
    pub active: bool,
    pub prohibit_login: bool,
    pub allow_create_organization: Option<bool>,
    pub max_repo_creation: Option<i64>,
}

/// The subset of Forgejo's `User` the user reconciler diffs against.
/// `allow_create_organization`/`max_repo_creation` are absent: Forgejo
/// never returns them, so they are re-sent whenever the spec changes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteUser {
    pub id: i64,
    pub login: String,
    pub email: String,
    pub full_name: String,
    pub admin: bool,
    pub restricted: bool,
    pub visibility: String,
    pub active: bool,
    pub prohibit_login: bool,
    pub source_id: i64,
    pub login_name: String,
}

// ── Organizations ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredOrganization {
    pub name: String,
    pub full_name: Option<String>,
    pub description: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
    pub email: Option<String>,
    pub visibility: &'static str,
    pub repo_admin_change_team_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteOrganization {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub description: String,
    pub website: String,
    pub location: String,
    pub email: String,
    pub visibility: String,
    pub repo_admin_change_team_access: bool,
}

// ── Teams ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredTeam {
    pub name: String,
    pub description: Option<String>,
    /// `read`, `write` or `admin`.
    pub permission: &'static str,
    pub units_map: BTreeMap<String, String>,
    pub includes_all_repositories: bool,
    pub can_create_org_repo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteTeam {
    pub id: i64,
    pub name: String,
    /// Name of the organization the team belongs to.
    pub organization: String,
    /// Its id, when Forgejo returned the embedded organization.
    pub organization_id: Option<i64>,
    pub description: String,
    pub permission: String,
    pub units_map: BTreeMap<String, String>,
    pub includes_all_repositories: bool,
    pub can_create_org_repo: bool,
}

// ── Repositories ──────────────────────────────────────────────────────────────

/// Repository settings that can be PATCHed. `None` = no opinion (never
/// forces a PATCH).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredRepository {
    pub name: String,
    pub description: Option<String>,
    pub website: Option<String>,
    pub private: bool,
    pub template: bool,
    pub default_branch: Option<String>,
    pub has_issues: Option<bool>,
    pub has_wiki: Option<bool>,
    pub has_pull_requests: Option<bool>,
    pub has_projects: Option<bool>,
    pub has_releases: Option<bool>,
    pub has_packages: Option<bool>,
    pub has_actions: Option<bool>,
    /// Only sent for mirrors.
    pub mirror_interval: Option<String>,
}

/// Creation-time options of an empty repository.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepositoryInitOptions {
    pub auto_init: bool,
    pub gitignores: Option<String>,
    pub license: Option<String>,
    pub readme: Option<String>,
    pub object_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GenerateOptions {
    pub git_content: bool,
    pub topics: bool,
    pub labels: bool,
    pub webhooks: bool,
    pub protected_branches: bool,
    pub git_hooks: bool,
    pub avatar: bool,
}

/// `POST /repos/migrate`, with the credentials already read from their
/// Secret by the controller.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MigrateOptions {
    pub clone_addr: String,
    pub service: String,
    pub mirror: bool,
    pub mirror_interval: Option<String>,
    pub lfs: bool,
    pub wiki: bool,
    pub issues: bool,
    pub pull_requests: bool,
    pub releases: bool,
    pub labels: bool,
    pub milestones: bool,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteRepository {
    pub id: i64,
    pub owner: String,
    pub name: String,
    pub description: String,
    pub website: String,
    pub private: bool,
    pub template: bool,
    pub archived: bool,
    pub default_branch: String,
    pub has_issues: bool,
    pub has_wiki: bool,
    pub has_pull_requests: bool,
    pub has_projects: bool,
    pub has_releases: bool,
    pub has_packages: bool,
    pub has_actions: bool,
    pub mirror: bool,
    pub mirror_interval: String,
    /// Address a migrated or mirrored repository was cloned from.
    pub original_url: String,
}

impl RemoteRepository {
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// One branch protection rule, in the shape both sides are compared in
/// (the `enable_*` switches derived from the lists).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectionRule {
    pub rule_name: String,
    pub enable_push: bool,
    pub enable_push_whitelist: bool,
    pub push_whitelist_usernames: Vec<String>,
    pub push_whitelist_teams: Vec<String>,
    pub push_whitelist_deploy_keys: bool,
    pub enable_merge_whitelist: bool,
    pub merge_whitelist_usernames: Vec<String>,
    pub merge_whitelist_teams: Vec<String>,
    pub required_approvals: i64,
    pub enable_approvals_whitelist: bool,
    pub approvals_whitelist_usernames: Vec<String>,
    pub approvals_whitelist_teams: Vec<String>,
    pub enable_status_check: bool,
    pub status_check_contexts: Vec<String>,
    pub block_on_rejected_reviews: bool,
    pub block_on_official_review_requests: bool,
    pub block_on_outdated_branch: bool,
    pub dismiss_stale_approvals: bool,
    pub ignore_stale_approvals: bool,
    pub require_signed_commits: bool,
    pub apply_to_admins: bool,
    pub protected_file_patterns: String,
    pub unprotected_file_patterns: String,
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

/// Where a webhook lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookTarget {
    Repository { owner: String, name: String },
    Organization(String),
}

impl std::fmt::Display for HookTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookTarget::Repository { owner, name } => write!(f, "repo:{owner}/{name}"),
            HookTarget::Organization(org) => write!(f, "org:{org}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct DesiredHook {
    pub type_: String,
    /// `url`, `content_type`, `http_method`, `secret` and type-specific keys.
    pub config: BTreeMap<String, String>,
    pub events: Vec<String>,
    pub branch_filter: String,
    pub active: bool,
    pub authorization_header: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteHook {
    pub id: i64,
    pub type_: String,
    /// Never contains the secret.
    pub config: BTreeMap<String, String>,
    pub events: Vec<String>,
    pub branch_filter: String,
    pub active: bool,
}

// ── SSH keys ──────────────────────────────────────────────────────────────────

/// A deploy key or user public key as Forgejo reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteKey {
    pub id: i64,
    pub title: String,
    pub key: String,
    pub read_only: bool,
}

// ── OAuth2 applications ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredOAuth2App {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub confidential_client: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteOAuth2App {
    pub id: i64,
    pub name: String,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub confidential_client: bool,
}

// ── Access tokens ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredToken {
    pub name: String,
    pub scopes: Vec<String>,
    /// `owner/name` of each repository the token is limited to.
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteToken {
    pub id: i64,
    pub name: String,
    pub scopes: Vec<String>,
    pub repositories: Vec<String>,
    /// Unix seconds.
    pub created_at: Option<i64>,
}

/// Operations against one Forgejo instance, acting as its admin token.
///
/// `#[async_trait]` rather than native `async fn` in trait: used as
/// `dyn ForgejoGateway` everywhere (dependency injection), which native
/// async-fn-in-traits don't allow on stable Rust.
#[async_trait::async_trait]
pub trait ForgejoGateway: Send + Sync {
    /// Version string reported by `GET /version` — doubles as the
    /// `ForgejoInstance` connectivity and token check.
    async fn server_version(&self) -> Result<String, GatewayError>;

    /// Instance web base, written as `FORGEJO_URL` into emitted secrets.
    fn web_url(&self) -> &str;

    /// `Ok(None)` when no user has that login.
    /// The account the instance token belongs to (`GET /user`).
    async fn token_user(&self) -> Result<RemoteUser, GatewayError>;
    async fn get_user(&self, username: &str) -> Result<Option<RemoteUser>, GatewayError>;
    /// Current login of the user with that Forgejo id; `Ok(None)` when
    /// the account is gone.
    async fn user_login(&self, id: i64) -> Result<Option<String>, GatewayError>;
    /// Attempt-create-first: a taken login is `GatewayError::AlreadyExists`,
    /// never a silent adopt. Only the creation fields are sent; callers
    /// follow with `edit_user`.
    async fn create_user(&self, user: &DesiredUser) -> Result<ForgejoRef, GatewayError>;
    /// `user.password` is only sent when `Some` — that's how a password is
    /// reset.
    async fn edit_user(&self, username: &str, user: &DesiredUser) -> Result<(), GatewayError>;
    async fn rename_user(&self, username: &str, new_username: &str) -> Result<(), GatewayError>;
    /// Never purges: repositories and attribution survive.
    async fn delete_user(&self, username: &str) -> Result<(), GatewayError>;

    async fn get_organization(
        &self,
        name: &str,
    ) -> Result<Option<RemoteOrganization>, GatewayError>;
    /// `owner`: login of the user that becomes the first owner; `None`
    /// makes the operator's admin account the owner.
    async fn create_organization(
        &self,
        owner: Option<&str>,
        org: &DesiredOrganization,
    ) -> Result<ForgejoRef, GatewayError>;
    async fn edit_organization(
        &self,
        name: &str,
        org: &DesiredOrganization,
    ) -> Result<(), GatewayError>;
    /// Current name of the organization with this id (`None`: deleted).
    /// Only called when the stored name no longer leads to it — a rename
    /// outside the operator — so it may list every organization.
    async fn organization_name(&self, id: i64) -> Result<Option<String>, GatewayError>;
    async fn rename_organization(&self, name: &str, new_name: &str) -> Result<(), GatewayError>;
    async fn delete_organization(&self, name: &str) -> Result<(), GatewayError>;

    async fn get_team(&self, id: i64) -> Result<Option<RemoteTeam>, GatewayError>;
    async fn create_team(&self, org: &str, team: &DesiredTeam) -> Result<ForgejoRef, GatewayError>;
    async fn edit_team(&self, id: i64, team: &DesiredTeam) -> Result<(), GatewayError>;
    async fn delete_team(&self, id: i64) -> Result<(), GatewayError>;
    /// Logins of every member.
    async fn list_team_members(&self, id: i64) -> Result<Vec<String>, GatewayError>;
    async fn add_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError>;
    async fn remove_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError>;

    /// By id, so renames and transfers never lose track of it.
    async fn get_repository(&self, id: i64) -> Result<Option<RemoteRepository>, GatewayError>;
    /// `owner_is_org` selects the org or the admin-for-user endpoint.
    async fn create_repository(
        &self,
        owner: &str,
        owner_is_org: bool,
        repo: &DesiredRepository,
        init: &RepositoryInitOptions,
    ) -> Result<ForgejoRef, GatewayError>;
    async fn generate_repository(
        &self,
        template: &str,
        owner: &str,
        repo: &DesiredRepository,
        options: &GenerateOptions,
    ) -> Result<ForgejoRef, GatewayError>;
    /// Synchronous in Forgejo: as long as the clone takes.
    async fn migrate_repository(
        &self,
        owner: &str,
        repo: &DesiredRepository,
        options: &MigrateOptions,
    ) -> Result<ForgejoRef, GatewayError>;
    /// `full_name` is `owner/name`; `repo.name` renames when it differs.
    async fn edit_repository(
        &self,
        full_name: &str,
        repo: &DesiredRepository,
    ) -> Result<(), GatewayError>;
    async fn set_repository_archived(
        &self,
        full_name: &str,
        archived: bool,
    ) -> Result<(), GatewayError>;
    async fn transfer_repository(
        &self,
        full_name: &str,
        new_owner: &str,
    ) -> Result<(), GatewayError>;
    async fn delete_repository(&self, full_name: &str) -> Result<(), GatewayError>;

    async fn list_branch_protections(
        &self,
        full_name: &str,
    ) -> Result<Vec<ProtectionRule>, GatewayError>;
    async fn create_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError>;
    async fn edit_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError>;
    async fn delete_branch_protection(
        &self,
        full_name: &str,
        rule_name: &str,
    ) -> Result<(), GatewayError>;

    /// Teams with access to an organization repository.
    async fn list_repository_teams(&self, full_name: &str)
    -> Result<Vec<RemoteTeam>, GatewayError>;
    async fn add_repository_team(&self, full_name: &str, team: &str) -> Result<(), GatewayError>;
    async fn remove_repository_team(&self, full_name: &str, team: &str)
    -> Result<(), GatewayError>;

    async fn get_hook(
        &self,
        target: &HookTarget,
        id: i64,
    ) -> Result<Option<RemoteHook>, GatewayError>;
    async fn create_hook(
        &self,
        target: &HookTarget,
        hook: &DesiredHook,
    ) -> Result<ForgejoRef, GatewayError>;
    async fn edit_hook(
        &self,
        target: &HookTarget,
        id: i64,
        hook: &DesiredHook,
    ) -> Result<(), GatewayError>;
    async fn delete_hook(&self, target: &HookTarget, id: i64) -> Result<(), GatewayError>;
    /// Every hook of `target` — before a create, to never add a twin of a
    /// hook whose create response was lost.
    async fn list_hooks(&self, target: &HookTarget) -> Result<Vec<RemoteHook>, GatewayError>;

    async fn get_deploy_key(
        &self,
        full_name: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError>;
    async fn create_deploy_key(
        &self,
        full_name: &str,
        title: &str,
        key: &str,
        read_only: bool,
    ) -> Result<ForgejoRef, GatewayError>;
    async fn delete_deploy_key(&self, full_name: &str, id: i64) -> Result<(), GatewayError>;

    async fn get_user_key(
        &self,
        username: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError>;
    async fn create_user_key(
        &self,
        username: &str,
        title: &str,
        key: &str,
    ) -> Result<ForgejoRef, GatewayError>;
    async fn delete_user_key(&self, username: &str, id: i64) -> Result<(), GatewayError>;

    /// OAuth2 applications belong to the calling user: `sudo` names the
    /// user to act as (`None` = the admin itself).
    async fn get_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
    ) -> Result<Option<RemoteOAuth2App>, GatewayError>;
    /// Returns the application and its client secret (shown only now).
    async fn create_oauth2_app(
        &self,
        sudo: Option<&str>,
        app: &DesiredOAuth2App,
    ) -> Result<(RemoteOAuth2App, String), GatewayError>;
    /// Every update regenerates the client secret, returned here.
    async fn update_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
        app: &DesiredOAuth2App,
    ) -> Result<String, GatewayError>;
    async fn delete_oauth2_app(&self, sudo: Option<&str>, id: i64) -> Result<(), GatewayError>;
    /// Every OAuth2 application of the account (`sudo`, or the admin).
    async fn list_oauth2_apps(
        &self,
        sudo: Option<&str>,
    ) -> Result<Vec<RemoteOAuth2App>, GatewayError>;

    async fn list_access_tokens(&self, username: &str) -> Result<Vec<RemoteToken>, GatewayError>;
    /// Returns the token and its value (shown only now).
    async fn create_access_token(
        &self,
        username: &str,
        token: &DesiredToken,
    ) -> Result<(ForgejoRef, String), GatewayError>;
    async fn delete_access_token(&self, username: &str, id: i64) -> Result<(), GatewayError>;
}

/// Listing calls only the importer needs (`.prompt/plan.md`, "Seul chemin
/// d'adoption"): reconcilers never enumerate, they address what they own
/// by id. Every list is complete (paginated by the adapter).
#[async_trait::async_trait]
pub trait ForgejoInventory: ForgejoGateway {
    async fn list_users(&self) -> Result<Vec<RemoteUser>, GatewayError>;
    async fn list_organizations(&self) -> Result<Vec<RemoteOrganization>, GatewayError>;
    async fn list_teams(&self, org: &str) -> Result<Vec<RemoteTeam>, GatewayError>;
    /// Repositories owned by `owner` (organization or user), private ones
    /// included.
    async fn list_repositories(
        &self,
        owner: &str,
        owner_is_org: bool,
    ) -> Result<Vec<RemoteRepository>, GatewayError>;
    async fn list_deploy_keys(&self, full_name: &str) -> Result<Vec<RemoteKey>, GatewayError>;
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayFactoryError {
    /// The instance resolved for a CR is gone.
    #[error("{0} not found")]
    InstanceNotFound(String),
    /// No `instanceRef` and more than one `ForgejoInstance` exists.
    #[error("ambiguous default ForgejoInstance: {0}")]
    AmbiguousDefault(String),
    /// The token `Secret` or its key is missing / not UTF-8.
    #[error("ForgejoInstance token secret: {0}")]
    TokenSecret(String),
    /// A `ForgejoLocalInstance`'s token `Secret` isn't labelled for it.
    #[error("ForgejoLocalInstance token secret: {0}")]
    TokenSecretNotAllowed(String),
    /// A Kubernetes API call (listing instances, reading a `Secret`)
    /// failed — usually transient, never a spec problem.
    #[error("Kubernetes API error resolving ForgejoInstance: {0}")]
    Kubernetes(String),
    /// The instance's settings can't produce a client (e.g. a CA bundle
    /// with no certificate).
    #[error("failed resolving ForgejoInstance: {0}")]
    ResolutionFailed(String),
}

impl GatewayFactoryError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            GatewayFactoryError::InstanceNotFound(_) => ReasonCode::InstanceNotFound,
            GatewayFactoryError::AmbiguousDefault(_) => ReasonCode::AmbiguousDefaultInstance,
            GatewayFactoryError::TokenSecret(_) => ReasonCode::TokenSecretNotFound,
            GatewayFactoryError::TokenSecretNotAllowed(_) => ReasonCode::TokenSecretNotAllowed,
            GatewayFactoryError::Kubernetes(_) => ReasonCode::KubernetesApiError,
            GatewayFactoryError::ResolutionFailed(_) => ReasonCode::InvalidSpec,
        }
    }
}

/// Produces a `ForgejoGateway` for a resolved instance — a
/// `ForgejoInstance` or a `ForgejoLocalInstance` (see
/// [`InstanceDirectory`]). The adapter re-reads the token `Secret` on every
/// call so rotation needs no restart.
#[async_trait::async_trait]
pub trait GatewayFactory: Send + Sync {
    async fn gateway_for(
        &self,
        instance: &BoundInstance,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError>;
}

/// Which instance a CR lives on — a `ForgejoInstance` or a
/// `ForgejoLocalInstance` — resolved by the kit's rules
/// (`weebo_kit_application::instances`) from its `instanceRef`, its
/// namespace and the operator's watch scope.
pub use weebo_kit_application::instances::{
    BoundInstance, InstanceDirectory, InstanceError, ResolveError, SharedWith,
};

/// The Vault connection of a resolved instance, as the admission webhook
/// reads it (from the binary's instance reflectors).
#[derive(Debug, Clone, PartialEq)]
pub enum InstanceVault {
    /// The instance doesn't exist (any more): the reconcile reports it.
    NotFound,
    /// No Vault: a `ForgejoLocalInstance`, or a `ForgejoInstance` without
    /// `secretStore.vault`.
    None,
    Vault(Box<api::instance::VaultSecretStoreSpec>),
}

#[async_trait::async_trait]
pub trait InstanceVaults: Send + Sync {
    async fn vault_of(&self, instance: &BoundInstance) -> Result<InstanceVault, String>;
}

/// Secret stores are the kit's: Kubernetes `Secret`s and Vault KV, routed
/// per target (`weebo_kit_adapters`).
pub use weebo_kit_application::ports::{
    SecretOwner, SecretStore, SecretStoreError, SecretStoreFactory,
};

// ── Cluster reads ─────────────────────────────────────────────────────────────

/// A Kubernetes API read (a referenced CR, a `Secret`, the policies)
/// failed — usually transient, never a spec problem. Retried by the
/// controller rather than surfaced as a `Ready` reason. The kit's.
pub use weebo_kit_application::ports::ClusterError;

/// What [`ReferenceReader::secret_key`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKey {
    /// No such `Secret`, or no such key in it.
    Missing,
    /// The `Secret` exists but isn't labelled
    /// `forgejo.weebo.io/credential: "true"`: its content wasn't read.
    NotLabelled,
    Value(Vec<u8>),
}

/// The kinds a `*Ref` field can point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    User,
    Organization,
    Team,
    Repository,
}

impl RefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RefKind::User => "ForgejoUser",
            RefKind::Organization => "ForgejoOrganization",
            RefKind::Team => "ForgejoTeam",
            RefKind::Repository => "ForgejoRepository",
        }
    }
}

/// What a referenced CR says about the Forgejo object behind it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReferencedCr {
    /// The instance its status records (`None` before its first
    /// resolution).
    pub instance: Option<BoundInstance>,
    /// Its `spec.sharedWith`: the other namespaces that may reference it.
    pub shared_with: Option<SharedWith>,
    /// `status.forgejoId`/`forgejoName` (`None` while either is missing
    /// or the id doesn't parse).
    pub forgejo: Option<ForgejoRef>,
    /// `status.forgejoName` alone, whatever the id.
    pub forgejo_name: Option<String>,
    /// Its `Ready` condition: `(status == "True", reason)`. `None` until
    /// it was first reconciled.
    pub ready: Option<(bool, String)>,
    /// The Forgejo name its spec asks for (`spec.username` of a user,
    /// `spec.name` otherwise), known before it is ever reconciled.
    pub spec_name: Option<String>,
    /// A team's organization, by its Forgejo name (`None` while unknown).
    pub organization: Option<String>,
    /// A user's `spec.admin`, or its `managementPolicy: Observe` (the
    /// account's flags aren't known): credentials minted for it are
    /// site-admin credentials.
    pub admin: bool,
}

/// Read access to what the `*Ref` fields of a CR point at.
#[async_trait::async_trait]
pub trait ReferenceReader: Send + Sync {
    /// The CR `name` of `kind` in `namespace` (every referenced kind is
    /// namespaced). `Ok(None)`: no such CR, or outside the watch scope.
    async fn referenced(
        &self,
        kind: RefKind,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ReferencedCr>, ClusterError>;
    /// The CRs (`Kind/namespace/name`) bound to `instance`: recorded in
    /// their status, or — not resolved yet — naming it in `instanceRef`, or
    /// naming nothing when `default` (it is the only instance they could
    /// default to).
    async fn instance_dependents(
        &self,
        instance: &BoundInstance,
        default: bool,
    ) -> Result<Vec<String>, ClusterError>;
    /// Labels of `namespace` (a cross-namespace target shared through a
    /// `namespaceSelector`). `Ok(None)`: no such namespace.
    async fn namespace_labels(
        &self,
        namespace: &str,
    ) -> Result<Option<BTreeMap<String, String>>, ClusterError>;
    /// The CRs (`Kind/namespace/name`) of `kind` owning the Forgejo object
    /// `forgejo_name` on the server `instance` points at — whatever their
    /// own instance, as long as it points at the same server.
    async fn claimants(
        &self,
        kind: RefKind,
        forgejo_name: &str,
        instance: &BoundInstance,
    ) -> Result<Vec<String>, ClusterError>;
    /// The `ForgejoAccessToken` CRs (`Kind/namespace/name`) issuing a
    /// token named `token_name` — or its rotated name — for the account
    /// `user` on the server `instance` points at (token names are unique
    /// per user only).
    async fn token_claimants(
        &self,
        user: &str,
        token_name: &str,
        instance: &BoundInstance,
    ) -> Result<Vec<String>, ClusterError>;
    /// One key of a `Secret` in `namespace` that a CR hands to Forgejo as a
    /// credential: only read from a `Secret` labelled
    /// `forgejo.weebo.io/credential: "true"`.
    async fn secret_key(
        &self,
        namespace: &str,
        name: &str,
        key: &str,
    ) -> Result<SecretKey, ClusterError>;
}

/// The `spec.rules` of every `ForgejoNamespacePolicy`, one entry per
/// policy (an existing policy with no rule still switches the cluster to
/// default-deny): the kit's port, as `PolicySource<NamespaceRule>`.
pub use weebo_kit_application::ports::PolicySource;

// ── Debug without secrets ─────────────────────────────────────────────────────

/// `Some("<redacted>")` / `None`: whether a secret is set, never its value.
fn redacted(v: &Option<String>) -> Option<&'static str> {
    v.as_ref().map(|_| "<redacted>")
}

impl std::fmt::Debug for DesiredUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesiredUser")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("full_name", &self.full_name)
            .field("password", &redacted(&self.password))
            .field("must_change_password", &self.must_change_password)
            .field("source_id", &self.source_id)
            .field("login_name", &self.login_name)
            .field("admin", &self.admin)
            .field("restricted", &self.restricted)
            .field("visibility", &self.visibility)
            .field("active", &self.active)
            .field("prohibit_login", &self.prohibit_login)
            .field("allow_create_organization", &self.allow_create_organization)
            .field("max_repo_creation", &self.max_repo_creation)
            .finish()
    }
}

impl std::fmt::Debug for MigrateOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrateOptions")
            .field("clone_addr", &self.clone_addr)
            .field("service", &self.service)
            .field("mirror", &self.mirror)
            .field("mirror_interval", &self.mirror_interval)
            .field("lfs", &self.lfs)
            .field("wiki", &self.wiki)
            .field("issues", &self.issues)
            .field("pull_requests", &self.pull_requests)
            .field("releases", &self.releases)
            .field("labels", &self.labels)
            .field("milestones", &self.milestones)
            .field("auth_username", &self.auth_username)
            .field("auth_password", &redacted(&self.auth_password))
            .field("auth_token", &redacted(&self.auth_token))
            .finish()
    }
}

impl std::fmt::Debug for DesiredHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let config: BTreeMap<&String, &str> = self
            .config
            .iter()
            .map(|(k, v)| {
                (
                    k,
                    if k == "secret" {
                        "<redacted>"
                    } else {
                        v.as_str()
                    },
                )
            })
            .collect();
        f.debug_struct("DesiredHook")
            .field("type_", &self.type_)
            .field("config", &config)
            .field("events", &self.events)
            .field("branch_filter", &self.branch_filter)
            .field("active", &self.active)
            .field(
                "authorization_header",
                &redacted(&self.authorization_header),
            )
            .finish()
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn secrets_never_show_in_debug() {
        let user = DesiredUser {
            password: Some("hunter2".into()),
            ..Default::default()
        };
        let migrate = MigrateOptions {
            auth_password: Some("hunter2".into()),
            auth_token: Some("hunter2".into()),
            ..Default::default()
        };
        let hook = DesiredHook {
            config: BTreeMap::from([("secret".to_string(), "hunter2".to_string())]),
            authorization_header: Some("Bearer hunter2".into()),
            ..Default::default()
        };
        for shown in [
            format!("{user:?}"),
            format!("{migrate:?}"),
            format!("{hook:?}"),
        ] {
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
    }
}
