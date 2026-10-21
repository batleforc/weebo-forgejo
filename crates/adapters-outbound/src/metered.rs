//! [`MeteredGateway`]: any [`ForgejoGateway`], with every Forgejo call
//! counted and timed (`weebo_forgejo_forgejo_requests_total{operation,
//! result}`, `weebo_forgejo_forgejo_request_duration_seconds{operation}`)
//! and bounded per instance: at most `WEEBO_FORGEJO_MAX_INFLIGHT` (default
//! [`DEFAULT_MAX_INFLIGHT`]) calls run at once against one Forgejo, however
//! many reconciles do — a startup sweep never floods it.

use std::future::Future;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use application::ports::{
    DesiredHook, DesiredOAuth2App, DesiredOrganization, DesiredRepository, DesiredTeam,
    DesiredToken, DesiredUser, ForgejoGateway, ForgejoRef, GatewayError, GenerateOptions,
    HookPatch, HookTarget, MigrateOptions, OrganizationPatch, ProtectionRule, RemoteHook,
    RemoteKey, RemoteOAuth2App, RemoteOrganization, RemoteRepository, RemoteTeam, RemoteToken,
    RemoteUser, RepositoryInitOptions, RepositoryPatch, TeamPatch, UserPatch,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};
use tokio::sync::Semaphore;

/// Default of `WEEBO_FORGEJO_MAX_INFLIGHT`.
pub const DEFAULT_MAX_INFLIGHT: usize = 8;

pub fn max_inflight() -> usize {
    let Ok(raw) = std::env::var("WEEBO_FORGEJO_MAX_INFLIGHT") else {
        return DEFAULT_MAX_INFLIGHT;
    };
    match raw.parse() {
        Ok(n) if n > 0 => n,
        _ => {
            tracing::warn!(
                value = %raw,
                default = DEFAULT_MAX_INFLIGHT,
                "WEEBO_FORGEJO_MAX_INFLIGHT is not a positive integer, using the default"
            );
            DEFAULT_MAX_INFLIGHT
        }
    }
}

struct Instruments {
    requests: Counter<u64>,
    duration: Histogram<f64>,
}

static INSTRUMENTS: LazyLock<Instruments> = LazyLock::new(|| {
    let meter = opentelemetry::global::meter("weebo-forgejo-operator");
    Instruments {
        requests: meter
            // The Prometheus exporter appends `_total` to counters and the
            // unit (`_seconds`) to histograms: the names leave them out.
            .u64_counter("weebo_forgejo_forgejo_requests")
            .with_description("Forgejo API calls, by gateway operation and result")
            .build(),
        duration: meter
            .f64_histogram("weebo_forgejo_forgejo_request_duration")
            .with_description("Forgejo API call duration, by gateway operation")
            .with_unit("s")
            .build(),
    }
});

/// The `result` label: bounded, unlike HTTP bodies.
fn result_of<T>(result: &Result<T, GatewayError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(GatewayError::NotFound(_)) => "not_found",
        Err(GatewayError::AlreadyExists(_)) => "already_exists",
        Err(GatewayError::Unreachable(_)) => "unreachable",
        Err(GatewayError::Api(_)) => "error",
    }
}

pub struct MeteredGateway {
    inner: Arc<dyn ForgejoGateway>,
    /// Shared by every gateway of the same instance.
    permits: Arc<Semaphore>,
}

impl MeteredGateway {
    pub fn new(inner: Arc<dyn ForgejoGateway>, permits: Arc<Semaphore>) -> Self {
        Self { inner, permits }
    }

    async fn metered<T>(
        &self,
        operation: &'static str,
        call: impl Future<Output = Result<T, GatewayError>>,
    ) -> Result<T, GatewayError> {
        // Never closed: a failed acquire can't happen, but must not panic.
        let _permit = self.permits.acquire().await.ok();
        let started = Instant::now();
        let result = call.await;
        let i = &*INSTRUMENTS;
        let op = KeyValue::new("operation", operation);
        i.requests.add(
            1,
            &[op.clone(), KeyValue::new("result", result_of(&result))],
        );
        i.duration.record(started.elapsed().as_secs_f64(), &[op]);
        result
    }
}

#[async_trait::async_trait]
impl ForgejoGateway for MeteredGateway {
    fn web_url(&self) -> &str {
        self.inner.web_url()
    }

    async fn server_version(&self) -> Result<String, GatewayError> {
        self.metered("server_version", self.inner.server_version())
            .await
    }

    async fn token_user(&self) -> Result<RemoteUser, GatewayError> {
        self.metered("token_user", self.inner.token_user()).await
    }

    async fn get_user(&self, username: &str) -> Result<Option<RemoteUser>, GatewayError> {
        self.metered("get_user", self.inner.get_user(username))
            .await
    }

    async fn user_login(&self, id: i64) -> Result<Option<String>, GatewayError> {
        self.metered("user_login", self.inner.user_login(id)).await
    }

    async fn create_user(&self, user: &DesiredUser) -> Result<ForgejoRef, GatewayError> {
        self.metered("create_user", self.inner.create_user(user))
            .await
    }

    async fn edit_user(&self, username: &str, user: &UserPatch) -> Result<(), GatewayError> {
        self.metered("edit_user", self.inner.edit_user(username, user))
            .await
    }

    async fn rename_user(&self, username: &str, new_username: &str) -> Result<(), GatewayError> {
        self.metered(
            "rename_user",
            self.inner.rename_user(username, new_username),
        )
        .await
    }

    async fn delete_user(&self, username: &str) -> Result<(), GatewayError> {
        self.metered("delete_user", self.inner.delete_user(username))
            .await
    }

    async fn get_organization(
        &self,
        name: &str,
    ) -> Result<Option<RemoteOrganization>, GatewayError> {
        self.metered("get_organization", self.inner.get_organization(name))
            .await
    }

    async fn create_organization(
        &self,
        owner: Option<&str>,
        org: &DesiredOrganization,
    ) -> Result<ForgejoRef, GatewayError> {
        self.metered(
            "create_organization",
            self.inner.create_organization(owner, org),
        )
        .await
    }

    async fn edit_organization(
        &self,
        name: &str,
        org: &OrganizationPatch,
    ) -> Result<(), GatewayError> {
        self.metered("edit_organization", self.inner.edit_organization(name, org))
            .await
    }

    async fn organization_name(&self, id: i64) -> Result<Option<String>, GatewayError> {
        self.metered("organization_name", self.inner.organization_name(id))
            .await
    }

    async fn rename_organization(&self, name: &str, new_name: &str) -> Result<(), GatewayError> {
        self.metered(
            "rename_organization",
            self.inner.rename_organization(name, new_name),
        )
        .await
    }

    async fn delete_organization(&self, name: &str) -> Result<(), GatewayError> {
        self.metered("delete_organization", self.inner.delete_organization(name))
            .await
    }

    async fn get_team(&self, id: i64) -> Result<Option<RemoteTeam>, GatewayError> {
        self.metered("get_team", self.inner.get_team(id)).await
    }

    async fn create_team(&self, org: &str, team: &DesiredTeam) -> Result<ForgejoRef, GatewayError> {
        self.metered("create_team", self.inner.create_team(org, team))
            .await
    }

    async fn edit_team(&self, id: i64, team: &TeamPatch) -> Result<(), GatewayError> {
        self.metered("edit_team", self.inner.edit_team(id, team))
            .await
    }

    async fn delete_team(&self, id: i64) -> Result<(), GatewayError> {
        self.metered("delete_team", self.inner.delete_team(id))
            .await
    }

    async fn list_team_members(&self, id: i64) -> Result<Vec<String>, GatewayError> {
        self.metered("list_team_members", self.inner.list_team_members(id))
            .await
    }

    async fn add_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError> {
        self.metered("add_team_member", self.inner.add_team_member(id, username))
            .await
    }

    async fn remove_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError> {
        self.metered(
            "remove_team_member",
            self.inner.remove_team_member(id, username),
        )
        .await
    }

    async fn get_repository(&self, id: i64) -> Result<Option<RemoteRepository>, GatewayError> {
        self.metered("get_repository", self.inner.get_repository(id))
            .await
    }

    async fn create_repository(
        &self,
        owner: &str,
        owner_is_org: bool,
        repo: &DesiredRepository,
        init: &RepositoryInitOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        self.metered(
            "create_repository",
            self.inner
                .create_repository(owner, owner_is_org, repo, init),
        )
        .await
    }

    async fn generate_repository(
        &self,
        template: &str,
        owner: &str,
        repo: &DesiredRepository,
        options: &GenerateOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        self.metered(
            "generate_repository",
            self.inner
                .generate_repository(template, owner, repo, options),
        )
        .await
    }

    async fn migrate_repository(
        &self,
        owner: &str,
        repo: &DesiredRepository,
        options: &MigrateOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        self.metered(
            "migrate_repository",
            self.inner.migrate_repository(owner, repo, options),
        )
        .await
    }

    async fn edit_repository(
        &self,
        full_name: &str,
        repo: &RepositoryPatch,
    ) -> Result<(), GatewayError> {
        self.metered(
            "edit_repository",
            self.inner.edit_repository(full_name, repo),
        )
        .await
    }

    async fn set_repository_archived(
        &self,
        full_name: &str,
        archived: bool,
    ) -> Result<(), GatewayError> {
        self.metered(
            "set_repository_archived",
            self.inner.set_repository_archived(full_name, archived),
        )
        .await
    }

    async fn transfer_repository(
        &self,
        full_name: &str,
        new_owner: &str,
    ) -> Result<(), GatewayError> {
        self.metered(
            "transfer_repository",
            self.inner.transfer_repository(full_name, new_owner),
        )
        .await
    }

    async fn delete_repository(&self, full_name: &str) -> Result<(), GatewayError> {
        self.metered("delete_repository", self.inner.delete_repository(full_name))
            .await
    }

    async fn list_branch_protections(
        &self,
        full_name: &str,
    ) -> Result<Vec<ProtectionRule>, GatewayError> {
        self.metered(
            "list_branch_protections",
            self.inner.list_branch_protections(full_name),
        )
        .await
    }

    async fn create_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError> {
        self.metered(
            "create_branch_protection",
            self.inner.create_branch_protection(full_name, rule),
        )
        .await
    }

    async fn edit_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError> {
        self.metered(
            "edit_branch_protection",
            self.inner.edit_branch_protection(full_name, rule),
        )
        .await
    }

    async fn delete_branch_protection(
        &self,
        full_name: &str,
        rule_name: &str,
    ) -> Result<(), GatewayError> {
        self.metered(
            "delete_branch_protection",
            self.inner.delete_branch_protection(full_name, rule_name),
        )
        .await
    }

    async fn list_repository_teams(
        &self,
        full_name: &str,
    ) -> Result<Vec<RemoteTeam>, GatewayError> {
        self.metered(
            "list_repository_teams",
            self.inner.list_repository_teams(full_name),
        )
        .await
    }

    async fn add_repository_team(&self, full_name: &str, team: &str) -> Result<(), GatewayError> {
        self.metered(
            "add_repository_team",
            self.inner.add_repository_team(full_name, team),
        )
        .await
    }

    async fn remove_repository_team(
        &self,
        full_name: &str,
        team: &str,
    ) -> Result<(), GatewayError> {
        self.metered(
            "remove_repository_team",
            self.inner.remove_repository_team(full_name, team),
        )
        .await
    }

    async fn get_hook(
        &self,
        target: &HookTarget,
        id: i64,
    ) -> Result<Option<RemoteHook>, GatewayError> {
        self.metered("get_hook", self.inner.get_hook(target, id))
            .await
    }

    async fn create_hook(
        &self,
        target: &HookTarget,
        hook: &DesiredHook,
    ) -> Result<ForgejoRef, GatewayError> {
        self.metered("create_hook", self.inner.create_hook(target, hook))
            .await
    }

    async fn edit_hook(
        &self,
        target: &HookTarget,
        id: i64,
        hook: &HookPatch,
    ) -> Result<(), GatewayError> {
        self.metered("edit_hook", self.inner.edit_hook(target, id, hook))
            .await
    }

    async fn delete_hook(&self, target: &HookTarget, id: i64) -> Result<(), GatewayError> {
        self.metered("delete_hook", self.inner.delete_hook(target, id))
            .await
    }

    async fn list_hooks(&self, target: &HookTarget) -> Result<Vec<RemoteHook>, GatewayError> {
        self.metered("list_hooks", self.inner.list_hooks(target))
            .await
    }

    async fn get_deploy_key(
        &self,
        full_name: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError> {
        self.metered("get_deploy_key", self.inner.get_deploy_key(full_name, id))
            .await
    }

    async fn create_deploy_key(
        &self,
        full_name: &str,
        title: &str,
        key: &str,
        read_only: bool,
    ) -> Result<ForgejoRef, GatewayError> {
        self.metered(
            "create_deploy_key",
            self.inner
                .create_deploy_key(full_name, title, key, read_only),
        )
        .await
    }

    async fn delete_deploy_key(&self, full_name: &str, id: i64) -> Result<(), GatewayError> {
        self.metered(
            "delete_deploy_key",
            self.inner.delete_deploy_key(full_name, id),
        )
        .await
    }

    async fn get_user_key(
        &self,
        username: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError> {
        self.metered("get_user_key", self.inner.get_user_key(username, id))
            .await
    }

    async fn create_user_key(
        &self,
        username: &str,
        title: &str,
        key: &str,
    ) -> Result<ForgejoRef, GatewayError> {
        self.metered(
            "create_user_key",
            self.inner.create_user_key(username, title, key),
        )
        .await
    }

    async fn delete_user_key(&self, username: &str, id: i64) -> Result<(), GatewayError> {
        self.metered("delete_user_key", self.inner.delete_user_key(username, id))
            .await
    }

    async fn get_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
    ) -> Result<Option<RemoteOAuth2App>, GatewayError> {
        self.metered("get_oauth2_app", self.inner.get_oauth2_app(sudo, id))
            .await
    }

    async fn create_oauth2_app(
        &self,
        sudo: Option<&str>,
        app: &DesiredOAuth2App,
    ) -> Result<(RemoteOAuth2App, String), GatewayError> {
        self.metered("create_oauth2_app", self.inner.create_oauth2_app(sudo, app))
            .await
    }

    async fn update_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
        app: &DesiredOAuth2App,
    ) -> Result<String, GatewayError> {
        self.metered(
            "update_oauth2_app",
            self.inner.update_oauth2_app(sudo, id, app),
        )
        .await
    }

    async fn delete_oauth2_app(&self, sudo: Option<&str>, id: i64) -> Result<(), GatewayError> {
        self.metered("delete_oauth2_app", self.inner.delete_oauth2_app(sudo, id))
            .await
    }

    async fn list_oauth2_apps(
        &self,
        sudo: Option<&str>,
    ) -> Result<Vec<RemoteOAuth2App>, GatewayError> {
        self.metered("list_oauth2_apps", self.inner.list_oauth2_apps(sudo))
            .await
    }

    async fn list_access_tokens(&self, username: &str) -> Result<Vec<RemoteToken>, GatewayError> {
        self.metered(
            "list_access_tokens",
            self.inner.list_access_tokens(username),
        )
        .await
    }

    async fn create_access_token(
        &self,
        username: &str,
        token: &DesiredToken,
    ) -> Result<(ForgejoRef, String), GatewayError> {
        self.metered(
            "create_access_token",
            self.inner.create_access_token(username, token),
        )
        .await
    }

    async fn delete_access_token(&self, username: &str, id: i64) -> Result<(), GatewayError> {
        self.metered(
            "delete_access_token",
            self.inner.delete_access_token(username, id),
        )
        .await
    }
}
