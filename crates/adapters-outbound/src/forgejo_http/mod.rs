//! `ForgejoGateway` over the generated client, one file per resource. This
//! module owns the client configuration (base path, admin token) and the
//! mapping of generated-client errors onto `GatewayError`.

mod hooks;
mod inventory;
mod keys;
mod oauth2;
mod organizations;
mod repositories;
mod teams;
mod tokens;
mod users;

use application::ports::{
    DesiredHook, DesiredOAuth2App, DesiredOrganization, DesiredRepository, DesiredTeam,
    DesiredToken, DesiredUser, ForgejoGateway, ForgejoInventory, ForgejoRef, GatewayError,
    GenerateOptions, HookTarget, MigrateOptions, ProtectionRule, RemoteHook, RemoteKey,
    RemoteOAuth2App, RemoteOrganization, RemoteRepository, RemoteTeam, RemoteToken, RemoteUser,
    RepositoryInitOptions,
};
use forgejo_client::apis::configuration::{ApiKey, Configuration};
use forgejo_client::apis::{Error, miscellaneous_api};
use serde::de::DeserializeOwned;

pub struct ForgejoHttpGateway {
    config: Configuration,
    /// Same as `config` but for calls that legitimately run long
    /// (`POST /repos/migrate` clones synchronously).
    slow_config: Configuration,
    web_url: String,
}

impl ForgejoHttpGateway {
    /// `api_base_path` must end in `/api/v1` and `web_url` is the instance
    /// root — `api::instance::split_urls` derives both from `spec.url`.
    pub fn new(
        api_base_path: String,
        web_url: String,
        token: String,
        http: reqwest::Client,
    ) -> Self {
        let config = Configuration {
            base_path: api_base_path,
            client: http,
            // Forgejo's `AuthorizationHeaderToken` security definition:
            // `Authorization: token <value>`.
            api_key: Some(ApiKey {
                prefix: Some("token".to_string()),
                key: token,
            }),
            user_agent: Some(concat!("weebo-forgejo-operator/", env!("CARGO_PKG_VERSION")).into()),
            ..Configuration::default()
        };
        Self {
            slow_config: config.clone(),
            config,
            web_url,
        }
    }

    /// Client used for synchronous long-running calls (migrations); by
    /// default the same as the regular one.
    pub fn with_slow_client(mut self, http: reqwest::Client) -> Self {
        self.slow_config.client = http;
        self
    }
}

#[async_trait::async_trait]
impl ForgejoGateway for ForgejoHttpGateway {
    async fn server_version(&self) -> Result<String, GatewayError> {
        let version = miscellaneous_api::get_version(&self.config)
            .await
            .map_err(classify)?;
        Ok(version.version.unwrap_or_default())
    }

    fn web_url(&self) -> &str {
        &self.web_url
    }

    async fn get_user(&self, username: &str) -> Result<Option<RemoteUser>, GatewayError> {
        users::get(&self.config, username).await
    }
    async fn create_user(&self, user: &DesiredUser) -> Result<ForgejoRef, GatewayError> {
        users::create(&self.config, user).await
    }
    async fn edit_user(&self, username: &str, user: &DesiredUser) -> Result<(), GatewayError> {
        users::edit(&self.config, username, user).await
    }
    async fn rename_user(&self, username: &str, new_username: &str) -> Result<(), GatewayError> {
        users::rename(&self.config, username, new_username).await
    }
    async fn delete_user(&self, username: &str) -> Result<(), GatewayError> {
        users::delete(&self.config, username).await
    }

    async fn get_organization(
        &self,
        name: &str,
    ) -> Result<Option<RemoteOrganization>, GatewayError> {
        organizations::get(&self.config, name).await
    }
    async fn create_organization(
        &self,
        owner: Option<&str>,
        org: &DesiredOrganization,
    ) -> Result<ForgejoRef, GatewayError> {
        organizations::create(&self.config, owner, org).await
    }
    async fn edit_organization(
        &self,
        name: &str,
        org: &DesiredOrganization,
    ) -> Result<(), GatewayError> {
        organizations::edit(&self.config, name, org).await
    }
    async fn rename_organization(&self, name: &str, new_name: &str) -> Result<(), GatewayError> {
        organizations::rename(&self.config, name, new_name).await
    }
    async fn delete_organization(&self, name: &str) -> Result<(), GatewayError> {
        organizations::delete(&self.config, name).await
    }

    async fn get_team(&self, id: i64) -> Result<Option<RemoteTeam>, GatewayError> {
        teams::get(&self.config, id).await
    }
    async fn create_team(&self, org: &str, team: &DesiredTeam) -> Result<ForgejoRef, GatewayError> {
        teams::create(&self.config, org, team).await
    }
    async fn edit_team(&self, id: i64, team: &DesiredTeam) -> Result<(), GatewayError> {
        teams::edit(&self.config, id, team).await
    }
    async fn delete_team(&self, id: i64) -> Result<(), GatewayError> {
        teams::delete(&self.config, id).await
    }
    async fn list_team_members(&self, id: i64) -> Result<Vec<String>, GatewayError> {
        teams::list_members(&self.config, id).await
    }
    async fn add_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError> {
        teams::add_member(&self.config, id, username).await
    }
    async fn remove_team_member(&self, id: i64, username: &str) -> Result<(), GatewayError> {
        teams::remove_member(&self.config, id, username).await
    }

    async fn get_repository(&self, id: i64) -> Result<Option<RemoteRepository>, GatewayError> {
        repositories::get(&self.config, id).await
    }
    async fn create_repository(
        &self,
        owner: &str,
        owner_is_org: bool,
        repo: &DesiredRepository,
        init: &RepositoryInitOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        repositories::create(&self.config, owner, owner_is_org, repo, init).await
    }
    async fn generate_repository(
        &self,
        template: &str,
        owner: &str,
        repo: &DesiredRepository,
        options: &GenerateOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        repositories::generate(&self.slow_config, template, owner, repo, options).await
    }
    async fn migrate_repository(
        &self,
        owner: &str,
        repo: &DesiredRepository,
        options: &MigrateOptions,
    ) -> Result<ForgejoRef, GatewayError> {
        repositories::migrate(&self.slow_config, owner, repo, options).await
    }
    async fn edit_repository(
        &self,
        full_name: &str,
        repo: &DesiredRepository,
    ) -> Result<(), GatewayError> {
        repositories::edit(&self.config, full_name, repo).await
    }
    async fn set_repository_archived(
        &self,
        full_name: &str,
        archived: bool,
    ) -> Result<(), GatewayError> {
        repositories::set_archived(&self.config, full_name, archived).await
    }
    async fn transfer_repository(
        &self,
        full_name: &str,
        new_owner: &str,
    ) -> Result<(), GatewayError> {
        repositories::transfer(&self.config, full_name, new_owner).await
    }
    async fn delete_repository(&self, full_name: &str) -> Result<(), GatewayError> {
        repositories::delete(&self.config, full_name).await
    }
    async fn list_branch_protections(
        &self,
        full_name: &str,
    ) -> Result<Vec<ProtectionRule>, GatewayError> {
        repositories::list_protections(&self.config, full_name).await
    }
    async fn create_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError> {
        repositories::create_protection(&self.config, full_name, rule).await
    }
    async fn edit_branch_protection(
        &self,
        full_name: &str,
        rule: &ProtectionRule,
    ) -> Result<(), GatewayError> {
        repositories::edit_protection(&self.config, full_name, rule).await
    }
    async fn delete_branch_protection(
        &self,
        full_name: &str,
        rule_name: &str,
    ) -> Result<(), GatewayError> {
        repositories::delete_protection(&self.config, full_name, rule_name).await
    }
    async fn list_repository_teams(
        &self,
        full_name: &str,
    ) -> Result<Vec<RemoteTeam>, GatewayError> {
        repositories::list_teams(&self.config, full_name).await
    }
    async fn add_repository_team(&self, full_name: &str, team: &str) -> Result<(), GatewayError> {
        repositories::add_team(&self.config, full_name, team).await
    }
    async fn remove_repository_team(
        &self,
        full_name: &str,
        team: &str,
    ) -> Result<(), GatewayError> {
        repositories::remove_team(&self.config, full_name, team).await
    }

    async fn get_hook(
        &self,
        target: &HookTarget,
        id: i64,
    ) -> Result<Option<RemoteHook>, GatewayError> {
        hooks::get(&self.config, target, id).await
    }
    async fn create_hook(
        &self,
        target: &HookTarget,
        hook: &DesiredHook,
    ) -> Result<ForgejoRef, GatewayError> {
        hooks::create(&self.config, target, hook).await
    }
    async fn edit_hook(
        &self,
        target: &HookTarget,
        id: i64,
        hook: &DesiredHook,
    ) -> Result<(), GatewayError> {
        hooks::edit(&self.config, target, id, hook).await
    }
    async fn delete_hook(&self, target: &HookTarget, id: i64) -> Result<(), GatewayError> {
        hooks::delete(&self.config, target, id).await
    }

    async fn get_deploy_key(
        &self,
        full_name: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError> {
        keys::get_deploy(&self.config, full_name, id).await
    }
    async fn create_deploy_key(
        &self,
        full_name: &str,
        title: &str,
        key: &str,
        read_only: bool,
    ) -> Result<ForgejoRef, GatewayError> {
        keys::create_deploy(&self.config, full_name, title, key, read_only).await
    }
    async fn delete_deploy_key(&self, full_name: &str, id: i64) -> Result<(), GatewayError> {
        keys::delete_deploy(&self.config, full_name, id).await
    }
    async fn get_user_key(
        &self,
        username: &str,
        id: i64,
    ) -> Result<Option<RemoteKey>, GatewayError> {
        keys::get_user(&self.config, username, id).await
    }
    async fn create_user_key(
        &self,
        username: &str,
        title: &str,
        key: &str,
    ) -> Result<ForgejoRef, GatewayError> {
        keys::create_user(&self.config, username, title, key).await
    }
    async fn delete_user_key(&self, username: &str, id: i64) -> Result<(), GatewayError> {
        keys::delete_user(&self.config, username, id).await
    }

    async fn get_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
    ) -> Result<Option<RemoteOAuth2App>, GatewayError> {
        oauth2::get(&self.config, sudo, id).await
    }
    async fn create_oauth2_app(
        &self,
        sudo: Option<&str>,
        app: &DesiredOAuth2App,
    ) -> Result<(RemoteOAuth2App, String), GatewayError> {
        oauth2::create(&self.config, sudo, app).await
    }
    async fn update_oauth2_app(
        &self,
        sudo: Option<&str>,
        id: i64,
        app: &DesiredOAuth2App,
    ) -> Result<String, GatewayError> {
        oauth2::update(&self.config, sudo, id, app).await
    }
    async fn delete_oauth2_app(&self, sudo: Option<&str>, id: i64) -> Result<(), GatewayError> {
        oauth2::delete(&self.config, sudo, id).await
    }

    async fn list_access_tokens(&self, username: &str) -> Result<Vec<RemoteToken>, GatewayError> {
        tokens::list(&self.config, username).await
    }
    async fn create_access_token(
        &self,
        username: &str,
        token: &DesiredToken,
    ) -> Result<(ForgejoRef, String), GatewayError> {
        tokens::create(&self.config, username, token).await
    }
    async fn delete_access_token(&self, username: &str, id: i64) -> Result<(), GatewayError> {
        tokens::delete(&self.config, username, id).await
    }
}

#[async_trait::async_trait]
impl ForgejoInventory for ForgejoHttpGateway {
    async fn list_users(&self) -> Result<Vec<RemoteUser>, GatewayError> {
        inventory::list_users(&self.config).await
    }
    async fn list_organizations(&self) -> Result<Vec<RemoteOrganization>, GatewayError> {
        inventory::list_organizations(&self.config).await
    }
    async fn list_teams(&self, org: &str) -> Result<Vec<RemoteTeam>, GatewayError> {
        inventory::list_teams(&self.config, org).await
    }
    async fn list_repositories(
        &self,
        owner: &str,
        owner_is_org: bool,
    ) -> Result<Vec<RemoteRepository>, GatewayError> {
        inventory::list_repositories(&self.config, owner, owner_is_org).await
    }
    async fn list_hooks(&self, target: &HookTarget) -> Result<Vec<RemoteHook>, GatewayError> {
        inventory::list_hooks(&self.config, target).await
    }
    async fn list_deploy_keys(&self, full_name: &str) -> Result<Vec<RemoteKey>, GatewayError> {
        inventory::list_deploy_keys(&self.config, full_name).await
    }
}

/// Maps a generated-client error onto the port's error classes.
///
/// A name collision is 409 for some resources, 422 for others (users,
/// organizations, teams) and 400 for access tokens ("has been used
/// already") — but 400/422 are also Forgejo's generic validation errors, so
/// they only count as "already exists" when the message says so.
pub(crate) fn classify<T: std::fmt::Debug>(err: Error<T>) -> GatewayError {
    match err {
        Error::ResponseError(resp) => {
            let body = resp.content;
            match resp.status.as_u16() {
                409 => GatewayError::AlreadyExists(body),
                400 | 422 if body.contains("already") || body.contains("is already taken") => {
                    GatewayError::AlreadyExists(body)
                }
                404 => GatewayError::NotFound(body),
                s if s >= 500 => GatewayError::Unreachable(format!("{s}: {body}")),
                s => GatewayError::Api(format!("{s}: {body}")),
            }
        }
        Error::Reqwest(e) => GatewayError::Unreachable(e.to_string()),
        other => GatewayError::Api(other.to_string()),
    }
}

/// `Ok(None)` for a 404, so lookups read as "absent" rather than failures.
pub(crate) fn found<T, E: std::fmt::Debug>(
    result: Result<T, Error<E>>,
) -> Result<Option<T>, GatewayError> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(e) => match classify(e) {
            GatewayError::NotFound(_) => Ok(None),
            other => Err(other),
        },
    }
}

/// Converts one of our lowercase wire strings into a generated enum (each
/// options struct generates its own `Visibility`/`Permission` type).
pub(crate) fn wire_enum<T: DeserializeOwned>(value: &str) -> Result<T, GatewayError> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|e| GatewayError::Api(format!("unsupported value {value:?}: {e}")))
}

/// The inverse of [`wire_enum`], for reading generated enums back.
pub(crate) fn wire_string<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

pub(crate) fn missing_id(what: &str) -> GatewayError {
    GatewayError::Api(format!("Forgejo returned a {what} without an id"))
}
