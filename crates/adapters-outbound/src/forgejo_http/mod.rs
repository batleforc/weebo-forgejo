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
use forgejo_client::models;
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
    async fn user_login(&self, id: i64) -> Result<Option<String>, GatewayError> {
        users::login_by_id(&self.config, id).await
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
    async fn organization_name(&self, id: i64) -> Result<Option<String>, GatewayError> {
        Ok(inventory::list_organizations(&self.config)
            .await?
            .into_iter()
            .find(|o| o.id == id)
            .map(|o| o.name))
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
    async fn list_oauth2_apps(
        &self,
        sudo: Option<&str>,
    ) -> Result<Vec<RemoteOAuth2App>, GatewayError> {
        oauth2::list(&self.config, sudo).await
    }
    async fn list_hooks(&self, target: &HookTarget) -> Result<Vec<RemoteHook>, GatewayError> {
        inventory::list_hooks(&self.config, target).await
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
    async fn list_deploy_keys(&self, full_name: &str) -> Result<Vec<RemoteKey>, GatewayError> {
        inventory::list_deploy_keys(&self.config, full_name).await
    }
}

/// Maps a generated-client error onto the port's error classes. 408/429
/// (timeout, rate limit) are transient, like a 5xx.
pub(crate) fn classify<T: std::fmt::Debug>(err: Error<T>) -> GatewayError {
    classify_as(err, false)
}

/// [`classify`] for calls that claim a name (create, rename, transfer).
///
/// A name collision is 409 for some resources, 422 for others (users,
/// organizations, teams) and 400 for access tokens ("has been used
/// already") — but 400/422 are also Forgejo's generic validation errors, so
/// they only count as "already exists" when the message says so, and only
/// on these calls: on an edit, "e-mail already in use" is no name collision.
pub(crate) fn classify_create<T: std::fmt::Debug>(err: Error<T>) -> GatewayError {
    classify_as(err, true)
}

fn classify_as<T: std::fmt::Debug>(err: Error<T>, claims_name: bool) -> GatewayError {
    match err {
        Error::ResponseError(resp) => {
            let raw = resp.content;
            let refused = token_refused(&raw);
            let collision = raw.contains("already");
            // What reaches a CR's status: never a whole proxy error page
            // (which may also differ on every response and defeat the
            // status' change detection).
            let body = summarize(&raw);
            match resp.status.as_u16() {
                409 => GatewayError::AlreadyExists(body),
                400 | 422 if claims_name && collision => GatewayError::AlreadyExists(body),
                404 => GatewayError::NotFound(body),
                s @ (408 | 429) => GatewayError::Unreachable(format!("{s}: {body}")),
                s if s >= 500 => GatewayError::Unreachable(format!("{s}: {body}")),
                s @ (401 | 403) if s == 401 || refused => GatewayError::Api(format!(
                    "{s}: the instance's admin token was refused (revoked, or missing a scope): {body}"
                )),
                // The token is fine, the object isn't its to touch (e.g. a
                // key that belongs to another repository or user).
                403 => {
                    GatewayError::Api(format!("403: Forgejo refused access to the object: {body}"))
                }
                s => GatewayError::Api(format!("{s}: {body}")),
            }
        }
        Error::Reqwest(e) => GatewayError::Unreachable(e.to_string()),
        other => GatewayError::Api(other.to_string()),
    }
}

/// Longest error detail kept from a Forgejo response.
const MAX_DETAIL: usize = 256;

/// The `message` of a Forgejo JSON error, else the body itself — unless it
/// is markup (a proxy's error page) — cut to [`MAX_DETAIL`] characters.
fn summarize(body: &str) -> String {
    let detail = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => match v.get("message").and_then(|m| m.as_str()) {
            Some(m) => m.to_string(),
            None => body.to_string(),
        },
        Err(_) if body.trim_start().starts_with('<') => {
            format!("non-JSON response ({} bytes)", body.len())
        }
        Err(_) => body.to_string(),
    };
    let detail = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    match detail.char_indices().nth(MAX_DETAIL) {
        Some((cut, _)) => format!("{}…", &detail[..cut]),
        None => detail,
    }
}

/// Whether a 403 is about the token itself — a missing scope, or an
/// account that isn't site admin — rather than about the object.
fn token_refused(body: &str) -> bool {
    body.contains("required scope") || body.contains("site admin")
}

/// Requested page size (Forgejo's `MAX_RESPONSE_ITEMS` default).
pub(crate) const PAGE_SIZE: i32 = 50;

/// Hard stop on a listing that never ends, counted in items rather than
/// pages: Forgejo clamps `limit` to its `MAX_RESPONSE_ITEMS`, so a page
/// count would shrink with that setting. Every page handed on holds at
/// least one item, so this bounds the requests too.
const MAX_ITEMS: usize = 50_000;

/// What a listed item is told apart by: its Forgejo id.
pub(crate) trait Listed {
    fn list_id(&self) -> Option<i64>;
}

macro_rules! listed_by_id {
    ($($t:ty),* $(,)?) => {$(
        impl Listed for $t {
            fn list_id(&self) -> Option<i64> {
                self.id
            }
        }
    )*};
}

listed_by_id!(
    models::AccessToken,
    models::DeployKey,
    models::Hook,
    models::OAuth2Application,
    models::Organization,
    models::PublicKey,
    models::Repository,
    models::Team,
    models::User,
);

/// Fetches pages until one comes back empty. A short page is no proof it
/// was the last one: Forgejo silently clamps `limit` to its `[api]
/// MAX_RESPONSE_ITEMS`, and some listings filter (visibility,
/// permissions) after paginating.
pub(crate) async fn all_pages<T, F, Fut>(fetch: F) -> Result<Vec<T>, GatewayError>
where
    T: Listed,
    F: FnMut(i32) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<T>, GatewayError>>,
{
    let mut out = Vec::new();
    each_page(fetch, |batch| {
        out.extend(batch);
        false
    })
    .await?;
    Ok(out)
}

/// Like [`all_pages`], but stops at the first item matching `pred`.
pub(crate) async fn find_in_pages<T, F, Fut>(
    fetch: F,
    mut pred: impl FnMut(&T) -> bool,
) -> Result<Option<T>, GatewayError>
where
    T: Listed,
    F: FnMut(i32) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<T>, GatewayError>>,
{
    let mut hit = None;
    each_page(fetch, |batch| {
        hit = batch.into_iter().find(&mut pred);
        hit.is_some()
    })
    .await?;
    Ok(hit)
}

/// Hands each page to `visit` until it returns `true` or a page comes
/// back empty. A page holding the same ids as the one before means the
/// endpoint ignored `page` (it returned everything already): that's the
/// end too. Ids, not whole items: a field like `updated` may change
/// between two requests.
async fn each_page<T, F, Fut>(
    mut fetch: F,
    mut visit: impl FnMut(Vec<T>) -> bool,
) -> Result<(), GatewayError>
where
    T: Listed,
    F: FnMut(i32) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<T>, GatewayError>>,
{
    let mut previous: Vec<Option<i64>> = Vec::new();
    let mut seen = 0usize;
    for page in 1.. {
        let batch = fetch(page).await?;
        if batch.is_empty() {
            return Ok(());
        }
        let ids: Vec<Option<i64>> = batch.iter().map(Listed::list_id).collect();
        if ids == previous {
            return Ok(());
        }
        seen += batch.len();
        if seen > MAX_ITEMS {
            break;
        }
        if visit(batch) {
            return Ok(());
        }
        previous = ids;
    }
    Err(GatewayError::Api(format!(
        "listing still not exhausted after {MAX_ITEMS} items"
    )))
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

#[cfg(test)]
mod paging_tests {
    use std::sync::Mutex;

    use super::*;

    impl Listed for i32 {
        fn list_id(&self) -> Option<i64> {
            Some(i64::from(*self))
        }
    }

    /// An item whose id is stable but whose other fields change between
    /// requests.
    #[derive(Debug)]
    struct Stamped {
        id: i64,
        updated: i32,
    }

    impl Listed for Stamped {
        fn list_id(&self) -> Option<i64> {
            Some(self.id)
        }
    }

    /// A listing of `total` items served `clamp` at a time.
    async fn served(
        total: i32,
        clamp: i32,
        ignore_page: bool,
    ) -> (Result<Vec<i32>, GatewayError>, i32) {
        let calls = Mutex::new(0);
        let result = all_pages(|page| {
            *calls.lock().unwrap() += 1;
            let page = if ignore_page { 1 } else { page };
            let start = (page - 1) * clamp;
            async move { Ok((start..(start + clamp).min(total)).collect()) }
        })
        .await;
        (result, calls.into_inner().unwrap())
    }

    #[tokio::test]
    async fn every_page_until_an_empty_one() {
        let (items, calls) = served(120, 50, false).await;
        assert_eq!(items.unwrap().len(), 120);
        assert_eq!(calls, 4);
    }

    #[tokio::test]
    async fn short_first_page_is_not_trusted() {
        // Clamped to 20 by the server: page 1 is short of PAGE_SIZE but
        // not the end.
        let (items, _) = served(45, 20, false).await;
        assert_eq!(items.unwrap(), (0..45).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn short_page_mid_listing_is_not_the_end() {
        // Page 2 filtered down after pagination, page 3 still full.
        let pages = [vec![1, 2, 3], vec![4], vec![5, 6, 7], vec![]];
        let items = all_pages(|page| {
            let batch = pages[page as usize - 1].clone();
            async move { Ok(batch) }
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[tokio::test]
    async fn endpoint_ignoring_page_terminates() {
        let (items, calls) = served(30, 50, true).await;
        assert_eq!(items.unwrap().len(), 30);
        assert_eq!(calls, 2);
    }

    #[tokio::test]
    async fn endpoint_ignoring_page_terminates_on_ids_alone() {
        // Two pages of the same ids, served by an endpoint ignoring
        // `page`: stops at the repeat even though nothing compares equal
        // beyond the id.
        let items = all_pages(|page| async move {
            Ok(vec![
                Stamped {
                    id: 1,
                    updated: page,
                },
                Stamped {
                    id: 2,
                    updated: page,
                },
            ])
        })
        .await
        .unwrap();
        assert_eq!(
            items.iter().map(|s| (s.id, s.updated)).collect::<Vec<_>>(),
            [(1, 1), (2, 1)]
        );
    }

    #[tokio::test]
    async fn cap_counts_items_not_pages() {
        // Clamped to 10 per page: 1 000 pages aren't the end of the cap.
        let (items, _) = served(20_000, 10, false).await;
        assert_eq!(items.unwrap().len(), 20_000);
        let (items, calls) = served(i32::MAX, 10_000, false).await;
        assert!(items.is_err());
        assert_eq!(calls, 6);
    }

    #[tokio::test]
    async fn find_stops_at_the_hit() {
        let calls = Mutex::new(0);
        let hit = find_in_pages(
            |page| {
                *calls.lock().unwrap() += 1;
                let start = (page - 1) * 50;
                async move { Ok((start..start + 50).collect::<Vec<i32>>()) }
            },
            |i| *i == 60,
        )
        .await
        .unwrap();
        assert_eq!(hit, Some(60));
        assert_eq!(calls.into_inner().unwrap(), 2);
    }
}

#[cfg(test)]
mod summarize_tests {
    use super::*;

    #[test]
    fn json_errors_keep_their_message() {
        assert_eq!(
            summarize(
                r#"{"message":"user does not exist [uid: 0, name: x]","url":"https://f/api/swagger"}"#
            ),
            "user does not exist [uid: 0, name: x]"
        );
    }

    #[test]
    fn markup_and_long_bodies_are_cut() {
        let page = "<html><body>502 Bad Gateway, request id 1234</body></html>";
        assert_eq!(
            summarize(page),
            format!("non-JSON response ({} bytes)", page.len())
        );
        let long = "é".repeat(1000);
        let cut = summarize(&long);
        assert_eq!(cut.chars().count(), MAX_DETAIL + 1);
        assert!(cut.ends_with('…'));
    }
}
