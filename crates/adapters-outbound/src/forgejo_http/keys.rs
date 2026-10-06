use application::ports::{ForgejoRef, GatewayError, RemoteKey};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::{admin_api, repository_api, user_api};
use forgejo_client::models;

use super::{classify, found, missing_id};

pub(super) fn split(full_name: &str) -> Result<(String, String), GatewayError> {
    full_name
        .split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .ok_or_else(|| GatewayError::Api(format!("{full_name:?} is not owner/name")))
}

/// Forgejo's maximum page size (`MAX_RESPONSE_ITEMS` default).
const PAGE_SIZE: i32 = 50;

pub(super) async fn get_deploy(
    config: &Configuration,
    full_name: &str,
    id: i64,
) -> Result<Option<RemoteKey>, GatewayError> {
    let (owner, repo) = split(full_name)?;
    let params = repository_api::RepoGetKeyParams { owner, repo, id };
    Ok(
        found(repository_api::repo_get_key(config, params).await)?.map(|k| RemoteKey {
            id: k.id.unwrap_or(id),
            ..deploy_remote(k)
        }),
    )
}

pub(super) fn deploy_remote(k: models::DeployKey) -> RemoteKey {
    RemoteKey {
        id: k.id.unwrap_or_default(),
        title: k.title.unwrap_or_default(),
        key: k.key.unwrap_or_default(),
        read_only: k.read_only.unwrap_or_default(),
    }
}

pub(super) async fn create_deploy(
    config: &Configuration,
    full_name: &str,
    title: &str,
    key: &str,
    read_only: bool,
) -> Result<ForgejoRef, GatewayError> {
    let (owner, repo) = split(full_name)?;
    let body = models::CreateKeyOption {
        read_only: Some(read_only),
        ..models::CreateKeyOption::new(key.to_string(), title.to_string())
    };
    let params = repository_api::RepoCreateKeyParams {
        owner,
        repo,
        body: Some(body),
    };
    let created = repository_api::repo_create_key(config, params)
        .await
        .map_err(classify)?;
    Ok(ForgejoRef {
        id: created.id.ok_or_else(|| missing_id("deploy key"))?,
        name: title.to_string(),
    })
}

pub(super) async fn delete_deploy(
    config: &Configuration,
    full_name: &str,
    id: i64,
) -> Result<(), GatewayError> {
    let (owner, repo) = split(full_name)?;
    let params = repository_api::RepoDeleteKeyParams { owner, repo, id };
    repository_api::repo_delete_key(config, params)
        .await
        .map_err(classify)
}

/// There is no admin "get key by id": the user's public key list is
/// scanned instead.
pub(super) async fn get_user(
    config: &Configuration,
    username: &str,
    id: i64,
) -> Result<Option<RemoteKey>, GatewayError> {
    for page in 1.. {
        let params = user_api::UserListKeysParams {
            username: username.to_string(),
            fingerprint: None,
            page: Some(page),
            limit: Some(PAGE_SIZE),
        };
        let Some(keys) = found(user_api::user_list_keys(config, params).await)? else {
            return Ok(None);
        };
        let len = keys.len();
        if let Some(k) = keys.into_iter().find(|k| k.id == Some(id)) {
            return Ok(Some(RemoteKey {
                id,
                title: k.title.unwrap_or_default(),
                key: k.key.unwrap_or_default(),
                read_only: k.read_only.unwrap_or_default(),
            }));
        }
        if len < PAGE_SIZE as usize {
            break;
        }
    }
    Ok(None)
}

pub(super) async fn create_user(
    config: &Configuration,
    username: &str,
    title: &str,
    key: &str,
) -> Result<ForgejoRef, GatewayError> {
    let params = admin_api::AdminCreatePublicKeyParams {
        username: username.to_string(),
        key: Some(models::CreateKeyOption::new(
            key.to_string(),
            title.to_string(),
        )),
    };
    let created = admin_api::admin_create_public_key(config, params)
        .await
        .map_err(classify)?;
    Ok(ForgejoRef {
        id: created.id.ok_or_else(|| missing_id("public key"))?,
        name: title.to_string(),
    })
}

pub(super) async fn delete_user(
    config: &Configuration,
    username: &str,
    id: i64,
) -> Result<(), GatewayError> {
    let params = admin_api::AdminDeleteUserPublicKeyParams {
        username: username.to_string(),
        id,
    };
    admin_api::admin_delete_user_public_key(config, params)
        .await
        .map_err(classify)
}
