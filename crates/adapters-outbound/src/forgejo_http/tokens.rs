use application::ports::{DesiredToken, ForgejoRef, GatewayError, RemoteToken};
use forgejo_client::apis::admin_api as api;
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::models;

use super::{classify, missing_id};

/// Forgejo's maximum page size (`MAX_RESPONSE_ITEMS` default).
const PAGE_SIZE: i32 = 50;

pub(super) async fn list(
    config: &Configuration,
    username: &str,
) -> Result<Vec<RemoteToken>, GatewayError> {
    let mut out = Vec::new();
    for page in 1.. {
        let params = api::AdminListUserAccessTokensParams {
            username: username.to_string(),
            page: Some(page),
            limit: Some(PAGE_SIZE),
        };
        let batch = api::admin_list_user_access_tokens(config, params)
            .await
            .map_err(classify)?;
        let len = batch.len();
        out.extend(batch.into_iter().map(|t| {
            RemoteToken {
                id: t.id.unwrap_or_default(),
                name: t.name.unwrap_or_default(),
                scopes: t.scopes.unwrap_or_default(),
                repositories: t
                    .repositories
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|r| {
                        r.full_name
                            .or_else(|| Some(format!("{}/{}", r.owner?, r.name?)))
                    })
                    .collect(),
                created_at: t.created_at.map(|c| c.timestamp()),
            }
        }));
        if len < PAGE_SIZE as usize {
            break;
        }
    }
    Ok(out)
}

pub(super) async fn create(
    config: &Configuration,
    username: &str,
    token: &DesiredToken,
) -> Result<(ForgejoRef, String), GatewayError> {
    let repositories = (!token.repositories.is_empty()).then(|| {
        token
            .repositories
            .iter()
            .filter_map(|full| full.split_once('/'))
            .map(|(owner, name)| models::RepoTargetOption::new(name.to_string(), owner.to_string()))
            .collect()
    });
    let body = models::CreateAccessTokenOption {
        repositories,
        scopes: Some(token.scopes.clone()),
        ..models::CreateAccessTokenOption::new(token.name.clone())
    };
    let params = api::AdminCreateUserAccessTokenParams {
        username: username.to_string(),
        body: Some(body),
    };
    let created = api::admin_create_user_access_token(config, params)
        .await
        .map_err(classify)?;
    let value = created
        .sha1
        .filter(|v| !v.is_empty())
        .ok_or_else(|| GatewayError::Api("token creation returned no value".into()))?;
    Ok((
        ForgejoRef {
            id: created.id.ok_or_else(|| missing_id("access token"))?,
            name: created.name.unwrap_or_else(|| token.name.clone()),
        },
        value,
    ))
}

/// Deleting by id (the path segment accepts an id or a name).
pub(super) async fn delete(
    config: &Configuration,
    username: &str,
    id: i64,
) -> Result<(), GatewayError> {
    let params = api::AdminDeleteUserAccessTokenParams {
        username: username.to_string(),
        token: id.to_string(),
    };
    api::admin_delete_user_access_token(config, params)
        .await
        .map_err(classify)
}
