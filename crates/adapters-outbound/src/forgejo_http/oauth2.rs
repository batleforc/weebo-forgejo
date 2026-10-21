use application::ports::{DesiredOAuth2App, GatewayError, RemoteOAuth2App};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::user_api as api;
use forgejo_client::models;

use super::{PAGE_SIZE, all_pages, classify, classify_create, found, missing_id};

fn remote(app: models::OAuth2Application, id: i64) -> RemoteOAuth2App {
    RemoteOAuth2App {
        id: app.id.unwrap_or(id),
        name: app.name.unwrap_or_default(),
        client_id: app.client_id.unwrap_or_default(),
        redirect_uris: app.redirect_uris.unwrap_or_default(),
        confidential_client: app.confidential_client.unwrap_or_default(),
    }
}

fn body(app: &DesiredOAuth2App) -> models::CreateOAuth2ApplicationOptions {
    models::CreateOAuth2ApplicationOptions {
        confidential_client: Some(app.confidential_client),
        name: Some(app.name.clone()),
        redirect_uris: Some(app.redirect_uris.clone()),
    }
}

pub(super) async fn get(
    config: &Configuration,
    sudo: Option<&str>,
    id: i64,
) -> Result<Option<RemoteOAuth2App>, GatewayError> {
    let params = api::UserGetOAuth2ApplicationParams {
        id,
        sudo: sudo.map(str::to_string),
    };
    Ok(found(api::user_get_o_auth2_application(config, params).await)?.map(|a| remote(a, id)))
}

pub(super) async fn create(
    config: &Configuration,
    sudo: Option<&str>,
    app: &DesiredOAuth2App,
) -> Result<(RemoteOAuth2App, String), GatewayError> {
    let params = api::UserCreateOAuth2ApplicationParams {
        body: body(app),
        sudo: sudo.map(str::to_string),
    };
    let mut created = api::user_create_o_auth2_application(config, params)
        .await
        .map_err(classify_create)?;
    let id = created.id.ok_or_else(|| missing_id("OAuth2 application"))?;
    // Only ever returned here: an app kept without one would be Ready with an
    // unusable, unrecoverable credential. It is removed (best effort, app
    // names aren't unique) so the retry starts clean instead of piling up.
    let Some(secret) = created.client_secret.take().filter(|s| !s.is_empty()) else {
        if let Err(e) = delete(config, sudo, id).await {
            tracing::warn!(
                error = %e,
                id,
                "OAuth2 application created without a secret could not be removed; delete it by hand"
            );
        }
        return Err(GatewayError::Api(format!(
            "OAuth2 application {id} was created without a client secret"
        )));
    };
    Ok((remote(created, id), secret))
}

pub(super) async fn update(
    config: &Configuration,
    sudo: Option<&str>,
    id: i64,
    app: &DesiredOAuth2App,
) -> Result<String, GatewayError> {
    let params = api::UserUpdateOAuth2ApplicationParams {
        id,
        body: body(app),
        sudo: sudo.map(str::to_string),
    };
    let updated = api::user_update_o_auth2_application(config, params)
        .await
        .map_err(classify)?;
    updated
        .client_secret
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GatewayError::Api("OAuth2 update returned no client secret".into()))
}

pub(super) async fn delete(
    config: &Configuration,
    sudo: Option<&str>,
    id: i64,
) -> Result<(), GatewayError> {
    let params = api::UserDeleteOAuth2ApplicationParams {
        id,
        sudo: sudo.map(str::to_string),
    };
    api::user_delete_o_auth2_application(config, params)
        .await
        .map_err(classify)
}

pub(super) async fn list(
    config: &Configuration,
    sudo: Option<&str>,
) -> Result<Vec<RemoteOAuth2App>, GatewayError> {
    let apps = all_pages(|page| async move {
        let params = api::UserGetOAuth2ApplicationsParams {
            page: Some(page),
            limit: Some(PAGE_SIZE),
            sudo: sudo.map(str::to_string),
        };
        api::user_get_o_auth2_applications(config, params)
            .await
            .map_err(classify)
    })
    .await?;
    Ok(apps.into_iter().map(|a| remote(a, 0)).collect())
}
