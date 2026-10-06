use application::ports::{DesiredUser, ForgejoRef, GatewayError, RemoteUser};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::{admin_api, user_api};
use forgejo_client::models;

use super::{classify, found, missing_id};

pub(super) async fn get(
    config: &Configuration,
    username: &str,
) -> Result<Option<RemoteUser>, GatewayError> {
    let params = user_api::UserGetParams {
        username: username.to_string(),
    };
    let user = found(user_api::user_get(config, params).await)?
        // Forgejo keeps redirects from a renamed account's old login: the
        // lookup "succeeds" with another login, which is not this name.
        .filter(|u| {
            u.login
                .as_deref()
                .is_some_and(|l| l.eq_ignore_ascii_case(username))
        });
    Ok(user.map(remote))
}

pub(super) fn remote(u: models::User) -> RemoteUser {
    RemoteUser {
        id: u.id.unwrap_or_default(),
        login: u.login.unwrap_or_default(),
        email: u.email.unwrap_or_default(),
        full_name: u.full_name.unwrap_or_default(),
        admin: u.is_admin.unwrap_or_default(),
        restricted: u.restricted.unwrap_or_default(),
        visibility: u.visibility.unwrap_or_default(),
        active: u.active.unwrap_or_default(),
        prohibit_login: u.prohibit_login.unwrap_or_default(),
        source_id: u.source_id.unwrap_or_default(),
        login_name: u.login_name.unwrap_or_default(),
    }
}

pub(super) async fn create(
    config: &Configuration,
    user: &DesiredUser,
) -> Result<ForgejoRef, GatewayError> {
    let body = models::CreateUserOption {
        full_name: user.full_name.clone(),
        login_name: user.login_name.clone(),
        must_change_password: Some(user.must_change_password),
        password: user.password.clone(),
        restricted: Some(user.restricted),
        send_notify: Some(false),
        source_id: user.source_id,
        visibility: Some(user.visibility.to_string()),
        ..models::CreateUserOption::new(user.email.clone(), user.username.clone())
    };
    let params = admin_api::AdminCreateUserParams { body: Some(body) };
    let created = admin_api::admin_create_user(config, params)
        .await
        .map_err(classify)?;
    Ok(ForgejoRef {
        id: created.id.ok_or_else(|| missing_id("user"))?,
        name: created.login.unwrap_or_else(|| user.username.clone()),
    })
}

pub(super) async fn edit(
    config: &Configuration,
    username: &str,
    user: &DesiredUser,
) -> Result<(), GatewayError> {
    let body = models::EditUserOption {
        active: Some(user.active),
        admin: Some(user.admin),
        allow_create_organization: user.allow_create_organization,
        email: Some(user.email.clone()),
        full_name: user.full_name.clone(),
        max_repo_creation: user.max_repo_creation,
        // Only meaningful alongside a password reset; Forgejo otherwise
        // keeps the account's current flag.
        must_change_password: user.password.as_ref().map(|_| user.must_change_password),
        password: user.password.clone(),
        prohibit_login: Some(user.prohibit_login),
        restricted: Some(user.restricted),
        visibility: Some(user.visibility.to_string()),
        // Forgejo requires both or neither; `0` switches back to a local
        // (password) login.
        source_id: Some(user.source_id.unwrap_or(0)),
        login_name: Some(
            user.login_name
                .clone()
                .unwrap_or_else(|| username.to_string()),
        ),
        ..Default::default()
    };
    let params = admin_api::AdminEditUserParams {
        username: username.to_string(),
        body: Some(body),
    };
    admin_api::admin_edit_user(config, params)
        .await
        .map(|_| ())
        .map_err(classify)
}

pub(super) async fn rename(
    config: &Configuration,
    username: &str,
    new_username: &str,
) -> Result<(), GatewayError> {
    let params = admin_api::AdminRenameUserParams {
        username: username.to_string(),
        body: models::RenameUserOption::new(new_username.to_string()),
    };
    admin_api::admin_rename_user(config, params)
        .await
        .map_err(classify)
}

pub(super) async fn delete(config: &Configuration, username: &str) -> Result<(), GatewayError> {
    let params = admin_api::AdminDeleteUserParams {
        username: username.to_string(),
        purge: Some(false),
    };
    admin_api::admin_delete_user(config, params)
        .await
        .map_err(classify)
}
