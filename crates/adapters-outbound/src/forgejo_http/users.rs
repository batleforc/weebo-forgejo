use application::ports::{DesiredUser, ForgejoRef, GatewayError, RemoteUser, UserPatch};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::{admin_api, user_api};
use forgejo_client::models;

use super::{classify, classify_create, found, missing_id, organizations};

/// `GET /users/search?uid=`: the only lookup by id (an admin token sees
/// every account, whatever its visibility).
pub(super) async fn login_by_id(
    config: &Configuration,
    id: i64,
) -> Result<Option<String>, GatewayError> {
    let params = user_api::UserSearchParams {
        q: None,
        uid: Some(id),
        sort: None,
        page: None,
        limit: Some(1),
    };
    let found = user_api::user_search(config, params)
        .await
        .map_err(classify)?;
    Ok(found
        .data
        .unwrap_or_default()
        .into_iter()
        .find(|u| u.id == Some(id))
        .and_then(|u| u.login))
}

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
    let Some(user) = user else {
        return Ok(None);
    };
    // `GET /users/{name}` also answers for organizations, and `User` carries
    // no account type: an org of that name is not a user.
    if organizations::get(config, username).await?.is_some() {
        return Ok(None);
    }
    Ok(Some(remote(user)))
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
        .map_err(classify_create)?;
    Ok(ForgejoRef {
        id: created.id.ok_or_else(|| missing_id("user"))?,
        name: created.login.unwrap_or_else(|| user.username.clone()),
    })
}

pub(super) async fn edit(
    config: &Configuration,
    username: &str,
    user: &UserPatch,
) -> Result<(), GatewayError> {
    let (source_id, login_name) = user.login_source.clone().unzip();
    let body = models::EditUserOption {
        active: user.active,
        admin: user.admin,
        allow_create_organization: user.allow_create_organization,
        email: user.email.clone(),
        full_name: user.full_name.clone(),
        max_repo_creation: user.max_repo_creation,
        must_change_password: user.must_change_password,
        password: user.password.clone(),
        prohibit_login: user.prohibit_login,
        restricted: user.restricted,
        visibility: user.visibility.map(str::to_string),
        // Forgejo requires both or neither; `0` switches back to a local
        // (password) login. Forgejo stores `login_name` verbatim, so a
        // local account gets "" — what a freshly created one has, and what
        // the diff expects (anything else would re-PATCH forever).
        source_id,
        login_name,
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
        .map_err(classify_create)
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
