//! `ForgejoInventory`: the paginated list calls only the importer uses.

use std::future::Future;

use application::ports::{
    GatewayError, HookTarget, RemoteHook, RemoteKey, RemoteOrganization, RemoteRepository,
    RemoteTeam, RemoteUser,
};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::{admin_api, organization_api, repository_api, user_api};

use super::teams::PAGE_SIZE;
use super::{classify, hooks, keys, organizations, repositories, teams, users};

/// Fetches pages until one comes back short.
async fn all<T, F, Fut>(mut fetch: F) -> Result<Vec<T>, GatewayError>
where
    F: FnMut(i32) -> Fut,
    Fut: Future<Output = Result<Vec<T>, GatewayError>>,
{
    let mut out = Vec::new();
    for page in 1.. {
        let batch = fetch(page).await?;
        let len = batch.len();
        out.extend(batch);
        if len < PAGE_SIZE as usize {
            break;
        }
    }
    Ok(out)
}

pub(super) async fn list_users(config: &Configuration) -> Result<Vec<RemoteUser>, GatewayError> {
    let users = all(|page| async move {
        let params = admin_api::AdminSearchUsersParams {
            source_id: None,
            login_name: None,
            is_2fa_enabled: None,
            sort: None,
            page: Some(page),
            limit: Some(PAGE_SIZE),
        };
        admin_api::admin_search_users(config, params)
            .await
            .map_err(classify)
    })
    .await?;
    Ok(users.into_iter().map(users::remote).collect())
}

pub(super) async fn list_organizations(
    config: &Configuration,
) -> Result<Vec<RemoteOrganization>, GatewayError> {
    let orgs = all(|page| async move {
        let params = admin_api::AdminGetAllOrgsParams {
            page: Some(page),
            limit: Some(PAGE_SIZE),
        };
        admin_api::admin_get_all_orgs(config, params)
            .await
            .map_err(classify)
    })
    .await?;
    Ok(orgs.into_iter().map(organizations::remote).collect())
}

pub(super) async fn list_teams(
    config: &Configuration,
    org: &str,
) -> Result<Vec<RemoteTeam>, GatewayError> {
    let list = all(|page| async move {
        let params = organization_api::OrgListTeamsParams {
            org: org.to_string(),
            page: Some(page),
            limit: Some(PAGE_SIZE),
        };
        organization_api::org_list_teams(config, params)
            .await
            .map_err(classify)
    })
    .await?;
    Ok(list
        .into_iter()
        .map(teams::remote)
        // The list omits the embedded organization.
        .map(|t| RemoteTeam {
            organization: org.to_string(),
            ..t
        })
        .collect())
}

pub(super) async fn list_repositories(
    config: &Configuration,
    owner: &str,
    owner_is_org: bool,
) -> Result<Vec<RemoteRepository>, GatewayError> {
    let repos = all(|page| async move {
        if owner_is_org {
            let params = organization_api::OrgListReposParams {
                org: owner.to_string(),
                page: Some(page),
                limit: Some(PAGE_SIZE),
            };
            organization_api::org_list_repos(config, params)
                .await
                .map_err(classify)
        } else {
            let params = user_api::UserListReposParams {
                username: owner.to_string(),
                page: Some(page),
                limit: Some(PAGE_SIZE),
            };
            user_api::user_list_repos(config, params)
                .await
                .map_err(classify)
        }
    })
    .await?;
    Ok(repos.into_iter().map(repositories::remote).collect())
}

pub(super) async fn list_hooks(
    config: &Configuration,
    target: &HookTarget,
) -> Result<Vec<RemoteHook>, GatewayError> {
    let list = all(|page| async move {
        match target {
            HookTarget::Repository { owner, name } => {
                let params = repository_api::RepoListHooksParams {
                    owner: owner.clone(),
                    repo: name.clone(),
                    page: Some(page),
                    limit: Some(PAGE_SIZE),
                };
                repository_api::repo_list_hooks(config, params)
                    .await
                    .map_err(classify)
            }
            HookTarget::Organization(org) => {
                let params = organization_api::OrgListHooksParams {
                    org: org.clone(),
                    page: Some(page),
                    limit: Some(PAGE_SIZE),
                };
                organization_api::org_list_hooks(config, params)
                    .await
                    .map_err(classify)
            }
        }
    })
    .await?;
    Ok(list.into_iter().map(|h| hooks::remote(h, 0)).collect())
}

pub(super) async fn list_deploy_keys(
    config: &Configuration,
    full_name: &str,
) -> Result<Vec<RemoteKey>, GatewayError> {
    let (owner, repo) = keys::split(full_name)?;
    let list = all(|page| {
        let (owner, repo) = (owner.clone(), repo.clone());
        async move {
            let params = repository_api::RepoListKeysParams {
                owner,
                repo,
                key_id: None,
                fingerprint: None,
                page: Some(page),
                limit: Some(PAGE_SIZE),
            };
            repository_api::repo_list_keys(config, params)
                .await
                .map_err(classify)
        }
    })
    .await?;
    Ok(list.into_iter().map(keys::deploy_remote).collect())
}
