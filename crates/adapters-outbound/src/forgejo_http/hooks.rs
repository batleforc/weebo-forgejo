use std::collections::HashMap;

use application::ports::{
    DesiredHook, ForgejoRef, GatewayError, HookPatch, HookTarget, RemoteHook,
};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::{organization_api, repository_api};
use forgejo_client::models;

use super::{classify, found, missing_id, wire_enum};

pub(super) fn remote(hook: models::Hook, id: i64) -> RemoteHook {
    RemoteHook {
        id: hook.id.unwrap_or(id),
        type_: hook.r#type.unwrap_or_default(),
        config: hook.config.unwrap_or_default().into_iter().collect(),
        events: hook.events.unwrap_or_default(),
        branch_filter: hook.branch_filter.unwrap_or_default(),
        active: hook.active.unwrap_or_default(),
    }
}

fn config(hook: &DesiredHook) -> HashMap<String, String> {
    hook.config.clone().into_iter().collect()
}

pub(super) async fn get(
    config: &Configuration,
    target: &HookTarget,
    id: i64,
) -> Result<Option<RemoteHook>, GatewayError> {
    let hook = match target {
        HookTarget::Repository { owner, name } => {
            let params = repository_api::RepoGetHookParams {
                owner: owner.clone(),
                repo: name.clone(),
                id,
            };
            found(repository_api::repo_get_hook(config, params).await)?
        }
        HookTarget::Organization(org) => {
            let params = organization_api::OrgGetHookParams {
                org: org.clone(),
                id,
            };
            found(organization_api::org_get_hook(config, params).await)?
        }
    };
    Ok(hook.map(|h| remote(h, id)))
}

pub(super) async fn create(
    cfg: &Configuration,
    target: &HookTarget,
    hook: &DesiredHook,
) -> Result<ForgejoRef, GatewayError> {
    let body = models::CreateHookOption {
        active: Some(hook.active),
        authorization_header: hook.authorization_header.clone(),
        branch_filter: Some(hook.branch_filter.clone()),
        events: Some(hook.events.clone()),
        ..models::CreateHookOption::new(config(hook), wire_enum(&hook.type_)?)
    };
    let created = match target {
        HookTarget::Repository { owner, name } => {
            let params = repository_api::RepoCreateHookParams {
                owner: owner.clone(),
                repo: name.clone(),
                body: Some(body),
            };
            repository_api::repo_create_hook(cfg, params)
                .await
                .map_err(classify)
        }
        HookTarget::Organization(org) => {
            let params = organization_api::OrgCreateHookParams {
                org: org.clone(),
                body,
            };
            organization_api::org_create_hook(cfg, params)
                .await
                .map_err(classify)
        }
    }?;
    Ok(ForgejoRef {
        id: created.id.ok_or_else(|| missing_id("webhook"))?,
        name: target.to_string(),
    })
}

pub(super) async fn edit(
    cfg: &Configuration,
    target: &HookTarget,
    id: i64,
    hook: &HookPatch,
) -> Result<(), GatewayError> {
    // See `HookPatch` for what Forgejo replaces on every edit (events,
    // branch filter: always sent) and what it leaves when absent (`config`,
    // never with the secret; the header, only when it changed).
    let body = models::EditHookOption {
        active: hook.active,
        authorization_header: hook.authorization_header.clone(),
        branch_filter: Some(hook.branch_filter.clone()),
        config: hook.config.clone().map(|c| c.into_iter().collect()),
        events: Some(hook.events.clone()),
    };
    match target {
        HookTarget::Repository { owner, name } => {
            let params = repository_api::RepoEditHookParams {
                owner: owner.clone(),
                repo: name.clone(),
                id,
                body: Some(body),
            };
            repository_api::repo_edit_hook(cfg, params)
                .await
                .map(|_| ())
                .map_err(classify)
        }
        HookTarget::Organization(org) => {
            let params = organization_api::OrgEditHookParams {
                org: org.clone(),
                id,
                body: Some(body),
            };
            organization_api::org_edit_hook(cfg, params)
                .await
                .map(|_| ())
                .map_err(classify)
        }
    }
}

pub(super) async fn delete(
    cfg: &Configuration,
    target: &HookTarget,
    id: i64,
) -> Result<(), GatewayError> {
    match target {
        HookTarget::Repository { owner, name } => {
            let params = repository_api::RepoDeleteHookParams {
                owner: owner.clone(),
                repo: name.clone(),
                id,
            };
            repository_api::repo_delete_hook(cfg, params)
                .await
                .map_err(classify)
        }
        HookTarget::Organization(org) => {
            let params = organization_api::OrgDeleteHookParams {
                org: org.clone(),
                id,
            };
            organization_api::org_delete_hook(cfg, params)
                .await
                .map_err(classify)
        }
    }
}
