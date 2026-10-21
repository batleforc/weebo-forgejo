use application::ports::{
    DesiredRepository, ForgejoRef, GatewayError, GenerateOptions, MigrateOptions, ProtectionRule,
    RemoteRepository, RemoteTeam, RepositoryInitOptions, RepositoryPatch,
};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::{admin_api, organization_api, repository_api as api};
use forgejo_client::models;
use serde_json::json;

use super::{classify, classify_create, found, missing_id, wire_enum, wire_string};

fn split(full_name: &str) -> Result<(String, String), GatewayError> {
    full_name
        .split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .ok_or_else(|| GatewayError::api(format!("{full_name:?} is not owner/name")))
}

fn created(repo: models::Repository, fallback: &str) -> Result<ForgejoRef, GatewayError> {
    Ok(ForgejoRef {
        id: repo.id.ok_or_else(|| missing_id("repository"))?,
        name: repo.full_name.unwrap_or_else(|| fallback.to_string()),
    })
}

pub(super) async fn get(
    config: &Configuration,
    id: i64,
) -> Result<Option<RemoteRepository>, GatewayError> {
    let repo = found(api::repo_get_by_id(config, api::RepoGetByIdParams { id }).await)?;
    Ok(repo.map(|r| RemoteRepository {
        id: r.id.unwrap_or(id),
        ..remote(r)
    }))
}

pub(super) fn remote(r: models::Repository) -> RemoteRepository {
    RemoteRepository {
        id: r.id.unwrap_or_default(),
        owner: r.owner.and_then(|o| o.login).unwrap_or_default(),
        name: r.name.unwrap_or_default(),
        description: r.description.unwrap_or_default(),
        website: r.website.unwrap_or_default(),
        private: r.private.unwrap_or_default(),
        template: r.template.unwrap_or_default(),
        archived: r.archived.unwrap_or_default(),
        default_branch: r.default_branch.unwrap_or_default(),
        has_issues: r.has_issues.unwrap_or_default(),
        has_wiki: r.has_wiki.unwrap_or_default(),
        has_pull_requests: r.has_pull_requests.unwrap_or_default(),
        has_projects: r.has_projects.unwrap_or_default(),
        has_releases: r.has_releases.unwrap_or_default(),
        has_packages: r.has_packages.unwrap_or_default(),
        has_actions: r.has_actions.unwrap_or_default(),
        mirror: r.mirror.unwrap_or_default(),
        mirror_interval: r.mirror_interval.unwrap_or_default(),
        original_url: r.original_url.unwrap_or_default(),
    }
}

pub(super) async fn create(
    config: &Configuration,
    owner: &str,
    owner_is_org: bool,
    repo: &DesiredRepository,
    init: &RepositoryInitOptions,
) -> Result<ForgejoRef, GatewayError> {
    let object_format_name = init.object_format.as_deref().map(wire_enum).transpose()?;
    let body = models::CreateRepoOption {
        auto_init: Some(init.auto_init),
        default_branch: repo.default_branch.clone(),
        description: repo.description.clone(),
        gitignores: init.gitignores.clone(),
        license: init.license.clone(),
        object_format_name,
        private: Some(repo.private),
        readme: init.readme.clone(),
        template: Some(repo.template),
        ..models::CreateRepoOption::new(repo.name.clone())
    };
    let fallback = format!("{owner}/{}", repo.name);
    let result = if owner_is_org {
        let params = organization_api::CreateOrgRepoParams {
            org: owner.to_string(),
            body: Some(body),
        };
        organization_api::create_org_repo(config, params)
            .await
            .map_err(classify_create)
    } else {
        let params = admin_api::AdminCreateRepoParams {
            username: owner.to_string(),
            repository: body,
        };
        admin_api::admin_create_repo(config, params)
            .await
            .map_err(classify_create)
    }?;
    created(result, &fallback)
}

pub(super) async fn generate(
    config: &Configuration,
    template: &str,
    owner: &str,
    repo: &DesiredRepository,
    options: &GenerateOptions,
) -> Result<ForgejoRef, GatewayError> {
    let (template_owner, template_repo) = split(template)?;
    let body = models::GenerateRepoOption {
        avatar: Some(options.avatar),
        default_branch: repo.default_branch.clone(),
        description: repo.description.clone(),
        git_content: Some(options.git_content),
        git_hooks: Some(options.git_hooks),
        labels: Some(options.labels),
        private: Some(repo.private),
        protected_branch: Some(options.protected_branches),
        topics: Some(options.topics),
        webhooks: Some(options.webhooks),
        ..models::GenerateRepoOption::new(repo.name.clone(), owner.to_string())
    };
    let params = api::GenerateRepoParams {
        template_owner,
        template_repo,
        body: Some(body),
    };
    let result = api::generate_repo(config, params)
        .await
        .map_err(classify_create)?;
    created(result, &format!("{owner}/{}", repo.name))
}

pub(super) async fn migrate(
    config: &Configuration,
    owner: &str,
    repo: &DesiredRepository,
    options: &MigrateOptions,
) -> Result<ForgejoRef, GatewayError> {
    let body = models::MigrateRepoOptions {
        auth_password: options.auth_password.clone(),
        auth_token: options.auth_token.clone(),
        auth_username: options.auth_username.clone(),
        description: repo.description.clone(),
        issues: Some(options.issues),
        labels: Some(options.labels),
        lfs: Some(options.lfs),
        milestones: Some(options.milestones),
        mirror: Some(options.mirror),
        mirror_interval: options.mirror_interval.clone(),
        private: Some(repo.private),
        pull_requests: Some(options.pull_requests),
        releases: Some(options.releases),
        repo_owner: Some(owner.to_string()),
        service: Some(wire_enum(&options.service)?),
        wiki: Some(options.wiki),
        ..models::MigrateRepoOptions::new(options.clone_addr.clone(), repo.name.clone())
    };
    let params = api::RepoMigrateParams { body: Some(body) };
    let result = api::repo_migrate(config, params)
        .await
        .map_err(classify_create)?;
    created(result, &format!("{owner}/{}", repo.name))
}

pub(super) async fn edit(
    config: &Configuration,
    full_name: &str,
    repo: &RepositoryPatch,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let body = models::EditRepoOption {
        default_branch: repo.default_branch.clone(),
        description: repo.description.clone(),
        has_actions: repo.has_actions,
        has_issues: repo.has_issues,
        has_packages: repo.has_packages,
        has_projects: repo.has_projects,
        has_pull_requests: repo.has_pull_requests,
        has_releases: repo.has_releases,
        has_wiki: repo.has_wiki,
        mirror_interval: repo.mirror_interval.clone(),
        name: repo.name.clone(),
        private: repo.private,
        template: repo.template,
        website: repo.website.clone(),
        ..Default::default()
    };
    let params = api::RepoEditParams {
        owner,
        repo: name,
        body: Some(body),
    };
    api::repo_edit(config, params)
        .await
        .map(|_| ())
        .map_err(classify)
}

pub(super) async fn set_archived(
    config: &Configuration,
    full_name: &str,
    archived: bool,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoEditParams {
        owner,
        repo: name,
        body: Some(models::EditRepoOption {
            archived: Some(archived),
            ..Default::default()
        }),
    };
    api::repo_edit(config, params)
        .await
        .map(|_| ())
        .map_err(classify)
}

pub(super) async fn transfer(
    config: &Configuration,
    full_name: &str,
    new_owner: &str,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoTransferParams {
        owner,
        repo: name,
        body: models::TransferRepoOption::new(new_owner.to_string()),
    };
    api::repo_transfer(config, params)
        .await
        .map(|_| ())
        .map_err(classify_create)
}

pub(super) async fn delete(config: &Configuration, full_name: &str) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    api::repo_delete(config, api::RepoDeleteParams { owner, repo: name })
        .await
        .map_err(classify)
}

pub(super) async fn list_protections(
    config: &Configuration,
    full_name: &str,
) -> Result<Vec<ProtectionRule>, GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoListBranchProtectionParams { owner, repo: name };
    let rules = api::repo_list_branch_protection(config, params)
        .await
        .map_err(classify)?;
    Ok(rules
        .into_iter()
        .map(|p| ProtectionRule {
            rule_name: p.rule_name.or(p.branch_name).unwrap_or_default(),
            enable_push: p.enable_push.unwrap_or_default(),
            enable_push_whitelist: p.enable_push_whitelist.unwrap_or_default(),
            push_whitelist_usernames: p.push_whitelist_usernames.unwrap_or_default(),
            push_whitelist_teams: p.push_whitelist_teams.unwrap_or_default(),
            push_whitelist_deploy_keys: p.push_whitelist_deploy_keys.unwrap_or_default(),
            enable_merge_whitelist: p.enable_merge_whitelist.unwrap_or_default(),
            merge_whitelist_usernames: p.merge_whitelist_usernames.unwrap_or_default(),
            merge_whitelist_teams: p.merge_whitelist_teams.unwrap_or_default(),
            required_approvals: p.required_approvals.unwrap_or_default(),
            enable_approvals_whitelist: p.enable_approvals_whitelist.unwrap_or_default(),
            approvals_whitelist_usernames: p.approvals_whitelist_username.unwrap_or_default(),
            approvals_whitelist_teams: p.approvals_whitelist_teams.unwrap_or_default(),
            enable_status_check: p.enable_status_check.unwrap_or_default(),
            status_check_contexts: p.status_check_contexts.unwrap_or_default(),
            block_on_rejected_reviews: p.block_on_rejected_reviews.unwrap_or_default(),
            block_on_official_review_requests: p
                .block_on_official_review_requests
                .unwrap_or_default(),
            block_on_outdated_branch: p.block_on_outdated_branch.unwrap_or_default(),
            dismiss_stale_approvals: p.dismiss_stale_approvals.unwrap_or_default(),
            ignore_stale_approvals: p.ignore_stale_approvals.unwrap_or_default(),
            require_signed_commits: p.require_signed_commits.unwrap_or_default(),
            apply_to_admins: p.apply_to_admins.unwrap_or_default(),
            protected_file_patterns: p.protected_file_patterns.unwrap_or_default(),
            unprotected_file_patterns: p.unprotected_file_patterns.unwrap_or_default(),
        })
        .collect())
}

/// The create and edit options share every field but `rule_name`; one
/// JSON shape deserializes into either.
fn protection_json(rule: &ProtectionRule) -> serde_json::Value {
    json!({
        "rule_name": rule.rule_name,
        "enable_push": rule.enable_push,
        "enable_push_whitelist": rule.enable_push_whitelist,
        "push_whitelist_usernames": rule.push_whitelist_usernames,
        "push_whitelist_teams": rule.push_whitelist_teams,
        "push_whitelist_deploy_keys": rule.push_whitelist_deploy_keys,
        "enable_merge_whitelist": rule.enable_merge_whitelist,
        "merge_whitelist_usernames": rule.merge_whitelist_usernames,
        "merge_whitelist_teams": rule.merge_whitelist_teams,
        "required_approvals": rule.required_approvals,
        "enable_approvals_whitelist": rule.enable_approvals_whitelist,
        "approvals_whitelist_username": rule.approvals_whitelist_usernames,
        "approvals_whitelist_teams": rule.approvals_whitelist_teams,
        "enable_status_check": rule.enable_status_check,
        "status_check_contexts": rule.status_check_contexts,
        "block_on_rejected_reviews": rule.block_on_rejected_reviews,
        "block_on_official_review_requests": rule.block_on_official_review_requests,
        "block_on_outdated_branch": rule.block_on_outdated_branch,
        "dismiss_stale_approvals": rule.dismiss_stale_approvals,
        "ignore_stale_approvals": rule.ignore_stale_approvals,
        "require_signed_commits": rule.require_signed_commits,
        "apply_to_admins": rule.apply_to_admins,
        "protected_file_patterns": rule.protected_file_patterns,
        "unprotected_file_patterns": rule.unprotected_file_patterns,
    })
}

fn protection_option<T: serde::de::DeserializeOwned>(
    rule: &ProtectionRule,
) -> Result<T, GatewayError> {
    serde_json::from_value(protection_json(rule))
        .map_err(|e| GatewayError::api(format!("branch protection body: {e}")))
}

pub(super) async fn create_protection(
    config: &Configuration,
    full_name: &str,
    rule: &ProtectionRule,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoCreateBranchProtectionParams {
        owner,
        repo: name,
        body: Some(protection_option(rule)?),
    };
    api::repo_create_branch_protection(config, params)
        .await
        .map(|_| ())
        .map_err(classify_create)
}

pub(super) async fn edit_protection(
    config: &Configuration,
    full_name: &str,
    rule: &ProtectionRule,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoEditBranchProtectionParams {
        owner,
        repo: name,
        name: rule.rule_name.clone(),
        body: Some(protection_option(rule)?),
    };
    api::repo_edit_branch_protection(config, params)
        .await
        .map(|_| ())
        .map_err(classify)
}

pub(super) async fn delete_protection(
    config: &Configuration,
    full_name: &str,
    rule_name: &str,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoDeleteBranchProtectionParams {
        owner,
        repo: name,
        name: rule_name.to_string(),
    };
    api::repo_delete_branch_protection(config, params)
        .await
        .map_err(classify)
}

pub(super) async fn list_teams(
    config: &Configuration,
    full_name: &str,
) -> Result<Vec<RemoteTeam>, GatewayError> {
    let (owner, name) = split(full_name)?;
    let teams = api::repo_list_teams(config, api::RepoListTeamsParams { owner, repo: name })
        .await
        .map_err(classify)?;
    Ok(teams
        .into_iter()
        .map(|t| RemoteTeam {
            id: t.id.unwrap_or_default(),
            name: t.name.unwrap_or_default(),
            organization_id: t.organization.as_ref().and_then(|o| o.id),
            organization: t
                .organization
                .and_then(|o| o.name.or(o.username))
                .unwrap_or_default(),
            description: t.description.unwrap_or_default(),
            permission: t.permission.as_ref().map(wire_string).unwrap_or_default(),
            units_map: t.units_map.unwrap_or_default().into_iter().collect(),
            includes_all_repositories: t.includes_all_repositories.unwrap_or_default(),
            can_create_org_repo: t.can_create_org_repo.unwrap_or_default(),
        })
        .collect())
}

pub(super) async fn add_team(
    config: &Configuration,
    full_name: &str,
    team: &str,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoAddTeamParams {
        owner,
        repo: name,
        team: team.to_string(),
    };
    api::repo_add_team(config, params).await.map_err(classify)
}

pub(super) async fn remove_team(
    config: &Configuration,
    full_name: &str,
    team: &str,
) -> Result<(), GatewayError> {
    let (owner, name) = split(full_name)?;
    let params = api::RepoDeleteTeamParams {
        owner,
        repo: name,
        team: team.to_string(),
    };
    api::repo_delete_team(config, params)
        .await
        .map_err(classify)
}
