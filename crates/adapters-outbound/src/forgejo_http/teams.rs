use std::collections::BTreeSet;

use application::ports::{DesiredTeam, ForgejoRef, GatewayError, RemoteTeam, TeamPatch};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::organization_api as api;
use forgejo_client::models;

use super::{
    PAGE_SIZE, all_pages, classify, classify_create, found, missing_id, wire_enum, wire_string,
};

pub(super) async fn get(
    config: &Configuration,
    id: i64,
) -> Result<Option<RemoteTeam>, GatewayError> {
    let team = found(api::org_get_team(config, api::OrgGetTeamParams { id }).await)?;
    Ok(team.map(|t| RemoteTeam {
        id: t.id.unwrap_or(id),
        ..remote(t)
    }))
}

pub(super) fn remote(t: models::Team) -> RemoteTeam {
    RemoteTeam {
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
    }
}

fn units(team: &DesiredTeam) -> Option<std::collections::HashMap<String, String>> {
    units_map(&team.units_map)
}

fn units_map(
    units: &std::collections::BTreeMap<String, String>,
) -> Option<std::collections::HashMap<String, String>> {
    (!units.is_empty()).then(|| units.clone().into_iter().collect())
}

pub(super) async fn create(
    config: &Configuration,
    org: &str,
    team: &DesiredTeam,
) -> Result<ForgejoRef, GatewayError> {
    let body = models::CreateTeamOption {
        can_create_org_repo: Some(team.can_create_org_repo),
        description: team.description.clone(),
        includes_all_repositories: Some(team.includes_all_repositories),
        permission: Some(wire_enum(team.permission)?),
        units_map: units(team),
        ..models::CreateTeamOption::new(team.name.clone())
    };
    let params = api::OrgCreateTeamParams {
        org: org.to_string(),
        body: Some(body),
    };
    let created = api::org_create_team(config, params)
        .await
        .map_err(classify_create)?;
    Ok(ForgejoRef {
        id: created.id.ok_or_else(|| missing_id("team"))?,
        name: created.name.unwrap_or_else(|| team.name.clone()),
    })
}

pub(super) async fn edit(
    config: &Configuration,
    id: i64,
    team: &TeamPatch,
) -> Result<(), GatewayError> {
    let access = team.access.as_ref();
    let body = models::EditTeamOption {
        can_create_org_repo: team.can_create_org_repo,
        description: team.description.clone(),
        includes_all_repositories: access.map(|a| a.includes_all_repositories),
        permission: access.map(|a| wire_enum(a.permission)).transpose()?,
        units_map: access.and_then(|a| units_map(&a.units_map)),
        ..models::EditTeamOption::new(team.name.clone())
    };
    let params = api::OrgEditTeamParams {
        id,
        body: Some(body),
    };
    api::org_edit_team(config, params)
        .await
        .map(|_| ())
        .map_err(classify)
}

pub(super) async fn delete(config: &Configuration, id: i64) -> Result<(), GatewayError> {
    api::org_delete_team(config, api::OrgDeleteTeamParams { id })
        .await
        .map_err(classify)
}

pub(super) async fn list_members(
    config: &Configuration,
    id: i64,
) -> Result<Vec<String>, GatewayError> {
    let members = all_pages(|page| async move {
        let params = api::OrgListTeamMembersParams {
            id,
            page: Some(page),
            limit: Some(PAGE_SIZE),
        };
        api::org_list_team_members(config, params)
            .await
            .map_err(classify)
    })
    .await?;
    let logins: BTreeSet<String> = members.into_iter().filter_map(|u| u.login).collect();
    Ok(logins.into_iter().collect())
}

pub(super) async fn add_member(
    config: &Configuration,
    id: i64,
    username: &str,
) -> Result<(), GatewayError> {
    let params = api::OrgAddTeamMemberParams {
        id,
        username: username.to_string(),
    };
    api::org_add_team_member(config, params)
        .await
        .map_err(classify)
}

pub(super) async fn remove_member(
    config: &Configuration,
    id: i64,
    username: &str,
) -> Result<(), GatewayError> {
    let params = api::OrgRemoveTeamMemberParams {
        id,
        username: username.to_string(),
    };
    api::org_remove_team_member(config, params)
        .await
        .map_err(classify)
}
