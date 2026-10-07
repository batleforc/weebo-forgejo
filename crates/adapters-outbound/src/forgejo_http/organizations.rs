use application::ports::{DesiredOrganization, ForgejoRef, GatewayError, RemoteOrganization};
use forgejo_client::apis::configuration::Configuration;
use forgejo_client::apis::{admin_api, organization_api};
use forgejo_client::models;

use super::{classify, classify_create, found, missing_id, wire_enum};

pub(super) async fn get(
    config: &Configuration,
    name: &str,
) -> Result<Option<RemoteOrganization>, GatewayError> {
    let params = organization_api::OrgGetParams {
        org: name.to_string(),
    };
    let org = found(organization_api::org_get(config, params).await)?
        // Same redirect-after-rename behaviour as users.
        .filter(|o| {
            o.name
                .as_deref()
                .or(o.username.as_deref())
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        });
    Ok(org.map(remote))
}

pub(super) fn remote(o: models::Organization) -> RemoteOrganization {
    RemoteOrganization {
        id: o.id.unwrap_or_default(),
        name: o.name.or(o.username).unwrap_or_default(),
        full_name: o.full_name.unwrap_or_default(),
        description: o.description.unwrap_or_default(),
        website: o.website.unwrap_or_default(),
        location: o.location.unwrap_or_default(),
        email: o.email.unwrap_or_default(),
        visibility: o.visibility.unwrap_or_default(),
        repo_admin_change_team_access: o.repo_admin_change_team_access.unwrap_or_default(),
    }
}

pub(super) async fn create(
    config: &Configuration,
    owner: Option<&str>,
    org: &DesiredOrganization,
) -> Result<ForgejoRef, GatewayError> {
    let body = models::CreateOrgOption {
        description: org.description.clone(),
        email: org.email.clone(),
        full_name: org.full_name.clone(),
        location: org.location.clone(),
        repo_admin_change_team_access: Some(org.repo_admin_change_team_access),
        visibility: Some(wire_enum(org.visibility)?),
        website: org.website.clone(),
        ..models::CreateOrgOption::new(org.name.clone())
    };
    let created = match owner {
        Some(owner) => {
            let params = admin_api::AdminCreateOrgParams {
                username: owner.to_string(),
                organization: body,
            };
            admin_api::admin_create_org(config, params)
                .await
                .map_err(classify_create)
        }
        None => {
            let params = organization_api::OrgCreateParams { organization: body };
            organization_api::org_create(config, params)
                .await
                .map_err(classify_create)
        }
    }?;
    Ok(ForgejoRef {
        id: created.id.ok_or_else(|| missing_id("organization"))?,
        name: created.name.unwrap_or_else(|| org.name.clone()),
    })
}

pub(super) async fn edit(
    config: &Configuration,
    name: &str,
    org: &DesiredOrganization,
) -> Result<(), GatewayError> {
    let body = models::EditOrgOption {
        description: org.description.clone(),
        email: org.email.clone(),
        full_name: org.full_name.clone(),
        location: org.location.clone(),
        repo_admin_change_team_access: Some(org.repo_admin_change_team_access),
        visibility: Some(wire_enum(org.visibility)?),
        website: org.website.clone(),
    };
    let params = organization_api::OrgEditParams {
        org: name.to_string(),
        body,
    };
    organization_api::org_edit(config, params)
        .await
        .map(|_| ())
        .map_err(classify)
}

pub(super) async fn rename(
    config: &Configuration,
    name: &str,
    new_name: &str,
) -> Result<(), GatewayError> {
    let params = organization_api::RenameOrgParams {
        org: name.to_string(),
        body: models::RenameOrgOption::new(new_name.to_string()),
    };
    organization_api::rename_org(config, params)
        .await
        .map_err(classify_create)
}

pub(super) async fn delete(config: &Configuration, name: &str) -> Result<(), GatewayError> {
    let params = organization_api::OrgDeleteParams {
        org: name.to_string(),
    };
    organization_api::org_delete(config, params)
        .await
        .map_err(classify)
}
