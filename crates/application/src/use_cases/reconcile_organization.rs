//! `ForgejoOrganization`: attempt-create-first, renamed in place when
//! `spec.name` changes, PATCHed only when it differs from Forgejo.

use api::common::DeletionPolicy;
use api::organization::ForgejoOrganizationSpec;

use crate::ports::{
    DesiredOrganization, ForgejoGateway, ForgejoRef, GatewayError, RemoteOrganization,
};
use crate::use_cases::{CleanupGateway, Failure, Outcome, differs};

pub struct OrganizationInput<'a> {
    pub spec: &'a ForgejoOrganizationSpec,
    /// From `status.forgejoId`/`status.forgejoName`.
    pub current: Option<ForgejoRef>,
    /// Login of the resolved `spec.ownerRef`, already `Ready`. Only used at
    /// creation.
    pub owner: Option<String>,
}

pub async fn reconcile_organization(
    input: OrganizationInput<'_>,
    gateway: &dyn ForgejoGateway,
) -> Outcome {
    let spec = input.spec;
    let desired = desired_organization(spec);

    let remote = match locate(spec, input.current.as_ref(), gateway).await {
        Ok(r) => r,
        Err(f) => return Outcome::failed(input.current, f),
    };
    let Some(remote) = remote else {
        return match gateway
            .create_organization(input.owner.as_deref(), &desired)
            .await
        {
            Ok(created) => Outcome::synced(Some(created), "organization created"),
            Err(e) => Outcome::failed(None, e),
        };
    };

    let current = Some(ForgejoRef {
        id: remote.id,
        name: remote.name.clone(),
    });
    if organization_differs(&desired, &remote)
        && let Err(e) = gateway.edit_organization(&remote.name, &desired).await
    {
        return Outcome::failed(current, e);
    }
    Outcome::synced(current, "organization synced")
}

pub async fn cleanup_organization(
    spec: &ForgejoOrganizationSpec,
    current: Option<&ForgejoRef>,
    gateway: CleanupGateway<'_>,
) -> Result<(), Failure> {
    if spec.deletion_policy != DeletionPolicy::Delete {
        return Ok(());
    }
    let Some(current) = current else {
        return Ok(());
    };
    match gateway
        .map_err(Clone::clone)?
        .delete_organization(&current.name)
        .await
    {
        Ok(()) | Err(GatewayError::NotFound(_)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

async fn locate(
    spec: &ForgejoOrganizationSpec,
    current: Option<&ForgejoRef>,
    gateway: &dyn ForgejoGateway,
) -> Result<Option<RemoteOrganization>, Failure> {
    let Some(current) = current else {
        return Ok(None);
    };
    if current.name != spec.name {
        match gateway.rename_organization(&current.name, &spec.name).await {
            Ok(()) | Err(GatewayError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(gateway
        .get_organization(&spec.name)
        .await?
        .filter(|o| o.id == current.id))
}

fn desired_organization(spec: &ForgejoOrganizationSpec) -> DesiredOrganization {
    DesiredOrganization {
        name: spec.name.clone(),
        full_name: spec.full_name.clone(),
        description: spec.description.clone(),
        website: spec.website.clone(),
        location: spec.location.clone(),
        email: spec.email.clone(),
        visibility: spec.visibility.as_str(),
        repo_admin_change_team_access: spec.repo_admin_change_team_access,
    }
}

fn organization_differs(d: &DesiredOrganization, r: &RemoteOrganization) -> bool {
    differs(&d.full_name, &r.full_name)
        || differs(&d.description, &r.description)
        || differs(&d.website, &r.website)
        || differs(&d.location, &r.location)
        || differs(&d.email, &r.email)
        || d.visibility != r.visibility
        || d.repo_admin_change_team_access != r.repo_admin_change_team_access
}

#[cfg(test)]
mod tests {
    use api::common::Visibility;
    use domain::error::ReasonCode;

    use super::*;
    use crate::test_support::FakeForgejo;

    fn spec(name: &str) -> ForgejoOrganizationSpec {
        ForgejoOrganizationSpec {
            instance_ref: None,
            name: name.into(),
            full_name: Some("Weebo".into()),
            description: None,
            website: None,
            location: None,
            email: None,
            visibility: Visibility::Public,
            repo_admin_change_team_access: false,
            owner_ref: None,
            deletion_policy: DeletionPolicy::Orphan,
        }
    }

    async fn run(
        spec: &ForgejoOrganizationSpec,
        current: Option<ForgejoRef>,
        owner: Option<&str>,
        fj: &FakeForgejo,
    ) -> Outcome {
        let input = OrganizationInput {
            spec,
            current,
            owner: owner.map(str::to_string),
        };
        reconcile_organization(input, fj).await
    }

    #[tokio::test]
    async fn creates_then_stays_quiet_until_drift() {
        let fj = FakeForgejo::default();
        let mut s = spec("weebo");
        let created = run(&s, None, None, &fj).await.forgejo;
        assert_eq!(fj.org("weebo").unwrap().remote.full_name, "Weebo");

        fj.clear_calls();
        run(&s, created.clone(), None, &fj).await;
        assert!(fj.calls().is_empty());

        s.visibility = Visibility::Private;
        run(&s, created, None, &fj).await;
        assert_eq!(fj.org("weebo").unwrap().remote.visibility, "private");
    }

    #[tokio::test]
    async fn owner_is_used_at_creation() {
        let fj = FakeForgejo::default();
        fj.insert_user("alice");
        run(&spec("weebo"), None, Some("alice"), &fj).await;
        assert_eq!(fj.org("weebo").unwrap().owner.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn rename_keeps_the_id() {
        let fj = FakeForgejo::default();
        let mut s = spec("weebo");
        let created = run(&s, None, None, &fj).await.forgejo.unwrap();
        s.name = "weebo-labs".into();
        let outcome = run(&s, Some(created.clone()), None, &fj).await;
        assert_eq!(outcome.forgejo.unwrap().id, created.id);
        assert!(fj.org("weebo").is_none());
    }

    #[tokio::test]
    async fn collision_is_reported_not_adopted() {
        let fj = FakeForgejo::default();
        run(&spec("weebo"), None, None, &fj).await;
        let outcome = run(&spec("weebo"), None, None, &fj).await;
        assert_eq!(outcome.reason(), ReasonCode::ForgejoObjectAlreadyExists);
    }

    #[tokio::test]
    async fn orphan_policy_keeps_the_org() {
        let fj = FakeForgejo::default();
        let s = spec("weebo");
        let created = run(&s, None, None, &fj).await.forgejo;
        cleanup_organization(&s, created.as_ref(), Ok(&fj))
            .await
            .unwrap();
        assert!(fj.org("weebo").is_some());

        let s = ForgejoOrganizationSpec {
            deletion_policy: DeletionPolicy::Delete,
            ..s
        };
        cleanup_organization(&s, created.as_ref(), Ok(&fj))
            .await
            .unwrap();
        assert!(fj.org("weebo").is_none());
    }
}
