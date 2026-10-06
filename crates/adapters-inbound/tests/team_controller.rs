//! Layer-3: organization + team + user controllers together — references,
//! the watches that re-trigger dependents, and `MemberPending`.

mod support;

use adapters_inbound::controller;
use api::common::{DeletionPolicy, ManagementPolicy, ObjectRef, Visibility};
use api::organization::ForgejoOrganizationSpec;
use api::team::{ForgejoTeamSpec, TeamPermission};
use api::user::ForgejoUserSpec;
use api::{ForgejoOrganization, ForgejoTeam, ForgejoUser};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use support::{condition, harness, wait_for, wait_for_absence};

fn meta(name: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        ..Default::default()
    }
}

fn org(name: &str) -> ForgejoOrganization {
    ForgejoOrganization {
        metadata: meta(name),
        spec: ForgejoOrganizationSpec {
            instance_ref: None,
            name: name.into(),
            full_name: None,
            description: None,
            website: None,
            location: None,
            email: None,
            visibility: Visibility::Public,
            repo_admin_change_team_access: false,
            owner_ref: None,
            deletion_policy: DeletionPolicy::Orphan,
        },
        status: None,
    }
}

fn team(name: &str, org: &str, members: &[&str]) -> ForgejoTeam {
    ForgejoTeam {
        metadata: meta(name),
        spec: ForgejoTeamSpec {
            instance_ref: None,
            organization_ref: ObjectRef { name: org.into() },
            name: name.into(),
            description: None,
            permission: TeamPermission::Write,
            units_map: Default::default(),
            includes_all_repositories: false,
            can_create_org_repo: false,
            member_refs: members
                .iter()
                .map(|m| ObjectRef {
                    name: m.to_string(),
                })
                .collect(),
            deletion_policy: DeletionPolicy::Delete,
        },
        status: None,
    }
}

fn observed(username: &str) -> ForgejoUser {
    ForgejoUser {
        metadata: meta(username),
        spec: ForgejoUserSpec {
            instance_ref: None,
            username: username.into(),
            management_policy: ManagementPolicy::Observe,
            email: None,
            full_name: None,
            login_source_id: None,
            login_name: None,
            bot: false,
            prohibit_login: false,
            must_change_password: None,
            admin: false,
            restricted: false,
            visibility: Visibility::Public,
            active: true,
            allow_create_organization: None,
            max_repo_creation: None,
            secret_targets: vec![],
            deletion_policy: DeletionPolicy::Orphan,
        },
        status: None,
    }
}

fn team_id(t: &ForgejoTeam) -> Option<i64> {
    t.status.as_ref()?.forgejo_id.as_ref()?.parse().ok()
}

#[tokio::test]
async fn team_waits_for_its_organization_then_syncs() {
    let h = harness().await;
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));
    tokio::spawn(controller::team::run(h.client.clone(), h.ctx.clone()));

    let teams: Api<ForgejoTeam> = Api::all(h.client.clone());
    teams
        .create(&PostParams::default(), &team("devs", "weebo", &[]))
        .await
        .unwrap();
    let waiting = wait_for(&teams, "devs", |t| condition(t.status.as_ref(), "Ready")).await;
    assert_eq!(waiting, ("False".into(), "ReferenceNotFound".into()));

    // The org showing up re-triggers the team through the watch, well
    // before the 30 s retry.
    let orgs: Api<ForgejoOrganization> = Api::all(h.client.clone());
    orgs.create(&PostParams::default(), &org("weebo"))
        .await
        .unwrap();
    let id = wait_for(&teams, "devs", team_id).await;
    assert_eq!(h.forgejo.team(id).unwrap().remote.organization, "weebo");

    teams.delete("devs", &Default::default()).await.unwrap();
    wait_for_absence(&teams, "devs").await;
    assert!(h.forgejo.team(id).is_none(), "teams default to Delete");
}

#[tokio::test]
async fn oidc_member_joins_as_soon_as_it_logs_in() {
    let h = harness().await;
    tokio::spawn(controller::user::run(h.client.clone(), h.ctx.clone()));
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));
    tokio::spawn(controller::team::run(h.client.clone(), h.ctx.clone()));

    let users: Api<ForgejoUser> = Api::all(h.client.clone());
    let orgs: Api<ForgejoOrganization> = Api::all(h.client.clone());
    let teams: Api<ForgejoTeam> = Api::all(h.client.clone());
    users
        .create(&PostParams::default(), &observed("carol"))
        .await
        .unwrap();
    orgs.create(&PostParams::default(), &org("weebo"))
        .await
        .unwrap();
    teams
        .create(&PostParams::default(), &team("devs", "weebo", &["carol"]))
        .await
        .unwrap();

    let pending = wait_for(&teams, "devs", |t| {
        condition(t.status.as_ref(), "MemberPending")
    })
    .await;
    assert_eq!(pending.0, "True");
    let ready = wait_for(&teams, "devs", |t| condition(t.status.as_ref(), "Ready")).await;
    assert_eq!(ready.0, "True", "a pending member doesn't block the team");
    let id = wait_for(&teams, "devs", team_id).await;

    // carol logs in through OIDC; her CR is nudged rather than waiting on
    // its 30 s retry, and the team follows through the user watch.
    h.forgejo.insert_user("carol");
    users
        .patch(
            "carol",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"metadata": {"annotations": {"nudge": "1"}}})),
        )
        .await
        .unwrap();
    wait_for(&teams, "devs", |t| {
        condition(t.status.as_ref(), "MemberPending")
            .is_none()
            .then_some(())
    })
    .await;
    assert_eq!(h.forgejo.team(id).unwrap().members, vec!["carol"]);
}

/// The importer creates CRs with `forgejo.weebo.io/import-pending` and
/// seeds their status before removing it: until then, hands off.
#[tokio::test]
async fn import_pending_cr_is_left_alone() {
    let h = harness().await;
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));
    let orgs: Api<ForgejoOrganization> = Api::all(h.client.clone());
    let mut paused = org("weebo");
    paused.metadata.annotations = Some(
        [(
            api::IMPORT_PENDING_ANNOTATION.to_string(),
            "true".to_string(),
        )]
        .into(),
    );
    orgs.create(&PostParams::default(), &paused).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(h.forgejo.org("weebo").is_none());
    assert!(orgs.get("weebo").await.unwrap().status.is_none());

    orgs.patch(
        "weebo",
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "metadata": { "annotations": {
            api::IMPORT_PENDING_ANNOTATION: null,
        }}})),
    )
    .await
    .unwrap();
    wait_for(&orgs, "weebo", |o| {
        (condition(o.status.as_ref(), "Ready")?.0 == "True").then_some(())
    })
    .await;
    assert!(h.forgejo.org("weebo").is_some());
}
