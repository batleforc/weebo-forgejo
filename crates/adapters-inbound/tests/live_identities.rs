//! Layer-4, identities: users in every mode, organizations, teams, instance
//! selection and failures, and the allow-list as the reconcilers enforce
//! it — every controller against envtest and the live Forgejo
//! (`task test:live-forgejo`; harness in `support::live`).

mod support;

use api::{
    ForgejoInstance, ForgejoNamespacePolicy, ForgejoOrganization, ForgejoRepository, ForgejoTeam,
    ForgejoUser,
};
use application::ports::{
    DesiredOrganization, DesiredUser, ForgejoGateway, ForgejoInventory, RemoteUser,
};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::api::{Api, Patch, PatchParams};
use serde_json::json;
use support::live::{Live, NS, failed_with, live, ready, ready_id, source_id};
use support::{condition, wait_for, wait_for_absence};

/// Forces a reconcile: controllers react to any change of the object.
async fn poke<K>(api: &Api<K>, name: &str)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();
    api.patch(
        name,
        &PatchParams::default(),
        &Patch::Merge(json!({"metadata": {"annotations": {"e2e/poke": nonce}}})),
    )
    .await
    .unwrap();
}

async fn merge<K>(api: &Api<K>, name: &str, patch: serde_json::Value)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    api.patch(name, &PatchParams::default(), &Patch::Merge(patch))
        .await
        .unwrap();
}

fn user(name: &str, spec: serde_json::Value) -> serde_json::Value {
    json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
        "metadata": {"name": name}, "spec": spec,
    })
}

fn org(name: &str, spec: serde_json::Value) -> serde_json::Value {
    json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOrganization",
        "metadata": {"name": name}, "spec": spec,
    })
}

fn team(name: &str, spec: serde_json::Value) -> serde_json::Value {
    json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoTeam",
        "metadata": {"name": name}, "spec": spec,
    })
}

/// A local account created behind the operator's back.
async fn forgejo_user(l: &Live, login: &str) {
    l.fj.create_user(&DesiredUser {
        username: login.into(),
        email: format!("{login}@weebo.local"),
        password: Some("Out-of-band-password-123".into()),
        visibility: "public",
        active: true,
        ..Default::default()
    })
    .await
    .unwrap();
}

async fn remote_user(l: &Live, login: &str) -> Option<RemoteUser> {
    l.fj.get_user(login).await.unwrap()
}

/// `GET /api/v1/user` with basic auth: whether the password logs in.
async fn logs_in(l: &Live, login: &str, password: &str) -> bool {
    reqwest::Client::new()
        .get(format!("{}/api/v1/user", l.url))
        .basic_auth(login, Some(password))
        .send()
        .await
        .unwrap()
        .status()
        .is_success()
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn observed_user_waits_for_the_account_then_publishes_its_id() {
    let l = live().await;
    let users: Api<ForgejoUser> = l.api();
    let login = l.name("carol");
    l.create(
        &users,
        user(
            "carol",
            json!({"username": login, "managementPolicy": "Observe"}),
        ),
    )
    .await;
    wait_for(&users, "carol", |u| {
        failed_with(u.status.as_ref(), "UserNotFound")
    })
    .await;
    assert!(
        remote_user(&l, &login).await.is_none(),
        "Observe never creates"
    );

    forgejo_user(&l, &login).await;
    poke(&users, "carol").await;
    let id = wait_for(&users, "carol", |u| ready_id(u.status.as_ref())).await;
    assert_eq!(remote_user(&l, &login).await.unwrap().id, id);

    // Observe never deletes either, whatever the policy.
    users.delete("carol", &Default::default()).await.unwrap();
    wait_for_absence(&users, "carol").await;
    assert!(remote_user(&l, &login).await.is_some());
    l.fj.delete_user(&login).await.unwrap();
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn local_user_password_is_emitted_and_reset_when_its_secret_is_lost() {
    let l = live().await;
    let users: Api<ForgejoUser> = l.api();
    let secrets: Api<Secret> = l.api();
    let login = l.name("dave");
    l.create(
        &users,
        user(
            "dave",
            json!({
                "username": login, "email": format!("{login}@weebo.local"),
                "mustChangePassword": false,
                "secretTargets": [{"name": "dave-forgejo", "namespace": NS}],
                "deletionPolicy": "Delete",
            }),
        ),
    )
    .await;
    wait_for(&users, "dave", |u| ready(u.status.as_ref())).await;
    let first = l
        .secret_value("dave-forgejo", "FORGEJO_PASSWORD")
        .await
        .unwrap();
    assert_eq!(
        l.secret_value("dave-forgejo", "FORGEJO_USERNAME")
            .await
            .as_deref(),
        Some(login.as_str())
    );
    assert_eq!(
        l.secret_value("dave-forgejo", "FORGEJO_URL")
            .await
            .as_deref(),
        Some(l.url.trim_end_matches('/'))
    );
    assert!(logs_in(&l, &login, &first).await);

    // The password can't be read back: losing the Secret resets it.
    secrets
        .delete("dave-forgejo", &Default::default())
        .await
        .unwrap();
    poke(&users, "dave").await;
    let mut second = None;
    for _ in 0..120 {
        second = l.secret_value("dave-forgejo", "FORGEJO_PASSWORD").await;
        if second.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let second = second.expect("the password was never re-emitted");
    assert_ne!(second, first);
    assert!(logs_in(&l, &login, &second).await);
    assert!(!logs_in(&l, &login, &first).await);

    users.delete("dave", &Default::default()).await.unwrap();
    wait_for_absence(&users, "dave").await;
    assert!(remote_user(&l, &login).await.is_none());
    assert!(secrets.get_opt("dave-forgejo").await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn user_rename_drift_and_orphan_deletion() {
    let l = live().await;
    let users: Api<ForgejoUser> = l.api();
    let login = l.name("erin");
    let renamed = l.name("erin2");
    l.create(
        &users,
        user(
            "erin",
            json!({"username": login, "email": format!("{login}@weebo.local"),
                   "fullName": "Erin", "bot": true}),
        ),
    )
    .await;
    let id = wait_for(&users, "erin", |u| ready_id(u.status.as_ref())).await;

    // Drift made in Forgejo is reverted on the next reconcile.
    let remote = remote_user(&l, &login).await.unwrap();
    l.fj.edit_user(
        &login,
        &DesiredUser {
            username: login.clone(),
            email: remote.email.clone(),
            full_name: Some("Hacked".into()),
            visibility: "public",
            active: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // (Not asserted: the operator may already have reverted it.)
    poke(&users, "erin").await;
    for _ in 0..60 {
        if remote_user(&l, &login).await.unwrap().full_name == "Erin" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(remote_user(&l, &login).await.unwrap().full_name, "Erin");

    // Renaming keeps the account (same id).
    merge(&users, "erin", json!({"spec": {"username": renamed}})).await;
    wait_for(&users, "erin", |u| {
        let s = u.status.as_ref()?;
        ready(Some(s))?;
        (s.forgejo_name.as_deref() == Some(renamed.as_str())).then_some(())
    })
    .await;
    assert_eq!(remote_user(&l, &renamed).await.unwrap().id, id);

    // Default deletionPolicy is Orphan: the account survives its CR.
    users.delete("erin", &Default::default()).await.unwrap();
    wait_for_absence(&users, "erin").await;
    assert!(remote_user(&l, &renamed).await.is_some());
    l.fj.delete_user(&renamed).await.unwrap();
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn bot_user_emits_no_password() {
    let l = live().await;
    let users: Api<ForgejoUser> = l.api();
    let login = l.name("bot");
    l.create(
        &users,
        user(
            "bot",
            json!({"username": login, "email": format!("{login}@weebo.local"), "bot": true,
                   "secretTargets": [{"name": "bot-forgejo", "namespace": NS}],
                   "deletionPolicy": "Delete"}),
        ),
    )
    .await;
    wait_for(&users, "bot", |u| ready(u.status.as_ref())).await;
    assert!(
        l.secret_value("bot-forgejo", "FORGEJO_PASSWORD")
            .await
            .is_none()
    );
    let remote = remote_user(&l, &login).await.unwrap();
    assert!(
        !remote.prohibit_login,
        "a prohibited bot couldn't use tokens"
    );
    users.delete("bot", &Default::default()).await.unwrap();
    wait_for_absence(&users, "bot").await;
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn external_user_is_linked_to_its_authentication_source() {
    let Some(source) = source_id() else {
        eprintln!("FORGEJO_SOURCE_ID unset: skipping");
        return;
    };
    let l = live().await;
    let users: Api<ForgejoUser> = l.api();
    let login = l.name("ext");
    l.create(
        &users,
        user(
            "ext",
            json!({"username": login, "email": format!("{login}@weebo.local"),
                   "loginSourceId": source, "loginName": "ext-subject",
                   "secretTargets": [{"name": "ext-forgejo", "namespace": NS}],
                   "deletionPolicy": "Delete"}),
        ),
    )
    .await;
    wait_for(&users, "ext", |u| ready(u.status.as_ref())).await;
    let remote = remote_user(&l, &login).await.unwrap();
    assert_eq!(remote.source_id, source);
    assert_eq!(remote.login_name, "ext-subject");
    // No password for an external account, whatever secretTargets says.
    assert!(
        l.secret_value("ext-forgejo", "FORGEJO_PASSWORD")
            .await
            .is_none()
    );
    users.delete("ext", &Default::default()).await.unwrap();
    wait_for_absence(&users, "ext").await;
    assert!(remote_user(&l, &login).await.is_none());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn organization_owner_rename_drift_and_collision() {
    let l = live().await;
    let users: Api<ForgejoUser> = l.api();
    let orgs: Api<ForgejoOrganization> = l.api();
    let owner = l.name("owner");
    let name = l.name("org");
    let renamed = l.name("org2");
    l.create(
        &users,
        user(
            "owner",
            json!({"username": owner, "email": format!("{owner}@weebo.local"), "bot": true,
                   "deletionPolicy": "Delete"}),
        ),
    )
    .await;
    l.create(
        &orgs,
        org(
            "weebo",
            json!({"name": name, "description": "managed", "ownerRef": {"name": "owner"},
                   "deletionPolicy": "Delete"}),
        ),
    )
    .await;
    let id = wait_for(&orgs, "weebo", |o| ready_id(o.status.as_ref())).await;

    // ownerRef: that user is in the Owners team.
    let owners =
        l.fj.list_teams(&name)
            .await
            .unwrap()
            .into_iter()
            .find(|t| t.name == "Owners")
            .unwrap();
    assert!(
        l.fj.list_team_members(owners.id)
            .await
            .unwrap()
            .contains(&owner)
    );

    // Drift is reverted.
    l.fj.edit_organization(
        &name,
        &DesiredOrganization {
            name: name.clone(),
            description: Some("hacked".into()),
            visibility: "public",
            ..Default::default()
        },
    )
    .await
    .unwrap();
    poke(&orgs, "weebo").await;
    for _ in 0..60 {
        if l.fj
            .get_organization(&name)
            .await
            .unwrap()
            .unwrap()
            .description
            == "managed"
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(
        l.fj.get_organization(&name)
            .await
            .unwrap()
            .unwrap()
            .description,
        "managed"
    );

    // Rename in place.
    merge(&orgs, "weebo", json!({"spec": {"name": renamed}})).await;
    wait_for(&orgs, "weebo", |o| {
        let s = o.status.as_ref()?;
        ready(Some(s))?;
        (s.forgejo_name.as_deref() == Some(renamed.as_str())).then_some(())
    })
    .await;
    assert_eq!(
        l.fj.get_organization(&renamed).await.unwrap().unwrap().id,
        id
    );

    // A second CR for a name that's taken is a collision, never an adoption.
    l.create(&orgs, org("squatter", json!({"name": renamed})))
        .await;
    wait_for(&orgs, "squatter", |o| {
        failed_with(o.status.as_ref(), "ForgejoObjectAlreadyExists")
    })
    .await;
    assert!(
        orgs.get("squatter")
            .await
            .unwrap()
            .status
            .unwrap()
            .forgejo_id
            .is_none()
    );

    orgs.delete("squatter", &Default::default()).await.unwrap();
    orgs.delete("weebo", &Default::default()).await.unwrap();
    wait_for_absence(&orgs, "squatter").await;
    wait_for_absence(&orgs, "weebo").await;
    assert!(l.fj.get_organization(&renamed).await.unwrap().is_none());
    users.delete("owner", &Default::default()).await.unwrap();
    wait_for_absence(&users, "owner").await;
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn team_members_units_and_gated_move() {
    let l = live().await;
    let users: Api<ForgejoUser> = l.api();
    let orgs: Api<ForgejoOrganization> = l.api();
    let teams: Api<ForgejoTeam> = l.api();
    let (a_org, b_org) = (l.name("torg-a"), l.name("torg-b"));
    let member = l.name("member");
    let pending = l.name("pending");
    let intruder = l.name("intruder");

    l.create(
        &users,
        user(
            "member",
            json!({"username": member, "email": format!("{member}@weebo.local"), "bot": true,
                   "deletionPolicy": "Delete"}),
        ),
    )
    .await;
    l.create(
        &users,
        user(
            "pending",
            json!({"username": pending, "managementPolicy": "Observe"}),
        ),
    )
    .await;
    wait_for(&users, "member", |u| ready(u.status.as_ref())).await;
    for (cr, n) in [("a", &a_org), ("b", &b_org)] {
        l.create(
            &orgs,
            org(cr, json!({"name": n, "deletionPolicy": "Delete"})),
        )
        .await;
    }
    l.create(
        &teams,
        team(
            "devs",
            json!({"organizationRef": {"name": "a"}, "name": "devs", "permission": "write",
                   "unitsMap": {"repo.code": "write", "repo.issues": "read",
                                "repo.pulls": "write"},
                   "memberRefs": [{"name": "member"}, {"name": "pending"}]}),
        ),
    )
    .await;

    // Ready with an advisory while one member doesn't exist yet.
    let id = wait_for(&teams, "devs", |t| {
        let s = t.status.as_ref()?;
        (condition(Some(s), "MemberPending")?.0 == "True").then_some(())?;
        ready_id(Some(s))
    })
    .await;
    assert_eq!(
        l.fj.list_team_members(id).await.unwrap(),
        vec![member.clone()]
    );
    let remote = l.fj.get_team(id).await.unwrap().unwrap();
    assert_eq!(remote.units_map["repo.issues"], "read");
    assert_eq!(remote.units_map["repo.code"], "write");

    // The pending user logs in for the first time: it joins.
    forgejo_user(&l, &pending).await;
    poke(&users, "pending").await;
    wait_for(&teams, "devs", |t| {
        let s = t.status.as_ref()?;
        ready(Some(s))?;
        condition(Some(s), "MemberPending").is_none().then_some(())
    })
    .await;
    let mut members = l.fj.list_team_members(id).await.unwrap();
    members.sort();
    let mut expected = vec![member.clone(), pending.clone()];
    expected.sort();
    assert_eq!(members, expected);

    // Membership is authoritative: an out-of-band member is removed.
    forgejo_user(&l, &intruder).await;
    l.fj.add_team_member(id, &intruder).await.unwrap();
    poke(&teams, "devs").await;
    for _ in 0..60 {
        if !l
            .fj
            .list_team_members(id)
            .await
            .unwrap()
            .contains(&intruder)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(
        !l.fj
            .list_team_members(id)
            .await
            .unwrap()
            .contains(&intruder)
    );

    // Moving to another organization is disruptive: refused, then allowed.
    merge(
        &teams,
        "devs",
        json!({"spec": {"organizationRef": {"name": "b"}}}),
    )
    .await;
    wait_for(&teams, "devs", |t| {
        failed_with(t.status.as_ref(), "DisruptiveUpdateRefused")
    })
    .await;
    assert_eq!(
        l.fj.get_team(id).await.unwrap().unwrap().organization,
        a_org
    );
    merge(
        &teams,
        "devs",
        json!({"metadata": {"annotations": {
            "forgejo.weebo.io/allow-disruptive-update": "true"}}}),
    )
    .await;
    let moved = wait_for(&teams, "devs", |t| {
        let id2 = ready_id(t.status.as_ref())?;
        (id2 != id).then_some(id2)
    })
    .await;
    assert!(l.fj.get_team(id).await.unwrap().is_none());
    assert_eq!(
        l.fj.get_team(moved).await.unwrap().unwrap().organization,
        b_org
    );
    assert_eq!(l.fj.list_team_members(moved).await.unwrap().len(), 2);

    teams.delete("devs", &Default::default()).await.unwrap();
    wait_for_absence(&teams, "devs").await;
    assert!(l.fj.get_team(moved).await.unwrap().is_none());
    for cr in ["a", "b"] {
        orgs.delete(cr, &Default::default()).await.unwrap();
        wait_for_absence(&orgs, cr).await;
    }
    for cr in ["member", "pending"] {
        users.delete(cr, &Default::default()).await.unwrap();
        wait_for_absence(&users, cr).await;
    }
    for login in [&pending, &intruder] {
        l.fj.delete_user(login).await.unwrap();
    }
}

/// `membersPolicy: External`: members added outside the operator (Forgejo's
/// OIDC group sync) survive reconciles that still drive the team itself.
#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn external_team_members_are_left_to_forgejo() {
    let l = live().await;
    let orgs: Api<ForgejoOrganization> = l.api();
    let teams: Api<ForgejoTeam> = l.api();
    let org_name = l.name("ext-org");
    let synced = l.name("synced");

    l.create(
        &orgs,
        org("ext", json!({"name": org_name, "deletionPolicy": "Delete"})),
    )
    .await;
    l.create(
        &teams,
        team(
            "ext",
            json!({"organizationRef": {"name": "ext"}, "name": "devs", "permission": "write",
                   "membersPolicy": "External"}),
        ),
    )
    .await;
    let id = wait_for(&teams, "ext", |t| ready_id(t.status.as_ref())).await;

    // What the group sync does at sign-in, then a reconcile that does
    // change the team: the member stays.
    forgejo_user(&l, &synced).await;
    l.fj.add_team_member(id, &synced).await.unwrap();
    merge(&teams, "ext", json!({"spec": {"description": "synced"}})).await;
    for _ in 0..60 {
        let remote = l.fj.get_team(id).await.unwrap().unwrap();
        if remote.description == "synced" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    wait_for(&teams, "ext", |t| ready(t.status.as_ref())).await;
    assert_eq!(
        l.fj.get_team(id).await.unwrap().unwrap().description,
        "synced"
    );
    assert_eq!(
        l.fj.list_team_members(id).await.unwrap(),
        vec![synced.clone()]
    );

    // memberRefs contradicts External: the API server refuses it (CRD
    // validation rule), Forgejo is left alone.
    let refused = teams
        .patch(
            "ext",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"memberRefs": [{"name": "nobody"}]}})),
        )
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("membersPolicy is External"),
        "{refused}"
    );
    assert_eq!(
        l.fj.list_team_members(id).await.unwrap(),
        vec![synced.clone()]
    );

    teams.delete("ext", &Default::default()).await.unwrap();
    wait_for_absence(&teams, "ext").await;
    orgs.delete("ext", &Default::default()).await.unwrap();
    wait_for_absence(&orgs, "ext").await;
    l.fj.delete_user(&synced).await.unwrap();
}

fn instance(name: &str, url: &str, secret: &str) -> serde_json::Value {
    json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoInstance",
        "metadata": {"name": name},
        "spec": {"url": url,
                 "tokenSecretRef": {"name": secret, "namespace": NS, "key": "token"}},
    })
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn a_second_instance_makes_the_default_ambiguous() {
    let l = live().await;
    let instances: Api<ForgejoInstance> = l.cluster_api();
    let users: Api<ForgejoUser> = l.api();
    l.create(&instances, instance("other", &l.url, "forgejo-admin"))
        .await;
    wait_for(&instances, "other", |i| ready(i.status.as_ref())).await;

    let login = l.name("amb");
    l.create(
        &users,
        user(
            "implicit",
            json!({"username": login, "managementPolicy": "Observe"}),
        ),
    )
    .await;
    wait_for(&users, "implicit", |u| {
        failed_with(u.status.as_ref(), "AmbiguousDefaultInstance")
    })
    .await;

    // Naming the instance works; naming a missing one doesn't.
    forgejo_user(&l, &login).await;
    l.create(
        &users,
        user(
            "explicit",
            json!({"username": login, "managementPolicy": "Observe", "instanceRef": {"name": "main"}}),
        ),
    )
    .await;
    wait_for(&users, "explicit", |u| ready(u.status.as_ref())).await;
    l.create(
        &users,
        user(
            "nowhere",
            json!({"username": login, "managementPolicy": "Observe", "instanceRef": {"name": "nope"}}),
        ),
    )
    .await;
    wait_for(&users, "nowhere", |u| {
        failed_with(u.status.as_ref(), "InstanceNotFound")
    })
    .await;
    l.fj.delete_user(&login).await.unwrap();
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn instance_failures_are_reported() {
    let l = live().await;
    let instances: Api<ForgejoInstance> = l.cluster_api();

    l.create(&instances, instance("no-secret", &l.url, "missing"))
        .await;
    wait_for(&instances, "no-secret", |i| {
        failed_with(i.status.as_ref(), "TokenSecretNotFound")
    })
    .await;

    // Forgejo answers 401 to an unknown token.
    l.secret("bad-token", "token", "not-a-real-token").await;
    l.create(&instances, instance("bad-token", &l.url, "bad-token"))
        .await;
    let message = wait_for(&instances, "bad-token", |i| {
        failed_with(i.status.as_ref(), "ForgejoApiError")?;
        Some(i.status.as_ref()?.conditions[0].message.clone())
    })
    .await;
    assert!(message.contains("401"), "{message}");

    l.create(
        &instances,
        instance("unreachable", "http://127.0.0.1:1", "forgejo-admin"),
    )
    .await;
    wait_for(&instances, "unreachable", |i| {
        failed_with(i.status.as_ref(), "InstanceUnreachable")
    })
    .await;

    // Fixing the Secret is picked up (it's re-read on every reconcile).
    l.secret("missing", "token", &l.token).await;
    poke(&instances, "no-secret").await;
    wait_for(&instances, "no-secret", |i| ready(i.status.as_ref())).await;
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn namespace_policy_is_enforced_by_the_reconcilers() {
    let l = live().await;
    let namespaces: Api<Namespace> = Api::all(l.client.clone());
    l.create(&namespaces, json!({"metadata": {"name": "team-x"}}))
        .await;
    let orgs: Api<ForgejoOrganization> = l.api();
    let policies: Api<ForgejoNamespacePolicy> = l.cluster_api();
    let repos: Api<ForgejoRepository> = Api::namespaced(l.client.clone(), "team-x");
    let org_name = l.name("porg");
    l.create(
        &orgs,
        org(
            "weebo",
            json!({"name": org_name, "deletionPolicy": "Delete"}),
        ),
    )
    .await;
    wait_for(&orgs, "weebo", |o| ready(o.status.as_ref())).await;

    // A policy exists but covers another organization: default-deny.
    l.create(
        &policies,
        json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoNamespacePolicy",
            "metadata": {"name": "teams"},
            "spec": {"rules": [{"namespaces": ["team-*"], "allowedKinds": ["ForgejoRepository"],
                                "allowedOrganizations": ["someone-else"]}]},
        }),
    )
    .await;
    l.create(
        &repos,
        json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoRepository",
            "metadata": {"name": "app"},
            "spec": {"organizationRef": {"name": "weebo"}, "name": "app"},
        }),
    )
    .await;
    wait_for(&repos, "app", |r| {
        failed_with(r.status.as_ref(), "NamespaceNotAllowed")
    })
    .await;
    let full = format!("{org_name}/app");
    assert!(
        l.fj.list_repositories(&org_name, true)
            .await
            .unwrap()
            .is_empty(),
        "a refused CR must not reach Forgejo"
    );

    // Allowing the organization re-reconciles it (policy watch).
    merge(
        &policies,
        "teams",
        json!({"spec": {"rules": [{"namespaces": ["team-*"],
                                    "allowedKinds": ["ForgejoRepository"],
                                    "allowedOrganizations": ["weebo"]}]}}),
    )
    .await;
    let id = wait_for(&repos, "app", |r| ready_id(r.status.as_ref())).await;
    assert_eq!(
        l.fj.get_repository(id).await.unwrap().unwrap().full_name(),
        full
    );

    // A Deny rule wins over the Allow.
    merge(
        &policies,
        "teams",
        json!({"spec": {"rules": [
            {"namespaces": ["team-*"], "allowedKinds": ["ForgejoRepository"],
             "allowedOrganizations": ["weebo"]},
            {"namespaces": ["team-x"], "allowedKinds": ["ForgejoRepository"], "effect": "Deny"},
        ]}}),
    )
    .await;
    wait_for(&repos, "app", |r| {
        failed_with(r.status.as_ref(), "NamespaceNotAllowed")
    })
    .await;
    // Refused, not destroyed: the repository is still there.
    assert!(l.fj.get_repository(id).await.unwrap().is_some());

    policies.delete("teams", &Default::default()).await.unwrap();
    repos.delete("app", &Default::default()).await.unwrap();
    wait_for_absence(&repos, "app").await;
    l.fj.delete_repository(&full).await.unwrap();
    orgs.delete("weebo", &Default::default()).await.unwrap();
    wait_for_absence(&orgs, "weebo").await;
}
