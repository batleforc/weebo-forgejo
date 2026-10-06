//! Layer-3: the real `ForgejoUser` controller against a real apiserver.

mod support;

use std::collections::BTreeMap;

use adapters_inbound::controller;
use api::ForgejoUser;
use api::common::{DeletionPolicy, ManagementPolicy, SecretTarget, Visibility};
use api::user::ForgejoUserSpec;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use support::{condition, harness, wait_for, wait_for_absence};

fn user(name: &str, spec: ForgejoUserSpec) -> ForgejoUser {
    ForgejoUser {
        metadata: ObjectMeta {
            name: Some(name.into()),
            ..Default::default()
        },
        spec,
        status: None,
    }
}

fn local_spec(username: &str) -> ForgejoUserSpec {
    ForgejoUserSpec {
        instance_ref: None,
        username: username.into(),
        management_policy: ManagementPolicy::Manage,
        email: Some(format!("{username}@example.com")),
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
        secret_targets: vec![SecretTarget {
            backend: Default::default(),
            name: format!("{username}-forgejo"),
            namespace: Some("default".into()),
            path: None,
        }],
        deletion_policy: DeletionPolicy::Orphan,
    }
}

#[tokio::test]
async fn local_user_gets_an_id_a_secret_and_is_orphaned_on_delete() {
    let h = harness().await;
    tokio::spawn(controller::user::run(h.client.clone(), h.ctx.clone()));

    let users: Api<ForgejoUser> = Api::all(h.client.clone());
    users
        .create(&PostParams::default(), &user("alice", local_spec("alice")))
        .await
        .unwrap();

    let id = wait_for(&users, "alice", |u| u.status.as_ref()?.forgejo_id.clone()).await;
    assert_eq!(id, h.forgejo.user("alice").unwrap().remote.id.to_string());
    let ready = wait_for(&users, "alice", |u| condition(u.status.as_ref(), "Ready")).await;
    assert_eq!(ready, ("True".into(), "Reconciled".into()));

    let secrets: Api<Secret> = Api::namespaced(h.client.clone(), "default");
    let secret = secrets.get("alice-forgejo").await.unwrap();
    let data: BTreeMap<_, _> = secret.data.unwrap().into_iter().collect();
    let password = String::from_utf8(data["FORGEJO_PASSWORD"].0.clone()).unwrap();
    assert_eq!(h.forgejo.user("alice").unwrap().password, Some(password));

    users.delete("alice", &Default::default()).await.unwrap();
    wait_for_absence(&users, "alice").await;
    assert!(
        h.forgejo.user("alice").is_some(),
        "Orphan keeps the account"
    );
    assert!(secrets.get_opt("alice-forgejo").await.unwrap().is_none());
}

#[tokio::test]
async fn observed_user_becomes_ready_once_it_exists() {
    let h = harness().await;
    tokio::spawn(controller::user::run(h.client.clone(), h.ctx.clone()));

    let users: Api<ForgejoUser> = Api::all(h.client.clone());
    let mut spec = local_spec("carol");
    spec.management_policy = ManagementPolicy::Observe;
    spec.email = None;
    spec.secret_targets.clear();
    users
        .create(&PostParams::default(), &user("carol", spec))
        .await
        .unwrap();

    let pending = wait_for(&users, "carol", |u| condition(u.status.as_ref(), "Ready")).await;
    assert_eq!(pending, ("False".into(), "UserNotFound".into()));

    let id = h.forgejo.insert_user("carol");
    // Nudge a reconcile instead of waiting for the 30 s retry.
    users
        .patch(
            "carol",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"metadata": {"annotations": {"nudge": "1"}}})),
        )
        .await
        .unwrap();
    let observed = wait_for(&users, "carol", |u| {
        u.status
            .as_ref()?
            .forgejo_id
            .clone()
            .filter(|_| condition(u.status.as_ref(), "Ready").is_some_and(|c| c.0 == "True"))
    })
    .await;
    assert_eq!(observed, id.to_string());
}

#[tokio::test]
async fn invalid_spec_is_reported_without_touching_forgejo() {
    let h = harness().await;
    tokio::spawn(controller::user::run(h.client.clone(), h.ctx.clone()));

    let users: Api<ForgejoUser> = Api::all(h.client.clone());
    let mut spec = local_spec("dave");
    spec.secret_targets.clear();
    users
        .create(&PostParams::default(), &user("dave", spec))
        .await
        .unwrap();

    let ready = wait_for(&users, "dave", |u| condition(u.status.as_ref(), "Ready")).await;
    assert_eq!(ready, ("False".into(), "InvalidSpec".into()));
    assert!(h.forgejo.calls().is_empty());
}
