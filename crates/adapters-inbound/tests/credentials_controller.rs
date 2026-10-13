//! Layer-3: OAuth2 application and access token controllers, emitting into
//! real Secrets of a real apiserver.

mod support;

use adapters_inbound::controller;
use api::{ForgejoAccessToken, ForgejoOAuth2Application, ForgejoUser, ForgejoUserKey};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams, PostParams};
use serde_json::json;
use support::{condition, harness, wait_for, wait_for_absence};

fn cr<K: serde::de::DeserializeOwned>(value: serde_json::Value) -> K {
    serde_json::from_value(value).expect("manifest must match the CRD")
}

fn read(secret: &Secret, key: &str) -> String {
    String::from_utf8(secret.data.as_ref().unwrap()[key].0.clone()).unwrap()
}

#[tokio::test]
async fn oauth2_app_and_token_emit_credentials() {
    let h = harness().await;
    let (c, ctx) = (&h.client, &h.ctx);
    tokio::spawn(controller::user::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::oauth2::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::token::run(c.clone(), ctx.clone()));

    let pp = PostParams::default();
    let users: Api<ForgejoUser> = Api::namespaced(c.clone(), "default");
    let apps: Api<ForgejoOAuth2Application> = Api::namespaced(c.clone(), "default");
    let tokens: Api<ForgejoAccessToken> = Api::namespaced(c.clone(), "default");
    let secrets: Api<Secret> = Api::namespaced(c.clone(), "default");

    users
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                "metadata": {"name": "sso-bot"},
                "spec": {"username": "sso-bot", "email": "sso-bot@example.com", "bot": true},
            })),
        )
        .await
        .unwrap();
    apps.create(
        &pp,
        &cr(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOAuth2Application",
            "metadata": {"name": "grafana"},
            "spec": {"ownerRef": {"name": "sso-bot"}, "redirectUris": ["https://g/cb"]},
        })),
    )
    .await
    .unwrap();
    tokens
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
                "metadata": {"name": "ci"},
                "spec": {"userRef": {"name": "sso-bot"}, "scopes": ["read:user"],
                         "secretTargets": [{"name": "ci-token"}, {"name": "ci-token-copy"}]},
            })),
        )
        .await
        .unwrap();

    let app_id: i64 = wait_for(&apps, "grafana", |a| {
        let s = a.status.as_ref()?;
        (condition(Some(s), "Ready")?.0 == "True").then_some(())?;
        s.forgejo_id.as_ref()?.parse().ok()
    })
    .await;
    let (owner, app, secret) = h.forgejo.oauth2_app(app_id).unwrap();
    assert_eq!(owner, "sso-bot", "created through Sudo as the owner");
    let emitted = secrets.get("grafana").await.unwrap();
    assert_eq!(read(&emitted, "FORGEJO_CLIENT_ID"), app.client_id);
    assert_eq!(read(&emitted, "FORGEJO_CLIENT_SECRET"), secret);

    let token_id: i64 = wait_for(&tokens, "ci", |t| {
        let s = t.status.as_ref()?;
        (condition(Some(s), "Ready")?.0 == "True").then_some(())?;
        s.forgejo_id.as_ref()?.parse().ok()
    })
    .await;
    let (_, value) = h.forgejo.token(token_id).unwrap();
    for target in ["ci-token", "ci-token-copy"] {
        assert_eq!(
            read(&secrets.get(target).await.unwrap(), "FORGEJO_TOKEN"),
            value
        );
    }

    // A scope change without the annotation is refused, not applied.
    tokens
        .patch(
            "ci",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"scopes": ["write:repository"]}})),
        )
        .await
        .unwrap();
    let refused = wait_for(&tokens, "ci", |t| {
        condition(t.status.as_ref(), "Ready").filter(|c| c.0 == "False")
    })
    .await;
    assert_eq!(refused.1, "DisruptiveUpdateRefused");
    assert!(h.forgejo.token(token_id).is_some(), "old token untouched");

    apps.delete("grafana", &Default::default()).await.unwrap();
    tokens.delete("ci", &Default::default()).await.unwrap();
    wait_for_absence(&apps, "grafana").await;
    wait_for_absence(&tokens, "ci").await;
    assert!(h.forgejo.oauth2_app(app_id).is_none());
    assert!(h.forgejo.token(token_id).is_none());
    assert!(secrets.get_opt("ci-token-copy").await.unwrap().is_none());
}

#[tokio::test]
async fn namespace_policy_gates_tokens_per_user() {
    use api::ForgejoNamespacePolicy;

    let h = harness().await;
    let (c, ctx) = (&h.client, &h.ctx);
    tokio::spawn(controller::user::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::token::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::namespace_policy::run(c.clone(), ctx.clone()));

    let pp = PostParams::default();
    let users: Api<ForgejoUser> = Api::namespaced(c.clone(), "default");
    let policies: Api<ForgejoNamespacePolicy> = Api::all(c.clone());
    let tokens: Api<ForgejoAccessToken> = Api::namespaced(c.clone(), "default");
    for name in ["ci-bot", "admin-bot"] {
        users
            .create(
                &pp,
                &cr(json!({
                    "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                    "metadata": {"name": name},
                    "spec": {"username": name, "email": format!("{name}@example.com"), "bot": true},
                })),
            )
            .await
            .unwrap();
    }
    policies.create(&pp, &cr(json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoNamespacePolicy",
        "metadata": {"name": "tokens"},
        "spec": {"rules": [{"namespaces": ["default"], "allowedKinds": ["ForgejoAccessToken"],
                            "allowedUsers": ["ci-bot"]},
                           // The accounts themselves: the policy governs them too.
                           {"namespaces": ["default"], "allowedKinds": ["ForgejoUser"]}]},
    }))).await.unwrap();
    let policy_ready = wait_for(&policies, "tokens", |p| {
        condition(p.status.as_ref(), "Ready")
    })
    .await;
    assert_eq!(policy_ready.0, "True");

    tokens
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
                "metadata": {"name": "escalation"},
                "spec": {"userRef": {"name": "admin-bot"}, "scopes": ["all"]},
            })),
        )
        .await
        .unwrap();
    let denied = wait_for(&tokens, "escalation", |t| {
        condition(t.status.as_ref(), "Ready")
    })
    .await;
    assert_eq!(denied, ("False".into(), "NamespaceNotAllowed".into()));
    assert!(
        h.forgejo
            .calls()
            .iter()
            .all(|c| !c.starts_with("create_access_token")),
        "nothing issued for a denied CR"
    );

    // Widening the policy re-triggers the token through the policy watch.
    policies
        .patch(
            "tokens",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"rules": [{
                "namespaces": ["default"], "allowedKinds": ["ForgejoAccessToken"],
                "allowedUsers": ["ci-bot", "admin-bot"]},
                {"namespaces": ["default"], "allowedKinds": ["ForgejoUser"]}]}})),
        )
        .await
        .unwrap();
    let issued = wait_for(&tokens, "escalation", |t| {
        condition(t.status.as_ref(), "Ready").filter(|c| c.0 == "True")
    })
    .await;
    assert_eq!(issued.1, "Reconciled");
}

#[tokio::test]
async fn site_admin_tokens_are_refused_and_revoked() {
    let h = harness().await;
    let (c, ctx) = (&h.client, &h.ctx);
    tokio::spawn(controller::user::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::token::run(c.clone(), ctx.clone()));

    let pp = PostParams::default();
    let users: Api<ForgejoUser> = Api::namespaced(c.clone(), "default");
    let tokens: Api<ForgejoAccessToken> = Api::namespaced(c.clone(), "default");
    // An observed account: its CR says nothing of its flags.
    h.forgejo.insert_user("root");
    users
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                "metadata": {"name": "root"},
                "spec": {"username": "root", "managementPolicy": "Observe"},
            })),
        )
        .await
        .unwrap();
    users
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                "metadata": {"name": "ci-bot"},
                "spec": {"username": "ci-bot", "email": "ci-bot@example.com", "bot": true},
            })),
        )
        .await
        .unwrap();
    for (name, user) in [("observed", "root"), ("ci", "ci-bot")] {
        tokens
            .create(
                &pp,
                &cr(json!({
                    "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
                    "metadata": {"name": name},
                    "spec": {"userRef": {"name": user}, "scopes": ["read:user"],
                             "secretTargets": [{"name": format!("{name}-token")}]},
                })),
            )
            .await
            .unwrap();
    }
    let denied = wait_for(&tokens, "observed", |t| {
        condition(t.status.as_ref(), "Ready")
    })
    .await;
    assert_eq!(denied, ("False".into(), "NamespaceNotAllowed".into()));

    let token_id: i64 = wait_for(&tokens, "ci", |t| {
        let s = t.status.as_ref()?;
        (condition(Some(s), "Ready")?.0 == "True").then_some(())?;
        s.forgejo_id.as_ref()?.parse().ok()
    })
    .await;
    // Made a site admin by hand in Forgejo: the issued token is revoked at
    // the next reconcile.
    h.forgejo.set_admin("ci-bot", true);
    tokens
        .patch(
            "ci",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"annotations": {"touch": "1"}}})),
        )
        .await
        .unwrap();
    let revoked = wait_for(&tokens, "ci", |t| {
        let s = t.status.as_ref()?;
        let ready = condition(Some(s), "Ready").filter(|c| c.0 == "False")?;
        s.forgejo_id.is_none().then_some(ready)
    })
    .await;
    assert_eq!(revoked.1, "NamespaceNotAllowed");
    assert!(h.forgejo.token(token_id).is_none(), "revoked in Forgejo");
}

/// The account behind an OAuth2 application and an SSH key becomes a
/// site admin in Forgejo: both are deleted, like a token, not left to live.
#[tokio::test]
async fn site_admin_applications_and_keys_are_revoked() {
    let h = harness().await;
    let (c, ctx) = (&h.client, &h.ctx);
    tokio::spawn(controller::user::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::oauth2::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::user_key::run(c.clone(), ctx.clone()));

    let pp = PostParams::default();
    let users: Api<ForgejoUser> = Api::namespaced(c.clone(), "default");
    let apps: Api<ForgejoOAuth2Application> = Api::namespaced(c.clone(), "default");
    let keys: Api<ForgejoUserKey> = Api::namespaced(c.clone(), "default");
    users
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                "metadata": {"name": "sso-bot"},
                "spec": {"username": "sso-bot", "email": "sso-bot@example.com", "bot": true},
            })),
        )
        .await
        .unwrap();
    apps.create(
        &pp,
        &cr(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOAuth2Application",
            "metadata": {"name": "grafana"},
            "spec": {"ownerRef": {"name": "sso-bot"}, "redirectUris": ["https://g/cb"]},
        })),
    )
    .await
    .unwrap();
    keys.create(
        &pp,
        &cr(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUserKey",
            "metadata": {"name": "push"},
            "spec": {"userRef": {"name": "sso-bot"}, "secretTargets": [{"name": "push-key"}]},
        })),
    )
    .await
    .unwrap();
    let ready_id = |s: Option<&api::status::ForgejoStatus>| -> Option<i64> {
        let s = s?;
        (condition(Some(s), "Ready")?.0 == "True").then_some(())?;
        s.forgejo_id.as_ref()?.parse().ok()
    };
    let app_id = wait_for(&apps, "grafana", |a| ready_id(a.status.as_ref())).await;
    let key_id = wait_for(&keys, "push", |k| ready_id(k.status.as_ref())).await;

    // Made a site admin by hand in Forgejo: what was issued goes at the
    // next reconcile.
    h.forgejo.set_admin("sso-bot", true);
    let touch = Patch::Merge(json!({"metadata": {"annotations": {"touch": "1"}}}));
    let params = PatchParams::default();
    apps.patch("grafana", &params, &touch).await.unwrap();
    keys.patch("push", &params, &touch).await.unwrap();
    let released = |s: Option<&api::status::ForgejoStatus>| {
        let s = s?;
        let ready = condition(Some(s), "Ready").filter(|c| c.0 == "False")?;
        s.forgejo_id.is_none().then_some(ready)
    };
    let app = wait_for(&apps, "grafana", |a| released(a.status.as_ref())).await;
    assert_eq!(app.1, "NamespaceNotAllowed");
    assert!(h.forgejo.oauth2_app(app_id).is_none(), "deleted in Forgejo");
    let key = wait_for(&keys, "push", |k| released(k.status.as_ref())).await;
    assert_eq!(key.1, "NamespaceNotAllowed");
    assert!(h.forgejo.key(key_id).is_none(), "deleted in Forgejo");
}

#[tokio::test]
async fn a_token_name_is_claimed_once_per_user() {
    let h = harness().await;
    let (c, ctx) = (&h.client, &h.ctx);
    tokio::spawn(controller::user::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::token::run(c.clone(), ctx.clone()));

    let pp = PostParams::default();
    // The instance the harness resolves to: its URL is the server the
    // claim compares.
    Api::<api::ForgejoInstance>::all(c.clone())
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoInstance",
                "metadata": {"name": "default"},
                "spec": {"url": "https://git.example.com",
                         "tokenSecretRef": {"name": "t", "namespace": "default", "key": "token"}},
            })),
        )
        .await
        .unwrap();
    let users: Api<ForgejoUser> = Api::namespaced(c.clone(), "default");
    let tokens: Api<ForgejoAccessToken> = Api::namespaced(c.clone(), "default");
    users
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                "metadata": {"name": "ci-bot"},
                "spec": {"username": "ci-bot", "email": "ci-bot@example.com", "bot": true},
            })),
        )
        .await
        .unwrap();
    let token = |name: &str| {
        cr::<ForgejoAccessToken>(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoAccessToken",
            "metadata": {"name": name},
            "spec": {"userRef": {"name": "ci-bot"}, "name": "deploy", "scopes": ["read:user"],
                     "secretTargets": [{"name": format!("{name}-token")}]},
        }))
    };
    tokens.create(&pp, &token("first")).await.unwrap();
    let first: i64 = wait_for(&tokens, "first", |t| {
        let s = t.status.as_ref()?;
        (condition(Some(s), "Ready")?.0 == "True").then_some(())?;
        s.forgejo_id.as_ref()?.parse().ok()
    })
    .await;
    tokens.create(&pp, &token("second")).await.unwrap();
    let claimed = wait_for(&tokens, "second", |t| {
        condition(t.status.as_ref(), "Ready").filter(|c| c.1 == "RemoteObjectClaimed")
    })
    .await;
    assert_eq!(claimed.0, "False");
    assert!(h.forgejo.token(first).is_some(), "the first one untouched");
}
