//! Layer-3: OAuth2 application and access token controllers, emitting into
//! real Secrets of a real apiserver.

mod support;

use adapters_inbound::controller;
use api::{ForgejoAccessToken, ForgejoOAuth2Application, ForgejoUser};
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
    let users: Api<ForgejoUser> = Api::all(c.clone());
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
    let users: Api<ForgejoUser> = Api::all(c.clone());
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
                            "allowedUsers": ["ci-bot"]}]},
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
                "allowedUsers": ["ci-bot", "admin-bot"]}]}})),
        )
        .await
        .unwrap();
    let issued = wait_for(&tokens, "escalation", |t| {
        condition(t.status.as_ref(), "Ready").filter(|c| c.0 == "True")
    })
    .await;
    assert_eq!(issued.1, "Reconciled");
}
