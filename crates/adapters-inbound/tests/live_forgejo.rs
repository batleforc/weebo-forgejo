//! Layer-4: every controller wired like `operator::main` — the real
//! `ForgejoGatewayFactory` reading a token `Secret` through a real
//! `ForgejoInstance`, the real HTTP gateway and `K8sSecretStore` — against a
//! real apiserver (envtest) and a real Forgejo. Ignored by default;
//! `task test:live-forgejo` runs it with `FORGEJO_URL`/`FORGEJO_TOKEN` (see
//! `crates/adapters-outbound/tests/live_forgejo.rs`).

mod support;

use api::common::IdentityRef;
use api::common::{DeletionPolicy, ManagementPolicy, SecretTarget, Visibility};
use api::organization::ForgejoOrganizationSpec;
use api::team::{ForgejoTeamSpec, TeamPermission};
use api::user::ForgejoUserSpec;
use api::{ForgejoOrganization, ForgejoTeam, ForgejoUser};
use application::ports::ForgejoGateway;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, PostParams};
use support::live::{Live, cr, live};
use support::{condition, wait_for, wait_for_absence};

fn meta(name: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        ..Default::default()
    }
}

/// The harness fields the tests below use, owned.
fn parts(l: &Live) -> (kube::Client, String, String, String) {
    (
        l.client.clone(),
        l.url.clone(),
        l.token.clone(),
        l.run.clone(),
    )
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn operator_manages_a_user_an_org_and_a_team_end_to_end() {
    let l = live().await;
    let (client, url, token, run) = parts(&l);
    let username = format!("e2e-alice-{run}");
    let org_name = format!("e2e-org-{run}");
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");

    let users: Api<ForgejoUser> = Api::namespaced(client.clone(), "default");
    users
        .create(
            &PostParams::default(),
            &ForgejoUser {
                metadata: meta("alice"),
                spec: ForgejoUserSpec {
                    instance_ref: None,
                    shared_with: None,
                    username: username.clone(),
                    management_policy: ManagementPolicy::Manage,
                    email: Some(format!("{username}@weebo.local")),
                    full_name: Some("Alice".into()),
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
                        name: "alice-forgejo".into(),
                        namespace: Some("default".into()),
                        path: None,
                    }],
                    deletion_policy: DeletionPolicy::Delete,
                },
                status: None,
            },
        )
        .await
        .unwrap();

    let orgs: Api<ForgejoOrganization> = Api::namespaced(client.clone(), "default");
    orgs.create(
        &PostParams::default(),
        &ForgejoOrganization {
            metadata: meta("weebo"),
            spec: ForgejoOrganizationSpec {
                instance_ref: None,
                shared_with: None,
                name: org_name.clone(),
                full_name: Some("Weebo E2E".into()),
                description: None,
                website: None,
                location: None,
                email: None,
                visibility: Visibility::Private,
                repo_admin_change_team_access: false,
                owner_ref: Some(IdentityRef::named("alice")),
                deletion_policy: DeletionPolicy::Delete,
            },
            status: None,
        },
    )
    .await
    .unwrap();

    let teams: Api<ForgejoTeam> = Api::namespaced(client.clone(), "default");
    teams
        .create(
            &PostParams::default(),
            &ForgejoTeam {
                metadata: meta("devs"),
                spec: ForgejoTeamSpec {
                    instance_ref: None,
                    shared_with: None,
                    organization_ref: IdentityRef::named("weebo"),
                    name: "devs".into(),
                    description: Some("e2e".into()),
                    permission: TeamPermission::Write,
                    units_map: Default::default(),
                    includes_all_repositories: false,
                    can_create_org_repo: false,
                    members_policy: Default::default(),
                    member_refs: vec![IdentityRef::named("alice")],
                    deletion_policy: DeletionPolicy::Delete,
                },
                status: None,
            },
        )
        .await
        .unwrap();

    let team_id: i64 = wait_for(&teams, "devs", |t| {
        let s = t.status.as_ref()?;
        (condition(Some(s), "Ready")?.0 == "True").then_some(())?;
        s.forgejo_id.as_ref()?.parse().ok()
    })
    .await;

    // What the operator did, read back through an independent gateway.
    let (api_base, web) = api::instance::split_urls(&url);
    let fj =
        adapters_outbound::ForgejoHttpGateway::new(api_base, web, token, reqwest::Client::new());
    assert_eq!(
        fj.get_user(&username).await.unwrap().unwrap().full_name,
        "Alice"
    );
    assert_eq!(
        fj.get_organization(&org_name)
            .await
            .unwrap()
            .unwrap()
            .visibility,
        "private"
    );
    assert_eq!(
        fj.list_team_members(team_id).await.unwrap(),
        vec![username.clone()]
    );
    assert!(secrets.get_opt("alice-forgejo").await.unwrap().is_some());

    // Teardown through the finalizers, all with deletionPolicy: Delete.
    teams.delete("devs", &Default::default()).await.unwrap();
    wait_for_absence(&teams, "devs").await;
    orgs.delete("weebo", &Default::default()).await.unwrap();
    wait_for_absence(&orgs, "weebo").await;
    users.delete("alice", &Default::default()).await.unwrap();
    wait_for_absence(&users, "alice").await;
    assert!(fj.get_team(team_id).await.unwrap().is_none());
    assert!(fj.get_organization(&org_name).await.unwrap().is_none());
    assert!(fj.get_user(&username).await.unwrap().is_none());
    assert!(secrets.get_opt("alice-forgejo").await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn operator_manages_repositories_hooks_and_keys_end_to_end() {
    use api::{ForgejoDeployKey, ForgejoRepository, ForgejoUserKey, ForgejoWebhook};
    use serde_json::json;

    let l = live().await;
    let (client, url, token, run) = parts(&l);
    let org_name = format!("e2e-rorg-{run}");
    let bot = format!("e2e-bot-{run}");
    let pp = PostParams::default();

    let users: Api<ForgejoUser> = Api::namespaced(client.clone(), "default");
    let orgs: Api<ForgejoOrganization> = Api::namespaced(client.clone(), "default");
    let teams: Api<ForgejoTeam> = Api::namespaced(client.clone(), "default");
    let repos: Api<ForgejoRepository> = Api::namespaced(client.clone(), "default");
    let hooks: Api<ForgejoWebhook> = Api::namespaced(client.clone(), "default");
    let deploy_keys: Api<ForgejoDeployKey> = Api::namespaced(client.clone(), "default");
    let user_keys: Api<ForgejoUserKey> = Api::namespaced(client.clone(), "default");
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");

    users
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                "metadata": {"name": "bot"},
                "spec": {"username": bot, "email": format!("{bot}@weebo.local"), "bot": true,
                         "deletionPolicy": "Delete"},
            })),
        )
        .await
        .unwrap();
    orgs.create(
        &pp,
        &cr(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOrganization",
            "metadata": {"name": "weebo"},
            "spec": {"name": org_name, "deletionPolicy": "Delete"},
        })),
    )
    .await
    .unwrap();
    teams.create(&pp, &cr(json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoTeam",
        "metadata": {"name": "devs"},
        "spec": {"organizationRef": {"name": "weebo"}, "name": "devs", "permission": "write"},
    }))).await.unwrap();
    repos
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoRepository",
                "metadata": {"name": "app"},
                "spec": {
                    "organizationRef": {"name": "weebo"},
                    "name": "app",
                    "description": "e2e",
                    "init": {"readme": "Default"},
                    "units": {"wiki": false},
                    "teamRefs": [{"name": "devs"}],
                    "branchProtections": [{
                        "ruleName": "main", "enablePush": true,
                        "pushWhitelistTeams": ["devs"], "requiredApprovals": 1,
                    }],
                    "deletionPolicy": "Delete",
                },
            })),
        )
        .await
        .unwrap();

    let ready_id = |s: Option<&api::ForgejoStatus>| -> Option<i64> {
        (condition(s, "Ready")?.0 == "True").then_some(())?;
        s?.forgejo_id.as_ref()?.parse().ok()
    };
    let repo_id = wait_for(&repos, "app", |r| ready_id(r.status.as_ref())).await;

    let fj = {
        let (api_base, web) = api::instance::split_urls(&url);
        adapters_outbound::ForgejoHttpGateway::new(
            api_base,
            web,
            token.clone(),
            reqwest::Client::new(),
        )
    };
    let full = format!("{org_name}/app");
    let repo = fj.get_repository(repo_id).await.unwrap().unwrap();
    assert_eq!(repo.full_name(), full);
    assert!(!repo.has_wiki);
    let protections = fj.list_branch_protections(&full).await.unwrap();
    assert_eq!(protections[0].push_whitelist_teams, vec!["devs"]);

    // Steady state: a forced re-reconcile must not change anything.
    let resource_version = repos.get("app").await.unwrap().metadata.resource_version;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        repos.get("app").await.unwrap().metadata.resource_version,
        resource_version,
        "a synced repository must not keep rewriting its status"
    );

    secrets
        .create(
            &pp,
            &cr(json!({
                "metadata": {"name": "hook",
                             "labels": {"forgejo.weebo.io/credential": "true"}},
                "stringData": {"hmac": "k1"},
            })),
        )
        .await
        .unwrap();
    hooks.create(&pp, &cr(json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoWebhook",
        "metadata": {"name": "ci"},
        "spec": {"repositoryRef": {"name": "app"}, "url": "https://ci.example.com/hook",
                 "events": ["push", "pull_request"], "secretRef": {"name": "hook", "key": "hmac"}},
    }))).await.unwrap();
    let hook_id = wait_for(&hooks, "ci", |h| ready_id(h.status.as_ref())).await;
    let target = application::ports::HookTarget::Repository {
        owner: org_name.clone(),
        name: "app".into(),
    };
    let hook = fj.get_hook(&target, hook_id).await.unwrap().unwrap();
    assert_eq!(hook.config["url"], "https://ci.example.com/hook");

    deploy_keys
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoDeployKey",
                "metadata": {"name": "ci-key"},
                "spec": {"repositoryRef": {"name": "app"}, "secretTargets": [{"name": "ci-key"}]},
            })),
        )
        .await
        .unwrap();
    let key_id = wait_for(&deploy_keys, "ci-key", |k| ready_id(k.status.as_ref())).await;
    let public = String::from_utf8(
        secrets.get("ci-key").await.unwrap().data.unwrap()["ssh-publickey"]
            .0
            .clone(),
    )
    .unwrap();
    let remote = fj.get_deploy_key(&full, key_id).await.unwrap().unwrap();
    assert!(
        public.starts_with(&remote.key),
        "{public} vs {}",
        remote.key
    );

    user_keys
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUserKey",
                "metadata": {"name": "bot-key"},
                "spec": {"userRef": {"name": "bot"},
                         "secretTargets": [{"name": "bot-key", "namespace": "default"}]},
            })),
        )
        .await
        .unwrap();
    let user_key_id = wait_for(&user_keys, "bot-key", |k| ready_id(k.status.as_ref())).await;
    assert!(fj.get_user_key(&bot, user_key_id).await.unwrap().is_some());

    // Teardown in dependency order, everything with deletionPolicy Delete.
    hooks.delete("ci", &Default::default()).await.unwrap();
    deploy_keys
        .delete("ci-key", &Default::default())
        .await
        .unwrap();
    user_keys
        .delete("bot-key", &Default::default())
        .await
        .unwrap();
    wait_for_absence(&hooks, "ci").await;
    wait_for_absence(&deploy_keys, "ci-key").await;
    wait_for_absence(&user_keys, "bot-key").await;
    assert!(fj.get_hook(&target, hook_id).await.unwrap().is_none());
    assert!(fj.get_user_key(&bot, user_key_id).await.unwrap().is_none());

    repos.delete("app", &Default::default()).await.unwrap();
    wait_for_absence(&repos, "app").await;
    assert!(fj.get_repository(repo_id).await.unwrap().is_none());
    teams.delete("devs", &Default::default()).await.unwrap();
    wait_for_absence(&teams, "devs").await;
    orgs.delete("weebo", &Default::default()).await.unwrap();
    users.delete("bot", &Default::default()).await.unwrap();
    wait_for_absence(&orgs, "weebo").await;
    wait_for_absence(&users, "bot").await;
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn operator_issues_oauth2_credentials_and_tokens_end_to_end() {
    use api::{ForgejoAccessToken, ForgejoOAuth2Application};
    use serde_json::json;

    let l = live().await;
    let (client, url, _token, run) = parts(&l);
    let bot = format!("e2e-sso-{run}");
    let pp = PostParams::default();
    let users: Api<ForgejoUser> = Api::namespaced(client.clone(), "default");
    let apps: Api<ForgejoOAuth2Application> = Api::namespaced(client.clone(), "default");
    let tokens: Api<ForgejoAccessToken> = Api::namespaced(client.clone(), "default");
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");
    let read = |secret: &Secret, key: &str| {
        String::from_utf8(secret.data.as_ref().unwrap()[key].0.clone()).unwrap()
    };

    users
        .create(
            &pp,
            &cr(json!({
                "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoUser",
                "metadata": {"name": "sso-bot"},
                "spec": {"username": bot, "email": format!("{bot}@weebo.local"), "bot": true,
                         "deletionPolicy": "Delete"},
            })),
        )
        .await
        .unwrap();
    apps.create(
        &pp,
        &cr(json!({
            "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": "ForgejoOAuth2Application",
            "metadata": {"name": "grafana"},
            "spec": {"ownerRef": {"name": "sso-bot"},
                     "redirectUris": ["https://grafana.example.com/login/generic_oauth"]},
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
                "spec": {"userRef": {"name": "sso-bot"}, "scopes": ["read:user"]},
            })),
        )
        .await
        .unwrap();

    let ready = |s: Option<&api::ForgejoStatus>| -> Option<()> {
        (condition(s, "Ready")?.0 == "True").then_some(())
    };
    wait_for(&apps, "grafana", |a| ready(a.status.as_ref())).await;
    wait_for(&tokens, "ci", |t| ready(t.status.as_ref())).await;

    // Default targets: a Secret named after each CR, in its namespace.
    let oauth = secrets.get("grafana").await.unwrap();
    assert!(!read(&oauth, "FORGEJO_CLIENT_ID").is_empty());
    assert!(!read(&oauth, "FORGEJO_CLIENT_SECRET").is_empty());
    let first_secret = read(&oauth, "FORGEJO_CLIENT_SECRET");

    // The emitted token really authenticates as the bot.
    let token = read(&secrets.get("ci").await.unwrap(), "FORGEJO_TOKEN");
    let me: serde_json::Value = reqwest::Client::new()
        .get(format!("{url}/api/v1/user"))
        .header("Authorization", format!("token {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["login"], bot.as_str());

    // Steady state: the client secret is not regenerated by requeues.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        read(
            &secrets.get("grafana").await.unwrap(),
            "FORGEJO_CLIENT_SECRET"
        ),
        first_secret
    );

    // Rotation through the annotation: same app, new secret.
    apps.patch(
        "grafana",
        &kube::api::PatchParams::default(),
        &kube::api::Patch::Merge(json!({
            "metadata": {"annotations": {"forgejo.weebo.io/rotate-secret": "1"}}
        })),
    )
    .await
    .unwrap();
    wait_for(&apps, "grafana", |a| {
        (a.status.as_ref()?.last_rotation.as_deref() == Some("1")).then_some(())
    })
    .await;
    assert_ne!(
        read(
            &secrets.get("grafana").await.unwrap(),
            "FORGEJO_CLIENT_SECRET"
        ),
        first_secret
    );

    apps.delete("grafana", &Default::default()).await.unwrap();
    tokens.delete("ci", &Default::default()).await.unwrap();
    wait_for_absence(&apps, "grafana").await;
    wait_for_absence(&tokens, "ci").await;
    assert!(secrets.get_opt("grafana").await.unwrap().is_none());
    let revoked = reqwest::Client::new()
        .get(format!("{url}/api/v1/user"))
        .header("Authorization", format!("token {token}"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(revoked, 401, "deleting the CR revokes the token");
    users.delete("sso-bot", &Default::default()).await.unwrap();
    wait_for_absence(&users, "sso-bot").await;
}
