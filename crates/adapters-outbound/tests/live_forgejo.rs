//! Layer-4: the real `ForgejoHttpGateway` against a real Forgejo. Ignored
//! by default; `task test:live-forgejo` runs it with:
//!
//! - `FORGEJO_URL` — e.g. `http://localhost:3000` (the devfile sidecar)
//! - `FORGEJO_TOKEN` — an all-scope site-admin token (`task forgejo:bootstrap`)
//! - `FORGEJO_SOURCE_ID` — optional id of an OAuth2 authentication source,
//!   to cover external users
//!
//! Object names carry a per-run suffix so reruns don't collide.

use adapters_outbound::ForgejoHttpGateway;
use application::ports::{
    DesiredOrganization, DesiredTeam, DesiredUser, ForgejoGateway, GatewayError,
};

fn gateway() -> ForgejoHttpGateway {
    let url = std::env::var("FORGEJO_URL").expect("FORGEJO_URL");
    let token = std::env::var("FORGEJO_TOKEN").expect("FORGEJO_TOKEN");
    let (api, web) = api::instance::split_urls(&url);
    ForgejoHttpGateway::new(api, web, token, reqwest::Client::new())
}

fn suffix() -> String {
    format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 1_000_000
    )
}

fn local_user(username: &str) -> DesiredUser {
    DesiredUser {
        username: username.into(),
        email: format!("{username}@weebo.local"),
        password: Some("Live-test-password-123".into()),
        must_change_password: true,
        visibility: "public",
        active: true,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn version_is_v16_or_later() {
    let version = gateway().server_version().await.unwrap();
    let major: u64 = version
        .split(['.', '-', '+'])
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(major >= 16, "{version}");
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn user_lifecycle() {
    let gw = gateway();
    let name = format!("live-user-{}", suffix());

    let created = gw.create_user(&local_user(&name)).await.unwrap();
    assert!(matches!(
        gw.create_user(&local_user(&name)).await,
        Err(GatewayError::AlreadyExists(_))
    ));

    // Edit-only fields round-trip through get_user.
    let mut desired = local_user(&name);
    desired.password = None;
    desired.admin = true;
    desired.prohibit_login = true;
    desired.visibility = "limited";
    desired.full_name = Some("Live Test".into());
    gw.edit_user(&name, &desired).await.unwrap();
    let remote = gw.get_user(&name).await.unwrap().unwrap();
    assert_eq!(remote.id, created.id);
    assert!(remote.admin);
    assert!(remote.prohibit_login);
    assert_eq!(remote.visibility, "limited");
    assert_eq!(remote.full_name, "Live Test");

    let renamed = format!("{name}-r");
    gw.rename_user(&name, &renamed).await.unwrap();
    assert!(
        gw.get_user(&name).await.unwrap().is_none(),
        "the old login redirects, but must read as absent"
    );
    assert_eq!(gw.get_user(&renamed).await.unwrap().unwrap().id, created.id);

    gw.delete_user(&renamed).await.unwrap();
    assert!(gw.get_user(&renamed).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn external_user_needs_no_password() {
    let Ok(source_id) = std::env::var("FORGEJO_SOURCE_ID") else {
        eprintln!("FORGEJO_SOURCE_ID unset, skipping");
        return;
    };
    let gw = gateway();
    let name = format!("live-ext-{}", suffix());
    let mut desired = local_user(&name);
    desired.password = None;
    desired.must_change_password = false;
    desired.source_id = Some(source_id.parse().unwrap());
    desired.login_name = Some(format!("{name}-sub"));

    gw.create_user(&desired).await.unwrap();
    gw.edit_user(&name, &desired).await.unwrap();
    let remote = gw.get_user(&name).await.unwrap().unwrap();
    assert_eq!(remote.source_id, desired.source_id.unwrap());
    assert_eq!(remote.login_name, format!("{name}-sub"));
    gw.delete_user(&name).await.unwrap();
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn organization_and_team_lifecycle() {
    let gw = gateway();
    let s = suffix();
    let owner = format!("live-owner-{s}");
    let member = format!("live-member-{s}");
    let org_name = format!("live-org-{s}");
    gw.create_user(&local_user(&owner)).await.unwrap();
    gw.create_user(&local_user(&member)).await.unwrap();

    let org = DesiredOrganization {
        name: org_name.clone(),
        full_name: Some("Live Org".into()),
        visibility: "private",
        ..Default::default()
    };
    let created = gw.create_organization(Some(&owner), &org).await.unwrap();
    assert!(matches!(
        gw.create_organization(None, &org).await,
        Err(GatewayError::AlreadyExists(_))
    ));
    let edited = DesiredOrganization {
        description: Some("from the live test".into()),
        repo_admin_change_team_access: true,
        ..org.clone()
    };
    gw.edit_organization(&org_name, &edited).await.unwrap();
    let remote = gw.get_organization(&org_name).await.unwrap().unwrap();
    assert_eq!(remote.id, created.id);
    assert_eq!(remote.visibility, "private");
    assert_eq!(remote.description, "from the live test");
    assert!(remote.repo_admin_change_team_access);

    let team = DesiredTeam {
        name: "devs".into(),
        permission: "write",
        units_map: [("repo.code".to_string(), "write".to_string())].into(),
        ..Default::default()
    };
    let t = gw.create_team(&org_name, &team).await.unwrap();
    assert!(matches!(
        gw.create_team(&org_name, &team).await,
        Err(GatewayError::AlreadyExists(_))
    ));
    let remote = gw.get_team(t.id).await.unwrap().unwrap();
    assert_eq!(remote.organization, org_name);
    assert_eq!(remote.permission, "write");
    assert_eq!(
        remote.units_map.get("repo.code").map(String::as_str),
        Some("write")
    );

    gw.edit_team(
        t.id,
        &DesiredTeam {
            description: Some("edited".into()),
            includes_all_repositories: true,
            ..team.clone()
        },
    )
    .await
    .unwrap();
    let remote = gw.get_team(t.id).await.unwrap().unwrap();
    assert_eq!(remote.description, "edited");
    assert!(remote.includes_all_repositories);

    gw.add_team_member(t.id, &member).await.unwrap();
    assert_eq!(
        gw.list_team_members(t.id).await.unwrap(),
        vec![member.clone()]
    );
    gw.remove_team_member(t.id, &member).await.unwrap();
    assert!(gw.list_team_members(t.id).await.unwrap().is_empty());

    let renamed = format!("{org_name}-r");
    gw.rename_organization(&org_name, &renamed).await.unwrap();
    assert_eq!(
        gw.get_team(t.id).await.unwrap().unwrap().organization,
        renamed
    );
    assert!(
        gw.get_organization(&org_name).await.unwrap().is_none(),
        "the old name redirects, but must read as absent"
    );

    gw.delete_team(t.id).await.unwrap();
    assert!(gw.get_team(t.id).await.unwrap().is_none());
    gw.delete_organization(&renamed).await.unwrap();
    assert!(gw.get_organization(&renamed).await.unwrap().is_none());
    gw.delete_user(&owner).await.unwrap();
    gw.delete_user(&member).await.unwrap();
}

const DEPLOY_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOi3ORI9t5mrEk3LU5c5tlzEKdwhW+w+rTJWDEzHXKw live-a";
const USER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMq33qJiU9prr8hszi/4R80YYAATIprF1JkB7pwgnQUv live-b";

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn repository_lifecycle() {
    use application::ports::{
        DesiredHook, DesiredRepository, GenerateOptions, HookTarget, ProtectionRule,
        RepositoryInitOptions,
    };

    let gw = gateway();
    let s = suffix();
    let org = format!("live-rorg-{s}");
    let user = format!("live-ruser-{s}");
    gw.create_user(&local_user(&user)).await.unwrap();
    gw.create_organization(
        None,
        &DesiredOrganization {
            name: org.clone(),
            visibility: "public",
            ..Default::default()
        },
    )
    .await
    .unwrap();
    gw.create_team(
        &org,
        &DesiredTeam {
            name: "devs".into(),
            permission: "write",
            units_map: [("repo.code".to_string(), "write".to_string())].into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Create, initialized.
    let desired = DesiredRepository {
        name: "app".into(),
        description: Some("live".into()),
        ..Default::default()
    };
    let init = RepositoryInitOptions {
        auto_init: true,
        readme: Some("Default".into()),
        ..Default::default()
    };
    let created = gw
        .create_repository(&org, true, &desired, &init)
        .await
        .unwrap();
    assert_eq!(created.name, format!("{org}/app"));
    assert!(matches!(
        gw.create_repository(&org, true, &desired, &init).await,
        Err(GatewayError::AlreadyExists(_))
    ));
    let remote = gw.get_repository(created.id).await.unwrap().unwrap();
    assert_eq!(
        (remote.owner.as_str(), remote.name.as_str()),
        (org.as_str(), "app")
    );
    assert!(!remote.default_branch.is_empty());

    // Edit + rename in one PATCH, then read back by id.
    let edited = DesiredRepository {
        name: "app2".into(),
        description: Some("edited".into()),
        private: true,
        template: true,
        has_wiki: Some(false),
        ..desired.clone()
    };
    gw.edit_repository(&format!("{org}/app"), &edited)
        .await
        .unwrap();
    let remote = gw.get_repository(created.id).await.unwrap().unwrap();
    assert_eq!(remote.name, "app2");
    assert!(remote.private && remote.template && !remote.has_wiki);
    let full = format!("{org}/app2");

    // Team access — before protections: an allow-listed team without
    // write access is silently dropped by Forgejo.
    gw.add_repository_team(&full, "devs").await.unwrap();
    let teams: Vec<_> = gw
        .list_repository_teams(&full)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert!(teams.contains(&"devs".to_string()), "{teams:?}");

    // Branch protection round trip: what we send is what we read back.
    let rule = ProtectionRule {
        rule_name: "main".into(),
        enable_push: true,
        enable_push_whitelist: true,
        push_whitelist_teams: vec!["devs".into()],
        required_approvals: 1,
        enable_status_check: true,
        status_check_contexts: vec!["ci/build".into()],
        ..Default::default()
    };
    gw.create_branch_protection(&full, &rule).await.unwrap();
    let listed = gw.list_branch_protections(&full).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], rule, "protection must round-trip exactly");
    let stricter = ProtectionRule {
        required_approvals: 2,
        ..rule.clone()
    };
    gw.edit_branch_protection(&full, &stricter).await.unwrap();
    assert_eq!(
        gw.list_branch_protections(&full).await.unwrap()[0],
        stricter
    );
    gw.delete_branch_protection(&full, "main").await.unwrap();
    assert!(gw.list_branch_protections(&full).await.unwrap().is_empty());

    gw.remove_repository_team(&full, "devs").await.unwrap();
    assert!(
        !gw.list_repository_teams(&full)
            .await
            .unwrap()
            .iter()
            .any(|t| t.name == "devs")
    );

    // Webhooks on the repo and the org.
    for target in [
        HookTarget::Repository {
            owner: org.clone(),
            name: "app2".into(),
        },
        HookTarget::Organization(org.clone()),
    ] {
        let hook = DesiredHook {
            type_: "forgejo".into(),
            config: [
                ("url".to_string(), "https://ci.example.com/hook".to_string()),
                ("content_type".to_string(), "json".to_string()),
                ("secret".to_string(), "s3cr3t".to_string()),
            ]
            .into(),
            events: vec!["push".into()],
            branch_filter: "main".into(),
            active: true,
            authorization_header: Some("Bearer x".into()),
        };
        let h = gw.create_hook(&target, &hook).await.unwrap();
        let remote = gw.get_hook(&target, h.id).await.unwrap().unwrap();
        assert_eq!(remote.config["url"], "https://ci.example.com/hook");
        assert_eq!(remote.config["content_type"], "json");
        assert!(
            !remote.config.contains_key("secret"),
            "secret is write-only"
        );
        assert_eq!(remote.events, vec!["push"]);
        assert_eq!(remote.branch_filter, "main");
        let disabled = DesiredHook {
            active: false,
            ..hook
        };
        gw.edit_hook(&target, h.id, &disabled).await.unwrap();
        assert!(!gw.get_hook(&target, h.id).await.unwrap().unwrap().active);
        gw.delete_hook(&target, h.id).await.unwrap();
        assert!(gw.get_hook(&target, h.id).await.unwrap().is_none());
    }

    // Deploy key.
    let k = gw
        .create_deploy_key(&full, "ci", DEPLOY_KEY, true)
        .await
        .unwrap();
    let remote = gw.get_deploy_key(&full, k.id).await.unwrap().unwrap();
    assert!(remote.read_only);
    assert!(
        DEPLOY_KEY.starts_with(
            remote
                .key
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
                .as_str()
        )
    );
    gw.delete_deploy_key(&full, k.id).await.unwrap();
    assert!(gw.get_deploy_key(&full, k.id).await.unwrap().is_none());

    // Generate from the template (app2 is one now).
    let generated = gw
        .generate_repository(
            &full,
            &org,
            &DesiredRepository {
                name: "from-tpl".into(),
                ..Default::default()
            },
            &GenerateOptions {
                git_content: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(generated.name, format!("{org}/from-tpl"));
    // A missing template is a 404 (the use-case reports it as such); one
    // that isn't a template is refused.
    let generate_from = |template: String| {
        let (gw, org) = (&gw, &org);
        async move {
            let desired = DesiredRepository {
                name: "never".into(),
                ..Default::default()
            };
            gw.generate_repository(&template, org, &desired, &GenerateOptions::default())
                .await
        }
    };
    assert!(matches!(
        generate_from(format!("{org}/no-such-template")).await,
        Err(GatewayError::NotFound(_))
    ));
    let refused = generate_from(format!("{org}/from-tpl")).await;
    assert!(matches!(refused, Err(GatewayError::Api(_))), "{refused:?}");

    // Pull mirror of the generated repo, through Forgejo's own URL.
    let base =
        std::env::var("FORGEJO_INTERNAL_URL").unwrap_or_else(|_| "http://localhost:3000".into());
    let mirror = gw
        .migrate_repository(
            &org,
            &DesiredRepository {
                name: "mirror".into(),
                ..Default::default()
            },
            &application::ports::MigrateOptions {
                clone_addr: format!("{base}/{org}/from-tpl.git"),
                service: "git".into(),
                mirror: true,
                mirror_interval: Some("8h".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let remote = gw.get_repository(mirror.id).await.unwrap().unwrap();
    assert!(remote.mirror);
    eprintln!("mirror_interval echoed as {:?}", remote.mirror_interval);
    assert_eq!(
        application::use_cases::reconcile_repository::go_duration_secs(&remote.mirror_interval),
        Some(8 * 3600)
    );

    // Archive round trip, transfer, delete.
    gw.set_repository_archived(&format!("{org}/from-tpl"), true)
        .await
        .unwrap();
    assert!(
        gw.get_repository(generated.id)
            .await
            .unwrap()
            .unwrap()
            .archived
    );
    gw.set_repository_archived(&format!("{org}/from-tpl"), false)
        .await
        .unwrap();
    gw.transfer_repository(&format!("{org}/from-tpl"), &user)
        .await
        .unwrap();
    assert_eq!(
        gw.get_repository(generated.id)
            .await
            .unwrap()
            .unwrap()
            .owner,
        user
    );

    for full in [
        format!("{user}/from-tpl"),
        format!("{org}/mirror"),
        full.clone(),
    ] {
        gw.delete_repository(&full).await.unwrap();
    }
    assert!(gw.get_repository(created.id).await.unwrap().is_none());

    // User key.
    let uk = gw.create_user_key(&user, "laptop", USER_KEY).await.unwrap();
    assert_eq!(
        gw.get_user_key(&user, uk.id).await.unwrap().unwrap().title,
        "laptop"
    );
    gw.delete_user_key(&user, uk.id).await.unwrap();
    assert!(gw.get_user_key(&user, uk.id).await.unwrap().is_none());

    gw.delete_organization(&org).await.unwrap();
    gw.delete_user(&user).await.unwrap();
}

const OTHER_DEPLOY_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDs3J/6KpTdghMXcL313VedZU2+QE8noabrP3etYEazY live-c";
const OTHER_USER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE3sH2n03276iqumX7xO1UkM88Z/EUWZQwPZRLJphckF live-d";

/// What the key reconcile and cleanup rely on: a key read through an owner
/// that doesn't hold it is absent, while deleting it there is refused
/// (403 "You do not have access to this key") — so the use-case only
/// deletes where `get` found the key. Once the key is gone, a deploy key
/// delete succeeds anywhere (204) and a user key delete is a 404.
#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn keys_are_only_visible_on_their_owner() {
    use application::ports::{DesiredRepository, RepositoryInitOptions};

    let gw = gateway();
    let s = suffix();
    let org = format!("live-korg-{s}");
    let (alice, bob) = (format!("live-kalice-{s}"), format!("live-kbob-{s}"));
    gw.create_organization(
        None,
        &DesiredOrganization {
            name: org.clone(),
            visibility: "public",
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut repos = Vec::new();
    for name in ["holder", "other"] {
        let desired = DesiredRepository {
            name: name.into(),
            ..Default::default()
        };
        let created = gw
            .create_repository(&org, true, &desired, &RepositoryInitOptions::default())
            .await
            .unwrap();
        repos.push(created.name);
    }
    let (holder, other) = (&repos[0], &repos[1]);

    // Deploy key.
    let k = gw
        .create_deploy_key(holder, "ci", OTHER_DEPLOY_KEY, true)
        .await
        .unwrap();
    assert!(gw.get_deploy_key(other, k.id).await.unwrap().is_none());
    let refused = gw.delete_deploy_key(other, k.id).await;
    assert!(
        matches!(refused, Err(GatewayError::Api(ref m)) if m.contains("refused access to the object")),
        "deleting through another repository: {refused:?}"
    );
    assert!(gw.get_deploy_key(holder, k.id).await.unwrap().is_some());
    gw.delete_deploy_key(holder, k.id).await.unwrap();
    gw.delete_deploy_key(other, k.id).await.unwrap();
    gw.delete_deploy_key(holder, k.id).await.unwrap();

    // User key.
    gw.create_user(&local_user(&alice)).await.unwrap();
    gw.create_user(&local_user(&bob)).await.unwrap();
    let uk = gw
        .create_user_key(&alice, "laptop", OTHER_USER_KEY)
        .await
        .unwrap();
    assert!(gw.get_user_key(&bob, uk.id).await.unwrap().is_none());
    let refused = gw.delete_user_key(&bob, uk.id).await;
    assert!(
        matches!(refused, Err(GatewayError::Api(ref m)) if m.contains("refused access to the object")),
        "deleting through another user: {refused:?}"
    );
    assert!(gw.get_user_key(&alice, uk.id).await.unwrap().is_some());
    gw.delete_user_key(&alice, uk.id).await.unwrap();
    assert!(matches!(
        gw.delete_user_key(&bob, uk.id).await,
        Err(GatewayError::NotFound(_))
    ));

    for repo in &repos {
        gw.delete_repository(repo).await.unwrap();
    }
    gw.delete_organization(&org).await.unwrap();
    gw.delete_user(&alice).await.unwrap();
    gw.delete_user(&bob).await.unwrap();
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn oauth2_apps_through_sudo_and_admin_tokens() {
    use application::ports::{DesiredOAuth2App, DesiredToken};

    let gw = gateway();
    let bot = format!("live-sso-{}", suffix());
    // As `bot: true` creates it: must_change_password would make Forgejo
    // refuse the account's API tokens ("You must change your password").
    gw.create_user(&DesiredUser {
        must_change_password: false,
        ..local_user(&bot)
    })
    .await
    .unwrap();

    let app = DesiredOAuth2App {
        name: "live-app".into(),
        redirect_uris: vec!["https://app.example.com/callback".into()],
        confidential_client: true,
    };
    let (created, secret) = gw.create_oauth2_app(Some(&bot), &app).await.unwrap();
    assert!(!secret.is_empty() && !created.client_id.is_empty());
    // Owned by the bot: invisible to the admin itself.
    assert!(gw.get_oauth2_app(None, created.id).await.unwrap().is_none());
    let remote = gw
        .get_oauth2_app(Some(&bot), created.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(remote.redirect_uris, app.redirect_uris);
    assert!(remote.confidential_client);

    let rotated = gw
        .update_oauth2_app(Some(&bot), created.id, &app)
        .await
        .unwrap();
    assert_ne!(rotated, secret, "every update regenerates the secret");
    gw.delete_oauth2_app(Some(&bot), created.id).await.unwrap();
    assert!(
        gw.get_oauth2_app(Some(&bot), created.id)
            .await
            .unwrap()
            .is_none()
    );

    let token = DesiredToken {
        name: "live-ci".into(),
        scopes: vec!["read:user".into(), "write:repository".into()],
        repositories: vec![],
    };
    let (t, value) = gw.create_access_token(&bot, &token).await.unwrap();
    assert_eq!(value.len(), 40);
    assert!(matches!(
        gw.create_access_token(&bot, &token).await,
        Err(GatewayError::AlreadyExists(_))
    ));
    let listed = gw.list_access_tokens(&bot).await.unwrap();
    let remote = listed.iter().find(|r| r.id == t.id).expect("listed");
    let mut scopes = remote.scopes.clone();
    scopes.sort();
    eprintln!("token scopes read back as {scopes:?}");
    assert_eq!(scopes, token.scopes);
    assert!(remote.created_at.is_some());

    // The token actually works, as the bot.
    let url = std::env::var("FORGEJO_URL").unwrap();
    let me: serde_json::Value = reqwest::Client::new()
        .get(format!("{url}/api/v1/user"))
        .header("Authorization", format!("token {value}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["login"], bot.as_str());

    // Why `bot: true` never sets prohibit_login: Forgejo then refuses the
    // account's API tokens as well.
    let mut prohibited = local_user(&bot);
    prohibited.password = None;
    prohibited.prohibit_login = true;
    gw.edit_user(&bot, &prohibited).await.unwrap();
    let status = reqwest::Client::new()
        .get(format!("{url}/api/v1/user"))
        .header("Authorization", format!("token {value}"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 403);

    gw.delete_access_token(&bot, t.id).await.unwrap();
    assert!(
        gw.list_access_tokens(&bot)
            .await
            .unwrap()
            .iter()
            .all(|r| r.id != t.id)
    );
    gw.delete_user(&bot).await.unwrap();
}
