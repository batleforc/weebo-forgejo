//! Layer-2 contract tests: `ForgejoHttpGateway` against scripted HTTP
//! (`wiremock`), pinning the wire format and the error classification the
//! use-cases depend on.

use adapters_outbound::ForgejoHttpGateway;
use application::ports::{
    DesiredOrganization, DesiredTeam, DesiredUser, ForgejoGateway, GatewayError,
};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn gateway(server: &MockServer) -> ForgejoHttpGateway {
    ForgejoHttpGateway::new(
        format!("{}/api/v1", server.uri()),
        server.uri(),
        "s3cr3t".to_string(),
        reqwest::Client::new(),
    )
}

fn user(username: &str) -> DesiredUser {
    DesiredUser {
        username: username.into(),
        email: format!("{username}@example.com"),
        password: Some("pw".into()),
        visibility: "public",
        active: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn every_call_carries_only_the_token_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .and(header("Authorization", "token s3cr3t"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "16.0.5"})))
        .mount(&server)
        .await;

    assert_eq!(gateway(&server).server_version().await.unwrap(), "16.0.5");
    let req = &server.received_requests().await.unwrap()[0];
    // The spec patch (spec/patches/10-token-auth-only.jq) exists so the
    // token is never also sent as a Sudo/OTP credential.
    assert!(req.headers.get("Sudo").is_none());
    assert!(req.headers.get("X-FORGEJO-OTP").is_none());
    assert!(!req.url.query().unwrap_or("").contains("sudo"));
}

#[tokio::test]
async fn server_errors_classify_as_unreachable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    assert!(matches!(
        gateway(&server).server_version().await,
        Err(GatewayError::Unreachable(_))
    ));
}

/// A 403 blames the token only when Forgejo says so (bodies as Forgejo 16
/// sends them); otherwise the object is what was refused.
#[tokio::test]
async fn forbidden_tells_the_token_from_the_object() {
    let cases = [
        (401, "token is required", "admin token was refused"),
        (
            403,
            "token does not have at least one of required scope(s): [write:admin]",
            "admin token was refused",
        ),
        (
            403,
            "user should be the site admin",
            "admin token was refused",
        ),
        (
            403,
            "You do not have access to this key",
            "Forgejo refused access to the object",
        ),
    ];
    for (status, message, expected) in cases {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/repos/weebo/app/keys/7"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"message": message})))
            .mount(&server)
            .await;
        let err = gateway(&server)
            .delete_deploy_key("weebo/app", 7)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, GatewayError::Api(m) if m.starts_with(&status.to_string()) && m.contains(expected)),
            "{status} {message:?}: {err:?}"
        );
    }
}

#[tokio::test]
async fn create_user_posts_to_admin_and_returns_the_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/users"))
        .and(body_partial_json(json!({
            "username": "alice",
            "email": "alice@example.com",
            "password": "pw",
            "send_notify": false,
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 7, "login": "alice"})))
        .mount(&server)
        .await;

    let created = gateway(&server).create_user(&user("alice")).await.unwrap();
    assert_eq!((created.id, created.name.as_str()), (7, "alice"));
}

#[tokio::test]
async fn a_422_saying_already_exists_is_a_collision() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/users"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(json!({"message": "user already exists [name: alice]"})),
        )
        .mount(&server)
        .await;
    assert!(matches!(
        gateway(&server).create_user(&user("alice")).await,
        Err(GatewayError::AlreadyExists(_))
    ));
}

#[tokio::test]
async fn any_other_422_is_an_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/users"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(json!({"message": "e-mail invalid"})),
        )
        .mount(&server)
        .await;
    assert!(matches!(
        gateway(&server).create_user(&user("alice")).await,
        Err(GatewayError::Api(_))
    ));
}

#[tokio::test]
async fn missing_user_reads_as_none() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/ghost"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
        .mount(&server)
        .await;
    assert_eq!(gateway(&server).get_user("ghost").await.unwrap(), None);
}

#[tokio::test]
async fn edit_user_switches_back_to_local_login_explicitly() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/admin/users/alice"))
        // Forgejo wants source_id and login_name together; 0 = local, and
        // it stores login_name verbatim: a local account keeps "".
        .and(body_partial_json(json!({
            "source_id": 0,
            "login_name": "",
            "prohibit_login": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 7})))
        .mount(&server)
        .await;
    let mut desired = user("alice");
    desired.password = None;
    gateway(&server).edit_user("alice", &desired).await.unwrap();
    let req = &server.received_requests().await.unwrap()[0];
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert!(
        body.get("password").is_none(),
        "no password unless resetting"
    );
}

#[tokio::test]
async fn delete_user_never_purges() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/admin/users/alice"))
        .and(query_param("purge", "false"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    gateway(&server).delete_user("alice").await.unwrap();
}

#[tokio::test]
async fn organization_owner_selects_the_admin_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/users/alice/orgs"))
        .and(body_partial_json(
            json!({"username": "weebo", "visibility": "private"}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 3, "name": "weebo"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 4, "name": "labs"})))
        .mount(&server)
        .await;

    let gw = gateway(&server);
    let org = |name: &str, visibility| DesiredOrganization {
        name: name.into(),
        visibility,
        ..Default::default()
    };
    assert_eq!(
        gw.create_organization(Some("alice"), &org("weebo", "private"))
            .await
            .unwrap()
            .id,
        3
    );
    assert_eq!(
        gw.create_organization(None, &org("labs", "public"))
            .await
            .unwrap()
            .id,
        4
    );
}

#[tokio::test]
async fn team_round_trip_reads_its_organization_and_permission() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/weebo/teams"))
        .and(body_partial_json(json!({
            "name": "devs",
            "permission": "write",
            "units_map": {"repo.code": "write"},
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 9, "name": "devs"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/teams/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 9,
            "name": "devs",
            "permission": "write",
            "organization": {"id": 3, "name": "weebo"},
            "units_map": {"repo.code": "write", "repo.wiki": "read"},
        })))
        .mount(&server)
        .await;

    let gw = gateway(&server);
    let desired = DesiredTeam {
        name: "devs".into(),
        permission: "write",
        units_map: [("repo.code".into(), "write".into())].into(),
        ..Default::default()
    };
    assert_eq!(gw.create_team("weebo", &desired).await.unwrap().id, 9);
    let team = gw.get_team(9).await.unwrap().unwrap();
    assert_eq!(team.organization, "weebo");
    assert_eq!(team.permission, "write");
    assert_eq!(team.units_map["repo.wiki"], "read");
}

/// Forgejo clamps `limit` to its `MAX_RESPONSE_ITEMS` (here 30): a short
/// page is not the last one, only an empty page is.
#[tokio::test]
async fn team_members_are_paginated_until_an_empty_page() {
    let server = MockServer::start().await;
    let page: Vec<_> = (0..30)
        .map(|i| json!({"login": format!("u{i:02}")}))
        .collect();
    Mock::given(method("GET"))
        .and(path("/api/v1/teams/9/members"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(page)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/teams/9/members"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"login": "zed"}])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/teams/9/members"))
        .and(query_param("page", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let members = gateway(&server).list_team_members(9).await.unwrap();
    assert_eq!(members.len(), 31);
    assert!(members.contains(&"zed".to_string()));
}

#[tokio::test]
async fn access_tokens_are_paginated_until_an_empty_page() {
    let server = MockServer::start().await;
    for (page, body) in [
        ("1", json!([{"id": 1, "name": "a"}])),
        ("2", json!([{"id": 2, "name": "b"}])),
        ("3", json!([])),
    ] {
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/users/bot/tokens"))
            .and(query_param("page", page))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
    }
    let tokens = gateway(&server).list_access_tokens("bot").await.unwrap();
    assert_eq!(tokens.iter().map(|t| t.id).collect::<Vec<_>>(), [1, 2]);
}

#[tokio::test]
async fn an_organization_is_not_a_user() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/weebo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 3, "login": "weebo"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/weebo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 3, "name": "weebo"})))
        .mount(&server)
        .await;
    assert_eq!(gateway(&server).get_user("weebo").await.unwrap(), None);
}

#[tokio::test]
async fn timeouts_and_rate_limits_are_transient() {
    for status in [408, 429] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/version"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        assert!(
            matches!(
                gateway(&server).server_version().await,
                Err(GatewayError::Unreachable(_))
            ),
            "{status}"
        );
    }
}

/// "already" only means a name collision on a call that claims a name.
#[tokio::test]
async fn an_edit_422_saying_already_is_an_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/admin/users/alice"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(json!({"message": "e-mail already in use"})),
        )
        .mount(&server)
        .await;
    assert!(matches!(
        gateway(&server).edit_user("alice", &user("alice")).await,
        Err(GatewayError::Api(_))
    ));
}

#[tokio::test]
async fn an_oauth2_app_created_without_a_secret_is_removed_and_fails() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/user/applications/oauth2"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 5, "client_id": "c"})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/user/applications/oauth2/5"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let app = application::ports::DesiredOAuth2App {
        name: "app".into(),
        ..Default::default()
    };
    assert!(matches!(
        gateway(&server).create_oauth2_app(None, &app).await,
        Err(GatewayError::Api(_))
    ));
}

#[tokio::test]
async fn repositories_are_read_by_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42, "name": "app", "owner": {"login": "weebo"},
            "mirror": true, "mirror_interval": "8h0m0s",
        })))
        .mount(&server)
        .await;
    let repo = gateway(&server).get_repository(42).await.unwrap().unwrap();
    assert_eq!(repo.full_name(), "weebo/app");
    assert!(repo.mirror);
}

#[tokio::test]
async fn branch_protection_uses_forgejos_field_names() {
    use application::ports::ProtectionRule;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repos/weebo/app/branch_protections"))
        // Note the singular `approvals_whitelist_username`: Forgejo's own
        // (inconsistent) spelling.
        .and(body_partial_json(json!({
            "rule_name": "main",
            "enable_approvals_whitelist": true,
            "approvals_whitelist_username": ["alice"],
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"rule_name": "main"})))
        .mount(&server)
        .await;
    let rule = ProtectionRule {
        rule_name: "main".into(),
        enable_approvals_whitelist: true,
        approvals_whitelist_usernames: vec!["alice".into()],
        ..Default::default()
    };
    gateway(&server)
        .create_branch_protection("weebo/app", &rule)
        .await
        .unwrap();
}

#[tokio::test]
async fn hook_secret_travels_in_the_config() {
    use application::ports::{DesiredHook, HookTarget};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/weebo/hooks"))
        .and(body_partial_json(json!({
            "type": "forgejo",
            "config": {"url": "https://x", "content_type": "json", "secret": "k"},
            "authorization_header": "Bearer t",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 5})))
        .mount(&server)
        .await;
    let hook = DesiredHook {
        type_: "forgejo".into(),
        config: [
            ("url".to_string(), "https://x".to_string()),
            ("content_type".to_string(), "json".to_string()),
            ("secret".to_string(), "k".to_string()),
        ]
        .into(),
        events: vec!["push".into()],
        branch_filter: String::new(),
        active: true,
        authorization_header: Some("Bearer t".into()),
    };
    let created = gateway(&server)
        .create_hook(&HookTarget::Organization("weebo".into()), &hook)
        .await
        .unwrap();
    assert_eq!((created.id, created.name.as_str()), (5, "org:weebo"));
}

#[tokio::test]
async fn migration_carries_credentials_and_owner() {
    use application::ports::{DesiredRepository, MigrateOptions};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repos/migrate"))
        .and(body_partial_json(json!({
            "clone_addr": "https://github.com/x/y.git",
            "repo_name": "y",
            "repo_owner": "weebo",
            "mirror": true,
            "mirror_interval": "8h",
            "service": "github",
            "auth_token": "ghp",
        })))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({"id": 6, "full_name": "weebo/y"})),
        )
        .mount(&server)
        .await;
    let created = gateway(&server)
        .migrate_repository(
            "weebo",
            &DesiredRepository {
                name: "y".into(),
                ..Default::default()
            },
            &MigrateOptions {
                clone_addr: "https://github.com/x/y.git".into(),
                service: "github".into(),
                mirror: true,
                mirror_interval: Some("8h".into()),
                auth_token: Some("ghp".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(created.name, "weebo/y");
}

#[tokio::test]
async fn a_400_saying_already_used_is_a_collision() {
    use application::ports::DesiredToken;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/users/bot/tokens"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"message": "access token name has been used already"})),
        )
        .mount(&server)
        .await;
    let token = DesiredToken {
        name: "ci".into(),
        scopes: vec!["read:user".into()],
        repositories: vec![],
    };
    assert!(matches!(
        gateway(&server).create_access_token("bot", &token).await,
        Err(GatewayError::AlreadyExists(_))
    ));
}

#[tokio::test]
async fn user_login_searches_by_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/search"))
        .and(query_param("uid", "7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "data": [{"id": 7, "login": "alicia"}]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/search"))
        .and(query_param("uid", "8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true, "data": []})))
        .mount(&server)
        .await;

    let gw = gateway(&server);
    assert_eq!(gw.user_login(7).await.unwrap().as_deref(), Some("alicia"));
    assert_eq!(gw.user_login(8).await.unwrap(), None, "account gone");
}

#[tokio::test]
async fn token_user_reads_the_authenticated_account() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(header("Authorization", "token s3cr3t"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id": 1, "login": "root", "is_admin": true})),
        )
        .mount(&server)
        .await;
    let user = gateway(&server).token_user().await.unwrap();
    assert_eq!((user.login.as_str(), user.admin), ("root", true));
}
