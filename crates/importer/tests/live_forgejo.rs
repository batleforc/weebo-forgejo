//! Smoke test of the importer against a real Forgejo (ignored by default;
//! `task test:live-forgejo`, needs `FORGEJO_URL`/`FORGEJO_TOKEN`): builds a
//! small org through the gateway, imports it, and checks that reconciling
//! the imported CRs keeps every object (same ids, nothing duplicated).

use std::collections::BTreeMap;

use adapters_outbound::ForgejoHttpGateway;
use api::common::ObjectRef;
use application::ports::{
    DesiredHook, DesiredOrganization, DesiredRepository, DesiredTeam, DesiredUser, ForgejoGateway,
    ForgejoInventory, ForgejoRef, HookTarget, ProtectionRule, RepositoryInitOptions,
};
use application::use_cases::import::{ImportOptions, import};
use application::use_cases::{
    reconcile_organization as org, reconcile_repository as repo, reconcile_team as team,
    reconcile_webhook as hook,
};

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

fn gateway() -> ForgejoHttpGateway {
    let url = std::env::var("FORGEJO_URL").expect("FORGEJO_URL");
    let token = std::env::var("FORGEJO_TOKEN").expect("FORGEJO_TOKEN");
    let (api, web) = api::instance::split_urls(&url);
    ForgejoHttpGateway::new(api, web, token, reqwest::Client::new())
}

fn current(status: &Option<api::ForgejoStatus>) -> Option<ForgejoRef> {
    let s = status.as_ref()?;
    Some(ForgejoRef {
        id: s.forgejo_id.as_ref()?.parse().ok()?,
        name: s.forgejo_name.clone()?,
    })
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn import_round_trips_a_live_organization() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let g = gateway();
    let sfx = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        % 1_000_000;
    let (org_name, login) = (format!("imp-{sfx}"), format!("imp-u-{sfx}"));

    g.create_user(&DesiredUser {
        username: login.clone(),
        email: format!("{login}@weebo.local"),
        password: Some("Live-test-password-123".into()),
        visibility: "public",
        active: true,
        ..Default::default()
    })
    .await
    .unwrap();
    g.create_organization(
        None,
        &DesiredOrganization {
            name: org_name.clone(),
            description: Some("imported".into()),
            visibility: "public",
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let dev = g
        .create_team(
            &org_name,
            &DesiredTeam {
                name: "Dev".into(),
                permission: "write",
                units_map: BTreeMap::from([
                    ("repo.code".into(), "write".into()),
                    ("repo.issues".into(), "read".into()),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    g.add_team_member(dev.id, &login).await.unwrap();
    let created = g
        .create_repository(
            &org_name,
            true,
            &DesiredRepository {
                name: "app".into(),
                private: true,
                ..Default::default()
            },
            &RepositoryInitOptions {
                auto_init: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let full = format!("{org_name}/app");
    g.add_repository_team(&full, "Dev").await.unwrap();
    g.create_branch_protection(
        &full,
        &ProtectionRule {
            rule_name: "main".into(),
            required_approvals: 1,
            enable_push: true,
            enable_push_whitelist: true,
            push_whitelist_teams: vec!["Dev".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let target = HookTarget::Repository {
        owner: org_name.clone(),
        name: "app".into(),
    };
    g.create_hook(
        &target,
        &DesiredHook {
            type_: "forgejo".into(),
            config: BTreeMap::from([
                ("url".into(), "https://ci.example.com/hook".into()),
                ("content_type".into(), "json".into()),
                ("secret".into(), "kept-secret".into()),
            ]),
            events: vec!["push".into(), "pull_request".into()],
            branch_filter: "main".into(),
            active: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let key = g.create_deploy_key(&full, "ci", KEY, true).await.unwrap();

    let out = import(
        &g,
        &ImportOptions {
            namespace: "default".into(),
            owners: vec![org_name.clone()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    assert_eq!(out.users.len(), 1, "only the team member");
    let t = &out.teams[0];
    assert_eq!(
        t.spec.member_refs,
        vec![ObjectRef {
            name: login.clone()
        }]
    );
    let r = &out.repositories[0];
    assert_eq!(current(&r.status).unwrap().id, created.id);
    assert!(r.spec.private);
    assert_eq!(
        r.spec.team_refs,
        vec![ObjectRef {
            name: format!("{org_name}-dev")
        }]
    );
    assert_eq!(
        r.spec.branch_protections[0].push_whitelist_teams,
        vec!["Dev"]
    );
    let h = &out.webhooks[0];
    assert_eq!(h.spec.url, "https://ci.example.com/hook");
    assert_eq!(h.spec.branch_filter.as_deref(), Some("main"));
    assert!(!h.spec.extra_config.contains_key("secret"));
    let k = &out.deploy_keys[0];
    assert_eq!(current(&k.status).unwrap().id, key.id);

    // Reconciling the imported CRs adopts everything in place.
    let o = &out.organizations[0];
    let outcome = org::reconcile_organization(
        org::OrganizationInput {
            spec: &o.spec,
            current: current(&o.status),
            owner: None,
        },
        &g,
    )
    .await;
    assert!(outcome.ready.is_ok(), "{outcome:?}");
    let outcome = team::reconcile_team(
        team::TeamInput {
            spec: &t.spec,
            current: current(&t.status),
            organization: org_name.clone(),
            organization_id: None,
            members: vec![team::Member::Ready(login.clone())],
            allow_disruptive_update: false,
        },
        &g,
    )
    .await;
    assert_eq!(outcome.forgejo.as_ref().map(|f| f.id), Some(dev.id));
    assert!(outcome.ready.is_ok(), "{outcome:?}");
    let outcome = repo::reconcile_repository(
        repo::RepositoryInput {
            spec: &r.spec,
            current: current(&r.status),
            owner: repo::Owner::Organization(org_name.clone()),
            source: None,
            teams: vec!["Dev".into()],
            allow_disruptive_update: false,
        },
        &g,
    )
    .await;
    assert_eq!(outcome.forgejo.as_ref().map(|f| f.id), Some(created.id));
    assert!(outcome.ready.is_ok(), "{outcome:?}");
    let outcome = hook::reconcile_webhook(
        hook::WebhookInput {
            spec: &h.spec,
            current: current(&h.status),
            target: target.clone(),
            secret: None,
            authorization_header: None,
            applied_secret_hash: None,
        },
        &g,
    )
    .await;
    assert!(outcome.ready.is_ok(), "{outcome:?}");
    assert_eq!(g.list_hooks(&target).await.unwrap().len(), 1);
    assert_eq!(g.list_deploy_keys(&full).await.unwrap().len(), 1);

    g.delete_repository(&full).await.unwrap();
    g.delete_organization(&org_name).await.unwrap();
    g.delete_user(&login).await.unwrap();
}
