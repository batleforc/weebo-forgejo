//! Layer-3: repository, webhook and deploy-key controllers on a real
//! apiserver, wired to the organization/team controllers they reference.

mod support;

use api::common::IdentityRef;
use std::collections::BTreeMap;

use adapters_inbound::controller;
use api::common::{DeletionPolicy, LocalSecretKeyRef, ObjectRef, SecretTarget, Visibility};
use api::keys::{ForgejoDeployKeySpec, KeySource};
use api::organization::ForgejoOrganizationSpec;
use api::repository::{BranchProtection, ForgejoRepositorySpec, TemplateSource};
use api::team::{ForgejoTeamSpec, TeamPermission};
use api::webhook::ForgejoWebhookSpec;
use api::{ForgejoDeployKey, ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoWebhook};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use support::{condition, harness, wait_for, wait_for_absence};

const NS: &str = "default";

fn meta(name: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        ..Default::default()
    }
}

fn id_when_ready(status: Option<&api::ForgejoStatus>) -> Option<i64> {
    (condition(status, "Ready")?.0 == "True").then_some(())?;
    status?.forgejo_id.as_ref()?.parse().ok()
}

async fn org_and_team(client: &kube::Client) {
    let orgs: Api<ForgejoOrganization> = Api::namespaced(client.clone(), "default");
    orgs.create(
        &PostParams::default(),
        &ForgejoOrganization {
            metadata: meta("weebo"),
            spec: ForgejoOrganizationSpec {
                instance_ref: None,
                shared_with: None,
                name: "weebo".into(),
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
        },
    )
    .await
    .unwrap();
    let teams: Api<ForgejoTeam> = Api::namespaced(client.clone(), "default");
    teams
        .create(
            &PostParams::default(),
            &ForgejoTeam {
                metadata: meta("weebo-devs"),
                spec: ForgejoTeamSpec {
                    instance_ref: None,
                    shared_with: None,
                    organization_ref: IdentityRef::named("weebo"),
                    name: "devs".into(),
                    description: None,
                    permission: TeamPermission::Write,
                    units_map: Default::default(),
                    includes_all_repositories: false,
                    can_create_org_repo: false,
                    members_policy: Default::default(),
                    member_refs: vec![],
                    deletion_policy: DeletionPolicy::Delete,
                },
                status: None,
            },
        )
        .await
        .unwrap();
}

fn repo_spec() -> ForgejoRepositorySpec {
    ForgejoRepositorySpec {
        instance_ref: None,
        organization_ref: Some(IdentityRef::named("weebo")),
        user_ref: None,
        name: "app".into(),
        description: Some("demo".into()),
        website: None,
        private: true,
        is_template: false,
        archived: false,
        default_branch: None,
        units: Default::default(),
        init: Some(Default::default()),
        from_template: None,
        migrate: None,
        branch_protections: Some(vec![BranchProtection {
            rule_name: "main".into(),
            required_approvals: 1,
            push_whitelist_teams: vec!["devs".into()],
            enable_push: true,
            ..Default::default()
        }]),
        team_refs: vec![IdentityRef::named("weebo-devs")],
        deletion_policy: DeletionPolicy::Orphan,
    }
}

#[tokio::test]
async fn repository_with_team_hook_and_generated_deploy_key() {
    let h = harness().await;
    let (c, ctx) = (&h.client, &h.ctx);
    tokio::spawn(controller::organization::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::team::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::repository::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::webhook::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::deploy_key::run(c.clone(), ctx.clone()));
    org_and_team(&h.client).await;

    let repos: Api<ForgejoRepository> = Api::namespaced(h.client.clone(), NS);
    repos
        .create(
            &PostParams::default(),
            &ForgejoRepository {
                metadata: meta("app"),
                spec: repo_spec(),
                status: None,
            },
        )
        .await
        .unwrap();
    let repo_id = wait_for(&repos, "app", |r| id_when_ready(r.status.as_ref())).await;
    let repo = h.forgejo.repo(repo_id).unwrap();
    assert_eq!(
        (repo.owner.as_str(), repo.name.as_str(), repo.private),
        ("weebo", "app", true)
    );
    assert_eq!(h.forgejo.repo_teams(repo_id), vec!["devs"]);
    assert_eq!(
        h.forgejo.protections(repo_id)[0].push_whitelist_teams,
        vec!["devs"]
    );

    // Webhook with an HMAC secret from a Secret in the same namespace —
    // only read once the Secret is labelled for it.
    let secrets: Api<Secret> = Api::namespaced(h.client.clone(), NS);
    secrets
        .create(
            &PostParams::default(),
            &serde_json::from_value(serde_json::json!({
                "metadata": {"name": "hook-secret"},
                "stringData": {"hmac": "k1"},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let hooks: Api<ForgejoWebhook> = Api::namespaced(h.client.clone(), NS);
    hooks
        .create(
            &PostParams::default(),
            &ForgejoWebhook {
                metadata: meta("ci"),
                spec: ForgejoWebhookSpec {
                    instance_ref: None,
                    repository_ref: Some(ObjectRef { name: "app".into() }),
                    organization_ref: None,
                    type_: "forgejo".into(),
                    url: "https://ci.example.com/hook".into(),
                    content_type: "json".into(),
                    http_method: None,
                    events: vec!["push".into()],
                    branch_filter: None,
                    active: true,
                    secret_ref: Some(LocalSecretKeyRef {
                        name: "hook-secret".into(),
                        key: "hmac".into(),
                    }),
                    authorization_header_secret_ref: None,
                    extra_config: BTreeMap::new(),
                    deletion_policy: DeletionPolicy::Delete,
                },
                status: None,
            },
        )
        .await
        .unwrap();
    let refused = wait_for(&hooks, "ci", |h| {
        condition(h.status.as_ref(), "Ready").filter(|(status, _)| status == "False")
    })
    .await;
    assert_eq!(refused.1, "SecretNotAllowed");
    secrets
        .patch(
            "hook-secret",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": {"labels": {"forgejo.weebo.io/credential": "true"}},
            })),
        )
        .await
        .unwrap();
    let hook_id = wait_for(&hooks, "ci", |h| id_when_ready(h.status.as_ref())).await;
    assert_eq!(h.forgejo.hook(hook_id).unwrap().1["secret"], "k1");
    let hook = hooks.get("ci").await.unwrap();
    assert_eq!(
        hook.status.as_ref().unwrap().forgejo_name.as_deref(),
        Some("repo:weebo/app")
    );
    assert!(hook.status.unwrap().applied_secret_hash.is_some());

    // Generated deploy key: private half lands in a Secret.
    let keys: Api<ForgejoDeployKey> = Api::namespaced(h.client.clone(), NS);
    keys.create(
        &PostParams::default(),
        &ForgejoDeployKey {
            metadata: meta("ci-key"),
            spec: ForgejoDeployKeySpec {
                instance_ref: None,
                repository_ref: ObjectRef { name: "app".into() },
                title: None,
                read_only: true,
                key: KeySource {
                    public_key: None,
                    secret_targets: vec![SecretTarget {
                        backend: Default::default(),
                        name: "ci-key".into(),
                        namespace: None,
                        path: None,
                    }],
                },
                deletion_policy: DeletionPolicy::Delete,
            },
            status: None,
        },
    )
    .await
    .unwrap();
    let key_id = wait_for(&keys, "ci-key", |k| id_when_ready(k.status.as_ref())).await;
    let secret = secrets.get("ci-key").await.unwrap();
    let data = secret.data.unwrap();
    let public = String::from_utf8(data["ssh-publickey"].0.clone()).unwrap();
    assert_eq!(h.forgejo.key(key_id).unwrap().key, public);
    assert_eq!(h.forgejo.key(key_id).unwrap().title, "ci-key");

    // Teardown: hook and key are deleted, the repository is orphaned.
    hooks.delete("ci", &Default::default()).await.unwrap();
    keys.delete("ci-key", &Default::default()).await.unwrap();
    wait_for_absence(&hooks, "ci").await;
    wait_for_absence(&keys, "ci-key").await;
    assert!(h.forgejo.hook(hook_id).is_none());
    assert!(h.forgejo.key(key_id).is_none());
    assert!(secrets.get_opt("ci-key").await.unwrap().is_none());

    repos.delete("app", &Default::default()).await.unwrap();
    wait_for_absence(&repos, "app").await;
    assert!(
        h.forgejo.repo(repo_id).is_some(),
        "repositories default to Orphan"
    );
}

#[tokio::test]
async fn repository_waits_for_its_team() {
    let h = harness().await;
    tokio::spawn(controller::repository::run(h.client.clone(), h.ctx.clone()));
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));

    let repos: Api<ForgejoRepository> = Api::namespaced(h.client.clone(), NS);
    repos
        .create(
            &PostParams::default(),
            &ForgejoRepository {
                metadata: meta("app"),
                spec: repo_spec(),
                status: None,
            },
        )
        .await
        .unwrap();
    // No team controller runs: the team CR exists but never becomes ready,
    // and the repository says so instead of being created without it.
    org_and_team(&h.client).await;
    let blocked = wait_for(&repos, "app", |r| {
        condition(r.status.as_ref(), "Ready").filter(|c| c.1 == "ReferenceNotReady")
    })
    .await;
    assert_eq!(blocked.0, "False");
    assert!(
        h.forgejo
            .calls()
            .iter()
            .all(|c| !c.starts_with("create_repository"))
    );
}

fn from_template(repository_ref: Option<&str>, repository: Option<&str>) -> ForgejoRepositorySpec {
    ForgejoRepositorySpec {
        init: None,
        from_template: Some(TemplateSource {
            repository_ref: repository_ref.map(|n| ObjectRef { name: n.into() }),
            repository: repository.map(Into::into),
            git_content: true,
            topics: false,
            labels: false,
            webhooks: false,
            protected_branches: false,
            git_hooks: false,
            avatar: false,
        }),
        branch_protections: None,
        team_refs: vec![],
        ..repo_spec()
    }
}

#[tokio::test]
async fn repository_generated_from_a_template_by_name() {
    use application::ports::{DesiredRepository, ForgejoGateway};

    let h = harness().await;
    let repos: Api<ForgejoRepository> = Api::namespaced(h.client.clone(), NS);
    let create = |name: &str, spec: ForgejoRepositorySpec| {
        let (repos, cr) = (
            repos.clone(),
            ForgejoRepository {
                metadata: meta(name),
                spec,
                status: None,
            },
        );
        async move { repos.create(&PostParams::default(), &cr).await }
    };
    // The schema refuses both sources at once, and a name without owner.
    for bad in [
        from_template(Some("tpl"), Some("weebo/base")),
        from_template(None, None),
        from_template(None, Some("base")),
    ] {
        let refused = create("bad", bad.clone()).await.unwrap_err();
        assert!(
            refused.to_string().contains("spec.fromTemplate"),
            "{bad:?}: {refused}"
        );
    }

    tokio::spawn(controller::repository::run(h.client.clone(), h.ctx.clone()));
    tokio::spawn(controller::organization::run(
        h.client.clone(),
        h.ctx.clone(),
    ));
    org_and_team(&h.client).await;
    let orgs: Api<ForgejoOrganization> = Api::namespaced(h.client.clone(), "default");
    wait_for(&orgs, "weebo", |o| id_when_ready(o.status.as_ref())).await;
    // A template no CR manages, made by hand in Forgejo.
    let template = DesiredRepository {
        name: "base".into(),
        template: true,
        ..Default::default()
    };
    h.forgejo
        .create_repository("weebo", true, &template, &Default::default())
        .await
        .unwrap();

    create("app", from_template(None, Some("weebo/base")))
        .await
        .unwrap();
    wait_for(&repos, "app", |r| id_when_ready(r.status.as_ref())).await;
    assert!(
        h.forgejo
            .calls()
            .contains(&"generate_repository weebo/base weebo/app".to_string()),
        "{:?}",
        h.forgejo.calls()
    );
}

/// A namespace deletion removes an `Orphan` repository CR and its deploy
/// keys together: the repository survives in Forgejo, so the key's own
/// finalizer must still delete the key there, without the repository CR.
#[tokio::test]
async fn deploy_key_outliving_its_repository_cr_is_still_deleted() {
    let h = harness().await;
    let (c, ctx) = (&h.client, &h.ctx);
    tokio::spawn(controller::organization::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::team::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::repository::run(c.clone(), ctx.clone()));
    tokio::spawn(controller::deploy_key::run(c.clone(), ctx.clone()));
    org_and_team(&h.client).await;

    let repos: Api<ForgejoRepository> = Api::namespaced(h.client.clone(), NS);
    repos
        .create(
            &PostParams::default(),
            &ForgejoRepository {
                metadata: meta("app"),
                spec: repo_spec(),
                status: None,
            },
        )
        .await
        .unwrap();
    let repo_id = wait_for(&repos, "app", |r| id_when_ready(r.status.as_ref())).await;

    let keys: Api<ForgejoDeployKey> = Api::namespaced(h.client.clone(), NS);
    keys.create(
        &PostParams::default(),
        &ForgejoDeployKey {
            metadata: meta("ci-key"),
            spec: ForgejoDeployKeySpec {
                instance_ref: None,
                repository_ref: ObjectRef { name: "app".into() },
                title: None,
                read_only: true,
                key: KeySource {
                    public_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb5yJ0ib7G0kO7HW2zVhgEqv9n0LjQeYv3tG9Z4yW7r ci".into()),
                    secret_targets: vec![],
                },
                deletion_policy: DeletionPolicy::Delete,
            },
            status: None,
        },
    )
    .await
    .unwrap();
    let key_id = wait_for(&keys, "ci-key", |k| {
        let owner = k
            .metadata
            .annotations
            .as_ref()?
            .get(controller::KEY_OWNER_ANNOTATION)?;
        (owner == "weebo/app").then_some(())?;
        id_when_ready(k.status.as_ref())
    })
    .await;

    repos.delete("app", &Default::default()).await.unwrap();
    wait_for_absence(&repos, "app").await;
    keys.delete("ci-key", &Default::default()).await.unwrap();
    wait_for_absence(&keys, "ci-key").await;
    assert!(h.forgejo.repo(repo_id).is_some(), "repository orphaned");
    assert!(h.forgejo.key(key_id).is_none(), "key left in Forgejo");
}
