//! Layer-4, repositories and what hangs off them: every scenario runs the
//! real controllers (envtest) against the live Forgejo — owners, creation
//! sources (template, authenticated pull mirror), renames, gated transfers,
//! archiving, authoritative protections and team access, drift, deletion
//! policies, webhooks (secrets, retyping, retargeting) and SSH keys.
//! Ignored by default; `task test:live-forgejo` runs it.

mod support;

use api::{
    ForgejoDeployKey, ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser,
    ForgejoUserKey, ForgejoWebhook,
};
use application::ports::{
    DesiredRepository, ForgejoGateway, HookPatch, HookTarget, RepositoryInitOptions,
    RepositoryPatch,
};
use kube::api::{Api, Patch, PatchParams};
use serde_json::json;
use support::live::{Live, failed_with, live, ready, ready_id};
use support::{wait_for, wait_for_absence};

const GROUP: &str = "forgejo.weebo.io/v1alpha1";

/// A fresh OpenSSH ed25519 public key: Forgejo refuses a key it already
/// knows, and live runs share one instance.
fn public_key() -> String {
    ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
}

/// Merge-patches `metadata`/`spec` of a CR (`value` is the whole patch).
async fn patch<K>(api: &Api<K>, name: &str, value: serde_json::Value)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    api.patch(name, &PatchParams::default(), &Patch::Merge(value))
        .await
        .unwrap_or_else(|e| panic!("patch {name}: {e}"));
}

/// Triggers a reconcile now (any metadata change wakes the controller)
/// instead of waiting for the 300 s drift requeue.
async fn nudge<K>(api: &Api<K>, name: &str)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();
    patch(
        api,
        name,
        json!({"metadata": {"annotations": {"e2e.weebo.io/nudge": stamp}}}),
    )
    .await;
}

async fn org(l: &Live, cr: &str, name: &str) {
    let orgs: Api<ForgejoOrganization> = l.api();
    l.create(
        &orgs,
        json!({"apiVersion": GROUP, "kind": "ForgejoOrganization",
               "metadata": {"name": cr},
               "spec": {"name": name, "deletionPolicy": "Delete"}}),
    )
    .await;
    wait_for(&orgs, cr, |o| ready(o.status.as_ref())).await;
}

async fn bot(l: &Live, cr: &str, name: &str) {
    let users: Api<ForgejoUser> = l.api();
    l.create(
        &users,
        json!({"apiVersion": GROUP, "kind": "ForgejoUser",
               "metadata": {"name": cr},
               "spec": {"username": name, "email": format!("{name}@weebo.local"),
                        "bot": true, "deletionPolicy": "Delete"}}),
    )
    .await;
    wait_for(&users, cr, |u| ready(u.status.as_ref())).await;
}

async fn team(l: &Live, cr: &str, org_cr: &str, name: &str, extra: serde_json::Value) {
    let teams: Api<ForgejoTeam> = l.api();
    let mut spec = json!({"organizationRef": {"name": org_cr}, "name": name,
                          "permission": "write"});
    spec.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    l.create(
        &teams,
        json!({"apiVersion": GROUP, "kind": "ForgejoTeam",
               "metadata": {"name": cr}, "spec": spec}),
    )
    .await;
    wait_for(&teams, cr, |t| ready(t.status.as_ref())).await;
}

/// Creates a `ForgejoRepository` and returns its Forgejo id once `Ready`.
async fn repo(l: &Live, cr: &str, spec: serde_json::Value) -> i64 {
    let repos: Api<ForgejoRepository> = l.api();
    l.create(
        &repos,
        json!({"apiVersion": GROUP, "kind": "ForgejoRepository",
               "metadata": {"name": cr}, "spec": spec}),
    )
    .await;
    wait_for(&repos, cr, |r| ready_id(r.status.as_ref())).await
}

/// `GET /api/v1{path}` as the admin, `None` on 404.
async fn get_json(l: &Live, path: &str) -> Option<serde_json::Value> {
    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1{path}", l.url))
        .header("Authorization", format!("token {}", l.token))
        .send()
        .await
        .unwrap();
    if resp.status() == 404 {
        return None;
    }
    assert!(resp.status().is_success(), "GET {path}: {}", resp.status());
    Some(resp.json().await.unwrap())
}

async fn team_names(l: &Live, full: &str) -> Vec<String> {
    let mut names: Vec<String> =
        l.fj.list_repository_teams(full)
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
    names.sort();
    names
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn user_owned_repository_and_template_generation() {
    let l = live().await;
    let owner = l.name("owner");
    bot(&l, "owner", &owner).await;

    // A user-owned template...
    let template_id = repo(
        &l,
        "tpl",
        json!({"userRef": {"name": "owner"}, "name": "tpl", "isTemplate": true,
               "init": {"readme": "Default"},
               "branchProtections": [{"ruleName": "main", "requiredApprovals": 1}],
               "deletionPolicy": "Delete"}),
    )
    .await;
    let template = l.fj.get_repository(template_id).await.unwrap().unwrap();
    assert_eq!(template.owner, owner);
    assert!(template.template);

    // ...and a repository generated from it, content included, keeping the
    // template's branch protections: its own `branchProtections` is unset.
    let generated_id = repo(
        &l,
        "from-tpl",
        json!({"userRef": {"name": "owner"}, "name": "generated",
               "fromTemplate": {"repositoryRef": {"name": "tpl"},
                                "protectedBranches": true},
               "deletionPolicy": "Delete"}),
    )
    .await;
    let repos: Api<ForgejoRepository> = l.api();
    nudge(&repos, "from-tpl").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let copied =
        l.fj.list_branch_protections(&format!("{owner}/generated"))
            .await
            .unwrap();
    assert_eq!(copied.len(), 1, "{copied:?}");
    assert_eq!(
        (copied[0].rule_name.as_str(), copied[0].required_approvals),
        ("main", 1)
    );
    let generated = l.fj.get_repository(generated_id).await.unwrap().unwrap();
    assert_eq!(generated.full_name(), format!("{owner}/generated"));
    assert!(!generated.template);
    let contents = get_json(&l, &format!("/repos/{owner}/generated/contents"))
        .await
        .expect("generated repository has content");
    assert!(
        contents
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "README.md"),
        "{contents}"
    );

    repos.delete("from-tpl", &Default::default()).await.unwrap();
    repos.delete("tpl", &Default::default()).await.unwrap();
    wait_for_absence(&repos, "from-tpl").await;
    wait_for_absence(&repos, "tpl").await;
    assert!(l.fj.get_repository(generated_id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn authenticated_pull_mirror_keeps_its_interval_in_sync_and_serves_as_a_template() {
    let l = live().await;
    let org_name = l.name("mirror");
    org(&l, "src", &org_name).await;
    // A private source: cloning it needs the credentials from the Secret.
    repo(
        &l,
        "upstream",
        json!({"organizationRef": {"name": "src"}, "name": "upstream", "private": true,
               "init": {"readme": "Default"}, "deletionPolicy": "Delete"}),
    )
    .await;
    l.secret("upstream-auth", "username", "fjadmin").await;
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = l.api();
    patch(
        &secrets,
        "upstream-auth",
        json!({"stringData": {"password": "dev-only-insecure-password-change-me"}}),
    )
    .await;

    let mirror_id = repo(
        &l,
        "mirror",
        json!({"organizationRef": {"name": "src"}, "name": "mirror",
               "migrate": {"cloneAddr": format!("{}/{org_name}/upstream.git", l.url),
                           "mirror": true, "mirrorInterval": "8h",
                           "authSecretRef": {"name": "upstream-auth",
                                             "usernameKey": "username",
                                             "passwordKey": "password"}},
               "deletionPolicy": "Delete"}),
    )
    .await;
    let mirror = l.fj.get_repository(mirror_id).await.unwrap().unwrap();
    assert!(mirror.mirror);
    assert_eq!(mirror.mirror_interval, "8h0m0s");
    let contents = get_json(&l, &format!("/repos/{org_name}/mirror/contents"))
        .await
        .unwrap();
    assert!(!contents.as_array().unwrap().is_empty(), "mirror is empty");

    let repos: Api<ForgejoRepository> = l.api();
    patch(
        &repos,
        "mirror",
        json!({"spec": {"migrate": {"mirrorInterval": "12h"}}}),
    )
    .await;
    for _ in 0..60 {
        if l.fj
            .get_repository(mirror_id)
            .await
            .unwrap()
            .unwrap()
            .mirror_interval
            == "12h0m0s"
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(
        l.fj.get_repository(mirror_id)
            .await
            .unwrap()
            .unwrap()
            .mirror_interval,
        "12h0m0s"
    );

    // A pull mirror can be a template (the upstream one on GitHub, say),
    // and others generated from it by Forgejo name.
    patch(&repos, "mirror", json!({"spec": {"isTemplate": true}})).await;
    for _ in 0..60 {
        if l.fj
            .get_repository(mirror_id)
            .await
            .unwrap()
            .unwrap()
            .template
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let mirror = l.fj.get_repository(mirror_id).await.unwrap().unwrap();
    assert!(mirror.mirror && mirror.template);
    let generated_id = repo(
        &l,
        "from-mirror",
        json!({"organizationRef": {"name": "src"}, "name": "from-mirror",
               "fromTemplate": {"repository": format!("{org_name}/mirror")},
               "deletionPolicy": "Delete"}),
    )
    .await;
    let generated = l.fj.get_repository(generated_id).await.unwrap().unwrap();
    assert!(!generated.mirror && !generated.template);
    let contents = get_json(&l, &format!("/repos/{org_name}/from-mirror/contents"))
        .await
        .unwrap();
    assert!(
        !contents.as_array().unwrap().is_empty(),
        "generated is empty"
    );
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn rename_gated_transfer_archive_and_unarchive() {
    let l = live().await;
    let (a, b) = (l.name("from"), l.name("to"));
    org(&l, "a", &a).await;
    org(&l, "b", &b).await;
    let repos: Api<ForgejoRepository> = l.api();
    let id = repo(
        &l,
        "app",
        json!({"organizationRef": {"name": "a"}, "name": "app",
               "init": {"readme": "Default"}, "deletionPolicy": "Delete"}),
    )
    .await;

    // Rename in place: same id, and Forgejo redirects the old name.
    patch(&repos, "app", json!({"spec": {"name": "app2"}})).await;
    wait_for(&repos, "app", |r| {
        (r.status.as_ref()?.forgejo_name.as_deref()? == format!("{a}/app2")).then_some(())
    })
    .await;
    assert_eq!(
        l.fj.get_repository(id).await.unwrap().unwrap().full_name(),
        format!("{a}/app2")
    );
    let redirected = get_json(&l, &format!("/repos/{a}/app")).await.unwrap();
    assert_eq!(redirected["id"], id);

    // Moving it to another organization is a transfer: refused...
    patch(
        &repos,
        "app",
        json!({"spec": {"organizationRef": {"name": "b"}}}),
    )
    .await;
    wait_for(&repos, "app", |r| {
        failed_with(r.status.as_ref(), "DisruptiveUpdateRefused")
    })
    .await;
    assert_eq!(l.fj.get_repository(id).await.unwrap().unwrap().owner, a);
    // ...until explicitly allowed.
    patch(
        &repos,
        "app",
        json!({"metadata": {"annotations": {
            "forgejo.weebo.io/allow-disruptive-update": "true"}}}),
    )
    .await;
    wait_for(&repos, "app", |r| {
        ready(r.status.as_ref())?;
        (r.status.as_ref()?.forgejo_name.as_deref()? == format!("{b}/app2")).then_some(())
    })
    .await;
    assert_eq!(l.fj.get_repository(id).await.unwrap().unwrap().owner, b);

    // Archive, then unarchive.
    patch(&repos, "app", json!({"spec": {"archived": true}})).await;
    for _ in 0..60 {
        if l.fj.get_repository(id).await.unwrap().unwrap().archived {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(l.fj.get_repository(id).await.unwrap().unwrap().archived);
    wait_for(&repos, "app", |r| ready(r.status.as_ref())).await;
    patch(&repos, "app", json!({"spec": {"archived": false}})).await;
    for _ in 0..60 {
        if !l.fj.get_repository(id).await.unwrap().unwrap().archived {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(!l.fj.get_repository(id).await.unwrap().unwrap().archived);
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn protections_and_team_access_are_authoritative() {
    let l = live().await;
    let (o, other) = (l.name("auth"), l.name("other"));
    org(&l, "o", &o).await;
    org(&l, "other", &other).await;
    team(&l, "devs", "o", "devs", json!({})).await;
    team(&l, "ops", "o", "ops", json!({})).await;
    team(
        &l,
        "all",
        "o",
        "all",
        json!({"includesAllRepositories": true}),
    )
    .await;
    team(&l, "foreign", "other", "foreign", json!({})).await;
    let repos: Api<ForgejoRepository> = l.api();
    let id = repo(
        &l,
        "app",
        json!({"organizationRef": {"name": "o"}, "name": "app",
               "init": {"readme": "Default"},
               "teamRefs": [{"name": "devs"}, {"name": "ops"}],
               "branchProtections": [
                   {"ruleName": "main", "requiredApprovals": 1},
                   {"ruleName": "release/*", "enablePush": true,
                    "pushWhitelistTeams": ["ops"]}],
               "deletionPolicy": "Delete"}),
    )
    .await;
    let full = format!("{o}/app");
    assert_eq!(
        team_names(&l, &full).await,
        vec!["Owners", "all", "devs", "ops"]
    );
    assert_eq!(l.fj.list_branch_protections(&full).await.unwrap().len(), 2);

    // Dropping a rule and a team removes them in Forgejo; Owners and the
    // includes-all team stay (Forgejo grants those on its own).
    patch(
        &repos,
        "app",
        json!({"spec": {"teamRefs": [{"name": "devs"}],
                        "branchProtections": [{"ruleName": "main", "requiredApprovals": 1}]}}),
    )
    .await;
    for _ in 0..60 {
        if team_names(&l, &full).await == ["Owners", "all", "devs"]
            && l.fj.list_branch_protections(&full).await.unwrap().len() == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(team_names(&l, &full).await, vec!["Owners", "all", "devs"]);
    let rules = l.fj.list_branch_protections(&full).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_name, "main");

    // A team of another organization can't be granted.
    patch(
        &repos,
        "app",
        json!({"spec": {"teamRefs": [{"name": "devs"}, {"name": "foreign"}]}}),
    )
    .await;
    wait_for(&repos, "app", |r| {
        failed_with(r.status.as_ref(), "InvalidSpec")
    })
    .await;
    assert_eq!(l.fj.get_repository(id).await.unwrap().unwrap().owner, o);
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn drift_is_corrected_orphan_survives_and_collisions_are_reported() {
    let l = live().await;
    let o = l.name("drift");
    org(&l, "o", &o).await;
    let repos: Api<ForgejoRepository> = l.api();
    let id = repo(
        &l,
        "app",
        json!({"organizationRef": {"name": "o"}, "name": "app",
               "description": "as declared", "units": {"wiki": false},
               "deletionPolicy": "Orphan"}),
    )
    .await;
    let full = format!("{o}/app");

    // Someone edits the repository in Forgejo: the CR wins.
    l.fj.edit_repository(
        &full,
        &RepositoryPatch {
            description: Some("edited by hand".into()),
            has_wiki: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let edited = l.fj.get_repository(id).await.unwrap().unwrap();
    assert_eq!(edited.description, "edited by hand");
    nudge(&repos, "app").await;
    for _ in 0..60 {
        let r = l.fj.get_repository(id).await.unwrap().unwrap();
        if r.description == "as declared" && !r.has_wiki {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let reverted = l.fj.get_repository(id).await.unwrap().unwrap();
    assert_eq!(reverted.description, "as declared");
    assert!(!reverted.has_wiki);

    // A repository nobody declared, then a CR claiming its name.
    l.fj.create_repository(
        &o,
        true,
        &DesiredRepository {
            name: "taken".into(),
            ..Default::default()
        },
        &RepositoryInitOptions::default(),
    )
    .await
    .unwrap();
    l.create(
        &repos,
        json!({"apiVersion": GROUP, "kind": "ForgejoRepository",
               "metadata": {"name": "taken"},
               "spec": {"organizationRef": {"name": "o"}, "name": "taken"}}),
    )
    .await;
    wait_for(&repos, "taken", |r| {
        failed_with(r.status.as_ref(), "ForgejoObjectAlreadyExists")
    })
    .await;
    assert!(
        repos
            .get("taken")
            .await
            .unwrap()
            .status
            .unwrap()
            .forgejo_id
            .is_none(),
        "a collision must never be adopted"
    );

    // Orphan: the CR goes, the repository stays.
    repos.delete("app", &Default::default()).await.unwrap();
    wait_for_absence(&repos, "app").await;
    assert!(l.fj.get_repository(id).await.unwrap().is_some());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn organization_hook_secrets_type_and_drift() {
    let l = live().await;
    let o = l.name("hooks");
    org(&l, "o", &o).await;
    let hooks: Api<ForgejoWebhook> = l.api();
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = l.api();
    l.secret("hook-auth", "header", "Bearer first").await;
    l.create(
        &hooks,
        json!({"apiVersion": GROUP, "kind": "ForgejoWebhook",
               "metadata": {"name": "audit"},
               "spec": {"organizationRef": {"name": "o"},
                        "url": "https://audit.example.com/hook",
                        "events": ["repository"], "branchFilter": "main",
                        "authorizationHeaderSecretRef": {"name": "hook-auth", "key": "header"}}}),
    )
    .await;
    let id = wait_for(&hooks, "audit", |h| ready_id(h.status.as_ref())).await;
    let target = HookTarget::Organization(o.clone());
    let remote = l.fj.get_hook(&target, id).await.unwrap().unwrap();
    assert_eq!(remote.config["url"], "https://audit.example.com/hook");
    let first_hash = hooks
        .get("audit")
        .await
        .unwrap()
        .status
        .unwrap()
        .applied_secret_hash
        .expect("a write-only header is tracked by hash");

    // A new header value is re-applied to the same hook.
    patch(
        &secrets,
        "hook-auth",
        json!({"stringData": {"header": "Bearer second"}}),
    )
    .await;
    nudge(&hooks, "audit").await;
    let second_hash = wait_for(&hooks, "audit", |h| {
        let hash = h.status.as_ref()?.applied_secret_hash.clone()?;
        (hash != first_hash).then_some(hash)
    })
    .await;
    assert_ne!(second_hash, first_hash);
    assert_eq!(
        hooks
            .get("audit")
            .await
            .unwrap()
            .status
            .unwrap()
            .forgejo_id
            .as_deref(),
        Some(id.to_string().as_str())
    );

    // Drift on the visible settings is reverted.
    l.fj.edit_hook(
        &target,
        id,
        &HookPatch {
            config: None,
            events: vec!["push".into()],
            branch_filter: "*".into(),
            active: Some(false),
            authorization_header: None,
        },
    )
    .await
    .unwrap();
    nudge(&hooks, "audit").await;
    for _ in 0..60 {
        let h = l.fj.get_hook(&target, id).await.unwrap().unwrap();
        if h.active && h.branch_filter == "main" && h.events == ["repository"] {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let reverted = l.fj.get_hook(&target, id).await.unwrap().unwrap();
    assert!(reverted.active);
    assert_eq!(reverted.branch_filter, "main");
    assert_eq!(reverted.events, vec!["repository"]);

    // The type is fixed at creation: changing it recreates the hook.
    patch(&hooks, "audit", json!({"spec": {"type": "gitea"}})).await;
    let new_id = wait_for(&hooks, "audit", |h| {
        let id2 = ready_id(h.status.as_ref())?;
        (id2 != id).then_some(id2)
    })
    .await;
    assert!(l.fj.get_hook(&target, id).await.unwrap().is_none());
    assert_eq!(
        l.fj.get_hook(&target, new_id).await.unwrap().unwrap().type_,
        "gitea"
    );

    hooks.delete("audit", &Default::default()).await.unwrap();
    wait_for_absence(&hooks, "audit").await;
    assert!(l.fj.get_hook(&target, new_id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn retargeted_hook_moves_to_the_other_repository() {
    let l = live().await;
    let o = l.name("retarget");
    org(&l, "o", &o).await;
    repo(
        &l,
        "one",
        json!({"organizationRef": {"name": "o"}, "name": "one"}),
    )
    .await;
    repo(
        &l,
        "two",
        json!({"organizationRef": {"name": "o"}, "name": "two"}),
    )
    .await;
    let hooks: Api<ForgejoWebhook> = l.api();
    l.create(
        &hooks,
        json!({"apiVersion": GROUP, "kind": "ForgejoWebhook",
               "metadata": {"name": "ci"},
               "spec": {"repositoryRef": {"name": "one"},
                        "url": "https://ci.example.com/hook"}}),
    )
    .await;
    let id = wait_for(&hooks, "ci", |h| ready_id(h.status.as_ref())).await;
    let one = HookTarget::Repository {
        owner: o.clone(),
        name: "one".into(),
    };
    let two = HookTarget::Repository {
        owner: o.clone(),
        name: "two".into(),
    };
    assert!(l.fj.get_hook(&one, id).await.unwrap().is_some());

    patch(
        &hooks,
        "ci",
        json!({"spec": {"repositoryRef": {"name": "two"}}}),
    )
    .await;
    let moved = wait_for(&hooks, "ci", |h| {
        let s = h.status.as_ref()?;
        ready(Some(s))?;
        (s.forgejo_name.as_deref()? == two.to_string())
            .then(|| s.forgejo_id.as_ref()?.parse::<i64>().ok())?
    })
    .await;
    assert!(
        l.fj.get_hook(&one, id).await.unwrap().is_none(),
        "old hook left behind"
    );
    assert!(l.fj.get_hook(&two, moved).await.unwrap().is_some());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn deploy_keys_provided_rotated_renewed_and_recreated() {
    let l = live().await;
    let o = l.name("keys");
    org(&l, "o", &o).await;
    repo(
        &l,
        "app",
        json!({"organizationRef": {"name": "o"}, "name": "app"}),
    )
    .await;
    let full = format!("{o}/app");
    let keys: Api<ForgejoDeployKey> = l.api();
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = l.api();

    // Provided: registered as is, nothing written anywhere.
    let provided = public_key();
    l.create(
        &keys,
        json!({"apiVersion": GROUP, "kind": "ForgejoDeployKey",
               "metadata": {"name": "provided"},
               "spec": {"repositoryRef": {"name": "app"}, "publicKey": provided}}),
    )
    .await;
    let provided_id = wait_for(&keys, "provided", |k| ready_id(k.status.as_ref())).await;
    let remote =
        l.fj.get_deploy_key(&full, provided_id)
            .await
            .unwrap()
            .unwrap();
    assert!(
        provided.starts_with(&remote.key),
        "{provided} vs {}",
        remote.key
    );
    assert!(remote.read_only);
    assert!(secrets.get_opt("provided").await.unwrap().is_none());

    // Generated: a rotation nonce issues a new pair.
    l.create(
        &keys,
        json!({"apiVersion": GROUP, "kind": "ForgejoDeployKey",
               "metadata": {"name": "gen"},
               "spec": {"repositoryRef": {"name": "app"},
                        "secretTargets": [{"name": "gen-key"}]}}),
    )
    .await;
    let first = wait_for(&keys, "gen", |k| ready_id(k.status.as_ref())).await;
    let first_public = l.secret_value("gen-key", "ssh-publickey").await.unwrap();
    patch(
        &keys,
        "gen",
        json!({"metadata": {"annotations": {"forgejo.weebo.io/rotate-secret": "r1"}}}),
    )
    .await;
    let second = wait_for(&keys, "gen", |k| {
        let s = k.status.as_ref()?;
        (s.last_rotation.as_deref()? == "r1").then_some(())?;
        let id = ready_id(Some(s))?;
        (id != first).then_some(id)
    })
    .await;
    let second_public = l.secret_value("gen-key", "ssh-publickey").await.unwrap();
    assert_ne!(first_public, second_public);
    assert!(l.fj.get_deploy_key(&full, first).await.unwrap().is_none());

    // The private key can't be read back: a lost target renews the pair.
    secrets
        .delete("gen-key", &Default::default())
        .await
        .unwrap();
    nudge(&keys, "gen").await;
    let third = wait_for(&keys, "gen", |k| {
        let id = ready_id(k.status.as_ref())?;
        (id != second).then_some(id)
    })
    .await;
    let third_public = l
        .secret_value("gen-key", "ssh-publickey")
        .await
        .expect("target rewritten");
    assert_ne!(third_public, second_public);

    // Keys are immutable in Forgejo: readOnly flips by recreating.
    patch(&keys, "gen", json!({"spec": {"readOnly": false}})).await;
    let fourth = wait_for(&keys, "gen", |k| {
        let id = ready_id(k.status.as_ref())?;
        (id != third).then_some(id)
    })
    .await;
    assert!(
        !l.fj
            .get_deploy_key(&full, fourth)
            .await
            .unwrap()
            .unwrap()
            .read_only
    );
    assert!(l.fj.get_deploy_key(&full, third).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs a live Forgejo: task test:live-forgejo"]
async fn user_key_with_a_provided_public_key() {
    let l = live().await;
    let login = l.name("keyed");
    bot(&l, "keyed", &login).await;
    let keys: Api<ForgejoUserKey> = l.api();
    let provided = public_key();
    l.create(
        &keys,
        json!({"apiVersion": GROUP, "kind": "ForgejoUserKey",
               "metadata": {"name": "laptop"},
               "spec": {"userRef": {"name": "keyed"}, "title": "laptop",
                        "publicKey": provided}}),
    )
    .await;
    let id = wait_for(&keys, "laptop", |k| ready_id(k.status.as_ref())).await;
    let remote = l.fj.get_user_key(&login, id).await.unwrap().unwrap();
    assert_eq!(remote.title, "laptop");
    assert!(provided.starts_with(&remote.key));

    keys.delete("laptop", &Default::default()).await.unwrap();
    wait_for_absence(&keys, "laptop").await;
    assert!(l.fj.get_user_key(&login, id).await.unwrap().is_none());
}
