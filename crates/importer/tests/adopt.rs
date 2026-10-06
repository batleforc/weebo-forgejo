//! `--apply` on a real apiserver (envtest), then the real controllers:
//! every imported object must be adopted as is — `Ready`, and not a single
//! create or edit sent to Forgejo.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx};
use adapters_outbound::K8sSecretStore;
use api::{ForgejoDeployKey, ForgejoRepository, ForgejoTeam, ForgejoWebhook};
use application::ports::{
    DesiredHook, DesiredOrganization, DesiredRepository, DesiredTeam, DesiredUser, ForgejoGateway,
    HookTarget, ProtectionRule, RepositoryInitOptions,
};
use application::test_support::FakeForgejo;
use application::use_cases::import::{ImportOptions, import};
use importer::{Summary, apply_all};
use kube::api::Api;
use kube::runtime::events::{Recorder, Reporter};
use testkit::envtest::EnvTestCluster;
use testkit::static_gateway_factory::StaticGatewayFactory;
use testkit::static_secret_store_factory::StaticSecretStoreFactory;

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

async fn forgejo() -> Arc<FakeForgejo> {
    let f = FakeForgejo::default();
    f.create_user(&DesiredUser {
        username: "alice".into(),
        email: "alice@example.com".into(),
        password: Some("pw".into()),
        visibility: "public",
        active: true,
        ..Default::default()
    })
    .await
    .unwrap();
    f.create_organization(
        None,
        &DesiredOrganization {
            name: "weebo".into(),
            visibility: "public",
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let dev = f
        .create_team(
            "weebo",
            &DesiredTeam {
                name: "Dev".into(),
                permission: "write",
                units_map: BTreeMap::from([("repo.code".into(), "write".into())]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    f.add_team_member(dev.id, "alice").await.unwrap();
    let app = DesiredRepository {
        name: "app".into(),
        ..Default::default()
    };
    f.create_repository("weebo", true, &app, &RepositoryInitOptions::default())
        .await
        .unwrap();
    f.add_repository_team("weebo/app", "Dev").await.unwrap();
    f.create_branch_protection(
        "weebo/app",
        &ProtectionRule {
            rule_name: "main".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    f.create_hook(
        &HookTarget::Repository {
            owner: "weebo".into(),
            name: "app".into(),
        },
        &DesiredHook {
            type_: "forgejo".into(),
            config: BTreeMap::from([
                ("url".into(), "https://ci.example.com/hook".into()),
                ("content_type".into(), "json".into()),
            ]),
            events: vec!["push".into()],
            active: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    f.create_deploy_key("weebo/app", "ci", KEY, true)
        .await
        .unwrap();
    f.clear_calls();
    Arc::new(f)
}

fn ready(status: Option<&api::ForgejoStatus>) -> Option<()> {
    let c = status?.conditions.iter().find(|c| c.type_ == "Ready")?;
    (c.status == "True").then_some(())
}

async fn wait_ready<K>(api: &Api<K>, name: &str, status: fn(&K) -> Option<&api::ForgejoStatus>)
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    testkit::polling::wait_for(
        api,
        name,
        Duration::from_secs(30),
        Duration::from_millis(200),
        |k| ready(status(k)),
    )
    .await
}

#[tokio::test]
async fn imported_objects_are_adopted_without_writes() {
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let forgejo = forgejo().await;

    let options = ImportOptions {
        namespace: "default".into(),
        ..Default::default()
    };
    let imported = import(forgejo.as_ref(), &options).await.unwrap();
    let summary = apply_all(&client, &imported).await;
    assert_eq!(
        summary,
        Summary {
            adopted: 6,
            skipped: 0,
            failed: 0
        }
    );

    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(forgejo.clone())),
        secrets: Arc::new(StaticSecretStoreFactory::new(Arc::new(
            K8sSecretStore::new(client.clone()),
        ))),
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: "weebo-forgejo-test".into(),
                instance: None,
            },
        ),
    });
    tokio::spawn(controller::user::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::organization::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::team::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::repository::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::webhook::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::deploy_key::run(client.clone(), ctx.clone()));

    let teams: Api<ForgejoTeam> = Api::all(client.clone());
    wait_ready(&teams, "weebo-dev", |t| t.status.as_ref()).await;
    let repos: Api<ForgejoRepository> = Api::namespaced(client.clone(), "default");
    wait_ready(&repos, "weebo-app", |r| r.status.as_ref()).await;
    let hooks: Api<ForgejoWebhook> = Api::namespaced(client.clone(), "default");
    let hook = imported.webhooks[0].metadata.name.clone().unwrap();
    wait_ready(&hooks, &hook, |h| h.status.as_ref()).await;
    let keys: Api<ForgejoDeployKey> = Api::namespaced(client.clone(), "default");
    let key = imported.deploy_keys[0].metadata.name.clone().unwrap();
    wait_ready(&keys, &key, |k| k.status.as_ref()).await;

    assert!(forgejo.calls().is_empty(), "{:?}", forgejo.calls());

    // A re-run recognises what it already adopted.
    let again = apply_all(&client, &imported).await;
    assert_eq!(again.skipped, 6);
    assert_eq!(again.failed, 0);

    // A CR owning another Forgejo object is reported, never overwritten.
    let mut other = imported.repositories[0].clone();
    other.status.as_mut().unwrap().forgejo_id = Some("999".into());
    let conflicting = application::use_cases::import::Import {
        repositories: vec![other],
        ..Default::default()
    };
    let conflict = apply_all(&client, &conflicting).await;
    assert_eq!(conflict.failed, 1);
    let kept = repos.get("weebo-app").await.unwrap();
    assert_ne!(kept.status.unwrap().forgejo_id.as_deref(), Some("999"));
}
