//! Layer-3: the operator full namespaced (`watch.clusterKinds: false`) —
//! running as a ServiceAccount that has one Role in its namespace and
//! nothing cluster-wide, with the real instance resolution and reference
//! reads (the gateway alone is in memory): a `ForgejoRepository` owned by a
//! `ForgejoOrganization` of the same namespace, both on a
//! `ForgejoLocalInstance`. The control plane authorizes with RBAC: any
//! cluster-wide read would be refused.
//!
//! The Role mirrors what the chart renders for `watch.namespace` (the kit
//! library chart's `watchRole`): keep them in step.

mod support;

use std::sync::Arc;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{ForgejoInstances, KubeClusterReader, kubernetes_secret_store};
use api::common::BoundInstance;
use api::{ForgejoInstance, ForgejoLocalInstance, ForgejoOrganization, ForgejoRepository};
use application::test_support::FakeForgejo;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
use kube::Client;
use kube::api::{Api, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use support::{condition, wait_for};
use testkit::envtest::EnvTestCluster;
use testkit::static_gateway_factory::StaticGatewayFactory;
use testkit::static_secret_store_factory::StaticSecretStoreFactory;
use weebo_kit_runtime::WatchScope;

const NS: &str = "team-a";
const NAMESPACED_KINDS: &[&str] = &[
    "forgejolocalinstances",
    "forgejousers",
    "forgejouserkeys",
    "forgejoorganizations",
    "forgejoteams",
    "forgejorepositories",
    "forgejowebhooks",
    "forgejodeploykeys",
    "forgejooauth2applications",
    "forgejoaccesstokens",
];

fn manifest<K: DeserializeOwned>(kind: &str, name: &str, spec: Value) -> K {
    serde_json::from_value(json!({
        "apiVersion": "forgejo.weebo.io/v1alpha1", "kind": kind,
        "metadata": {"name": name, "namespace": NS}, "spec": spec,
    }))
    .unwrap()
}

fn rule(groups: &[&str], resources: Vec<String>, verbs: &[&str]) -> PolicyRule {
    PolicyRule {
        api_groups: Some(groups.iter().map(|g| g.to_string()).collect()),
        resources: Some(resources),
        verbs: verbs.iter().map(|v| v.to_string()).collect(),
        ..Default::default()
    }
}

/// The chart's watch Role, and nothing cluster-wide.
async fn grant_one_role(admin: &Client) {
    let pp = PostParams::default();
    for ns in ["operator", NS] {
        let ns: Namespace = serde_json::from_value(json!({"metadata": {"name": ns}})).unwrap();
        Api::<Namespace>::all(admin.clone())
            .create(&pp, &ns)
            .await
            .unwrap();
    }
    let kinds = |suffix: &str| {
        NAMESPACED_KINDS
            .iter()
            .map(|k| format!("{k}{suffix}"))
            .collect::<Vec<_>>()
    };
    let group = ["forgejo.weebo.io"];
    let role = Role {
        metadata: serde_json::from_value(json!({"name": "watch", "namespace": NS})).unwrap(),
        rules: Some(vec![
            rule(
                &group,
                kinds(""),
                &["get", "list", "watch", "update", "patch"],
            ),
            rule(&group, kinds("/status"), &["get", "patch", "update"]),
            rule(&group, kinds("/finalizers"), &["update"]),
            rule(
                &[""],
                vec!["secrets".into()],
                &["get", "create", "update", "patch", "delete"],
            ),
            rule(
                &["events.k8s.io"],
                vec!["events".into()],
                &["create", "patch"],
            ),
        ]),
    };
    Api::<Role>::namespaced(admin.clone(), NS)
        .create(&pp, &role)
        .await
        .unwrap();
    let binding = RoleBinding {
        metadata: serde_json::from_value(json!({"name": "watch", "namespace": NS})).unwrap(),
        role_ref: RoleRef {
            api_group: Some("rbac.authorization.k8s.io".into()),
            kind: "Role".into(),
            name: "watch".into(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".into(),
            name: "operator".into(),
            namespace: Some("operator".into()),
            ..Default::default()
        }]),
    };
    Api::<RoleBinding>::namespaced(admin.clone(), NS)
        .create(&pp, &binding)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_full_namespaced_operator_runs_on_one_role() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = EnvTestCluster::start().await;
    let admin = cluster.client();
    grant_one_role(&admin).await;
    let operator = cluster
        .client_as_service_account("operator", "operator")
        .await;
    assert!(
        Api::<ForgejoInstance>::all(operator.clone())
            .list(&Default::default())
            .await
            .is_err(),
        "nothing cluster-scoped is granted"
    );

    let scope = WatchScope::namespace(NS).without_cluster_kinds().unwrap();
    let (watched, cluster_kinds) = (Some(NS.to_string()), false);
    let ctx = Arc::new(Ctx {
        client: operator.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(Arc::new(FakeForgejo::default()))),
        secrets: Arc::new(StaticSecretStoreFactory::new(Arc::new(
            kubernetes_secret_store(operator.clone()),
        ))),
        instances: Arc::new(ForgejoInstances::new(operator.clone()).with_scope(
            watched.clone(),
            None,
            cluster_kinds,
        )),
        refs: Arc::new(KubeClusterReader::new(operator.clone()).with_scope(
            watched.clone(),
            None,
            cluster_kinds,
        )),
        policies: Arc::new(KubeClusterReader::new(operator.clone()).with_scope(
            watched,
            None,
            cluster_kinds,
        )),
        recorder: Recorder::new(
            operator.clone(),
            Reporter {
                controller: "weebo-forgejo-test".into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: Default::default(),
        scope,
        watches: Default::default(),
    });
    let health = ctx.health.clone();
    tokio::spawn(controller::local_instance::run(
        operator.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::organization::run(operator.clone(), ctx.clone()));
    tokio::spawn(controller::repository::run(operator.clone(), ctx));

    let pp = PostParams::default();
    let local: ForgejoLocalInstance = manifest(
        "ForgejoLocalInstance",
        "own",
        json!({"url": "https://git.team-a.example", "tokenSecretRef": {"name": "t", "key": "token"}}),
    );
    Api::<ForgejoLocalInstance>::namespaced(admin.clone(), NS)
        .create(&pp, &local)
        .await
        .unwrap();
    let org: ForgejoOrganization =
        manifest("ForgejoOrganization", "weebo", json!({"name": "weebo"}));
    Api::<ForgejoOrganization>::namespaced(admin.clone(), NS)
        .create(&pp, &org)
        .await
        .unwrap();
    let repo: ForgejoRepository = manifest(
        "ForgejoRepository",
        "app",
        json!({"organizationRef": {"name": "weebo"}, "name": "app"}),
    );
    let repos: Api<ForgejoRepository> = Api::namespaced(admin.clone(), NS);
    repos.create(&pp, &repo).await.unwrap();

    let (bound, name) = wait_for(&repos, "app", |r| {
        let status = r.status.as_ref()?;
        (condition(Some(status), "Ready")?.0 == "True")
            .then(|| (status.instance.clone(), status.forgejo_name.clone()))
    })
    .await;
    assert_eq!(bound, Some(BoundInstance::local(NS, "own")));
    assert_eq!(name.as_deref(), Some("weebo/app"));
    assert_eq!(health.live(), Ok(()));
}
