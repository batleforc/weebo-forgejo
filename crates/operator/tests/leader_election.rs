//! Leader election on a real apiserver (envtest): one replica holds the
//! lease while the other waits; a lost lease is reported at once (`main`
//! then exits) and the waiting replica takes over.

use std::time::Duration;

use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, Patch, PatchParams};
use operator::leader;
use testkit::envtest::EnvTestCluster;

const NAME: &str = "weebo-forgejo-operator-leader";
const TTL: Duration = Duration::from_secs(2);
const RENEW: Duration = Duration::from_millis(200);

#[tokio::test]
async fn one_leader_loss_is_reported_and_the_other_takes_over() {
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let a = leader::lease(client.clone(), "default", NAME, "a".into(), TTL);
    let b = leader::lease(client.clone(), "default", NAME, "b".into(), TTL);

    leader::acquire(&a, RENEW).await;
    let held = tokio::spawn(async move { leader::hold(&a, RENEW, TTL).await });

    // While `a` renews, `b` never gets in — even well past the TTL.
    let blocked = tokio::time::timeout(TTL * 2, leader::acquire(&b, RENEW)).await;
    assert!(blocked.is_err(), "b acquired a lease a still holds");
    assert!(!held.is_finished());

    // Someone else takes the lease over: `a` must notice on its next renew.
    let leases: Api<Lease> = Api::namespaced(client.clone(), "default");
    leases
        .patch(
            NAME,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "spec": {
                "holderIdentity": "intruder",
                "renewTime": MicroTime(Timestamp::now()),
            }})),
        )
        .await
        .unwrap();
    let why = tokio::time::timeout(Duration::from_secs(3), held)
        .await
        .expect("a did not notice it lost the lease")
        .unwrap();
    assert!(why.contains("lost"), "{why}");

    // The intruder never renews: once its lease expires, `b` leads.
    tokio::time::timeout(TTL * 3, leader::acquire(&b, RENEW))
        .await
        .expect("b never took over the expired lease");
    let lease = leases.get(NAME).await.unwrap();
    assert_eq!(lease.spec.unwrap().holder_identity.as_deref(), Some("b"));
}
