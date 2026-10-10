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

/// Two standbys racing for the same expired lease: the `resourceVersion`
/// precondition lets exactly one of them in — never both (split brain).
#[tokio::test]
async fn racing_standbys_never_both_acquire() {
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let name = "race-leader";
    let gone = leader::lease(client.clone(), "default", name, "gone".into(), TTL);
    leader::acquire(&gone, RENEW).await;
    // `gone` stops renewing; both standbys watch the lease expire.
    let b = leader::lease(client.clone(), "default", name, "b".into(), TTL);
    let c = leader::lease(client.clone(), "default", name, "c".into(), TTL);
    assert!(!b.try_acquire_or_renew().await.unwrap());
    assert!(!c.try_acquire_or_renew().await.unwrap());
    tokio::time::sleep(TTL + RENEW).await;

    for _ in 0..5 {
        let (rb, rc) = tokio::join!(b.try_acquire_or_renew(), c.try_acquire_or_renew());
        let (rb, rc) = (rb.unwrap(), rc.unwrap());
        assert!(!(rb && rc), "both standbys acquired the lease");
        if rb || rc {
            let holder = Api::<Lease>::namespaced(client.clone(), "default")
                .get(name)
                .await
                .unwrap()
                .spec
                .unwrap()
                .holder_identity;
            assert_eq!(holder.as_deref(), Some(if rb { "b" } else { "c" }));
            return;
        }
    }
    panic!("neither standby took over the expired lease");
}
