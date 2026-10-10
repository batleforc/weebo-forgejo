//! Layer-3: the Kubernetes secret store on a real apiserver — the owner
//! annotation guards every write and delete, namespaced owners stay in
//! their namespace, and keys no longer emitted are pruned.

use std::collections::BTreeMap;

use adapters_outbound::kubernetes_secret_store;
use api::common::SecretTarget;
use application::ports::{SecretOwner, SecretStore};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, PostParams};
use testkit::envtest::EnvTestCluster;

fn target(name: &str, namespace: Option<&str>) -> SecretTarget {
    SecretTarget {
        backend: Default::default(),
        name: name.into(),
        namespace: namespace.map(str::to_string),
        path: None,
    }
}

fn data(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[tokio::test]
async fn emitted_secrets_are_owned_and_never_taken_over() {
    let cluster = EnvTestCluster::start().await;
    let client = cluster.client();
    let store = kubernetes_secret_store(client.clone());
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");
    let token = SecretOwner::namespaced("ForgejoAccessToken", "default", "ci");
    let other = SecretOwner::namespaced("ForgejoAccessToken", "default", "other");

    // Created, annotated, pruned on rewrite.
    let t = target("ci-token", None);
    store
        .write(&t, &token, &data(&[("A", "1"), ("B", "2")]))
        .await
        .unwrap();
    store.write(&t, &token, &data(&[("A", "3")])).await.unwrap();
    let written = secrets.get("ci-token").await.unwrap();
    let keys: Vec<_> = written.data.as_ref().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["A"], "a key no longer emitted is pruned");
    assert_eq!(
        written.metadata.annotations.unwrap()[api::SECRET_OWNER_ANNOTATION],
        "ForgejoAccessToken/default/ci"
    );
    assert!(store.exists(&t, &token).await.unwrap());

    // Another CR can neither see it as its own, overwrite it nor delete it.
    assert!(!store.exists(&t, &other).await.unwrap());
    assert!(store.write(&t, &other, &data(&[("A", "x")])).await.is_err());
    store.delete(&t, &other).await.unwrap();
    assert!(secrets.get_opt("ci-token").await.unwrap().is_some());

    // A Secret the operator never created is left alone too.
    let foreign = Secret {
        metadata: ObjectMeta {
            name: Some("db-credentials".into()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(
            "password".to_string(),
            ByteString(b"s3cr3t".to_vec()),
        )])),
        ..Default::default()
    };
    secrets
        .create(&PostParams::default(), &foreign)
        .await
        .unwrap();
    let db = target("db-credentials", None);
    assert!(
        store
            .write(&db, &token, &data(&[("A", "1")]))
            .await
            .is_err()
    );
    store.delete(&db, &token).await.unwrap();
    let kept = secrets.get("db-credentials").await.unwrap();
    assert_eq!(kept.data.unwrap()["password"].0, b"s3cr3t");

    // A namespaced owner never writes elsewhere.
    let elsewhere = target("ci-token", Some("kube-system"));
    assert!(
        store
            .write(&elsewhere, &token, &data(&[("A", "1")]))
            .await
            .is_err()
    );

    // The owner deletes its own.
    store.delete(&t, &token).await.unwrap();
    assert!(secrets.get_opt("ci-token").await.unwrap().is_none());
}
