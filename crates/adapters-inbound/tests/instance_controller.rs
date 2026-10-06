//! Layer-3: `ForgejoInstance` readiness (connectivity + version gate).

mod support;

use adapters_inbound::controller;
use api::ForgejoInstance;
use api::common::SecretKeyRef;
use api::instance::ForgejoInstanceSpec;
use kube::api::{Api, ObjectMeta, PostParams};
use support::{harness, wait_for};

#[tokio::test]
async fn instance_reports_the_forgejo_version() {
    let h = harness().await;
    tokio::spawn(controller::instance::run(h.client.clone(), h.ctx.clone()));

    let instances: Api<ForgejoInstance> = Api::all(h.client.clone());
    instances
        .create(
            &PostParams::default(),
            &ForgejoInstance {
                metadata: ObjectMeta {
                    name: Some("main".into()),
                    ..Default::default()
                },
                spec: ForgejoInstanceSpec {
                    url: "https://git.example.com".into(),
                    token_secret_ref: SecretKeyRef {
                        name: "forgejo-admin".into(),
                        namespace: "default".into(),
                        key: "token".into(),
                    },
                    tls: Default::default(),
                    secret_store: Default::default(),
                },
                status: None,
            },
        )
        .await
        .unwrap();

    let ready = wait_for(&instances, "main", |i| {
        let s = i.status.as_ref()?;
        let c = s.conditions.iter().find(|c| c.type_ == "Ready")?;
        Some((c.status.clone(), c.message.clone()))
    })
    .await;
    assert_eq!(ready, ("True".into(), "Forgejo 16.0.5".into()));
}
