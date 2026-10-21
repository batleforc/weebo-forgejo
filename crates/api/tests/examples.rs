//! Every CR in `deploy/examples/` and the kind e2e manifests
//! (`deploy/e2e/`) must deserialize into its CRD type and set no field the
//! CRD doesn't have, so neither can drift from the API.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test helpers fail the test on purpose"
)]

use serde::Deserialize;
use serde_norway::Value;

/// Deserializes into `T` and back. Serde ignores unknown fields, so a typo
/// would vanish silently: every key the example's `spec` sets must survive
/// the round trip.
fn check<T: serde::de::DeserializeOwned + serde::Serialize>(doc: &Value, origin: &str) {
    let typed: T =
        serde_norway::from_value(doc.clone()).unwrap_or_else(|e| panic!("{origin}: {e}"));
    let back = serde_norway::to_value(typed).unwrap();
    for key in doc["spec"].as_mapping().unwrap().keys() {
        let key = key.as_str().unwrap();
        assert!(
            back["spec"].get(key).is_some(),
            "{origin}: spec.{key} is not a field of the CRD"
        );
    }
}

#[test]
fn examples_match_the_crds() {
    check_dir(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/examples"
    ));
}

#[test]
fn e2e_manifests_match_the_crds() {
    check_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/e2e"));
}

fn check_dir(dir: &str) {
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for doc in serde_norway::Deserializer::from_str(&text) {
            let doc = Value::deserialize(doc).unwrap();
            let kind = doc["kind"].as_str().unwrap();
            if doc["apiVersion"].as_str() != Some("forgejo.weebo.io/v1alpha1") {
                continue;
            }
            let origin = format!(
                "{} ({kind} {})",
                path.display(),
                doc["metadata"]["name"].as_str().unwrap_or("?")
            );
            match kind {
                "ForgejoInstance" => check::<api::ForgejoInstance>(&doc, &origin),
                "ForgejoUser" => check::<api::ForgejoUser>(&doc, &origin),
                "ForgejoOrganization" => check::<api::ForgejoOrganization>(&doc, &origin),
                "ForgejoTeam" => check::<api::ForgejoTeam>(&doc, &origin),
                "ForgejoRepository" => check::<api::ForgejoRepository>(&doc, &origin),
                "ForgejoWebhook" => check::<api::ForgejoWebhook>(&doc, &origin),
                "ForgejoDeployKey" => check::<api::ForgejoDeployKey>(&doc, &origin),
                "ForgejoUserKey" => check::<api::ForgejoUserKey>(&doc, &origin),
                "ForgejoOAuth2Application" => check::<api::ForgejoOAuth2Application>(&doc, &origin),
                "ForgejoAccessToken" => check::<api::ForgejoAccessToken>(&doc, &origin),
                "ForgejoNamespacePolicy" => check::<api::ForgejoNamespacePolicy>(&doc, &origin),
                other => panic!("{origin}: unexpected kind {other}"),
            }
            seen += 1;
        }
    }
    assert!(seen > 0, "no CR found in {dir}");
}
