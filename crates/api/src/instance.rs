use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::{SecretStoreBackend, TlsOptions};

use crate::common::SecretKeyRef;
use crate::status::ForgejoStatus;

/// Connection to a real Forgejo server (v16 or later). Cluster-scoped — an
/// org-wide, shared piece of infrastructure, not owned by a single
/// namespace. CRs without an `instanceRef` use the cluster's only
/// `ForgejoInstance`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoInstance",
    plural = "forgejoinstances",
    shortname = "fji",
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoInstanceSpec {
    /// Base web URL of the Forgejo instance, e.g. `https://git.example.com`
    /// — not the `/api/v1` REST endpoint, which is derived from it (see
    /// [`split_urls`]). Written as `FORGEJO_URL` into emitted secrets.
    pub url: String,
    /// `Secret` key holding an API token of a Forgejo **site admin**. The
    /// operator acts as that admin, and through the `Sudo` header as other
    /// users for per-user objects (OAuth2 applications). The token needs the
    /// scopes covering every kind it manages — `write:admin`,
    /// `write:organization`, `write:repository`, `write:user` at least.
    /// Re-read on every gateway call, so rotating it needs no restart.
    pub token_secret_ref: SecretKeyRef,
    /// TLS verification for the API connection above — a private CA to trust
    /// (`tls.caSecretRef`), or the `tls.insecureSkipVerify` escape hatch.
    /// Defaults to plain platform-trust-store verification.
    #[serde(default)]
    pub tls: TlsOptions,
    /// Default destination of the secrets this instance's CRs emit (OAuth2
    /// credentials, access tokens, generated passwords and deploy keys) when
    /// a CR sets no `secretTargets`. Defaults to a Kubernetes `Secret`.
    #[serde(default)]
    pub secret_store: SecretStoreSpec,
}

/// Deliberately **not** a Rust sum type (`enum SecretStoreSpec { Kubernetes,
/// Vault(..) }`), same reason as the other one-of fields of this
/// API: kube-core's CRD schema generation cannot merge an
/// internally-tagged enum whose variants carry different `backend`
/// discriminator schemas. "`vault` set iff `backend: Vault`" is validated
/// by the secret store factory, not the schema.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretStoreSpec {
    #[serde(default)]
    pub backend: SecretStoreBackend,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultSecretStoreSpec>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultSecretStoreSpec {
    /// Vault server address, e.g. `https://vault.example.com:8200`.
    pub address: String,
    /// KV v2 secrets engine mount (e.g. `secret`) credentials are written
    /// under.
    pub mount: String,
    /// Path prefix under `mount` — the final KV path is
    /// `<pathPrefix>/<namespace>/<name>`, one secret per emitting CR
    /// (same convention as the Kubernetes backend's Secret naming).
    #[serde(default = "default_vault_path_prefix")]
    pub path_prefix: String,
    /// Vault Kubernetes-auth role this operator authenticates as — its own
    /// ServiceAccount JWT is exchanged for a Vault token via
    /// `auth/<kubernetesAuthMount>/login`.
    pub kubernetes_auth_role: String,
    /// Mount path of Vault's Kubernetes auth backend. Defaults to
    /// `kubernetes`, Vault's own default mount name.
    #[serde(default = "default_kubernetes_auth_mount")]
    pub kubernetes_auth_mount: String,
    /// Optional custom CA certificate to verify Vault's TLS with, read from
    /// a Kubernetes `Secret` (the referenced `key` must hold a PEM bundle).
    /// Use this to trust a private CA without mounting
    /// it into the operator pod — the operator reads the Secret via the
    /// API and hands the PEM to its Vault client. When unset, the system
    /// trust store is used. Only consulted for `https://` Vault addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_secret_ref: Option<SecretKeyRef>,
}

fn default_vault_path_prefix() -> String {
    "weebo-forgejo".to_string()
}

fn default_kubernetes_auth_mount() -> String {
    "kubernetes".to_string()
}

/// Derives the two base URLs a client needs from the single [`url`] field
/// this CRD exposes: the generated REST client appends every path to a base
/// that must end in `/api/v1`, while emitted secrets carry the web base.
///
/// A `url` that already carries `/api/v1` is accepted rather than taken
/// literally — pasting the API URL is the obvious mistake, and honouring it
/// would write `.../api/v1` as `FORGEJO_URL` into every emitted secret.
///
/// Returns `(api_base_path, web_base_url)`.
///
/// [`url`]: ForgejoInstanceSpec::url
pub fn split_urls(url: &str) -> (String, String) {
    let web = url
        .trim_end_matches('/')
        .trim_end_matches("/api/v1")
        .trim_end_matches('/')
        .to_string();
    let api = format!("{web}/api/v1");
    (api, web)
}

#[cfg(test)]
mod url_tests {
    use super::split_urls;

    #[test]
    fn web_base_gets_the_api_suffix_for_rest_calls() {
        assert_eq!(
            split_urls("https://git.weebo.poc"),
            (
                "https://git.weebo.poc/api/v1".to_string(),
                "https://git.weebo.poc".to_string()
            )
        );
    }

    #[test]
    fn trailing_slash_and_api_suffix_are_normalised() {
        for url in [
            "https://git.weebo.poc/",
            "https://git.weebo.poc/api/v1",
            "https://git.weebo.poc/api/v1/",
        ] {
            assert_eq!(
                split_urls(url),
                (
                    "https://git.weebo.poc/api/v1".to_string(),
                    "https://git.weebo.poc".to_string()
                ),
                "{url}"
            );
        }
    }
}
