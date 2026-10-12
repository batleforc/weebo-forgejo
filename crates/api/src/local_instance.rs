use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::{LocalTlsOptions, SharedWith};

use crate::common::LocalSecretKeyRef;
use crate::status::ForgejoStatus;

/// Connection to a real Forgejo server (v16 or later), owned by a
/// namespace: its token is that namespace's, and only the objects of this
/// namespace use it unless `sharedWith` says otherwise. What an operator
/// limited to one namespace uses. Objects bound to it are not governed by
/// `ForgejoNamespacePolicy` — the namespace's own token bounds what they
/// can do — and write their secrets as Kubernetes `Secret`s only: the
/// operator's Vault identity is shared by every namespace.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoLocalInstance",
    plural = "forgejolocalinstances",
    shortname = "fjli",
    namespaced,
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoLocalInstanceSpec {
    /// Base web URL of the Forgejo instance, e.g. `https://git.example.com`
    /// — not the `/api/v1` REST endpoint, which is derived from it. Written
    /// as `FORGEJO_URL` into emitted secrets.
    pub url: String,
    /// Key of a `Secret` of this namespace holding the API token the
    /// operator acts with (a site admin's for user and organization
    /// management). Re-read on every gateway call, so rotating it needs no
    /// restart.
    pub token_secret_ref: LocalSecretKeyRef,
    /// TLS verification for the API connection above; the CA `Secret`
    /// lives in this namespace.
    #[serde(default)]
    pub tls: LocalTlsOptions,
    /// Other namespaces (or cluster-scoped objects) allowed to use this
    /// instance — and its token. Unset: this namespace only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<SharedWith>,
}

impl weebo_kit_api::SharesItself for ForgejoLocalInstance {
    fn shared_with(&self) -> Option<&SharedWith> {
        self.spec.shared_with.as_ref()
    }
}
