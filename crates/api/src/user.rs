use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::{
    DeletionPolicy, InstanceRef, ManagementPolicy, SecretTarget, SharedWith, Visibility,
};
use crate::status::ForgejoStatus;

/// A Forgejo user, in one of three modes:
///
/// - **external** — `loginSourceId` set: the account is pre-provisioned
///   against an authentication source (e.g. Authentik over OIDC) and linked
///   on the person's first login. No password.
/// - **local** — no `loginSourceId`: a random password is generated and
///   written to `secretTargets`. With `bot: true` the password is generated
///   and never stored anywhere: nobody can use it, and the account works
///   only through its tokens and SSH keys.
/// - **observed** — `managementPolicy: Observe`: the user is never created,
///   modified or deleted, only resolved by `username` so other CRs can
///   reference an account Forgejo auto-created at OIDC login.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "forgejo.weebo.io",
    version = "v1alpha1",
    kind = "ForgejoUser",
    namespaced,
    validation = kube::core::Rule::new("(has(self.spec.managementPolicy) && self.spec.managementPolicy == 'Observe') || has(self.spec.email)").message("spec.email is required unless managementPolicy is Observe"),
    plural = "forgejousers",
    shortname = "fjuser",
    status = "ForgejoStatus",
    printcolumn = r#"{"name":"Username","type":"string","jsonPath":".spec.username"}"#,
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.managementPolicy"}"#,
    printcolumn = r#"{"name":"ID","type":"string","jsonPath":".status.forgejoId"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ForgejoUserSpec {
    /// The `ForgejoInstance` or `ForgejoLocalInstance` this object lives
    /// on. Unset: the cluster's only `ForgejoInstance`, else the only
    /// `ForgejoLocalInstance` of this namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<InstanceRef>,
    /// Other namespaces allowed to reference this object (when the operator
    /// enables cross-namespace references). Unset: this namespace only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<SharedWith>,
    /// Forgejo login. Changing it renames the account in place.
    pub username: String,
    #[serde(default)]
    pub management_policy: ManagementPolicy,
    /// Required unless `managementPolicy: Observe`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// ID of the Forgejo authentication source (Site administration →
    /// Authentication sources) the account logs in through. Forgejo has no
    /// API to list sources, so this is the numeric id, not its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_source_id: Option<i64>,
    /// Identity of the account at the authentication source (for OIDC, the
    /// `sub` claim or the configured username claim). Defaults to
    /// `username`. Only used with `loginSourceId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_name: Option<String>,
    /// Service account: its password is random and never emitted, so it is
    /// only usable through `ForgejoAccessToken`s and `ForgejoUserKey`s.
    /// (Not `prohibitLogin`: Forgejo refuses a prohibited account's API
    /// tokens too.)
    #[serde(default)]
    pub bot: bool,
    /// Disable the account entirely — web, git and API tokens alike.
    #[serde(default)]
    pub prohibit_login: bool,
    /// Force a password change at first login. Local, non-bot users only;
    /// defaults to `true`. Until it's changed, Forgejo also refuses the
    /// account's API tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must_change_password: Option<bool>,
    /// Site administrator.
    #[serde(default)]
    pub admin: bool,
    /// Restricted users only see what they are explicitly granted.
    #[serde(default)]
    pub restricted: bool,
    #[serde(default)]
    pub visibility: Visibility,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_create_organization: Option<bool>,
    /// `-1` uses the instance default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_repo_creation: Option<i64>,
    /// Where the generated password of a local, non-bot user is written
    /// (`FORGEJO_USERNAME`, `FORGEJO_PASSWORD`, `FORGEJO_URL`). Required for
    /// those users; ignored otherwise. A target deleted later triggers a
    /// password reset, since the old value can't be read back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_targets: Vec<SecretTarget>,
    /// Defaults to `Orphan`: deleting the CR keeps the account and the
    /// attribution of everything it authored. Users are never purged.
    #[serde(default = "DeletionPolicy::orphan")]
    pub deletion_policy: DeletionPolicy,
}

fn default_true() -> bool {
    true
}

impl ForgejoUserSpec {
    /// Local accounts are the only ones with a password the operator owns.
    pub fn is_local(&self) -> bool {
        self.login_source_id.is_none()
    }

    /// Whether this user's generated password must be emitted.
    pub fn emits_password(&self) -> bool {
        self.management_policy == ManagementPolicy::Manage && self.is_local() && !self.bot
    }
}
