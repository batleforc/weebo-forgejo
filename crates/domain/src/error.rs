//! Single source of truth for every reason the operator surfaces. Status
//! conditions, Kubernetes Events, and admission webhook denials all
//! reference one of these variants — never an ad-hoc string at the call
//! site. See `.prompt/plan.md`, "Convention d'erreurs : codes stables".

pub use weebo_kit_domain::Severity;
use weebo_kit_domain::{Reason, reason_codes};

reason_codes! {
    pub enum ReasonCode {
        /// Generic success reason for `Ready: True` — every condition must
        /// carry a `ReasonCode`, so this is the one every reconciler uses on
        /// the happy path rather than each inventing its own "it worked" code.
        Reconciled,
        /// `spec.instanceRef` does not resolve to a `ForgejoInstance`, or no
        /// `instanceRef` was given and the cluster has no `ForgejoInstance`.
        InstanceNotFound,
        /// No `instanceRef` was given and the cluster has more than one
        /// `ForgejoInstance` to choose from.
        AmbiguousDefaultInstance,
        /// The Forgejo API could not be reached (DNS, TCP, TLS) or answered
        /// with a 5xx.
        InstanceUnreachable,
        /// The `ForgejoInstance` token `Secret` (or the key in it) is missing.
        TokenSecretNotFound,
        /// A Kubernetes API call made while resolving the `ForgejoInstance`
        /// (listing instances, reading its token or CA `Secret`) failed.
        /// Usually transient (apiserver hiccup); retried like any error.
        KubernetesApiError,
        /// Create was rejected because an object with the same name already
        /// exists in Forgejo and isn't tracked by this CR. Never adopted
        /// implicitly — only the `importer` binds a CR to an existing object.
        ForgejoObjectAlreadyExists,
        /// Catch-all for a Forgejo API call that failed for a reason not
        /// covered by a more specific code.
        ForgejoApiError,
        /// A `*Ref` field does not resolve to a CR.
        ReferenceNotFound,
        /// A `*Ref` field resolves to a CR that isn't `Ready` yet (no
        /// `status.forgejoId`). The controller watches the referenced kind, so
        /// this clears as soon as the reference becomes ready.
        ReferenceNotReady,
        /// A `ForgejoUser` in `managementPolicy: Observe` does not exist in
        /// Forgejo yet — typically an OIDC user who hasn't logged in once.
        UserNotFound,
        /// A `ForgejoTeam` member is a `ForgejoUser` that doesn't exist in
        /// Forgejo yet; the other members are still synced. Advisory.
        MemberPending,
        /// `ForgejoUser.spec.loginSource` doesn't match any authentication
        /// source configured in Forgejo.
        LoginSourceNotFound,
        /// The `ForgejoInstance` runs a Forgejo older than v16 — the admin
        /// token API this operator relies on is missing (see `.prompt/plan.md`,
        /// "Périmètre").
        UnsupportedForgejoVersion,
        /// The change requires a delete-and-recreate (repository transfer,
        /// token scope change, OAuth2 owner change) and the CR lacks the
        /// `forgejo.weebo.io/allow-disruptive-update: "true"` annotation.
        DisruptiveUpdateRefused,
        /// Refused by `ForgejoNamespacePolicy` (webhook and/or reconciler).
        NamespaceNotAllowed,
        /// A namespaced CR references a namespaced CR in another namespace.
        CrossNamespaceReference,
        /// A `SecretStore` (Kubernetes or Vault) write/delete/auth call failed.
        SecretTargetFailed,
        /// The spec is schema-valid but not a shape a reconciler can act on
        /// (e.g. a one-of discriminator without its matching sub-struct).
        InvalidSpec,
    }
}

impl ReasonCode {
    pub const fn severity(self) -> Severity {
        match self {
            ReasonCode::Reconciled | ReasonCode::MemberPending => Severity::Advisory,
            _ => Severity::Blocking,
        }
    }
}

impl Reason for ReasonCode {
    const SUCCESS: Self = ReasonCode::Reconciled;

    fn as_str(self) -> &'static str {
        ReasonCode::as_str(self)
    }

    fn severity(self) -> Severity {
        ReasonCode::severity(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_is_pascal_case_no_whitespace() {
        weebo_kit_domain::reason::assert_pascal_case(ReasonCode::ALL);
    }

    #[test]
    fn only_success_and_member_pending_are_advisory() {
        let advisory: Vec<_> = ReasonCode::ALL
            .iter()
            .filter(|c| c.severity() == Severity::Advisory)
            .collect();
        assert_eq!(
            advisory,
            [&ReasonCode::Reconciled, &ReasonCode::MemberPending]
        );
    }
}
