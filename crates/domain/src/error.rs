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
        /// `spec.instanceRef` does not resolve to a `ForgejoInstance` nor a
        /// `ForgejoLocalInstance` the operator sees (or can't be satisfied as
        /// written), or no `instanceRef` was given and there is no instance
        /// to default to.
        InstanceNotFound,
        /// No `instanceRef` was given and there is more than one instance to
        /// choose from.
        AmbiguousDefaultInstance,
        /// The instance named is out of reach: a `ForgejoLocalInstance` of
        /// another namespace that doesn't share itself with this one, or
        /// outside the namespace the operator is limited to.
        InstanceNotAllowed,
        /// `spec.instanceRef` now designates another instance than the one
        /// recorded in `status.instance`: a bound CR never moves — the ids in
        /// its status belong to the instance they were created on. Nothing
        /// is done until `instanceRef` designates it again.
        InstanceBindingChanged,
        /// The Forgejo API could not be reached (DNS, TCP, TLS) or answered
        /// with a 5xx.
        InstanceUnreachable,
        /// The `ForgejoInstance` token `Secret` (or the key in it) is missing.
        TokenSecretNotFound,
        /// The `ForgejoInstance` token doesn't belong to a Forgejo site
        /// admin: the admin APIs the operator relies on would fail on every
        /// CR. Use a site admin's token.
        InstanceTokenNotAdmin,
        /// The token `Secret` of a `ForgejoLocalInstance` doesn't carry the
        /// `forgejo.weebo.io/instance-token: "true"` label. The operator
        /// reads Secrets with its own rights: a local instance may only use
        /// a Secret its namespace labelled for it. Label the Secret.
        TokenSecretNotAllowed,
        /// This CR is now bound to a Forgejo object — created, adopted by the
        /// importer, or observed (Event only: `status.forgejoId` was just
        /// recorded).
        Bound,
        /// The finalizer finished: the Forgejo object was deleted or kept
        /// per `deletionPolicy`/`managementPolicy` (or force-orphaned), the
        /// emitted secrets removed (Event only).
        Released,
        /// A `ForgejoInstance` can't be deleted while CRs still use it.
        InstanceInUse,
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
        /// A `*Ref` field does not resolve to a CR (or its `remoteName` to an
        /// object of the instance).
        ReferenceNotFound,
        /// A `*Ref` field names a CR of another namespace while the operator
        /// doesn't allow cross-namespace references
        /// (`references.crossNamespace`), or the target doesn't list this
        /// namespace in its `sharedWith`.
        ReferenceNotAllowed,
        /// The Forgejo object this CR would create or adopt (same server,
        /// kind and name) is already owned by another CR, possibly in
        /// another namespace or through another instance of the same
        /// server. Nothing is called; reference it with `remoteName`
        /// instead, or rename it. For an access token: another CR already
        /// issues a token of that name for the same user.
        RemoteObjectClaimed,
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
        /// An update would take a CR still carrying the finalizer out of
        /// the operator's label selector (`watch.labelSelector`): refused at
        /// admission.
        LeavesWatchScope,
    }
}

impl ReasonCode {
    pub const fn severity(self) -> Severity {
        match self {
            ReasonCode::Reconciled
            | ReasonCode::MemberPending
            | ReasonCode::Bound
            | ReasonCode::Released => Severity::Advisory,
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
    fn only_success_member_pending_and_lifecycle_events_are_advisory() {
        let advisory: Vec<_> = ReasonCode::ALL
            .iter()
            .filter(|c| c.severity() == Severity::Advisory)
            .collect();
        assert_eq!(
            advisory,
            [
                &ReasonCode::Reconciled,
                &ReasonCode::Bound,
                &ReasonCode::Released,
                &ReasonCode::MemberPending
            ]
        );
    }
}
