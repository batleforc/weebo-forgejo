//! Single source of truth for every reason the operator surfaces. Status
//! conditions, Kubernetes Events, and admission webhook denials all
//! reference one of these variants — never an ad-hoc string at the call
//! site. See `.prompt/plan.md`, "Convention d'erreurs : codes stables".

/// Whether a `ReasonCode` blocks `Ready` or is purely advisory (the object
/// still functions, the condition is just a stable, discoverable signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Blocking,
    Advisory,
}

/// Declares the enum, its `as_str()` and an `ALL` slice from one list, so a
/// new variant can't be added without its string form (and the tests below
/// iterate every variant without a hand-maintained copy of the list).
macro_rules! reason_codes {
    ($($(#[$doc:meta])* $variant:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ReasonCode {
            $($(#[$doc])* $variant,)+
        }

        impl ReasonCode {
            pub const ALL: &'static [ReasonCode] = &[$(ReasonCode::$variant,)+];

            /// PascalCase representation, valid as both a Kubernetes
            /// `Condition`/`Event` `reason` and an admission response
            /// message prefix.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(ReasonCode::$variant => stringify!($variant),)+
                }
            }
        }
    };
}

reason_codes! {
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

impl ReasonCode {
    pub const fn severity(self) -> Severity {
        match self {
            ReasonCode::Reconciled | ReasonCode::MemberPending => Severity::Advisory,
            _ => Severity::Blocking,
        }
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_is_pascal_case_no_whitespace() {
        for code in ReasonCode::ALL {
            let s = code.as_str();
            assert!(s.chars().next().unwrap().is_ascii_uppercase(), "{s}");
            assert!(s.chars().all(|c| c.is_ascii_alphanumeric()), "{s}");
        }
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
