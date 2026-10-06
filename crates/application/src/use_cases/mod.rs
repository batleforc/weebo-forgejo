//! One `reconcile_*` use-case per CRD. Each returns an [`Outcome`] the
//! controller adapter turns into a status patch and, on transitions, a
//! Kubernetes `Event` — always through a `ReasonCode`, never a free string.

pub mod admission;
pub mod emit;
pub mod import;
pub mod reconcile_instance;
pub mod reconcile_key;
pub mod reconcile_namespace_policy;
pub mod reconcile_oauth2;
pub mod reconcile_organization;
pub mod reconcile_repository;
pub mod reconcile_team;
pub mod reconcile_token;
pub mod reconcile_user;
pub mod reconcile_webhook;

use domain::error::ReasonCode;

use crate::ports::{ForgejoRef, GatewayError};

/// A `Ready: False` cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub reason: ReasonCode,
    pub message: String,
}

impl Failure {
    pub fn new(reason: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

impl From<GatewayError> for Failure {
    fn from(err: GatewayError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

/// A non-blocking condition shown next to `Ready: True` (its `type` is the
/// reason's name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub reason: ReasonCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The Forgejo object this CR now owns (or observes). Persisted even
    /// alongside a failure: a create that succeeded before a later step
    /// failed must never be attempted twice.
    pub forgejo: Option<ForgejoRef>,
    /// `Ok(message)` for `Ready: True`.
    pub ready: Result<String, Failure>,
    pub advisories: Vec<Advisory>,
    /// New `status.appliedSecretHash`, when write-only inputs were sent.
    pub secret_hash: Option<String>,
    /// New `status.lastRotation`, when a secret was (re)issued.
    pub last_rotation: Option<String>,
    /// Reconcile again no later than this (seconds), when something is due
    /// sooner than the steady-state requeue (a token's `rotationPeriod`).
    pub due_in: Option<u64>,
}

impl Outcome {
    pub fn synced(forgejo: Option<ForgejoRef>, message: impl Into<String>) -> Self {
        Self {
            forgejo,
            ready: Ok(message.into()),
            advisories: Vec::new(),
            secret_hash: None,
            last_rotation: None,
            due_in: None,
        }
    }

    pub fn failed(forgejo: Option<ForgejoRef>, failure: impl Into<Failure>) -> Self {
        Self {
            forgejo,
            ready: Err(failure.into()),
            advisories: Vec::new(),
            secret_hash: None,
            last_rotation: None,
            due_in: None,
        }
    }

    /// The reason `Ready` ends on — what metrics and Events are keyed by.
    pub fn reason(&self) -> ReasonCode {
        match &self.ready {
            Ok(_) => ReasonCode::Reconciled,
            Err(f) => f.reason,
        }
    }
}

/// Ignores a `NotFound`: deleting what is already gone succeeds.
pub(crate) fn gone_ok(result: Result<(), GatewayError>) -> Result<(), GatewayError> {
    match result {
        Err(GatewayError::NotFound(_)) => Ok(()),
        other => other,
    }
}

/// `None` = no opinion; otherwise the remote flag must match.
pub(crate) fn differs_flag(desired: Option<bool>, remote: bool) -> bool {
    desired.is_some_and(|d| d != remote)
}

/// Distinguishes "the spec carries no opinion" (`None`) from a value that
/// must match: an unset optional field never forces a PATCH.
pub(crate) fn differs(desired: &Option<String>, remote: &str) -> bool {
    desired.as_deref().is_some_and(|d| d != remote)
}
