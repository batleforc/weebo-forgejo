//! Resolution of `*Ref` fields to the Forgejo objects behind them. A ref
//! is usable once the referenced CR has a `status.forgejoId` and is
//! `Ready` — controllers watch the referenced kinds, so a ref that becomes
//! ready re-triggers the referencing CR right away.

use std::fmt::Debug;

use application::ports::ForgejoRef;
use application::use_cases::Failure;
use domain::error::ReasonCode;
use kube::Resource;
use kube::api::Api;
use serde::de::DeserializeOwned;

use super::status::{HasStatus, current_ref, ready_condition};

/// CRs that target a `ForgejoInstance` through `spec.instanceRef`.
pub trait InstanceScoped {
    fn instance_ref(&self) -> Option<&str>;
}

macro_rules! impl_instance_scoped {
    ($($kind:ty),+) => {$(
        impl InstanceScoped for $kind {
            fn instance_ref(&self) -> Option<&str> {
                self.spec.instance_ref.as_deref()
            }
        }
    )+};
}
impl_instance_scoped!(
    api::ForgejoUser,
    api::ForgejoOrganization,
    api::ForgejoTeam,
    api::ForgejoRepository
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefState {
    Ready(ForgejoRef),
    NotFound,
    /// Exists but isn't usable yet; carries the referenced CR's `Ready`
    /// reason (e.g. `UserNotFound` for an observed OIDC user).
    NotReady(String),
    /// Targets another `ForgejoInstance` than the referencing CR: an id
    /// from one instance means nothing on another.
    OtherInstance(Option<String>),
}

/// `our_instance` is the referencing CR's `spec.instanceRef`.
pub async fn resolve<K>(
    api: &Api<K>,
    name: &str,
    our_instance: Option<&str>,
) -> Result<RefState, kube::Error>
where
    K: Resource + HasStatus + InstanceScoped + Clone + Debug + DeserializeOwned,
{
    let Some(obj) = api.get_opt(name).await? else {
        return Ok(RefState::NotFound);
    };
    if obj.instance_ref() != our_instance {
        return Ok(RefState::OtherInstance(
            obj.instance_ref().map(str::to_string),
        ));
    }
    let ready = ready_condition(obj.forgejo_status());
    match (current_ref(&obj), ready) {
        (Some(r), Some(c)) if c.status == "True" => Ok(RefState::Ready(r)),
        (_, Some(c)) => Ok(RefState::NotReady(c.reason.clone())),
        (_, None) => Ok(RefState::NotReady("NotReconciledYet".to_string())),
    }
}

/// A single required ref: anything but `Ready` fails the reconcile.
pub fn require(kind: &str, name: &str, state: RefState) -> Result<ForgejoRef, Failure> {
    match state {
        RefState::Ready(r) => Ok(r),
        RefState::NotFound => Err(Failure::new(
            ReasonCode::ReferenceNotFound,
            format!("{kind} {name:?} does not exist"),
        )),
        RefState::NotReady(why) => Err(Failure::new(
            ReasonCode::ReferenceNotReady,
            format!("{kind} {name:?} is not ready yet ({why})"),
        )),
        RefState::OtherInstance(theirs) => Err(Failure::new(
            ReasonCode::InvalidSpec,
            format!(
                "{kind} {name:?} targets ForgejoInstance {:?}, not this CR's",
                theirs.as_deref().unwrap_or("<default>")
            ),
        )),
    }
}

/// One key of a `Secret` in `namespace`, as UTF-8. Missing Secret/key or
/// non-UTF-8 content is a `ReferenceNotFound` failure, not a kube error.
pub async fn read_secret_key(
    client: &kube::Client,
    namespace: &str,
    name: &str,
    key: &str,
) -> Result<Result<String, Failure>, kube::Error> {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), namespace);
    let value = secrets
        .get_opt(name)
        .await?
        .and_then(|s| s.data)
        .and_then(|mut d| d.remove(key))
        .and_then(|v| String::from_utf8(v.0).ok());
    Ok(value.ok_or_else(|| {
        Failure::new(
            ReasonCode::ReferenceNotFound,
            format!("Secret {namespace}/{name} has no UTF-8 key {key:?}"),
        )
    }))
}
