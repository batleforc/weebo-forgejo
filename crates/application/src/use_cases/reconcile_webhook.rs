//! `ForgejoWebhook` on a repository or an organization. The HMAC secret and
//! authorization header are write-only in Forgejo, so their last applied
//! values are tracked as a hash (`status.appliedSecretHash`).

use std::collections::BTreeSet;

use api::common::DeletionPolicy;
use api::webhook::ForgejoWebhookSpec;
use domain::error::ReasonCode;
use sha2::{Digest, Sha256};

use crate::ports::{DesiredHook, ForgejoGateway, ForgejoRef, HookTarget, RemoteHook};
use crate::use_cases::{Failure, Outcome, gone_ok};

pub struct WebhookInput<'a> {
    pub spec: &'a ForgejoWebhookSpec,
    /// `status.forgejoId` (hook id) / `status.forgejoName` (target, as
    /// `HookTarget`'s display form).
    pub current: Option<ForgejoRef>,
    pub target: HookTarget,
    /// Values of `spec.secretRef` / `spec.authorizationHeaderSecretRef`.
    pub secret: Option<String>,
    pub authorization_header: Option<String>,
    pub applied_secret_hash: Option<String>,
}

pub fn validate(spec: &ForgejoWebhookSpec) -> Result<(), Failure> {
    match (&spec.repository_ref, &spec.organization_ref) {
        (Some(_), None) | (None, Some(_)) => Ok(()),
        _ => Err(Failure::new(
            ReasonCode::InvalidSpec,
            "set exactly one of spec.repositoryRef and spec.organizationRef",
        )),
    }
}

pub async fn reconcile_webhook(input: WebhookInput<'_>, gateway: &dyn ForgejoGateway) -> Outcome {
    let desired = desired_hook(&input);
    let hash = secret_hash(&input);
    let target_name = input.target.to_string();

    // Looked up on the *current* target: after a repository rename the
    // hook is still there (same id); after a retarget it's not.
    let remote = match &input.current {
        Some(c) => match gateway.get_hook(&input.target, c.id).await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(input.current.clone(), e),
        },
        None => None,
    };
    if remote.is_none()
        && let Some(old) = &input.current
        && old.name != target_name
        && let Some(old_target) = parse_target(&old.name)
        && let Err(e) = gone_ok(gateway.delete_hook(&old_target, old.id).await)
    {
        return Outcome::failed(input.current.clone(), e);
    }

    let id = match remote {
        // The type is fixed at creation.
        Some(r) if r.type_ != desired.type_ => {
            if let Err(e) = gone_ok(gateway.delete_hook(&input.target, r.id).await) {
                return Outcome::failed(input.current.clone(), e);
            }
            None
        }
        Some(r) => {
            if (hook_differs(&desired, &r) || input.applied_secret_hash != hash)
                && let Err(e) = gateway.edit_hook(&input.target, r.id, &desired).await
            {
                return Outcome::failed(input.current.clone(), e);
            }
            Some(r.id)
        }
        None => None,
    };
    let id = match id {
        Some(id) => id,
        None => match gateway.create_hook(&input.target, &desired).await {
            Ok(r) => r.id,
            Err(e) => return Outcome::failed(None, e),
        },
    };

    let mut outcome = Outcome::synced(
        Some(ForgejoRef {
            id,
            name: target_name,
        }),
        "webhook synced",
    );
    outcome.secret_hash = hash;
    outcome
}

pub async fn cleanup_webhook(
    spec: &ForgejoWebhookSpec,
    current: Option<&ForgejoRef>,
    gateway: &dyn ForgejoGateway,
) -> Result<(), Failure> {
    if spec.deletion_policy != DeletionPolicy::Delete {
        return Ok(());
    }
    let Some(current) = current else {
        return Ok(());
    };
    let Some(target) = parse_target(&current.name) else {
        return Ok(());
    };
    gone_ok(gateway.delete_hook(&target, current.id).await).map_err(Into::into)
}

/// Inverse of `HookTarget`'s `Display`.
pub fn parse_target(s: &str) -> Option<HookTarget> {
    if let Some(full) = s.strip_prefix("repo:") {
        let (owner, name) = full.split_once('/')?;
        return Some(HookTarget::Repository {
            owner: owner.to_string(),
            name: name.to_string(),
        });
    }
    s.strip_prefix("org:")
        .map(|org| HookTarget::Organization(org.to_string()))
}

fn desired_hook(input: &WebhookInput<'_>) -> DesiredHook {
    let spec = input.spec;
    let mut config = spec.extra_config.clone();
    config.insert("url".into(), spec.url.clone());
    config.insert("content_type".into(), spec.content_type.clone());
    if let Some(method) = &spec.http_method {
        config.insert("http_method".into(), method.clone());
    }
    if let Some(secret) = &input.secret {
        config.insert("secret".into(), secret.clone());
    }
    let mut events = spec.events.clone();
    events.sort();
    events.dedup();
    DesiredHook {
        type_: spec.type_.clone(),
        config,
        events,
        branch_filter: spec.branch_filter.clone().unwrap_or_default(),
        active: spec.active,
        authorization_header: input.authorization_header.clone(),
    }
}

/// `secret` is write-only and never part of the visible diff.
fn hook_differs(d: &DesiredHook, r: &RemoteHook) -> bool {
    let visible = d
        .config
        .iter()
        .filter(|(k, _)| k.as_str() != "secret")
        .any(|(k, v)| r.config.get(k) != Some(v));
    let remote_events: BTreeSet<&String> = r.events.iter().collect();
    let desired_events: BTreeSet<&String> = d.events.iter().collect();
    visible
        || remote_events != desired_events
        || d.branch_filter != r.branch_filter
        || d.active != r.active
}

/// `None` when there's nothing write-only to track.
fn secret_hash(input: &WebhookInput<'_>) -> Option<String> {
    if input.secret.is_none() && input.authorization_header.is_none() {
        return None;
    }
    let mut h = Sha256::new();
    for part in [&input.secret, &input.authorization_header] {
        // Length-prefixed so ("ab", "c") and ("a", "bc") differ.
        let bytes = part.as_deref().unwrap_or("").as_bytes();
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use api::common::ObjectRef;

    use super::*;
    use crate::test_support::FakeForgejo;

    fn spec() -> ForgejoWebhookSpec {
        ForgejoWebhookSpec {
            instance_ref: None,
            repository_ref: Some(ObjectRef { name: "app".into() }),
            organization_ref: None,
            type_: "forgejo".into(),
            url: "https://ci.example.com/hook".into(),
            content_type: "json".into(),
            http_method: None,
            events: vec!["push".into()],
            branch_filter: None,
            active: true,
            secret_ref: None,
            authorization_header_secret_ref: None,
            extra_config: Default::default(),
            deletion_policy: DeletionPolicy::Delete,
        }
    }

    fn repo(name: &str) -> HookTarget {
        HookTarget::Repository {
            owner: "weebo".into(),
            name: name.into(),
        }
    }

    async fn run(
        spec: &ForgejoWebhookSpec,
        current: Option<ForgejoRef>,
        target: HookTarget,
        secret: Option<&str>,
        applied: Option<String>,
        fj: &FakeForgejo,
    ) -> Outcome {
        let input = WebhookInput {
            spec,
            current,
            target,
            secret: secret.map(str::to_string),
            authorization_header: None,
            applied_secret_hash: applied,
        };
        reconcile_webhook(input, fj).await
    }

    #[tokio::test]
    async fn creates_and_stays_quiet() {
        let fj = FakeForgejo::default();
        let s = spec();
        let first = run(&s, None, repo("app"), Some("k"), None, &fj).await;
        let current = first.forgejo.clone().unwrap();
        assert_eq!(current.name, "repo:weebo/app");
        assert_eq!(fj.hook(current.id).unwrap().1.get("secret").unwrap(), "k");

        fj.clear_calls();
        run(
            &s,
            Some(current),
            repo("app"),
            Some("k"),
            first.secret_hash,
            &fj,
        )
        .await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn a_new_secret_value_is_pushed() {
        let fj = FakeForgejo::default();
        let s = spec();
        let first = run(&s, None, repo("app"), Some("k1"), None, &fj).await;
        let current = first.forgejo.clone().unwrap();
        let second = run(
            &s,
            Some(current.clone()),
            repo("app"),
            Some("k2"),
            first.secret_hash.clone(),
            &fj,
        )
        .await;
        assert_ne!(second.secret_hash, first.secret_hash);
        assert_eq!(fj.hook(current.id).unwrap().1.get("secret").unwrap(), "k2");
    }

    #[tokio::test]
    async fn retargeting_moves_the_hook() {
        let fj = FakeForgejo::default();
        let s = spec();
        let old = run(&s, None, repo("app"), None, None, &fj)
            .await
            .forgejo
            .unwrap();
        let new = run(&s, Some(old.clone()), repo("other"), None, None, &fj)
            .await
            .forgejo
            .unwrap();
        assert_ne!(old.id, new.id);
        assert!(fj.hook(old.id).is_none(), "old hook deleted");
        assert_eq!(new.name, "repo:weebo/other");
    }

    #[tokio::test]
    async fn type_change_recreates() {
        let fj = FakeForgejo::default();
        let mut s = spec();
        let old = run(&s, None, repo("app"), None, None, &fj)
            .await
            .forgejo
            .unwrap();
        s.type_ = "slack".into();
        let new = run(&s, Some(old.clone()), repo("app"), None, None, &fj)
            .await
            .forgejo
            .unwrap();
        assert_ne!(old.id, new.id);
        assert_eq!(fj.hook(new.id).unwrap().0, "slack");
    }

    #[test]
    fn targets_round_trip() {
        for t in [repo("app"), HookTarget::Organization("weebo".into())] {
            assert_eq!(parse_target(&t.to_string()), Some(t));
        }
    }
}
