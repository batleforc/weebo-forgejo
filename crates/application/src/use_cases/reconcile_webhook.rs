//! `ForgejoWebhook` on a repository or an organization. The HMAC secret and
//! authorization header are write-only in Forgejo, so their last applied
//! values are tracked as a hash (`status.appliedSecretHash`).
//!
//! Forgejo (v16) reads back only `url` and `content_type` (plus the Slack
//! meta keys) and its hook edit ignores everything else in `config` — the
//! secret and `http_method` included. Those are "create-only": a change
//! means a new hook, like a type change. The authorization header is
//! editable. An edit only happens on a drift of what Forgejo shows, or a
//! new header, and never carries the secret (see `HookPatch`).

use std::collections::{BTreeMap, BTreeSet};

use api::common::DeletionPolicy;
use api::webhook::ForgejoWebhookSpec;
use domain::error::ReasonCode;
use sha2::{Digest, Sha256};

use crate::ports::{
    DesiredHook, ForgejoGateway, ForgejoRef, GatewayError, HookPatch, HookTarget, RemoteHook,
};
use crate::use_cases::{CleanupGateway, Drift, Failure, Outcome, RemoteWrite, gone_ok};

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
    let stored = input.applied_secret_hash.as_deref();
    let applied = Applied::of(&desired, stored);
    let change = applied.compare(stored, &desired, &input);
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

    let mut recreating = false;
    let mut corrected = None;
    let id = match remote {
        // The type and the create-only inputs are fixed at creation.
        Some(r) if r.type_ != desired.type_ || change == Change::Recreate => {
            if let Err(e) = gone_ok(gateway.delete_hook(&input.target, r.id).await) {
                return Outcome::failed(input.current.clone(), e);
            }
            recreating = true;
            None
        }
        Some(r) => {
            // A new header (from its Secret) is a write without a drifted
            // field: counted, not announced.
            let (drift, patch) = hook_differs(&desired, &r, change == Change::Edit);
            if !drift.is_empty() || change == Change::Edit {
                if let Err(e) = gateway.edit_hook(&input.target, r.id, &patch).await {
                    return Outcome::failed(input.current.clone(), e);
                }
                corrected = Some(drift);
            }
            Some(r.id)
        }
        None => None,
    };
    let id = match id {
        Some(id) => id,
        None => {
            // Never a twin: a hook with this URL already on the target is
            // one whose create response was lost, or someone else's —
            // either way not adopted implicitly (the importer does that).
            if !recreating {
                match gateway.list_hooks(&input.target).await {
                    Ok(hooks) => {
                        let url = desired.config.get("url");
                        if let Some(twin) = hooks.iter().find(|h| h.config.get("url") == url) {
                            return Outcome::failed(
                                input.current.clone(),
                                Failure::new(
                                    ReasonCode::ForgejoObjectAlreadyExists,
                                    format!(
                                        "{target_name} already has hook {} for {}; delete it or \
                                         adopt it with weebo-forgejo-importer",
                                        twin.id,
                                        url.map_or("", String::as_str)
                                    ),
                                ),
                            );
                        }
                    }
                    Err(e) => return Outcome::failed(input.current.clone(), e),
                }
            }
            match gateway.create_hook(&input.target, &desired).await {
                Ok(r) => r.id,
                Err(e) => return Outcome::failed(None, e),
            }
        }
    };

    let mut outcome = Outcome::synced(
        Some(ForgejoRef {
            id,
            name: target_name,
        }),
        "webhook synced",
    );
    outcome = match corrected {
        Some(drift) => outcome.corrected(drift),
        None if input.current.as_ref().map(|c| c.id) != Some(id) => {
            outcome.wrote(RemoteWrite::Created)
        }
        None => outcome,
    };
    // Always set, so removing every write-only input is recorded too.
    outcome.secret_hash = Some(applied.encode());
    outcome
}

/// Deleted on the recorded target, else on `now` — where the referenced
/// repository or organization lives now, which differs after a rename the
/// status hasn't caught up with. `Ok(true)`: the hook was deleted by this
/// call.
pub async fn cleanup_webhook(
    spec: &ForgejoWebhookSpec,
    current: Option<&ForgejoRef>,
    now: Option<HookTarget>,
    gateway: CleanupGateway<'_>,
) -> Result<bool, Failure> {
    if spec.deletion_policy != DeletionPolicy::Delete {
        return Ok(false);
    }
    let Some(current) = current else {
        return Ok(false);
    };
    let recorded = parse_target(&current.name);
    let gateway = gateway.map_err(Clone::clone)?;
    for target in recorded
        .iter()
        .chain(now.iter().filter(|t| Some(*t) != recorded.as_ref()))
    {
        match gateway.delete_hook(target, current.id).await {
            Ok(()) => return Ok(true),
            Err(GatewayError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
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

/// Only what Forgejo reads back is part of the visible diff; the rest is
/// create-only and tracked by [`Applied`]. Returns the drifted fields and
/// the edit putting them back: `config` (its editable keys only — never
/// the secret) only when one of them drifted, `active` only when it did,
/// the header only when its digest changed (`new_header`); events and
/// branch filter always, since Forgejo replaces them on every edit (see
/// [`HookPatch`]).
fn hook_differs(d: &DesiredHook, r: &RemoteHook, new_header: bool) -> (Drift, HookPatch) {
    let mut drift = Drift::default();
    let editable: BTreeMap<String, String> = d
        .config
        .iter()
        .filter(|(k, _)| forgejo_echoes(&d.type_, k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (key, value) in &editable {
        drift.note(echoed_key(key), r.config.get(key) != Some(value));
    }
    let config = (!drift.is_empty()).then_some(editable);
    let remote_events: BTreeSet<String> = r.events.iter().map(|e| e.to_lowercase()).collect();
    drift.note("events", remote_events != forgejo_events(&d.events));
    drift.note("branch_filter", d.branch_filter != r.branch_filter);
    let mut active = Some(d.active);
    drift.keep("active", &mut active, &r.active);
    let patch = HookPatch {
        config,
        events: d.events.clone(),
        branch_filter: d.branch_filter.clone(),
        active,
        authorization_header: d.authorization_header.clone().filter(|_| new_header),
    };
    (drift, patch)
}

/// A key [`forgejo_echoes`] accepts, as the field a drift names.
fn echoed_key(key: &str) -> &'static str {
    match key {
        "url" => "config.url",
        "content_type" => "config.content_type",
        "channel" => "config.channel",
        "username" => "config.username",
        "icon_url" => "config.icon_url",
        "color" => "config.color",
        _ => "config",
    }
}

/// Config keys Forgejo returns on a GET and applies on an edit.
pub fn forgejo_echoes(type_: &str, key: &str) -> bool {
    matches!(key, "url" | "content_type")
        || (type_ == "slack" && matches!(key, "channel" | "username" | "icon_url" | "color"))
}

/// The events Forgejo reports for a hook created or edited with `events`:
/// it matches names case-insensitively, defaults to `push`, and expands
/// the umbrella events into the sub-events it stores (`issues_only` /
/// `pull_request_only` select the umbrella event alone).
pub fn forgejo_events(events: &[String]) -> BTreeSet<String> {
    const ISSUES: &[&str] = &[
        "issues",
        "issue_assign",
        "issue_label",
        "issue_milestone",
        "issue_comment",
    ];
    const REVIEWS: &[&str] = &[
        "pull_request_review_approved",
        "pull_request_review_rejected",
        "pull_request_review_comment",
    ];
    const PULLS: &[&str] = &[
        "pull_request",
        "pull_request_assign",
        "pull_request_label",
        "pull_request_milestone",
        "pull_request_comment",
        "pull_request_sync",
        "pull_request_review_request",
    ];
    let mut out = BTreeSet::new();
    for event in events {
        let event = event.to_lowercase();
        let expanded: Vec<&str> = match event.as_str() {
            "issues" => ISSUES.to_vec(),
            "issues_only" => vec!["issues"],
            "pull_request" => PULLS.iter().chain(REVIEWS).copied().collect(),
            "pull_request_only" => vec!["pull_request"],
            "pull_request_review" => REVIEWS.to_vec(),
            other => vec![other],
        };
        out.extend(expanded.into_iter().map(str::to_string));
    }
    if out.is_empty() {
        out.insert("push".to_string());
    }
    out
}

/// What `status.appliedSecretHash` records, as
/// `v3:<salt>:<create-only>:<header>`: digests of the create-only inputs
/// (the secret and every config key Forgejo doesn't echo) and of the
/// authorization header, `-` when absent. The status is readable by anyone
/// who can read the CR, so the digests are salted per CR and stretched: a
/// low-entropy secret can't be looked up, and guessing it offline is slow.
/// Earlier releases stored `v2:` (unsalted digests), or one digest of
/// (secret, header) — both still compared, then upgraded.
#[derive(Debug, PartialEq, Eq)]
struct Applied {
    salt: String,
    create_only: String,
    header: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Change {
    None,
    /// Only editable inputs changed.
    Edit,
    /// A create-only input changed: the hook must be recreated.
    Recreate,
}

/// Rounds of the v3 digest stretching.
const STRETCH_ROUNDS: u32 = 10_000;

/// The create-only parts of `desired`, as `(key, value)` pairs.
fn create_only(desired: &DesiredHook) -> Vec<&str> {
    let create_only: BTreeMap<&String, &String> = desired
        .config
        .iter()
        .filter(|(k, _)| !forgejo_echoes(&desired.type_, k))
        .collect();
    create_only
        .into_iter()
        .flat_map(|(k, v)| [k.as_str(), v.as_str()])
        .collect()
}

impl Applied {
    /// With the salt of `stored` when it is v3, a fresh one otherwise.
    fn of(desired: &DesiredHook, stored: Option<&str>) -> Self {
        let salt = stored
            .and_then(|s| s.strip_prefix("v3:"))
            .and_then(|rest| rest.split(':').next())
            .filter(|salt| !salt.is_empty())
            .map_or_else(fresh_salt, str::to_string);
        Self {
            create_only: stretched(&salt, create_only(desired)),
            header: stretched(&salt, desired.authorization_header.as_deref()),
            salt,
        }
    }

    fn encode(&self) -> String {
        format!("v3:{}:{}:{}", self.salt, self.create_only, self.header)
    }

    fn compare(
        &self,
        stored: Option<&str>,
        desired: &DesiredHook,
        input: &WebhookInput<'_>,
    ) -> Change {
        let split = |rest: &str, create_only: &str, header: &str| match rest.split_once(':') {
            Some((c, _)) if c != create_only => Change::Recreate,
            Some((_, h)) if h != header => Change::Edit,
            Some(_) => Change::None,
            None => Change::Recreate,
        };
        if let Some(rest) = stored.and_then(|s| s.strip_prefix("v3:")) {
            return match rest.split_once(':') {
                Some((_, digests)) => split(digests, &self.create_only, &self.header),
                None => Change::Recreate,
            };
        }
        if let Some(rest) = stored.and_then(|s| s.strip_prefix("v2:")) {
            let header = digest(desired.authorization_header.as_deref());
            return split(rest, &digest(create_only(desired)), &header);
        }
        // Pre-v2 status: unchanged inputs need no call; otherwise which
        // part changed is unknown, and recreating covers both.
        if stored.map(str::to_string) == legacy_hash(input) {
            Change::None
        } else {
            Change::Recreate
        }
    }
}

fn fresh_salt() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `-` for nothing; a length-prefixed SHA-256 of the parts otherwise (so
/// ("ab", "c") and ("a", "bc") differ). The v2 digest.
fn digest<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    raw_digest(parts).map_or_else(|| "-".to_string(), |h| hex(&h))
}

fn raw_digest<'a>(parts: impl IntoIterator<Item = &'a str>) -> Option<[u8; 32]> {
    let mut parts = parts.into_iter().peekable();
    parts.peek()?;
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    Some(h.finalize().into())
}

/// The v3 digest: [`digest`]'s, then `STRETCH_ROUNDS` of SHA-256 over
/// (salt, previous).
fn stretched<'a>(salt: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let Some(mut h) = raw_digest(parts) else {
        return "-".to_string();
    };
    for _ in 0..STRETCH_ROUNDS {
        let mut next = Sha256::new();
        next.update(salt.as_bytes());
        next.update(h);
        h = next.finalize().into();
    }
    hex(&h)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The pre-v2 `appliedSecretHash`: `None` when neither input was set.
fn legacy_hash(input: &WebhookInput<'_>) -> Option<String> {
    if input.secret.is_none() && input.authorization_header.is_none() {
        return None;
    }
    let mut h = Sha256::new();
    for part in [&input.secret, &input.authorization_header] {
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
    use crate::test_support::{Edit, FakeForgejo};

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

    /// Forgejo's hook edit ignores the secret: a new value means a new hook.
    #[tokio::test]
    async fn a_new_secret_value_recreates_the_hook() {
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
        let new = second.forgejo.unwrap();
        assert_ne!(new.id, current.id);
        assert!(fj.hook(current.id).is_none(), "old hook deleted");
        assert_eq!(fj.hook(new.id).unwrap().1.get("secret").unwrap(), "k2");
    }

    #[tokio::test]
    async fn removing_the_secret_clears_it_once_then_stays_quiet() {
        let fj = FakeForgejo::default();
        let s = spec();
        let first = run(&s, None, repo("app"), Some("k"), None, &fj).await;
        let second = run(
            &s,
            first.forgejo.clone(),
            repo("app"),
            None,
            first.secret_hash.clone(),
            &fj,
        )
        .await;
        let new = second.forgejo.clone().unwrap();
        assert!(!fj.hook(new.id).unwrap().1.contains_key("secret"));

        fj.clear_calls();
        run(&s, Some(new), repo("app"), None, second.secret_hash, &fj).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn a_new_authorization_header_is_edited_in_place() {
        let fj = FakeForgejo::default();
        let s = spec();
        let input = |current, header: &str, applied| WebhookInput {
            spec: &s,
            current,
            target: repo("app"),
            secret: Some("k".into()),
            authorization_header: Some(header.into()),
            applied_secret_hash: applied,
        };
        let first = reconcile_webhook(input(None, "Bearer a", None), &fj).await;
        let current = first.forgejo.clone().unwrap();
        fj.clear_calls();
        let second = reconcile_webhook(
            input(Some(current.clone()), "Bearer b", first.secret_hash.clone()),
            &fj,
        )
        .await;
        assert_eq!(second.forgejo.unwrap().id, current.id);
        assert_eq!(
            fj.calls(),
            vec![format!("edit_hook repo:weebo/app {}", current.id)]
        );
        // Nothing Forgejo shows drifted: counted, not announced, and the
        // config (with the secret) stays out of the edit.
        assert_eq!(second.write, Some(RemoteWrite::Drift));
        assert!(second.drift.is_empty());
        let edits: [Edit; 1] = fj.edits().try_into().unwrap();
        let [Edit::Hook(patch)] = edits else {
            panic!("one hook edit expected");
        };
        assert_eq!(patch.config, None);
        assert_eq!(patch.active, None);
        assert_eq!(patch.authorization_header.as_deref(), Some("Bearer b"));
    }

    /// Forgejo replaces events and branch filter on every edit: they are
    /// always sent; `config` (and the secret) never, unless an editable
    /// key drifted; the header only when it changed.
    #[tokio::test]
    async fn a_drifted_active_flag_is_edited_without_the_config() {
        let fj = FakeForgejo::default();
        let s = spec();
        let input = |current, applied| WebhookInput {
            spec: &s,
            current,
            target: repo("app"),
            secret: Some("k".into()),
            authorization_header: Some("Bearer a".into()),
            applied_secret_hash: applied,
        };
        let first = reconcile_webhook(input(None, None), &fj).await;
        assert_eq!(first.write, Some(RemoteWrite::Created));
        let current = first.forgejo.clone().unwrap();
        let disabled = HookPatch {
            active: Some(false),
            events: vec!["push".into()],
            ..Default::default()
        };
        fj.edit_hook(&repo("app"), current.id, &disabled)
            .await
            .unwrap();

        fj.clear_calls();
        let again = reconcile_webhook(input(Some(current.clone()), first.secret_hash), &fj).await;
        assert_eq!(again.drift.fields(), ["active"]);
        assert_eq!(again.write, Some(RemoteWrite::Drift));
        assert_eq!(
            fj.edits(),
            [Edit::Hook(HookPatch {
                config: None,
                events: vec!["push".into()],
                branch_filter: String::new(),
                active: Some(true),
                authorization_header: None,
            })]
        );
        let (_, config) = fj.hook(current.id).unwrap();
        assert_eq!(config.get("secret").map(String::as_str), Some("k"));
    }

    #[tokio::test]
    async fn a_drifted_url_sends_the_editable_config_only() {
        let fj = FakeForgejo::default();
        let s = spec();
        let first = run(&s, None, repo("app"), Some("k"), None, &fj).await;
        let current = first.forgejo.clone().unwrap();
        let moved = HookPatch {
            config: Some(BTreeMap::from([(
                "url".to_string(),
                "https://elsewhere.example.com".to_string(),
            )])),
            events: vec!["push".into()],
            ..Default::default()
        };
        fj.edit_hook(&repo("app"), current.id, &moved)
            .await
            .unwrap();

        fj.clear_calls();
        let again = run(
            &s,
            Some(current),
            repo("app"),
            Some("k"),
            first.secret_hash,
            &fj,
        )
        .await;
        assert_eq!(again.drift.fields(), ["config.url"]);
        let edits: [Edit; 1] = fj.edits().try_into().unwrap();
        let [Edit::Hook(patch)] = edits else {
            panic!("one hook edit expected");
        };
        let keys: Vec<&str> = patch
            .config
            .iter()
            .flatten()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(keys, ["content_type", "url"]);
        assert_eq!(patch.active, None);
    }

    #[tokio::test]
    async fn umbrella_events_and_create_only_config_stay_quiet() {
        let fj = FakeForgejo::default();
        let mut s = spec();
        s.events = vec!["pull_request".into(), "Issues".into()];
        s.http_method = Some("post".into());
        s.extra_config.insert("custom".into(), "x".into());
        let first = run(&s, None, repo("app"), None, None, &fj).await;
        fj.clear_calls();
        run(&s, first.forgejo, repo("app"), None, first.secret_hash, &fj).await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
    }

    #[tokio::test]
    async fn a_create_only_config_change_recreates() {
        let fj = FakeForgejo::default();
        let mut s = spec();
        let first = run(&s, None, repo("app"), None, None, &fj).await;
        s.http_method = Some("get".into());
        let second = run(
            &s,
            first.forgejo.clone(),
            repo("app"),
            None,
            first.secret_hash,
            &fj,
        )
        .await;
        assert_ne!(second.forgejo.unwrap().id, first.forgejo.unwrap().id);
    }

    /// Status written by earlier releases: unchanged inputs need no call.
    #[tokio::test]
    async fn a_pre_v2_hash_is_upgraded_without_calls() {
        let fj = FakeForgejo::default();
        let s = spec();
        let first = run(&s, None, repo("app"), Some("k"), None, &fj).await;
        let legacy = legacy_hash(&WebhookInput {
            spec: &s,
            current: None,
            target: repo("app"),
            secret: Some("k".into()),
            authorization_header: None,
            applied_secret_hash: None,
        });
        fj.clear_calls();
        let second = run(
            &s,
            first.forgejo.clone(),
            repo("app"),
            Some("k"),
            legacy,
            &fj,
        )
        .await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
        let upgraded = second.secret_hash.clone().unwrap();
        assert!(upgraded.starts_with("v3:"), "{upgraded}");
        // From then on the salted digest is stable.
        let third = run(
            &s,
            first.forgejo.clone(),
            repo("app"),
            Some("k"),
            Some(upgraded.clone()),
            &fj,
        )
        .await;
        assert!(fj.calls().is_empty(), "{:?}", fj.calls());
        assert_eq!(third.secret_hash.as_deref(), Some(upgraded.as_str()));
    }

    #[test]
    fn digests_are_salted_per_cr() {
        let hook = DesiredHook {
            type_: "forgejo".into(),
            config: BTreeMap::from([("secret".to_string(), "hunter2".to_string())]),
            events: vec![],
            branch_filter: String::new(),
            active: true,
            authorization_header: None,
        };
        let (a, b) = (Applied::of(&hook, None), Applied::of(&hook, None));
        assert_ne!(a.salt, b.salt);
        assert_ne!(
            a.create_only, b.create_only,
            "same secret, different digests"
        );
        assert_ne!(
            a.create_only,
            digest(create_only(&hook)),
            "not the bare SHA-256"
        );
        let again = Applied::of(&hook, Some(&a.encode()));
        assert_eq!(again, a);
    }

    #[test]
    fn umbrella_events_expand_like_forgejo() {
        let ev = |e: &[&str]| forgejo_events(&e.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(ev(&[]), ev(&["push"]));
        assert_eq!(ev(&["issues_only"]).len(), 1);
        assert_eq!(ev(&["issues"]).len(), 5);
        assert_eq!(ev(&["pull_request"]).len(), 10);
        assert!(ev(&["pull_request_review"]).contains("pull_request_review_approved"));
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

    #[tokio::test]
    async fn a_twin_hook_is_never_created() {
        let fj = FakeForgejo::default();
        let s = spec();
        let first = run(&s, None, repo("app"), Some("k"), None, &fj).await;
        assert!(first.ready.is_ok(), "{first:?}");
        // The status update was lost: the next reconcile knows of no hook.
        let again = run(&s, None, repo("app"), Some("k"), None, &fj).await;
        assert_eq!(again.reason(), ReasonCode::ForgejoObjectAlreadyExists);
        assert_eq!(fj.list_hooks(&repo("app")).await.unwrap().len(), 1);
    }
}
