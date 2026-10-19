//! One watch per kind, shared by every controller watching it (as its
//! primary kind or as a referenced one) and by the claim and policy reads
//! (their stores): without it, each `Controller::watches` opens its own
//! watch — `ForgejoNamespacePolicy` was listed and watched nine times,
//! `ForgejoUser` seven, `ForgejoRepository` five — and every one of them
//! LISTs when the controllers start, right after the lease is taken.
//!
//! The binary spawns them before it campaigns for the lease: a standby
//! replica keeps its stores warm, and the new leader's controllers start
//! from stores that already listed. A controller subscribing gets every
//! object of the store once it has listed, then every change: what its own
//! watch would have yielded.

use std::collections::VecDeque;
use std::fmt::Debug;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

use api::{
    ForgejoAccessToken, ForgejoDeployKey, ForgejoInstance, ForgejoLocalInstance,
    ForgejoNamespacePolicy, ForgejoOAuth2Application, ForgejoOrganization, ForgejoRepository,
    ForgejoTeam, ForgejoUser, ForgejoUserKey, ForgejoWebhook,
};
use futures::{Stream, StreamExt};
use kube::api::Api;
use kube::runtime::controller::Config;
use kube::runtime::reflector::{self, Store};
use kube::runtime::utils::Predicate;
use kube::runtime::{Controller, WatchStreamExt, predicates, watcher};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use tokio::sync::broadcast;
use weebo_kit_runtime::controller::concurrency;
use weebo_kit_runtime::scope::KindScope;
use weebo_kit_runtime::{Health, WatchScope};

/// Changes a subscriber may fall behind by before it re-reads the whole
/// store (it then sees every object again: nothing is lost, the
/// controller's predicates drop what didn't change).
const BUFFER: usize = 256;

/// A change: the object, and whether it was deleted.
type Change<K> = (Arc<K>, bool);

/// A reflector whose changes are broadcast to its subscribers.
pub struct SharedWatch<K: Resource<DynamicType = ()> + 'static> {
    store: Store<K>,
    changes: broadcast::Sender<Change<K>>,
    /// `true` once the store has listed. Subscribers wait on this, not on
    /// `Store::wait_until_ready`: kube's readiness wakes one waiter only
    /// (a single oneshot), and the controller's runner waits on it too.
    listed: tokio::sync::watch::Receiver<bool>,
}

impl<K: Resource<DynamicType = ()> + 'static> Clone for SharedWatch<K> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            changes: self.changes.clone(),
            listed: self.listed.clone(),
        }
    }
}

/// What a watch event broadcasts, and whether it says the store listed.
fn change<K>(event: watcher::Event<K>) -> (Option<Change<K>>, bool) {
    match event {
        watcher::Event::Apply(o) | watcher::Event::InitApply(o) => {
            (Some((Arc::new(o), false)), false)
        }
        watcher::Event::Delete(o) => (Some((Arc::new(o), true)), false),
        watcher::Event::Init => (None, false),
        watcher::Event::InitDone => (None, true),
    }
}

impl<K> SharedWatch<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Send + Sync + 'static,
{
    /// Watches `api` through `config` in the background: watch errors back
    /// off exponentially and are reported to `health` under `name`, as the
    /// kit's `spawn_reflector`. Nothing is buffered while no one
    /// subscribes.
    pub fn spawn(
        api: Api<K>,
        config: watcher::Config,
        health: Arc<Health>,
        name: &'static str,
    ) -> Self {
        let (store, writer) = reflector::store::<K>();
        let (changes, _) = broadcast::channel(BUFFER);
        let (listed_tx, listed) = tokio::sync::watch::channel(false);
        let sender = changes.clone();
        // The reflector applies each event to the store before yielding it.
        let stream = reflector::reflector(writer, watcher(api, config).default_backoff());
        tokio::spawn(async move {
            stream
                .for_each(|event| {
                    match event {
                        Ok(event) => {
                            health.ok(name);
                            let (change, done) = change(event);
                            if let Some(change) = change {
                                // No subscriber yet (standby): dropped.
                                let _ = sender.send(change);
                            }
                            if done {
                                listed_tx.send_replace(true);
                            }
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "{name} watch error");
                            health.failed(name, err.to_string());
                        }
                    }
                    futures::future::ready(())
                })
                .await;
        });
        Self {
            store,
            changes,
            listed,
        }
    }

    /// The live store (`wait_until_ready` before trusting it empty).
    pub fn store(&self) -> Store<K> {
        self.store.clone()
    }

    /// Every object of the store once it has listed, then every change —
    /// the whole store again when this subscriber fell behind.
    fn subscribe(&self) -> impl Stream<Item = Change<K>> + Send + 'static {
        struct State<K: Resource<DynamicType = ()> + 'static> {
            changes: broadcast::Receiver<Change<K>>,
            listed: tokio::sync::watch::Receiver<bool>,
            store: Store<K>,
            pending: VecDeque<Change<K>>,
            read: bool,
        }
        // Subscribed before the store is read: a change in between is seen
        // twice, never missed.
        let state = State {
            changes: self.changes.subscribe(),
            listed: self.listed.clone(),
            store: self.store.clone(),
            pending: VecDeque::new(),
            read: false,
        };
        futures::stream::unfold(state, |mut state| async move {
            loop {
                if let Some(change) = state.pending.pop_front() {
                    return Some((change, state));
                }
                if !state.read {
                    // Its watch gone before listing: the process is
                    // stopping.
                    state.listed.wait_for(|listed| *listed).await.ok()?;
                    let all = state.store.state().into_iter().map(|o| (o, false));
                    state.pending = all.collect();
                    state.read = true;
                    continue;
                }
                match state.changes.recv().await {
                    Ok(change) => return Some((change, state)),
                    Err(broadcast::error::RecvError::Lagged(_)) => state.read = false,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
    }

    /// What a `Controller::watches` on the kind yields: every object
    /// touched, deleted ones included.
    pub fn touched(&self) -> impl Stream<Item = Result<K, watcher::Error>> + Send + 'static {
        self.subscribe().map(|(o, _)| Ok(K::clone(&o)))
    }

    /// The objects applied, deletions left out: a controller's primary
    /// watch (`applied_objects`).
    fn applied(&self) -> impl Stream<Item = Result<K, watcher::Error>> + Send + 'static {
        self.subscribe()
            .filter_map(|(o, deleted)| futures::future::ready((!deleted).then(|| Ok(K::clone(&o)))))
    }
}

/// Hash of `deletionTimestamp`: a deletion must always reach the finalizer
/// (as the kit's controller).
fn deletion<K: Resource>(obj: &K) -> Option<u64> {
    obj.meta().deletion_timestamp.as_ref().map(|t| {
        let mut h = DefaultHasher::new();
        t.0.to_string().hash(&mut h);
        h.finish()
    })
}

/// The kit's controller (`weebo_kit_runtime::controller::controller`) on a
/// shared watch: same predicates — spec (`generation`), annotations,
/// labels, finalizers, deletion, never the CR's own status patches — and
/// the same concurrency.
pub fn controller_on<K>(shared: &SharedWatch<K>) -> Controller<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Send + Sync + 'static,
{
    let trigger = shared.applied().predicate_filter(
        predicates::generation
            .combine(predicates::annotations)
            .combine(predicates::labels)
            .combine(predicates::finalizers)
            .combine(deletion),
        Default::default(),
    );
    Controller::for_stream(trigger, shared.store())
        .with_config(Config::default().concurrency(concurrency()))
}

/// The binary's shared watches. A kind without one (a test's `Ctx`, the
/// instances, `ForgejoNamespacePolicy` as a primary kind) is watched by
/// each controller on its own.
///
/// `policies` is watched without the label selector: the policy checks
/// read every policy, whichever release selects it, so a change to any of
/// them re-checks the CRs. Every other one is on the watch scope.
#[derive(Clone, Default)]
pub struct Watches {
    pub policies: Option<SharedWatch<ForgejoNamespacePolicy>>,
    pub users: Option<SharedWatch<ForgejoUser>>,
    pub organizations: Option<SharedWatch<ForgejoOrganization>>,
    pub teams: Option<SharedWatch<ForgejoTeam>>,
    pub repositories: Option<SharedWatch<ForgejoRepository>>,
    pub user_keys: Option<SharedWatch<ForgejoUserKey>>,
    pub webhooks: Option<SharedWatch<ForgejoWebhook>>,
    pub deploy_keys: Option<SharedWatch<ForgejoDeployKey>>,
    pub oauth2_applications: Option<SharedWatch<ForgejoOAuth2Application>>,
    pub access_tokens: Option<SharedWatch<ForgejoAccessToken>>,
}

/// `scope` without its label selector: its namespace only.
pub fn unselected(scope: &WatchScope) -> WatchScope {
    match scope.watched_namespace() {
        Some(ns) => WatchScope::namespace(ns),
        None => WatchScope::cluster(),
    }
}

impl Watches {
    /// Every shared watch, on `scope` (`policies` without its label
    /// selector, and only when it watches cluster-scoped kinds).
    pub fn spawn(client: &Client, scope: &WatchScope, health: &Arc<Health>) -> Self {
        fn on<K>(
            client: &Client,
            scope: &WatchScope,
            health: &Arc<Health>,
            name: &'static str,
        ) -> Option<SharedWatch<K>>
        where
            K: Resource<DynamicType = ()>
                + Clone
                + Debug
                + DeserializeOwned
                + Send
                + Sync
                + 'static,
            K::Scope: KindScope,
        {
            let api = scope.api::<K>(client.clone());
            Some(SharedWatch::spawn(
                api,
                scope.watcher_config(),
                health.clone(),
                name,
            ))
        }
        let (c, s, h) = (client, scope, health);
        Self {
            policies: scope
                .cluster_kinds()
                .then(|| on(c, &unselected(s), h, "ForgejoNamespacePolicy watch"))
                .flatten(),
            users: on(c, s, h, "ForgejoUser watch"),
            organizations: on(c, s, h, "ForgejoOrganization watch"),
            teams: on(c, s, h, "ForgejoTeam watch"),
            repositories: on(c, s, h, "ForgejoRepository watch"),
            user_keys: on(c, s, h, "ForgejoUserKey watch"),
            webhooks: on(c, s, h, "ForgejoWebhook watch"),
            deploy_keys: on(c, s, h, "ForgejoDeployKey watch"),
            oauth2_applications: on(c, s, h, "ForgejoOAuth2Application watch"),
            access_tokens: on(c, s, h, "ForgejoAccessToken watch"),
        }
    }
}

impl Watches {
    /// Resolves once every shared watch has listed (or is gone).
    pub async fn listed(&self) {
        let all = [
            self.policies.as_ref().map(|w| w.listed.clone()),
            self.users.as_ref().map(|w| w.listed.clone()),
            self.organizations.as_ref().map(|w| w.listed.clone()),
            self.teams.as_ref().map(|w| w.listed.clone()),
            self.repositories.as_ref().map(|w| w.listed.clone()),
            self.user_keys.as_ref().map(|w| w.listed.clone()),
            self.webhooks.as_ref().map(|w| w.listed.clone()),
            self.deploy_keys.as_ref().map(|w| w.listed.clone()),
            self.oauth2_applications.as_ref().map(|w| w.listed.clone()),
            self.access_tokens.as_ref().map(|w| w.listed.clone()),
        ];
        for mut listed in all.into_iter().flatten() {
            let _ = listed.wait_for(|listed| *listed).await;
        }
    }
}

/// Picks a kind's shared watch out of [`Watches`] (none: its own watch).
pub trait Shared: Resource<DynamicType = ()> + Sized + 'static {
    fn shared(_watches: &Watches) -> Option<&SharedWatch<Self>> {
        None
    }
}

macro_rules! shared {
    ($($kind:ty => $field:ident),+ $(,)?) => {$(
        impl Shared for $kind {
            fn shared(watches: &Watches) -> Option<&SharedWatch<Self>> {
                watches.$field.as_ref()
            }
        }
    )+};
}
shared!(
    ForgejoNamespacePolicy => policies,
    ForgejoUser => users,
    ForgejoOrganization => organizations,
    ForgejoTeam => teams,
    ForgejoRepository => repositories,
    ForgejoUserKey => user_keys,
    ForgejoWebhook => webhooks,
    ForgejoDeployKey => deploy_keys,
    ForgejoOAuth2Application => oauth2_applications,
    ForgejoAccessToken => access_tokens,
);
impl Shared for ForgejoInstance {}
impl Shared for ForgejoLocalInstance {}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::ObjectMeta;

    fn cm(name: &str) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some("ns".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// A shared watch fed by hand: its writer, to apply events, and its
    /// "listed" signal.
    struct Fed {
        shared: SharedWatch<ConfigMap>,
        writer: reflector::store::Writer<ConfigMap>,
        listed: tokio::sync::watch::Sender<bool>,
    }

    fn fed() -> Fed {
        let (store, writer) = reflector::store::<ConfigMap>();
        let (changes, _) = broadcast::channel(BUFFER);
        let (listed, rx) = tokio::sync::watch::channel(false);
        Fed {
            shared: SharedWatch {
                store,
                changes,
                listed: rx,
            },
            writer,
            listed,
        }
    }

    /// As the background task: the store, then the broadcast.
    fn apply(fed: &mut Fed, event: watcher::Event<ConfigMap>) {
        fed.writer.apply_watcher_event(&event);
        let (change, done) = change(event);
        if let Some(change) = change {
            let _ = fed.shared.changes.send(change);
        }
        if done {
            fed.listed.send_replace(true);
        }
    }

    fn names(changes: &[Change<ConfigMap>]) -> Vec<(String, bool)> {
        let mut names: Vec<_> = changes
            .iter()
            .map(|(o, d)| (o.metadata.name.clone().unwrap_or_default(), *d))
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn a_subscriber_sees_the_listed_objects_then_the_changes() {
        let mut fed = fed();
        let mut stream = Box::pin(fed.shared.subscribe());
        // Nothing before the store has listed.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
                .await
                .is_err()
        );
        apply(&mut fed, watcher::Event::Init);
        apply(&mut fed, watcher::Event::InitApply(cm("a")));
        apply(&mut fed, watcher::Event::InitDone);
        let first: Vec<_> = vec![stream.next().await.unwrap()];
        // Listed: the store's object (and the buffered change, twice at
        // worst — never missed).
        assert_eq!(names(&first), [("a".into(), false)]);
        apply(&mut fed, watcher::Event::Delete(cm("a")));
        let mut seen = Vec::new();
        while let Ok(Some(change)) =
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next()).await
        {
            seen.push(change);
        }
        assert!(names(&seen).contains(&("a".into(), true)));
    }

    #[tokio::test]
    async fn a_lagging_subscriber_rereads_the_whole_store() {
        let mut fed = fed();
        apply(&mut fed, watcher::Event::Init);
        apply(&mut fed, watcher::Event::InitDone);
        let mut stream = Box::pin(fed.shared.subscribe());
        for i in 0..BUFFER + 10 {
            apply(&mut fed, watcher::Event::Apply(cm(&format!("o{i}"))));
        }
        let mut seen = Vec::new();
        while let Ok(Some(change)) =
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next()).await
        {
            seen.push(change);
        }
        let names = names(&seen);
        for i in 0..BUFFER + 10 {
            assert!(names.contains(&(format!("o{i}"), false)), "o{i} missed");
        }
    }

    #[tokio::test]
    async fn the_primary_stream_leaves_deletions_out() {
        let mut fed = fed();
        apply(&mut fed, watcher::Event::Init);
        apply(&mut fed, watcher::Event::InitDone);
        let mut stream = Box::pin(fed.shared.applied());
        // Listed (empty): now waiting for changes.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
                .await
                .is_err()
        );
        apply(&mut fed, watcher::Event::Apply(cm("a")));
        apply(&mut fed, watcher::Event::Delete(cm("a")));
        apply(&mut fed, watcher::Event::Apply(cm("b")));
        let mut seen = Vec::new();
        while let Ok(Some(Ok(o))) =
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next()).await
        {
            seen.push(o.metadata.name.unwrap_or_default());
        }
        assert_eq!(seen, ["a", "b"]);
    }

    #[tokio::test]
    async fn the_watches_are_listed_once_every_one_has() {
        let none = Watches::default();
        none.listed().await;

        let (store, _writer) = reflector::store::<ForgejoUser>();
        let (changes, _) = broadcast::channel(BUFFER);
        let (tx, listed) = tokio::sync::watch::channel(false);
        let users = SharedWatch {
            store,
            changes,
            listed,
        };
        let watches = Watches {
            users: Some(users),
            ..Default::default()
        };
        let wait = tokio::time::timeout(std::time::Duration::from_millis(50), watches.listed());
        assert!(wait.await.is_err());
        tx.send_replace(true);
        watches.listed().await;
    }

    #[tokio::test]
    async fn changes_are_dropped_while_no_one_subscribes() {
        let mut fed = fed();
        apply(&mut fed, watcher::Event::Apply(cm("a")));
        assert_eq!(fed.shared.changes.len(), 0);
    }
}
