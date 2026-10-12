use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoNamespacePolicy, ForgejoUser, ForgejoUserKey};
use application::ports::{BoundInstance, ForgejoGateway, RefKind, SecretOwner};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_key::{KeyInput, KeyOwner, cleanup_key, reconcile_key};
use application::use_cases::refs::{recorded_identity, resolve_identity_required};
use application::use_cases::{Failure, Outcome};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};

use super::status::current_ref;
use super::{
    Ctx, Error, FINALIZER, ScopedWatches, error_policy, requeue_after, rotate_nonce, status,
};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoUserKey";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(ctx.scope.api::<ForgejoUserKey>(client.clone()), &ctx.scope);
    let keys = controller.store();
    // A policy change may allow or forbid any CR of this kind.
    let by_policy = controller.store();
    let results = controller
        .watches_in::<ForgejoUser, _>(&ctx, &client, move |user| {
            let (name, ns) = (user.name_any(), user.namespace());
            keys.state()
                .into_iter()
                .filter(|k| {
                    let key_ns = k.namespace();
                    k.spec
                        .user_ref
                        .points_at(key_ns.as_deref(), ns.as_deref(), &name)
                })
                .map(|k| ObjectRef::from_obj(k.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<ForgejoNamespacePolicy, _>(&ctx, &client, move |_| {
            by_policy
                .state()
                .into_iter()
                .map(|o| ObjectRef::from_obj(o.as_ref()))
                .collect::<Vec<_>>()
        })
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<ForgejoUserKey>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoUserKey> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(key) => apply(&api, &key, &ctx).await,
            FinalizerEvent::Cleanup(key) => {
                super::finalize(key.as_ref(), &ctx, cleanup(&key, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

/// The namespace policy, then the user's login.
async fn user(
    key: &ForgejoUserKey,
    instance: &BoundInstance,
    gateway: &dyn ForgejoGateway,
    ctx: &Ctx,
) -> Result<Result<String, Failure>, Error> {
    let ns = key.namespace().unwrap_or_default();
    let (policies, refs) = (ctx.policies.as_ref(), ctx.refs.as_ref());
    if let Err(f) = enforce_on(policies, refs, &ns, key, Some(instance)).await? {
        return Ok(Err(f));
    }
    let from = super::referrer(ctx, &ns, instance, Some(gateway));
    let user = resolve_identity_required(&from, RefKind::User, &key.spec.user_ref);
    Ok(user.await?.map(|r| r.name))
}

async fn apply(
    api: &Api<ForgejoUserKey>,
    key: &ForgejoUserKey,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&key.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);
    let (name, ns) = (current.name_any(), current.namespace().unwrap_or_default());

    let mut resolved = None;
    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(owned.clone(), f),
        Ok(bound) => match super::backends(ctx, &bound).await {
            Err(f) => Outcome::failed(owned.clone(), f),
            Ok((gateway, secrets)) => match user(&current, &bound, gateway.as_ref(), ctx).await? {
                Ok(login) => {
                    resolved = Some(login.clone());
                    let input = KeyInput {
                        owner: KeyOwner::User(login),
                        title: current
                            .spec
                            .title
                            .clone()
                            .unwrap_or_else(|| current.name_any()),
                        read_only: false,
                        source: &current.spec.key,
                        secret_owner: SecretOwner::namespaced(KIND, &ns, &name)
                            .formerly(api::ANNOTATIONS.previous_owner(&current.metadata)),
                        current: owned.clone(),
                        created_on: super::key_owner(&current.metadata)
                            .map(|o| KeyOwner::User(o.to_string())),
                        rotate_nonce: rotate_nonce(&current.metadata),
                        last_rotation: current
                            .status
                            .as_ref()
                            .and_then(|s| s.last_rotation.clone()),
                        secret_pending: status::secret_pending(&current.status),
                    };
                    reconcile_key(input, gateway.as_ref(), secrets.as_ref()).await
                }
                Err(f) => Outcome::failed(owned.clone(), f),
            },
        }
        .on(bound),
    };

    record_reconcile("ForgejoUserKey", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    super::record_key_owner(api, &current, resolved.as_deref(), owned.as_ref(), &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn cleanup(key: &ForgejoUserKey, ctx: &Ctx) -> Result<Action, Error> {
    let instance = super::cleanup_instance(ctx, key).await;
    // Where the key was created first (the ref may have changed since),
    // then the user's current login; the user CR may be not ready or
    // already gone (an `Orphan` user).
    let ns = key.namespace().unwrap_or_default();
    let user = &key.spec.user_ref;
    let parent = match &instance {
        Ok(bound) => recorded_identity(ctx.refs.as_ref(), RefKind::User, &ns, user, bound).await?,
        Err(_) => None,
    };
    let delete = key.spec.deletion_policy == api::common::DeletionPolicy::Delete;
    let owners: Vec<KeyOwner> = super::key_cleanup_owners(key, parent, delete)
        .into_iter()
        .map(KeyOwner::User)
        .collect();
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    let secrets = super::cleanup_secrets(ctx, &instance).await;
    cleanup_key(
        &owners,
        &key.spec.key,
        &SecretOwner::namespaced(KIND, &ns, &key.name_any())
            .formerly(api::ANNOTATIONS.previous_owner(&key.metadata)),
        key.spec.deletion_policy,
        current_ref(key).as_ref(),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    Ok(Action::await_change())
}
