use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoUser, ForgejoUserKey};
use application::ports::{RefKind, SecretOwner};
use application::use_cases::reconcile_key::{KeyInput, KeyOwner, cleanup_key, reconcile_key};
use application::use_cases::refs::{recorded_name, resolve_required};
use application::use_cases::{Failure, Outcome};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher;
use kube::{Client, ResourceExt};

use super::status::current_ref;
use super::{Ctx, Error, FINALIZER, error_policy, requeue_after, rotate_nonce, status};
use crate::metrics::record_reconcile;

const KIND: &str = "ForgejoUserKey";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(Api::<ForgejoUserKey>::all(client.clone()));
    let keys = controller.store();
    let results = controller
        .watches(
            Api::<ForgejoUser>::all(client),
            watcher::Config::default(),
            move |user| {
                let name = user.name_any();
                keys.state()
                    .into_iter()
                    .filter(|k| k.spec.user_ref.name == name)
                    .map(|k| ObjectRef::from_obj(k.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<ForgejoUserKey>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<ForgejoUserKey> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(key) => apply(&api, &key, &ctx).await,
            FinalizerEvent::Cleanup(key) => {
                super::finalize(key.as_ref(), &ctx, cleanup(&key, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

async fn user(key: &ForgejoUserKey, ctx: &Ctx) -> Result<Result<String, Failure>, Error> {
    let name = &key.spec.user_ref.name;
    let instance = key.spec.instance_ref.as_deref();
    let user = resolve_required(ctx.refs.as_ref(), RefKind::User, "", name, instance);
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
    let name = current.name_any();

    let mut resolved = None;
    let outcome = match user(&current, ctx).await? {
        Err(f) => Outcome::failed(owned.clone(), f),
        Ok(login) => match super::backends(ctx, current.spec.instance_ref.as_deref()).await {
            Ok((gateway, secrets)) => {
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
                    secret_owner: SecretOwner::cluster("ForgejoUserKey", &name),
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
    };

    record_reconcile("ForgejoUserKey", outcome.reason(), started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    super::record_key_owner(api, &current, resolved.as_deref(), owned.as_ref(), &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn cleanup(key: &ForgejoUserKey, ctx: &Ctx) -> Result<Action, Error> {
    let instance = key.spec.instance_ref.as_deref();
    // Where the key was created first (the ref may have changed since),
    // then the user's current login; the user CR may be not ready or
    // already gone (an `Orphan` user).
    let user = &key.spec.user_ref.name;
    let parent = recorded_name(ctx.refs.as_ref(), RefKind::User, "", user, instance).await?;
    let delete = key.spec.deletion_policy == api::common::DeletionPolicy::Delete;
    let owners: Vec<KeyOwner> = super::key_cleanup_owners(key, parent, delete)
        .into_iter()
        .map(KeyOwner::User)
        .collect();
    let gateway = super::cleanup_gateway(ctx, instance).await;
    let secrets = super::cleanup_secrets(ctx, instance).await;
    cleanup_key(
        &owners,
        &key.spec.key,
        &SecretOwner::cluster("ForgejoUserKey", &key.name_any()),
        key.spec.deletion_policy,
        current_ref(key).as_ref(),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(|f| Error::Cleanup(f.message))?;
    Ok(Action::await_change())
}
