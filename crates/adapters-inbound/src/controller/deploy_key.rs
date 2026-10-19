use std::sync::Arc;
use std::time::Instant;

use api::{ForgejoDeployKey, ForgejoRepository};
use application::ports::{BoundInstance, RefKind, SecretOwner};
use application::use_cases::admission::enforce_on;
use application::use_cases::reconcile_key::{KeyInput, KeyOwner, cleanup_key, reconcile_key};
use application::use_cases::refs::{recorded_name, resolve_required};
use application::use_cases::{Failure, Outcome, RemoteWrite};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};

use super::status::current_ref;
use super::{
    Ctx, Error, FINALIZER, ScopedWatches, error_policy, requeue_after, rotate_nonce, status,
};
use crate::metrics::{record_reconcile, record_write};

const KIND: &str = "ForgejoDeployKey";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(
        ctx.scope.api::<ForgejoDeployKey>(client.clone()),
        &ctx.scope,
    );
    // A policy change may allow or forbid any CR of this kind: re-check
    // them all (policies change rarely, and the check is a local list).
    let by_policy = controller.store();
    let keys = controller.store();
    let results = controller
        .watches_in::<ForgejoRepository, _>(&ctx, &client, move |repo| {
            let (name, ns) = (repo.name_any(), repo.namespace());
            keys.state()
                .into_iter()
                .filter(|k| k.namespace() == ns && k.spec.repository_ref.name == name)
                .map(|k| ObjectRef::from_obj(k.as_ref()))
                .collect::<Vec<_>>()
        })
        .watches_in::<api::ForgejoNamespacePolicy, _>(&ctx, &client, move |_| {
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

async fn reconcile(obj: Arc<ForgejoDeployKey>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if super::import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<ForgejoDeployKey> = Api::namespaced(ctx.client.clone(), &ns);
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

async fn repository(
    key: &ForgejoDeployKey,
    instance: &BoundInstance,
    ctx: &Ctx,
) -> Result<Result<String, Failure>, Error> {
    let ns = key.namespace().unwrap_or_default();
    let name = &key.spec.repository_ref.name;
    let repo = resolve_required(ctx.refs.as_ref(), RefKind::Repository, &ns, name, instance);
    Ok(repo.await?.map(|r| r.name))
}

async fn apply(
    api: &Api<ForgejoDeployKey>,
    key: &ForgejoDeployKey,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&key.name_any()).await?;
    let started = Instant::now();
    let owned = current_ref(&current);
    let ns = current.namespace().unwrap_or_default();
    let name = current.name_any();

    let namespace = current.namespace().unwrap_or_default();
    let mut resolved = None;
    let outcome = match super::instance_of(ctx, &current).await {
        Err(f) => Outcome::failed(current_ref(&current), f),
        Ok(bound) => match enforce_on(
            ctx.policies.as_ref(),
            ctx.refs.as_ref(),
            &namespace,
            &current,
            Some(&bound),
        )
        .await?
        {
            // Re-checked here too: a policy may have changed since admission.
            Err(f) => Outcome::failed(current_ref(&current), f),
            Ok(()) => match repository(&current, &bound, ctx).await? {
                Err(f) => Outcome::failed(owned.clone(), f),
                Ok(full_name) => match super::backends(ctx, &bound).await {
                    Ok((gateway, secrets)) => {
                        resolved = Some(full_name.clone());
                        let input = KeyInput {
                            owner: KeyOwner::Repository(full_name),
                            title: current
                                .spec
                                .title
                                .clone()
                                .unwrap_or_else(|| current.name_any()),
                            read_only: current.spec.read_only,
                            source: &current.spec.key,
                            secret_owner: SecretOwner::namespaced("ForgejoDeployKey", &ns, &name),
                            current: owned.clone(),
                            created_on: super::key_owner(&current.metadata)
                                .map(|o| KeyOwner::Repository(o.to_string())),
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
            },
        }
        .on(bound),
    };

    record_reconcile("ForgejoDeployKey", &outcome, started.elapsed());
    status::publish(api, &ctx.recorder, &current, &outcome).await?;
    super::record_key_owner(api, &current, resolved.as_deref(), owned.as_ref(), &outcome).await?;
    Ok(requeue_after(&outcome))
}

async fn cleanup(key: &ForgejoDeployKey, ctx: &Ctx) -> Result<Action, Error> {
    let ns = key.namespace().unwrap_or_default();
    let instance = super::cleanup_instance(ctx, key).await;
    // Where the key was created first (the ref may have changed since),
    // then the repository's current name; the repository CR may be not
    // ready or already gone (a namespace deletion, an `Orphan` repository).
    let repo = &key.spec.repository_ref.name;
    let parent = match &instance {
        Ok(bound) => {
            recorded_name(ctx.refs.as_ref(), RefKind::Repository, &ns, repo, bound).await?
        }
        Err(_) => None,
    };
    let delete = key.spec.deletion_policy == api::common::DeletionPolicy::Delete;
    let owners: Vec<KeyOwner> = super::key_cleanup_owners(key, parent, delete)
        .into_iter()
        .map(KeyOwner::Repository)
        .collect();
    let gateway = super::cleanup_gateway(ctx, &instance).await;
    let secrets = super::cleanup_secrets(ctx, &instance).await;
    let deleted = cleanup_key(
        &owners,
        &key.spec.key,
        &SecretOwner::namespaced("ForgejoDeployKey", &ns, &key.name_any()),
        key.spec.deletion_policy,
        current_ref(key).as_ref(),
        gateway.as_deref(),
        secrets.as_ref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    if deleted {
        record_write("ForgejoDeployKey", RemoteWrite::Deleted);
    }
    Ok(Action::await_change())
}
