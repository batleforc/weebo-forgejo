//! Leader election over a `coordination.k8s.io` `Lease`: only one replica
//! may reconcile — two would both attempt-create the same Forgejo object.
//! Split out of `main` so the acquire/lose behaviour is testable.

use std::time::Duration;

use kube::Client;
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};

pub fn lease(
    client: Client,
    namespace: &str,
    name: &str,
    holder_id: String,
    ttl: Duration,
) -> LeaseLock {
    LeaseLock::new(
        client,
        namespace,
        LeaseLockParams {
            holder_id,
            lease_name: name.to_string(),
            lease_ttl: ttl,
        },
    )
}

/// Blocks until this replica holds the lease.
pub async fn acquire(lease: &LeaseLock, retry: Duration) {
    loop {
        match lease.try_acquire_or_renew().await {
            Ok(LeaseLockResult::Acquired(_)) => return,
            Ok(LeaseLockResult::NotAcquired(_)) => {}
            Err(err) => tracing::error!(error = %err, "leader lease acquisition failed, retrying"),
        }
        tokio::time::sleep(retry).await;
    }
}

/// Renews the lease every `renew` and returns as soon as it is lost (taken
/// over, or a renewal failed): the caller must stop reconciling at once.
pub async fn hold(lease: &LeaseLock, renew: Duration) -> String {
    let mut interval = tokio::time::interval(renew);
    interval.tick().await;
    loop {
        interval.tick().await;
        match lease.try_acquire_or_renew().await {
            Ok(LeaseLockResult::Acquired(_)) => {}
            Ok(LeaseLockResult::NotAcquired(_)) => return "lost the leader lease".to_string(),
            Err(err) => return format!("failed to renew the leader lease: {err}"),
        }
    }
}
