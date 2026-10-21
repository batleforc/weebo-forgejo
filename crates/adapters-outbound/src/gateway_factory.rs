use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api::ForgejoInstance;
use api::common::SecretKeyRef;
use api::instance::TlsOptions;
use application::ports::{BoundInstance, ForgejoGateway, GatewayFactory, GatewayFactoryError};
use kube::{Client, ResourceExt};

use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::forgejo_http::ForgejoHttpGateway;
use crate::instance_resolver::ForgejoInstances;
use crate::metered::{MeteredGateway, max_inflight};
use weebo_kit_adapters::{Resolved, TokenSecretError, read_local_instance_token, read_secret_key};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Forgejo clones synchronously inside `POST /repos/migrate` (and
/// `generate`): a timeout there would leave a half-imported repository the
/// next reconcile collides with, so it gets a generous budget.
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Builds a [`ForgejoHttpGateway`] per call from the resolved
/// `ForgejoInstance` or `ForgejoLocalInstance` (whose token and CA live in
/// its own namespace), wrapped in a [`MeteredGateway`]. The token `Secret`
/// (and CA) are re-read on every call — a rotation needs no restart — but
/// the HTTP clients (connection pools, TLS sessions) are reused per
/// instance until its TLS settings or CA content change, and every gateway
/// of one instance shares its in-flight limit.
pub struct ForgejoGatewayFactory {
    client: Client,
    instances: Arc<ForgejoInstances>,
    cache: Mutex<HashMap<String, CachedClients>>,
}

/// What a gateway is built from, whichever the instance kind.
struct Connection {
    /// The clients' cache key: the instance (kind, namespace, name).
    key: String,
    url: String,
    token_secret_ref: SecretKeyRef,
    /// A `ForgejoLocalInstance`: its token `Secret` must be labelled for
    /// it (`forgejo.weebo.io/instance-token: "true"`).
    local: bool,
    tls: TlsOptions,
}

impl Connection {
    fn of_cluster(instance: &ForgejoInstance) -> Self {
        Self {
            key: BoundInstance::cluster(instance.name_any()).to_string(),
            url: instance.spec.url.clone(),
            token_secret_ref: instance.spec.token_secret_ref.clone(),
            local: false,
            tls: instance.spec.tls.clone(),
        }
    }
}

/// What the HTTP clients of an instance were built from.
#[derive(Clone, PartialEq, Eq)]
struct ClientKey {
    insecure_skip_verify: bool,
    ca_digest: Option<Vec<u8>>,
}

struct CachedClients {
    key: ClientKey,
    http: reqwest::Client,
    slow: reqwest::Client,
    permits: Arc<Semaphore>,
}

impl ForgejoGatewayFactory {
    /// `instances`: both kinds, from the reflectors `operator::main` keeps
    /// live, or from the API on each call (tests).
    pub fn new(client: Client, instances: Arc<ForgejoInstances>) -> Self {
        Self {
            instances,
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The instance's cached clients, rebuilt when what they were built
    /// from changed.
    fn clients(
        &self,
        instance: &Connection,
        ca_pem: Option<&[u8]>,
    ) -> Result<(reqwest::Client, reqwest::Client, Arc<Semaphore>), GatewayFactoryError> {
        let key = ClientKey {
            insecure_skip_verify: instance.tls.insecure_skip_verify,
            ca_digest: ca_pem.map(|pem| Sha256::digest(pem).to_vec()),
        };
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let name = instance.key.clone();
        if let Some(c) = cache.get(&name)
            && c.key == key
        {
            return Ok((c.http.clone(), c.slow.clone(), c.permits.clone()));
        }
        let http = build_http_client(&instance.tls, ca_pem, REQUEST_TIMEOUT)?;
        let slow = build_http_client(&instance.tls, ca_pem, MIGRATION_TIMEOUT)?;
        // A TLS change keeps the in-flight limit: calls still running on
        // the old clients count against it.
        let permits = cache
            .get(&name)
            .map(|c| c.permits.clone())
            .unwrap_or_else(|| Arc::new(Semaphore::new(max_inflight())));
        cache.insert(
            name,
            CachedClients {
                key,
                http: http.clone(),
                slow: slow.clone(),
                permits: permits.clone(),
            },
        );
        Ok((http, slow, permits))
    }

    /// The gateway of `instance`, a `ForgejoInstance`.
    pub async fn build(
        &self,
        instance: &ForgejoInstance,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError> {
        self.connect(Connection::of_cluster(instance)).await
    }

    async fn connect(
        &self,
        instance: Connection,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError> {
        let token_ref = &instance.token_secret_ref;
        let token = if instance.local {
            read_local_instance_token(&self.client, token_ref, &api::ANNOTATIONS)
                .await
                .map_err(|e| match e {
                    TokenSecretError::NotAllowed { .. } => {
                        GatewayFactoryError::TokenSecretNotAllowed(e.to_string())
                    }
                    TokenSecretError::Kubernetes(e) => GatewayFactoryError::Kubernetes(e),
                })?
        } else {
            read_secret_key(&self.client, token_ref)
                .await
                .map_err(GatewayFactoryError::Kubernetes)?
        }
        .ok_or_else(|| {
            GatewayFactoryError::TokenSecret(format!(
                "secret {}/{} has no key {:?}",
                token_ref.namespace, token_ref.name, token_ref.key
            ))
        })?;
        let token = String::from_utf8(token)
            .map_err(|_| GatewayFactoryError::TokenSecret("token is not UTF-8".into()))?;

        let ca_pem = match &instance.tls.ca_secret_ref {
            Some(ca_ref) => Some(
                read_secret_key(&self.client, ca_ref)
                    .await
                    .map_err(GatewayFactoryError::Kubernetes)?
                    .ok_or_else(|| {
                        GatewayFactoryError::ResolutionFailed(format!(
                            "tls.caSecretRef {}/{} has no key {:?}",
                            ca_ref.namespace, ca_ref.name, ca_ref.key
                        ))
                    })?,
            ),
            None => None,
        };
        let (http, slow, permits) = self.clients(&instance, ca_pem.as_deref())?;

        let (api_base, web_url) = api::instance::split_urls(&instance.url);
        let gateway = ForgejoHttpGateway::new(api_base, web_url, token.trim().to_string(), http)
            .with_slow_client(slow);
        Ok(Arc::new(MeteredGateway::new(Arc::new(gateway), permits)))
    }
}

#[async_trait::async_trait]
impl GatewayFactory for ForgejoGatewayFactory {
    async fn gateway_for(
        &self,
        bound: &BoundInstance,
    ) -> Result<Arc<dyn ForgejoGateway>, GatewayFactoryError> {
        let connection = match self
            .instances
            .get(bound)
            .await
            .map_err(|e| GatewayFactoryError::Kubernetes(e.to_string()))?
            .ok_or_else(|| GatewayFactoryError::InstanceNotFound(bound.to_string()))?
        {
            Resolved::Cluster(instance) => Connection::of_cluster(&instance),
            Resolved::Local(local) => {
                let namespace = local.namespace().unwrap_or_default();
                Connection {
                    key: bound.to_string(),
                    url: local.spec.url.clone(),
                    token_secret_ref: local.spec.token_secret_ref.in_namespace(&namespace),
                    local: true,
                    tls: local.spec.tls.in_namespace(&namespace),
                }
            }
        };
        self.connect(connection).await
    }
}

/// `ca_pem` is added on top of the platform trust store. A configured CA
/// that holds no certificate is an error, never a silent fallback to the
/// platform roots.
fn build_http_client(
    tls: &TlsOptions,
    ca_pem: Option<&[u8]>,
    timeout: Duration,
) -> Result<reqwest::Client, GatewayFactoryError> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(pem) = ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| {
            GatewayFactoryError::ResolutionFailed(format!("parsing tls.caSecretRef: {e}"))
        })?;
        if certs.is_empty() {
            return Err(GatewayFactoryError::ResolutionFailed(
                "tls.caSecretRef contains no PEM certificate".to_string(),
            ));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if tls.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().map_err(|e| {
        GatewayFactoryError::ResolutionFailed(format!("building the Forgejo HTTP client: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_ca_is_refused() {
        assert!(build_http_client(&TlsOptions::default(), Some(b"nope"), REQUEST_TIMEOUT).is_err());
        assert!(build_http_client(&TlsOptions::default(), None, REQUEST_TIMEOUT).is_ok());
    }
}
