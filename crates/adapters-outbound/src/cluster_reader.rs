//! [`KubeClusterReader`]: the [`ReferenceReader`] and [`PolicySource`]
//! ports over the Kubernetes API — the referenced CRs, `Secret` keys and
//! `ForgejoNamespacePolicy` objects the reconcilers and the admission
//! webhook decide on.

use std::fmt::Debug;

use api::namespace_policy::NamespaceRule;
use api::status::ForgejoStatus;
use api::{
    ForgejoNamespacePolicy, ForgejoOrganization, ForgejoRepository, ForgejoTeam, ForgejoUser,
};
use application::ports::{
    ClusterError, ForgejoRef, PolicySource, RefKind, ReferenceReader, ReferencedCr,
};
use kube::{Api, Client};
use serde::de::DeserializeOwned;

use weebo_kit_adapters::read_secret_key;

pub struct KubeClusterReader {
    client: Client,
}

impl KubeClusterReader {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

/// What [`read`] needs from each referenced kind.
struct View<'a> {
    instance_ref: Option<&'a String>,
    status: Option<&'a ForgejoStatus>,
    spec_name: &'a str,
    organization_ref: Option<&'a str>,
}

async fn read<K>(
    api: Api<K>,
    name: &str,
    view: fn(&K) -> View<'_>,
) -> Result<Option<ReferencedCr>, ClusterError>
where
    K: kube::Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned,
{
    let Some(obj) = api
        .get_opt(name)
        .await
        .map_err(|e| ClusterError(format!("reading {} {name}: {e}", K::kind(&()))))?
    else {
        return Ok(None);
    };
    let View {
        instance_ref,
        status,
        spec_name,
        organization_ref,
    } = view(&obj);
    // An unparsable id (hand-edited status) reads as "nothing owned yet".
    let forgejo = status.and_then(|s| {
        Some(ForgejoRef {
            id: s.forgejo_id.as_deref()?.parse().ok()?,
            name: s.forgejo_name.clone()?,
        })
    });
    let ready = status
        .and_then(|s| s.conditions.iter().find(|c| c.type_ == "Ready"))
        .map(|c| (c.status == "True", c.reason.clone()));
    Ok(Some(ReferencedCr {
        instance_ref: instance_ref.cloned(),
        forgejo,
        forgejo_name: status.and_then(|s| s.forgejo_name.clone()),
        ready,
        spec_name: Some(spec_name.to_string()),
        organization_ref: organization_ref.map(str::to_string),
    }))
}

#[async_trait::async_trait]
impl ReferenceReader for KubeClusterReader {
    async fn referenced(
        &self,
        kind: RefKind,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ReferencedCr>, ClusterError> {
        let client = self.client.clone();
        match kind {
            RefKind::User => {
                read(Api::<ForgejoUser>::all(client), name, |o| View {
                    instance_ref: o.spec.instance_ref.as_ref(),
                    status: o.status.as_ref(),
                    spec_name: &o.spec.username,
                    organization_ref: None,
                })
                .await
            }
            RefKind::Organization => {
                read(Api::<ForgejoOrganization>::all(client), name, |o| View {
                    instance_ref: o.spec.instance_ref.as_ref(),
                    status: o.status.as_ref(),
                    spec_name: &o.spec.name,
                    organization_ref: None,
                })
                .await
            }
            RefKind::Team => {
                read(Api::<ForgejoTeam>::all(client), name, |o| View {
                    instance_ref: o.spec.instance_ref.as_ref(),
                    status: o.status.as_ref(),
                    spec_name: &o.spec.name,
                    organization_ref: Some(&o.spec.organization_ref.name),
                })
                .await
            }
            RefKind::Repository => {
                let api = Api::<ForgejoRepository>::namespaced(client, namespace);
                read(api, name, |o| View {
                    instance_ref: o.spec.instance_ref.as_ref(),
                    status: o.status.as_ref(),
                    spec_name: &o.spec.name,
                    organization_ref: None,
                })
                .await
            }
        }
    }

    async fn secret_key(
        &self,
        namespace: &str,
        name: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, ClusterError> {
        let secret_ref = api::common::SecretKeyRef {
            namespace: namespace.to_string(),
            name: name.to_string(),
            key: key.to_string(),
        };
        read_secret_key(&self.client, &secret_ref)
            .await
            .map_err(ClusterError)
    }
}

#[async_trait::async_trait]
impl PolicySource for KubeClusterReader {
    async fn policies(&self) -> Result<Vec<Vec<NamespaceRule>>, ClusterError> {
        let api: Api<ForgejoNamespacePolicy> = Api::all(self.client.clone());
        Ok(api
            .list(&Default::default())
            .await
            .map_err(|e| ClusterError(format!("listing ForgejoNamespacePolicy: {e}")))?
            .into_iter()
            .map(|p| p.spec.rules)
            .collect())
    }
}
