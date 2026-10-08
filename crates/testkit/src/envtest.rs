//! Real `kube-apiserver` + `etcd` through the kit's envtest harness
//! (`weebo_kit_testkit::envtest`), with this operator's CRDs from
//! `deploy/crd/` installed — layer 3 of `.prompt/plan.md`'s test strategy.
//! See the kit for the build requirements (Go, `libclang.so`; `task doctor`
//! checks them).

use std::ops::Deref;
use std::path::Path;

pub struct EnvTestCluster(weebo_kit_testkit::envtest::EnvTestCluster);

impl EnvTestCluster {
    /// Panics on any setup failure: a broken harness should fail loudly at
    /// the call site rather than be threaded through every test.
    pub async fn start() -> Self {
        let crd_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crd");
        Self(weebo_kit_testkit::envtest::EnvTestCluster::start(&crd_dir).await)
    }
}

/// `client()`, `kubeconfig()`, `write_kubeconfig()`.
impl Deref for EnvTestCluster {
    type Target = weebo_kit_testkit::envtest::EnvTestCluster;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
