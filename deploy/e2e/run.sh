#!/usr/bin/env bash
# kind e2e (`task e2e`, .github/workflows/e2e.yml): deploys cert-manager, a
# disposable Forgejo and the operator chart into the current kube context,
# then walks the golden path — instance → identities (users, org, team in
# the `identities` namespace) → the team's repository, across namespaces
# → hook/keys → OAuth2/token → policy denials — and checks leader election
# and deletion policies on the real deployment.
#
# With a previously published chart, it first installs that release, creates
# the golden-path CRs with it, then upgrades to this checkout's chart and
# checks they stay Ready (skipped when no release exists yet).
#
# Env: IMAGE (operator image already loaded in the cluster, default
# weebo-forgejo-operator:e2e), CERT_MANAGER_VERSION (default: the pinned
# release below; its manifest is checksum-verified only for the pinned one),
# UPGRADE_FROM (previous chart version to upgrade from: empty = the latest
# published one, `none` = skip the upgrade test).
# -E: functions (ready, ...) inherit the ERR trap that dumps diagnostics.
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHART="$HERE/../charts/weebo-forgejo"
IMAGE="${IMAGE:-weebo-forgejo-operator:e2e}"
# Pinned: bump both together (sha256 of the release's cert-manager.yaml).
CERT_MANAGER_PINNED=v1.21.2
CERT_MANAGER_SHA256=e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-$CERT_MANAGER_PINNED}"
CHART_OCI=oci://ghcr.io/batleforc/charts/weebo-forgejo
UPGRADE_FROM="${UPGRADE_FROM:-}"
OPERATOR_NS=weebo-forgejo-system
RELEASE=weebo-forgejo
# The chart's default Lease name (leaderElection.leaseName).
LEASE=weebo-forgejo-operator-leader
WAIT=180s

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() {
  printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2
  dump
  exit 1
}

# Diagnostics for whatever failed: operator logs, CR conditions, events.
dump() {
  set +e
  step "diagnostics"
  kubectl -n "$OPERATOR_NS" get pods -o wide
  kubectl -n "$OPERATOR_NS" logs -l app.kubernetes.io/name=weebo-forgejo --tail=200 --prefix --all-containers
  kubectl get forgejoinstances -o wide
  kubectl -n identities get forgejousers,forgejoorganizations,forgejoteams,forgejouserkeys -o yaml
  kubectl -n team-a get forgejorepositories,forgejowebhooks,forgejodeploykeys,forgejooauth2applications,forgejoaccesstokens -o yaml
  kubectl get events -A --sort-by=.lastTimestamp | tail -n 50
}
# dump turns errexit off: leave right after it.
trap 'dump; exit 1' ERR

ready() { kubectl wait --for=condition=Ready=True --timeout="$WAIT" "$@"; }

# Forgejo API through a port-forward, as the admin.
forgejo_api() {
  curl -fsS -H "Authorization: token $ADMIN_TOKEN" "http://127.0.0.1:13000/api/v1$1"
}

# Every CR of the golden path must be Ready.
all_ready() {
  ready forgejoinstance/main
  ready -n identities forgejouser/alice forgejouser/ci-bot forgejoorganization/weebo \
    forgejoteam/weebo-devs forgejouserkey/ci-bot
  ready -n team-a forgejorepository/app forgejowebhook/app-ci forgejodeploykey/app-ci \
    forgejooauth2application/grafana forgejoaccesstoken/ci
}

ensure_ns() { kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; }

step "cert-manager ($CERT_MANAGER_VERSION)"
manifest="$(mktemp)"
curl -fsSLo "$manifest" \
  "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
if [ "$CERT_MANAGER_VERSION" = "$CERT_MANAGER_PINNED" ]; then
  echo "$CERT_MANAGER_SHA256  $manifest" | sha256sum -c - >/dev/null || fail "cert-manager.yaml checksum mismatch"
fi
kubectl apply -f "$manifest"
kubectl -n cert-manager wait --for=condition=Available --timeout="$WAIT" deploy --all

step "Forgejo"
kubectl apply -f "$HERE/forgejo.yaml"
kubectl -n forgejo rollout status deploy/forgejo --timeout="$WAIT"
kubectl -n forgejo exec deploy/forgejo -- forgejo admin user create --admin \
  --username e2e-admin --password 'e2e-only-insecure-password' \
  --email e2e-admin@e2e.local --must-change-password=false
ADMIN_TOKEN="$(kubectl -n forgejo exec deploy/forgejo -- forgejo admin user \
  generate-access-token --username e2e-admin --token-name operator --scopes all --raw)"
kubectl -n forgejo create secret generic forgejo-admin --from-literal=token="$ADMIN_TOKEN"
kubectl -n forgejo port-forward svc/forgejo 13000:3000 >/dev/null 2>&1 &
PORT_FORWARD=$!
trap 'kill "$PORT_FORWARD" 2>/dev/null || true' EXIT

# ── Upgrade test, part 1: the previous release ────────────────────────────
head_version="$(awk '/^version:/ {print $2}' "$CHART/Chart.yaml")"
previous=""
if [ "$UPGRADE_FROM" != none ]; then
  if [ -n "$UPGRADE_FROM" ]; then
    previous="$UPGRADE_FROM"
  else
    previous="$(helm show chart "$CHART_OCI" 2>/dev/null | awk '/^version:/ {print $2}' || true)"
  fi
  if [ -z "$previous" ]; then
    echo "no published chart at $CHART_OCI: upgrade test skipped"
  elif [ "$previous" = "$head_version" ]; then
    echo "latest published chart is this version ($head_version): upgrade test skipped"
    previous=""
  fi
fi

if [ -n "$previous" ]; then
  step "upgrade test: install the published chart $previous"
  # Its own release image, pulled from ghcr.io.
  helm install "$RELEASE" "$CHART_OCI" --version "$previous" \
    --namespace "$OPERATOR_NS" --create-namespace \
    --set extraEnv[0].name=RUST_LOG --set extraEnv[0].value=info \
    --wait --timeout 5m
  ensure_ns identities
  ensure_ns team-a
  ensure_ns other
  kubectl apply -f "$HERE/golden-path.yaml"
  # The namespaced kinds go through the old release's webhook: retry while
  # cert-manager injects its CA.
  for _ in $(seq 1 30); do kubectl apply -f "$HERE/team-a.yaml" && break; sleep 2; done
  all_ready
  # Charts up to 0.1.0 shipped the CRDs in crds/, outside the release:
  # adopt them so the templated CRDs of this chart can take over.
  for crd in $(kubectl get crd -o name | grep '\.forgejo\.weebo\.io$'); do
    kubectl label "$crd" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null
    kubectl annotate "$crd" meta.helm.sh/release-name="$RELEASE" \
      meta.helm.sh/release-namespace="$OPERATOR_NS" --overwrite >/dev/null
  done
  step "upgrade test: upgrade $previous -> $head_version (this checkout)"
fi

step "operator chart ($IMAGE)"
# The kit's library chart, as Chart.lock pins it.
helm dependency build --skip-refresh "$CHART"
helm upgrade --install "$RELEASE" "$CHART" \
  --namespace "$OPERATOR_NS" --create-namespace \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE##*:}" \
  --set image.pullPolicy=Never \
  --set references.crossNamespace=true \
  --set extraEnv[0].name=RUST_LOG --set extraEnv[0].value=info \
  --wait --timeout 5m
kubectl -n "$OPERATOR_NS" rollout status "deploy/$RELEASE" --timeout="$WAIT"

if [ -n "$previous" ]; then
  step "upgrade test: CRs created by $previous stay Ready"
  # The new leader re-reconciles everything; give it one pass, then every
  # CR must (still) be Ready and the CRDs must carry the keep policy.
  sleep 15
  all_ready
  for crd in $(kubectl get crd -o name | grep '\.forgejo\.weebo\.io$'); do
    [ "$(kubectl get "$crd" -o jsonpath='{.metadata.annotations.helm\.sh/resource-policy}')" = keep ] \
      || fail "$crd lacks helm.sh/resource-policy: keep after the upgrade"
  done
fi

step "golden path: instance, policy and identities"
ensure_ns identities
ensure_ns team-a
ensure_ns other
# The identities go through the admission webhook: retry while it comes up
# (cert-manager injecting its CA, endpoints getting ready).
applied=""
for _ in $(seq 1 30); do
  if kubectl apply -f "$HERE/golden-path.yaml"; then applied=1; break; fi
  sleep 2
done
[ -n "$applied" ] || fail "the golden path was never admitted"
ready forgejoinstance/main
ready -n identities forgejouser/alice forgejouser/ci-bot forgejoorganization/weebo \
  forgejoteam/weebo-devs forgejouserkey/ci-bot
kubectl -n identities get secret alice-password ci-bot-ssh >/dev/null

step "golden path: namespaced kinds (through the admission webhook)"
kubectl apply -f "$HERE/team-a.yaml"
ready -n team-a forgejorepository/app forgejowebhook/app-ci forgejodeploykey/app-ci \
  forgejooauth2application/grafana forgejoaccesstoken/ci
kubectl -n team-a get secret app-deploy-key grafana ci >/dev/null

step "Forgejo really holds it"
forgejo_api /repos/weebo/app | jq -e '.private == true' >/dev/null || fail "weebo/app not private"
[ "$(forgejo_api /repos/weebo/app/hooks | jq length)" = 1 ] || fail "expected one hook on weebo/app"
[ "$(forgejo_api /repos/weebo/app/keys | jq length)" = 1 ] || fail "expected one deploy key"
forgejo_api /repos/weebo/app/teams | jq -e 'any(.name == "devs")' >/dev/null || fail "devs has no access"
forgejo_api /teams/"$(kubectl -n identities get forgejoteam weebo-devs -o jsonpath='{.status.forgejoId}')"/members \
  | jq -e '[.[].login] | sort == ["alice", "ci-bot"]' >/dev/null || fail "team members"
token="$(kubectl -n team-a get secret ci -o jsonpath='{.data.FORGEJO_TOKEN}' | base64 -d)"
curl -fsS -H "Authorization: token $token" http://127.0.0.1:13000/api/v1/repos/weebo/app \
  | jq -e '.full_name == "weebo/app"' >/dev/null || fail "the issued token can't read weebo/app"

step "policy denials"
# One document per apply, so each refusal is checked on its own.
doc() { awk -v n="$1" '/^---$/{d++; next} d==n' "$HERE/denied.yaml"; }
for n in 0 1; do
  if out="$(doc "$n" | kubectl apply -f - 2>&1)"; then
    fail "admission accepted denied document $n: $out"
  fi
  grep -q NamespaceNotAllowed <<<"$out" || fail "unexpected refusal for document $n: $out"
done

step "leader election"
lease() { kubectl -n "$OPERATOR_NS" get lease "$LEASE" -o jsonpath='{.spec.holderIdentity}'; }
leader="$(lease)"
[ -n "$leader" ] || fail "nobody holds the lease"
acquired="$(kubectl -n "$OPERATOR_NS" logs -l app.kubernetes.io/name=weebo-forgejo --prefix --tail=-1 \
  | grep -c 'acquired the leader lease' || true)"
[ "$acquired" = 1 ] || fail "expected exactly one leader, $acquired replicas acquired the lease"
restarts() { kubectl -n "$OPERATOR_NS" get pod "$leader" -o jsonpath='{.status.containerStatuses[0].restartCount}'; }
before="$(restarts)"
# Steal the lease: the leader must notice on its next renewal and exit.
kubectl -n "$OPERATOR_NS" patch lease "$LEASE" --type merge \
  -p "{\"spec\":{\"holderIdentity\":\"e2e-intruder\",\"renewTime\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)\"}}"
for _ in $(seq 1 30); do
  [ "$(restarts)" -gt "$before" ] && break
  sleep 2
done
[ "$(restarts)" -gt "$before" ] || fail "$leader kept running after losing the lease"
# The intruder never renews: after the TTL a replica takes over.
for _ in $(seq 1 30); do
  holder="$(lease)"
  [ "$holder" != e2e-intruder ] && [ -n "$holder" ] && break
  sleep 2
done
[ "$holder" != e2e-intruder ] || fail "no replica took the lease back"
echo "lease: $leader -> e2e-intruder -> $holder"
# The new leader reconciles: a change goes through.
kubectl -n identities patch forgejoorganization weebo --type merge -p '{"spec":{"description":"after failover"}}'
for _ in $(seq 1 30); do
  [ "$(forgejo_api /orgs/weebo | jq -r .description)" = "after failover" ] && break
  sleep 2
done
[ "$(forgejo_api /orgs/weebo | jq -r .description)" = "after failover" ] || fail "no reconcile after failover"

step "deletion policies"
kubectl -n team-a delete forgejowebhook app-ci --wait --timeout="$WAIT"
[ "$(forgejo_api /repos/weebo/app/hooks | jq length)" = 0 ] || fail "Delete policy left the hook"
kubectl -n team-a delete forgejorepository app --wait --timeout="$WAIT"
forgejo_api /repos/weebo/app >/dev/null || fail "Orphan policy deleted the repository"

step "e2e passed"
