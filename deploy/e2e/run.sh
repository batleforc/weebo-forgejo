#!/usr/bin/env bash
# kind e2e (`task e2e`, .github/workflows/e2e.yml): deploys cert-manager, a
# disposable Forgejo and the operator chart into the current kube context,
# then walks the golden path — instance → users → org → team → repository
# → hook/keys → OAuth2/token → policy denials — and checks leader election
# and deletion policies on the real deployment.
#
# Env: IMAGE (operator image already loaded in the cluster, default
# weebo-forgejo-operator:e2e), CERT_MANAGER_VERSION (default latest).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHART="$HERE/../charts/weebo-forgejo"
IMAGE="${IMAGE:-weebo-forgejo-operator:e2e}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-latest}"
OPERATOR_NS=weebo-forgejo-system
RELEASE=weebo-forgejo
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
  kubectl get forgejoinstances,forgejousers,forgejoorganizations,forgejoteams,forgejouserkeys -o wide
  kubectl -n team-a get forgejorepositories,forgejowebhooks,forgejodeploykeys,forgejooauth2applications,forgejoaccesstokens -o yaml
  kubectl get events -A --sort-by=.lastTimestamp | tail -n 50
}
trap 'dump' ERR

ready() { kubectl wait --for=condition=Ready=True --timeout="$WAIT" "$@"; }

# Forgejo API through a port-forward, as the admin.
forgejo_api() {
  curl -fsS -H "Authorization: token $ADMIN_TOKEN" "http://127.0.0.1:13000/api/v1$1"
}

step "cert-manager ($CERT_MANAGER_VERSION)"
if [ "$CERT_MANAGER_VERSION" = latest ]; then
  url=https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
else
  url="https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
fi
kubectl apply -f "$url"
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

step "operator chart ($IMAGE)"
helm upgrade --install "$RELEASE" "$CHART" \
  --namespace "$OPERATOR_NS" --create-namespace \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE##*:}" \
  --set image.pullPolicy=Never \
  --set extraEnv[0].name=RUST_LOG --set extraEnv[0].value=info \
  --wait --timeout 5m

step "golden path: cluster-scoped kinds"
kubectl create namespace team-a
kubectl create namespace other
kubectl apply -f "$HERE/golden-path.yaml"
ready forgejoinstance/main
ready forgejouser/alice forgejouser/ci-bot forgejoorganization/weebo forgejoteam/weebo-devs forgejouserkey/ci-bot
kubectl -n team-a get secret alice-password ci-bot-ssh >/dev/null

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
forgejo_api /teams/"$(kubectl get forgejoteam weebo-devs -o jsonpath='{.status.forgejoId}')"/members \
  | jq -e '[.[].login] | sort == ["alice", "ci-bot"]' >/dev/null || fail "team members"
token="$(kubectl -n team-a get secret ci -o jsonpath='{.data.FORGEJO_TOKEN}' | base64 -d)"
curl -fsS -H "Authorization: token $token" http://127.0.0.1:13000/api/v1/user \
  | jq -e '.login == "ci-bot"' >/dev/null || fail "the issued token does not act as ci-bot"

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
lease() { kubectl -n "$OPERATOR_NS" get lease weebo-forgejo-operator-leader -o jsonpath='{.spec.holderIdentity}'; }
leader="$(lease)"
[ -n "$leader" ] || fail "nobody holds the lease"
acquired="$(kubectl -n "$OPERATOR_NS" logs -l app.kubernetes.io/name=weebo-forgejo --prefix --tail=-1 \
  | grep -c 'acquired the leader lease' || true)"
[ "$acquired" = 1 ] || fail "expected exactly one leader, $acquired replicas acquired the lease"
restarts() { kubectl -n "$OPERATOR_NS" get pod "$leader" -o jsonpath='{.status.containerStatuses[0].restartCount}'; }
before="$(restarts)"
# Steal the lease: the leader must notice on its next renewal and exit.
kubectl -n "$OPERATOR_NS" patch lease weebo-forgejo-operator-leader --type merge \
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
kubectl patch forgejoorganization weebo --type merge -p '{"spec":{"description":"after failover"}}'
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
