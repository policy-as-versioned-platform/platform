#!/usr/bin/env bash
# up.sh <cage-dir> <apps-dir> [--no-netpol]
# Build the kind cluster "loop": Kyverno, the cage, the reference, then the apps.
# The cage is in place before any workload, so no pod is admitted uncaged.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cage=$1 apps=$2 netpol=yes
[ "${3:-}" = --no-netpol ] && netpol=no

k() { kubectl --context kind-loop "$@"; }
poll() {  # poll <seconds> <command...>: true as soon as the command succeeds
  local tries=$(($1 / 3)); shift
  for _ in $(seq "$tries"); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 3
  done
  return 1
}
policy_ready() { [ "$(k get -f "$1" -o jsonpath='{.status.conditionStatus.ready}')" = true ]; }
policy() {  # apply one cage file and wait until Kyverno serves it
  k apply -f "$1"
  poll 180 policy_ready "$1" || { echo "up.sh: $1 is not ready after 180 seconds" >&2; return 1; }
}
diagnose() {  # what a red run needs in its log
  k get pods,networkpolicy -A -o wide || true
  k get mutatingpolicies.policies.kyverno.io,generatingpolicies.policies.kyverno.io \
    -o jsonpath='{range .items[*]}{.kind}/{.metadata.name} {.status}{"\n"}{end}' || true
}

# 1. The pinned binaries, checked, in a temporary directory and never in the checkout.
tmp=${RUNNER_TEMP:-$(mktemp -d)}
if [[ "$(kind version 2>/dev/null)" != "kind v0.32.0 "* ]]; then
  [ "$(uname -s)" = Linux ] || { echo "up.sh: kind v0.32.0 must be on the path" >&2; exit 1; }
  curl -fsSL -o "$tmp/kind" https://github.com/kubernetes-sigs/kind/releases/download/v0.32.0/kind-linux-amd64
  echo "50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54  $tmp/kind" | sha256sum -c -
  chmod +x "$tmp/kind"
  export PATH="$tmp:$PATH"
fi
curl -fsSL -o "$tmp/kyverno.yaml" https://github.com/kyverno/kyverno/releases/download/v1.18.2/install.yaml
echo "3dcd43eaf11f0719084217148cd0c82a8fa49faa9b1a783ea5bea2cf84041bda  $tmp/kyverno.yaml" | sha256sum -c -

# 2. The cluster.
if ! kind get clusters 2>/dev/null | grep -x loop >/dev/null; then
  kind create cluster --name loop --wait 120s
fi
trap '[ $? -eq 0 ] || diagnose' EXIT

# 3. Kyverno. Server-side, because two of its CRDs are too large for a client-side apply.
k apply --server-side --force-conflicts -f "$tmp/kyverno.yaml"
k -n kyverno rollout status deployment/kyverno-admission-controller --timeout=300s
k -n kyverno rollout status deployment/kyverno-background-controller --timeout=300s

# 4. The cage.
policy "$cage/cage-tier.yaml"
if [ "$netpol" = yes ]; then
  policy "$cage/cage-netpol.yaml"
fi

# 5. The reference, outside the cage.
k apply -f "$here/reference.yaml" -f "$apps/namespace.yaml"
k -n loop-reference wait --for=condition=Ready pod/sink pod/client --timeout=300s

# 6. The apps. Kyverno writes the network rule after the pod is admitted, so a probe that ran
# first would read a false "open". The probe's settle step waits for the pods themselves.
k apply -k "$apps"
ns=$(k get namespace -l policy-as-versioned.dev/governed=true -o jsonpath='{.items[*].metadata.name}')
rung=$(k get namespace -l policy-as-versioned.dev/governed=true -o jsonpath='{.items[*].metadata.labels.posture\.acme\.io/tier}')
if [ "$netpol" = yes ] && [ "$rung" != baseline ]; then
  poll 120 k -n "$ns" get networkpolicy "cage-reach-$rung" ||
    echo "up.sh: no NetworkPolicy cage-reach-$rung in $ns after 120 seconds. The probe reports what it finds."
fi
