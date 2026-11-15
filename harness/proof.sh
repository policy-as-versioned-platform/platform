#!/usr/bin/env bash
# proof.sh: the four cluster runs of the proof, on the cluster that
# "up.sh cage harness/fixture/apps --no-netpol" built. It is green only if all four hold.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
fixture=$here/fixture
tmp=$(mktemp -d)
failed=0

k() { kubectl --context kind-loop "$@"; }
trap 'rm -rf "$tmp"' EXIT

holds() {  # holds <line-file> <field=value>...: every field of the ledger line equals its value, money to the penny
  python3 - "$@" <<'PY'
import json, sys
line = json.load(open(sys.argv[1]))
wrong = 0
for pair in sys.argv[2:]:
    field, want = pair.split("=", 1)
    try:
        want = json.loads(want)
    except ValueError:
        pass
    got = line
    for key in field.split("."):
        got = got.get(key) if isinstance(got, dict) else None
    if got != want:
        print(f"  {field}: want {want!r}, got {got!r}")
        wrong = 1
sys.exit(wrong)
PY
}

run() {  # run <n> <field=value>...: one probe, one cycle, then compare the ledger line
  local n=$1 code=0; shift
  python3 "$root/loop/probe.py" --context kind-loop --out "$tmp/probe-$n.json" >/dev/null || true
  echo "run $n: probe: $(cat "$tmp/probe-$n.json" 2>&1)"
  python3 "$root/loop/loop.py" cycle --party "$fixture/party.json" --namespace-file "$fixture/apps/namespace.yaml" \
    --penalties "$fixture/penalties.json" --threats "$fixture/threats.json" --rungs "$root/cage/rungs.json" \
    --probe "$tmp/probe-$n.json" --cause proof --cluster harness \
    --run none --commit none --rung-set-by harness \
    --out "$tmp/line-$n.json" >/dev/null || code=$?
  echo "run $n: loop.py exit $code: $(cat "$tmp/line-$n.json" 2>&1)"
  if holds "$tmp/line-$n.json" "$@"; then
    echo "run $n: green"
  else
    echo "run $n: RED"
    failed=1
    bash "$here/diagnose.sh"
  fi
}

echo "== run 1: the label-only control. The cage stamps the pod and writes no network rule."
# An exposure below 51000.00 here means the money follows the label, not the measurement.
run 1 'pods=[{"name": "shop", "ready": true, "rung": "quarantine"}]' capabilities.egress=open \
  exposure=51000.00 verdict=cage-ineffective

echo "== run 2: the positive run. The network rule is written when the pod is admitted again."
k -n fixture delete pod shop --timeout=120s
bash "$here/up.sh" "$root/cage" "$fixture/apps" || echo "proof.sh: up.sh did not finish. The probe reports what it finds."
run 2 capabilities.egress=closed capabilities.inbound=open 'serving={"ok": 1, "total": 1}' \
  exposure=1000.00 figure=7000.00 verdict=within
k -n fixture get networkpolicy cage-reach-isolated >/dev/null ||
  { echo "run 2: no NetworkPolicy cage-reach-isolated, so a move in place to isolated would start under no rule: RED"; failed=1; }

echo "== run 3: the break test. The rule is deleted. Git and the labels still say quarantine."
k -n fixture delete networkpolicy cage-reach-quarantine
sleep 15
run 3 capabilities.egress=open exposure=51000.00 verdict=cage-ineffective

pod() { k -n fixture get pod shop -o jsonpath="$1"; }
climb() {  # run 4's steps before the probe. It names the first step that does not hold, and fails there.
  local start uid cpu rules
  # 1. A pod created at baseline. Kyverno reads the Namespace from a cache, hence the waits.
  k label namespace fixture posture.acme.io/tier=baseline --overwrite || return 1
  sleep 5
  k -n fixture delete pod shop --timeout=120s || return 1
  k apply -f "$fixture/apps/shop.yaml" || return 1
  k -n fixture wait --for=condition=Ready pod/shop --timeout=180s || return 1
  [ "$(pod '{.metadata.labels.posture\.acme\.io/tier}')" = baseline ] ||
    { echo "run 4: the pod was not created at baseline"; return 1; }
  start=$(pod '{.status.startTime}')
  uid=$(pod '{.metadata.uid}')
  [ -n "$start" ] && [ -n "$uid" ] || { echo "run 4: the pod has no start time or no uid"; return 1; }
  # 2. The Namespace back at quarantine, and one update to the running pod. It must be admitted.
  k label namespace fixture posture.acme.io/tier=quarantine --overwrite || return 1
  sleep 5
  # A pod created at baseline writes no rule: cage-reach-quarantine, deleted in run 3, is still gone.
  rules=$(k -n fixture get networkpolicy -o name) || { echo "run 4: cannot list the NetworkPolicies"; return 1; }
  case "$rules" in *cage-reach-quarantine*) echo "run 4: a pod created at baseline wrote a network rule"; return 1;; esac
  k -n fixture annotate pod shop --overwrite "loop.policy-as-versioned.dev/touched=$(date +%s)" ||
    { echo "run 4: the update to the running pod was refused"; return 1; }
  # 3. The label follows, and the network rule that run 3 deleted is written again.
  for _ in $(seq 40); do
    [ "$(pod '{.metadata.labels.posture\.acme\.io/tier}')" = quarantine ] &&
      k -n fixture get networkpolicy cage-reach-quarantine >/dev/null 2>&1 && break
    sleep 3
  done
  [ "$(pod '{.metadata.labels.posture\.acme\.io/tier}')" = quarantine ] ||
    { echo "run 4: the pod's label is not quarantine after 120 seconds"; return 1; }
  k -n fixture get networkpolicy cage-reach-quarantine >/dev/null ||
    { echo "run 4: no NetworkPolicy cage-reach-quarantine after 120 seconds"; return 1; }
  # 4. No restart, and baseline's limits stay until the pod is replaced.
  [ "$(pod '{.status.startTime}')" = "$start" ] && [ "$(pod '{.metadata.uid}')" = "$uid" ] ||
    { echo "run 4: the pod was replaced"; return 1; }
  [ "$(pod '{.status.containerStatuses[0].restartCount}')" = 0 ] || { echo "run 4: the container restarted"; return 1; }
  cpu=$(pod '{.spec.containers[0].resources.limits.cpu}')
  [ "$cpu" = 500m ] || { echo "run 4: CPU limit $cpu, want 500m until the pod is replaced"; return 1; }
}

echo "== run 4: a climb in place. A running pod created at baseline is moved to quarantine by one update."
# Before cage 8.0.2 that update was refused: the cage tried to lower a running pod's limits.
climb || { echo "run 4: RED before the probe"; failed=1; bash "$here/diagnose.sh"; }
run 4 'pods=[{"name": "shop", "ready": true, "rung": "quarantine"}]' capabilities.egress=closed \
  capabilities.inbound=open 'serving={"ok": 1, "total": 1}' exposure=1000.00 figure=7000.00 verdict=within

echo "== the cage acts on pods only. Kyverno's rewrite of it for pod controllers is switched off."
if ! configs=$(k get -f "$root/cage/cage-tier.yaml" -o jsonpath='{.status.autogen.configs}'); then
  echo "cannot read cage-tier's status: RED"
  failed=1
elif [ -z "$configs" ]; then
  echo "no rewrite for pod controllers: green"
else
  echo "cage-tier is rewritten for pod controllers: RED"
  failed=1
fi

echo "== the cage's guards. A pod that asks for the host and for privilege comes back without them."
# Server-side dry runs go through Kyverno's admission and start nothing. Namespace cage-check is not
# governed, so its tier label is ignored and a claiming pod falls to isolated. A pod there that claims
# no cage version must not make the cage write a rule.
cat > "$tmp/hostile.py" <<'PY'
import json, sys
pod = json.load(sys.stdin)
pod["metadata"].update(name="guard-check", namespace=sys.argv[1])
pod["metadata"]["labels"].pop("loop.policy-as-versioned.dev/probe")
pod["spec"].pop("securityContext")
pod["spec"].update(hostNetwork=True, hostPID=True, hostIPC=True)
c = pod["spec"]["containers"][0]
c.pop("ports")
c["securityContext"] = {"privileged": True, "allowPrivilegeEscalation": True, "capabilities": {"add": ["NET_ADMIN"]}}
json.dump(pod, sys.stdout)
PY
cat > "$tmp/hardened.py" <<'PY'
import json, sys
namespace, want = sys.argv[1], sys.argv[2]
pod = json.load(sys.stdin)
spec, wrong = pod["spec"], []
tier = pod["metadata"]["labels"].get("posture.acme.io/tier")
if tier != want:
    wrong.append(f"tier {tier}, want {want}")
wrong += [f"{key} kept" for key in ("hostNetwork", "hostPID", "hostIPC") if spec.get(key)]
for c in spec["containers"] + spec.get("initContainers", []):
    sc = c.get("securityContext") or {}
    if sc.get("privileged") is not False or sc.get("allowPrivilegeEscalation") is not False:
        wrong.append(f"{c['name']}: privilege kept")
    if sc.get("runAsNonRoot") is not True:
        wrong.append(f"{c['name']}: runAsNonRoot not set")
    if sc.get("capabilities") != {"drop": ["ALL"]}:
        wrong.append(f"{c['name']}: capabilities {sc.get('capabilities')}")
print(f"guards in {namespace}: " + ("; ".join(wrong) + ": RED" if wrong else "green"))
sys.exit(1 if wrong else 0)
PY
guard() {  # guard <namespace> <tier wanted>
  k create --dry-run=client -o json -f "$fixture/apps/shop.yaml" | python3 "$tmp/hostile.py" "$1" |
    k create --dry-run=server -o json -f - | python3 "$tmp/hardened.py" "$1" "$2"
}
printf '%s\n' 'apiVersion: v1' 'kind: Namespace' \
  'metadata: {name: cage-check, labels: {posture.acme.io/tier: baseline}}' | k apply -f - || failed=1
k -n cage-check run unclaimed --restart=Never --image="$(pod '{.spec.containers[0].image}')" \
  --labels=posture.acme.io/caged=true,posture.acme.io/tier=quarantine || failed=1
sleep 10  # Kyverno reads the Namespace from a cache, and writes rules in the background
if ! rules=$(k -n cage-check get networkpolicy -o name); then
  echo "cannot list the NetworkPolicies in cage-check: RED"; failed=1
elif [ -n "$rules" ]; then
  echo "a pod that claims no cage version made the cage write a rule: RED"; failed=1
fi
guard fixture quarantine || failed=1
guard cage-check isolated || failed=1
k delete namespace cage-check --wait=false || failed=1

[ "$failed" -eq 0 ] || { echo "proof.sh: red"; exit 1; }
echo "proof.sh: green, all four runs hold"
