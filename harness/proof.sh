#!/usr/bin/env bash
# proof.sh: the three cluster runs of the proof, on the cluster that
# "up.sh cage harness/fixture/apps --no-netpol" built. It is green only if all three hold.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
fixture=$here/fixture
tmp=$(mktemp -d)
failed=0

k() { kubectl --context kind-loop "$@"; }
diagnose() {  # what a red run needs in its log
  k get pods,networkpolicy -A -o wide || true
  k get mutatingpolicies.policies.kyverno.io,generatingpolicies.policies.kyverno.io \
    -o jsonpath='{range .items[*]}{.kind}/{.metadata.name} {.status}{"\n"}{end}' || true
}
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
    --probe "$tmp/probe-$n.json" --cause "${GITHUB_EVENT_NAME:-workflow_dispatch}" --cluster harness \
    --run "${GITHUB_RUN_ID:-none}" --commit "${GITHUB_SHA:-none}" --rung-set-by harness \
    --out "$tmp/line-$n.json" >/dev/null || code=$?
  echo "run $n: loop.py exit $code: $(cat "$tmp/line-$n.json" 2>&1)"
  if [ -s "$tmp/line-$n.json" ] && holds "$tmp/line-$n.json" "$@"; then
    echo "run $n: green"
  else
    echo "run $n: RED"
    failed=1
    diagnose
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

echo "== run 3: the break test. The rule is deleted. Git and the labels still say quarantine."
k -n fixture delete networkpolicy cage-reach-quarantine
sleep 15
run 3 capabilities.egress=open exposure=51000.00 verdict=cage-ineffective

[ "$failed" -eq 0 ] || { echo "proof.sh: red"; exit 1; }
echo "proof.sh: green, all three runs hold"
