#!/usr/bin/env bash
# verify-fair-tail.sh — every £ number names the severity model that drew it, and
# the heavy tail is actually heavier (ticket 08 decision 7, ADR-0021).
# Offline. exit 0 observed true, 3 could not look, non-zero observed false.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIR="$HERE/fair.py"

command -v python3 >/dev/null 2>&1 || { echo "SKIP: no python3 on PATH"; exit 3; }

echo "==> 1. the engine's own assertions (tail names, heavy > bounded, sums refuse)"
python3 "$FAIR" selfcheck || { echo "FAIL: fair.py selfcheck did not pass"; exit 1; }

echo "==> 2. the CLI reports the tail, and a spliced tail out-prices a bounded one"
python3 - "$FAIR" "$HERE/scenarios" <<'PY' || exit 1
import json, subprocess, sys
fair, scen = sys.argv[1], sys.argv[2]


def summary(name):
    out = subprocess.run([sys.executable, fair, "summary", "%s/%s.json" % (scen, name)],
                         capture_output=True, text=True)
    if out.returncode:
        print("FAIL: fair.py summary %s exited %d: %s" % (name, out.returncode, out.stderr.strip()))
        sys.exit(1)
    return json.loads(out.stdout)


bounded = summary("driftwood-cart-pii")
heavy = summary("driftwood-twin-heavy-tail")
for want, got in (("bounded-pert", bounded), ("lognormal-gpd", heavy)):
    if got.get("tail") != want:
        print("FAIL: expected tail %r, summary printed %r" % (want, got.get("tail")))
        sys.exit(1)
    print("  ok   %-40s tail=%s VaR95=%.0f" % (got["name"][:40], got["tail"], got["var95"]))
if heavy["var95"] <= bounded["var95"]:
    print("FAIL: the spliced tail priced no heavier than the bounded one")
    sys.exit(1)
print("  ok   same shock, heavier tail: VaR95 %.0f > %.0f" % (heavy["var95"], bounded["var95"]))
PY

echo "==> 3. a malformed severity spec refuses, it does not price"
BAD="$(mktemp -t fair-bad-spec.XXXXXX)"
trap 'rm -f "$BAD"' EXIT
cat > "$BAD" <<'JSON'
{"version":"v1","name":"malformed severity spec","lef":[2,4,9],
 "lm":{"model":"lognormal-gpd","mu":8.0,"sigma":1.0,"u":20000,"xi":0.5}}
JSON
if out="$(python3 "$FAIR" summary "$BAD" 2>&1)"; then
  echo "FAIL: a severity spec missing beta priced anyway: $out"; exit 1
fi
case "$out" in
  *"missing beta"*) echo "  ok   refused: $out" ;;
  *) echo "FAIL: refused without saying what was wrong: $out"; exit 1 ;;
esac

echo "PASS: fair.py names its tail, the lognormal-GPD splice prices heavier than the"
echo "bounded PERT at the same shock, and a malformed severity spec refuses."
