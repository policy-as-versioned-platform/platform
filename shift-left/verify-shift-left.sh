#!/usr/bin/env bash
# verify-shift-left.sh -- the offline proof behind the "CI catches an
# Audit->Deny flip pre-merge" beat (ticket 12). Runs the REAL kyverno CLI,
# needs no cluster. Exits non-zero if the beat would fail on stage.
#
# 2026-08-29: the whole 2.x/3.x fan-out was retired from
# distribution/versions.yaml, so the declared array holds ONE major line. The
# flip beat is about a NEIGHBOUR's tightened rule; with one line there is no
# neighbour, so that beat is graded could-not-look with its reason rather than
# passed on a technicality (it would "pass" today only because ci-check.py
# refuses the retired target the fixture used to claim, which is the right
# answer to the wrong question).
#
# 2026-09-24: 4.0.0 retired too (owner-instructed), after 5.0.0 had made the
# array two majors for a while. One major line again, and the fixtures claim
# 5.0.0. .github/workflows/release.yml runs this script as its release gate,
# so a could-not-look here failed every release. The flip beat now reads the
# served array first. With two or more majors it runs there. With one it says
# NOTHING-TO-FLIP for the served array, by name, and runs against the planted
# two-line window fixtures/flip-window.yaml. That window reuses the real
# signed 4.0.0 and 5.0.0 bodies still on disk, so the beat still proves what
# it proves: the +/-1 window catches, with the real kyverno CLI, a workload
# that passes its own target and fails a neighbour's rule. The beat also now
# insists the failure IS a flip. A workload that fails its own target is a
# failure, not a caught flip, and the beat says so instead of passing on it.
#
# 2026-09-26, eco-system ticket 148 (hub ADR-0033 point 7): ci-check.py runs each
# line only on an engine that line supports, read from the adopter's declared
# engine. The fixtures belong to no adopter, so every call below hands it
# fixtures/engine/kyverno.yaml (1.18.2, the engine table's row). That needs the
# kyverno CLI on PATH to report 1.18.2: another CLI is a could-not-look here, by
# name. The engine beats at the end plant an undeclared engine, an engine the
# target does not support, a neighbour whose tested_engines supports nothing, a
# CLI that reports another version, and a workload whose own repository
# declares the engine.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v kyverno >/dev/null; then
  echo "SKIP: kyverno CLI not found -- shift-left check needs it (offline, no cluster)"
  exit 3
fi
DECL=fixtures/engine/kyverno.yaml
DECLARED="$(python3 ../engine/declaration.py read "$DECL")"
REPORTED="$(kyverno version | sed -n 's/^Version: v\{0,1\}//p')"
if [ "$REPORTED" != "$DECLARED" ]; then
  echo "SKIP: the fixtures declare kyverno $DECLARED ($DECL), and the kyverno CLI on PATH reports ${REPORTED:-no version}"
  exit 3
fi
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

echo "== a compliant change passes across its ±1 supported window =="
python3 ci-check.py --resource fixtures/workload-compliant.yaml --engine-declaration "$DECL"

echo
echo "== an unversioned workload is out of scope, passes trivially =="
python3 ci-check.py --resource fixtures/workload-unversioned.yaml --engine-declaration "$DECL"

echo
echo "== a version the array doesn't declare is refused, not silently skipped =="
if python3 ci-check.py --resource fixtures/workload-compliant.yaml --target 9.9.9 --engine-declaration "$DECL" 2>"$WORK/orphan.err"; then
  echo "FAIL: ci-check.py did not reject an orphan target version" >&2
  exit 1
fi
grep -q "not in the platform-declared array" "$WORK/orphan.err"

# The flip beat needs two major lines in a window: the target's own, and a
# neighbour whose rule the workload fails. flip_window.py reads the served array
# first and falls back to the planted window only when it declares one major,
# printing NOTHING-TO-FLIP by name when it does.
echo
echo "== an Audit->Deny flip is caught pre-merge (must fail CI) =="
FLIP_VERSIONS="$(python3 flip_window.py)"
echo "window read from: ${FLIP_VERSIONS#"$(cd .. && pwd)/"}"
FLIP_OUT="$WORK/flip.out"
set +e
python3 ci-check.py --resource fixtures/workload-flip.yaml --versions-file "$FLIP_VERSIONS" --engine-declaration "$DECL" >"$FLIP_OUT" 2>&1
flip_rc=$?
set -e
cat "$FLIP_OUT"
if [ "$flip_rc" -ne 1 ]; then
  echo "FAIL: ci-check.py exited $flip_rc on a workload that fails a neighbour's real rule in its window; a caught flip exits 1" >&2
  exit 1
fi
# Non-zero is not enough. It must be a FLIP: the target passes, a neighbour fails.
FLIP_TARGET="$(sed -n 's/^.*: targets \([0-9][0-9.]*\), checking supported window .*$/\1/p' "$FLIP_OUT")"
if [ -z "$FLIP_TARGET" ]; then
  echo "FAIL: ci-check.py stopped before it checked a window, so no flip was caught" >&2
  exit 1
fi
if grep -qx "FAIL @ v${FLIP_TARGET}" "$FLIP_OUT"; then
  echo "FAIL: fixtures/workload-flip.yaml fails its own target ${FLIP_TARGET}; that is a plain failure, not a caught flip" >&2
  exit 1
fi
if ! grep -q '^FAIL @ v[0-9.]* (Audit->Deny flip' "$FLIP_OUT"; then
  echo "FAIL: ci-check.py failed the flip fixture, but at no neighbour of ${FLIP_TARGET}" >&2
  exit 1
fi
echo "(non-zero above is expected -- the flip was caught at a neighbour of ${FLIP_TARGET})"

# --- the engine (eco-system ticket 148, hub ADR-0033 point 7) ---------------------------------
# expect <name> <want exit> <needle|-> <must-not-contain|-> -- ci-check.py args...
expect() {
  local name="$1" want="$2" needle="$3" absent="$4"; shift 5
  local out="$WORK/case.out" rc
  set +e; python3 ci-check.py "$@" >"$out" 2>&1; rc=$?; set -e
  cat "$out"
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $name: ci-check.py exited $rc, want $want" >&2; exit 1
  fi
  if [ "$needle" != "-" ] && ! grep -q -- "$needle" "$out"; then
    echo "FAIL: $name: the output does not say: $needle" >&2; exit 1
  fi
  if [ "$absent" != "-" ] && grep -q -- "$absent" "$out"; then
    echo "FAIL: $name: the output says: $absent" >&2; exit 1
  fi
  echo "ok  $name (exit $rc)"
}
# A planted versions file: the served array's own lines, or the planted window, with one
# element's tested_engines replaced. Nothing it writes is served.
plant() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json, sys, yaml
src, out, version, value = sys.argv[1:]
doc = yaml.safe_load(open(src))
for e in doc["spec"]["inputs"][0]["versions"]:
    if e["version"] == version:
        if value == "absent":
            e.pop("tested_engines", None)
        else:
            e["tested_engines"] = json.loads(value)
yaml.safe_dump(doc, open(out, "w"), sort_keys=False)
PY
}
python3 - "$WORK/decl-1.19.1.yaml" <<'PY'
import sys, yaml
sys.path.insert(0, "../engine")
import declaration
yaml.safe_dump(declaration.from_table("1.19.1"), open(sys.argv[1], "w"), sort_keys=False)
PY

echo
echo "== no declared engine: every line is an unsupported pairing, and the check could not look =="
expect "no declaration" 3 "no engine is declared" "kyverno apply @" -- \
  --resource fixtures/workload-compliant.yaml --engine-declaration "$WORK/absent.yaml"

echo
echo "== a declaration that does not read refuses by name =="
printf 'schema: 1\nengine: kyverno\nversion: ">=1.18"\n' >"$WORK/bad.yaml"
expect "a malformed declaration" 3 "COULD NOT LOOK: gitops/engine/kyverno.yaml must carry exactly the keys" "kyverno apply @" -- \
  --resource fixtures/workload-compliant.yaml --engine-declaration "$WORK/bad.yaml"

echo
echo "== the served target does not support the declared engine (1.19.1): named, not run, could not look =="
expect "an engine the target does not support" 3 "UNSUPPORTED PAIRING @ v5.0.0: kyverno 1.19.1 is not a supported engine of v5.0.0" "kyverno apply @" -- \
  --resource fixtures/workload-compliant.yaml --engine-declaration "$WORK/decl-1.19.1.yaml"

echo
echo "== a neighbour whose tested_engines supports no engine is named and not run; the target still runs =="
plant fixtures/flip-window.yaml "$WORK/window-retired.yaml" 4.0.0 '{"scope": "published-cage-fixtures-v1", "kyverno": ["1.18.2"]}'
expect "an unsupported neighbour" 0 "UNSUPPORTED PAIRING @ v4.0.0: kyverno 1.18.2 is not a supported engine of v4.0.0 (tested_engines is scoped published-cage-fixtures-v1" "kyverno apply @ v4.0.0" -- \
  --resource fixtures/workload-compliant.yaml --versions-file "$WORK/window-retired.yaml" --engine-declaration "$DECL"
grep -q "unsupported pairing(s), not run and not passed: v4.0.0" "$WORK/case.out" \
  || { echo "FAIL: the verdict line does not name the neighbour it did not run" >&2; exit 1; }
plant fixtures/flip-window.yaml "$WORK/window-absent.yaml" 4.0.0 absent
expect "a neighbour with no tested_engines" 0 "declares no tested_engines" "kyverno apply @ v4.0.0" -- \
  --resource fixtures/workload-flip.yaml --versions-file "$WORK/window-absent.yaml" --engine-declaration "$DECL"

echo
echo "== a CLI that reports another version than the declared engine could not look =="
plant fixtures/flip-window.yaml "$WORK/window-1.19.1.yaml" 5.0.0 '{"scope": "every-served-body-v1", "kyverno": ["1.19.1"]}'
expect "a CLI of another version" 3 "the kyverno CLI on PATH reports $REPORTED, and the declared engine is 1.19.1" "kyverno apply @" -- \
  --resource fixtures/workload-compliant.yaml --versions-file "$WORK/window-1.19.1.yaml" --engine-declaration "$WORK/decl-1.19.1.yaml"

echo
echo "== an adopter's own repository declares the engine, and the check finds it with no flag =="
mkdir -p "$WORK/adopter/deploy" "$WORK/adopter/gitops/engine"
cp fixtures/workload-compliant.yaml "$WORK/adopter/deploy/pod.yaml"
cp "$DECL" "$WORK/adopter/gitops/engine/kyverno.yaml"
git init -q "$WORK/adopter"
expect "the declaration of the resource's own repository" 0 "adopter/gitops/engine/kyverno.yaml, the top of adopter, the repository" "UNSUPPORTED" -- \
  --resource "$WORK/adopter/deploy/pod.yaml"
rm "$WORK/adopter/gitops/engine/kyverno.yaml"
expect "a repository that declares no engine" 3 "no engine is declared" "kyverno apply @" -- \
  --resource "$WORK/adopter/deploy/pod.yaml"

echo
echo "shift-left: all offline proofs passed"
