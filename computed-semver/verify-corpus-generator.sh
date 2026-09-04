#!/usr/bin/env bash
# verify-corpus-generator.sh -- ticket cs-19.
#
# 1. corpus_generator.py's own --selfcheck (pure python, no kyverno needed).
# 2. CI's actual story ("CI regenerates it and fails on any diff"): regenerate
#    the spine into a scratch dir and diff it against the committed
#    generated-corpus/ tree byte-for-byte (manifest compared minus wall_clock,
#    which is measured, not enforced, and legitimately differs run to run).
# 3. a sample generated entry is a real Pod the kyverno CLI can parse and
#    evaluate without erroring -- SKIPs (exit 3, could not look) if kyverno is
#    absent, same convention as verify-rederive-bumps.sh and verify-gate.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Ticket 76 (every green rests on an observation): the kyverno-absent branch below used to
# print SKIP and exit 0, which talk/verify-all.sh grades PASS -- a green on the absence of the
# instrument. A could-not-look is exit 3 (lib.sh's `skip`). And because that branch only runs on
# a machine without the CLI, it was never itself tested: `selfcheck_absent` re-runs this script
# with kyverno unreachable and requires exit 3 with a SKIP: last line, so every run observes the
# branch. `--selfcheck` runs that leg alone.
. ../lib.sh
SELF="$PWD/${BASH_SOURCE##*/}"
if [ "${1:-}" = "--selfcheck" ]; then selfcheck_absent "$SELF" kyverno; exit 0; fi

echo "== 1. corpus_generator.py --selfcheck =="
python3 corpus_generator.py --selfcheck

echo
echo "== 2. regenerating the committed spine is byte-identical (CI's regenerate-and-diff) =="
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 corpus_generator.py --out "$tmp" >/dev/null
diff -r "$tmp/spine" generated-corpus/spine
python3 - "$tmp/manifest.yaml" generated-corpus/manifest.yaml <<'PY'
import sys, yaml
a, b = (yaml.safe_load(open(p)) for p in sys.argv[1:])
a.pop("wall_clock"); b.pop("wall_clock")
if a != b:
    sys.exit(f"manifest mismatch (minus wall_clock):\n regenerated: {a}\n committed:   {b}")
PY
echo "ok  regenerated spine/ and manifest.yaml (minus wall_clock) match the committed tree"

echo
if ! command -v kyverno >/dev/null; then
  skip "step 3 could not look -- kyverno CLI not found, so a generated entry was never proved to evaluate (steps 1 and 2 held)"
fi
selfcheck_absent "$SELF" kyverno

echo "== 3. a sample generated entry is a real Pod kyverno can evaluate =="
# A glob, not `ls | head -1`: under `set -o pipefail` head closes the pipe on the first
# line, ls dies of SIGPIPE, and the script exited 2 with "ls: write error: Broken pipe" on
# the CI runner for two recorded runs while the generator itself was healthy. The shell
# sorts a glob, so the sample is the same file the pipeline picked.
set -- generated-corpus/spine/*.yaml
sample="$1"
[ -e "$sample" ] || { echo "FAIL: the generator produced no spine entries to sample"; exit 1; }
# ../distribution, not distribution -- computed-semver/ and distribution/ are
# siblings under the repo root, not parent/child. A wrong path here still
# exits 0 with "Applying 0 policy rule(s)" and no "Error:" line, which is why
# this step also asserts the loaded-rule count below rather than trusting a
# clean exit code alone -- a prior round of this ticket shipped exactly that
# vacuous pass.
policy=../distribution/policies/v1.0.0/require-nonroot.yaml
[ -f "$policy" ] || { echo "FAIL: policy file not found at $policy"; exit 1; }
out=$(kyverno apply "$policy" --resource "$sample" 2>&1) || true
if echo "$out" | grep -qi "^Error:"; then
  echo "FAIL: kyverno choked on a generated entry ($sample):"
  echo "$out"
  exit 1
fi
rules=$(echo "$out" | grep -oE 'Applying [0-9]+ policy rule\(s\)' | grep -oE '[0-9]+' || echo 0)
if [ "$rules" -lt 1 ]; then
  echo "FAIL: kyverno loaded 0 policy rules against $sample -- this proves nothing, not a pass:"
  echo "$out"
  exit 1
fi
echo "ok  kyverno loaded $rules real policy rule(s) and evaluated $sample without erroring"

echo
echo "PASS: corpus generator selfcheck ok, spine regenerates byte-identical, sample entry is a real Pod"
