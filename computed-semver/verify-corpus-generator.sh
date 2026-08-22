#!/usr/bin/env bash
# verify-corpus-generator.sh -- ticket cs-19.
#
# 1. corpus_generator.py's own --selfcheck (pure python, no kyverno needed).
# 2. CI's actual story ("CI regenerates it and fails on any diff"): regenerate
#    the spine into a scratch dir and diff it against the committed
#    generated-corpus/ tree byte-for-byte (manifest compared minus wall_clock,
#    which is measured, not enforced, and legitimately differs run to run).
# 3. a sample generated entry is a real Pod the kyverno CLI can parse and
#    evaluate without erroring -- SKIPs (exit 0) if kyverno is absent, same
#    convention as verify-rederive-bumps.sh and verify-gate.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

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
  echo "SKIP (step 3): kyverno CLI not found -- cannot prove a generated entry evaluates"
  exit 0
fi

echo "== 3. a sample generated entry is a real Pod kyverno can evaluate =="
sample=$(ls generated-corpus/spine/*.yaml | head -1)
out=$(kyverno apply distribution/policies/v1.0.0/require-nonroot.yaml --resource "$sample" 2>&1) || true
if echo "$out" | grep -qi "^Error:"; then
  echo "FAIL: kyverno choked on a generated entry ($sample):"
  echo "$out"
  exit 1
fi
echo "ok  kyverno parsed and evaluated $sample without erroring"

echo
echo "PASS: corpus generator selfcheck ok, spine regenerates byte-identical, sample entry is a real Pod"
