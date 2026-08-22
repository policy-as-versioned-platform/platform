#!/usr/bin/env bash
# verify-witness-set.sh -- ticket cs-20.
#
# 1. witness_set.py's own --selfcheck (pure python, no kyverno needed) --
#    includes the ticket's own regression test: removing an axis value from
#    the generator makes a previously-covered witness shape fail.
# 2. the real missing-shape gate against the committed generated-corpus/ and
#    the platform's real live subject -- must pass (exit 0) for the witnesses
#    that ARE committed.
# 3. CI's regenerate-and-diff story for the witness manifest, same convention
#    verify-corpus-generator.sh already uses for the spine's own manifest.
# 4. the named gap: the six real infrastructure witnesses are not yet
#    committed. This is expected right now (see witness_set.py's docstring)
#    and does NOT fail the script -- but it prints loud, every run, so it
#    cannot go unnoticed once real captures exist and someone forgets to add
#    them here.
# 5. the _CONTAINER_BOOL_RE regression: probe_for's real "satisfied" pod for
#    require-nonroot@1.0.0's pod-level predicate is kyverno-applied against
#    the real require-nonroot@1.0.0 policy and must PASS -- SKIPs (exit 0)
#    if kyverno is absent, same convention as verify-corpus-generator.sh and
#    verify-gate.sh. This is the precise cell the unanchored regex broke
#    (the probe wrote into containers[0].securityContext instead of
#    spec.securityContext, so the "satisfied" pod actually FAILED real
#    admission); a claim in a commit message is not a check that runs again
#    next time the regex changes.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "== 1. witness_set.py --selfcheck =="
python3 witness_set.py --selfcheck

echo
echo "== 2. the missing-shape gate against the committed generated-corpus/ =="
if ! python3 witness_set.py --corpus-dir generated-corpus --out generated-corpus; then
  echo "FAIL: the missing-shape gate refused against the committed corpus"
  exit 1
fi

echo
echo "== 3. regenerating the witness manifest is byte-identical (CI's regenerate-and-diff) =="
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 witness_set.py --corpus-dir generated-corpus --out "$tmp" >/dev/null
diff "$tmp/witness-manifest.yaml" generated-corpus/witness-manifest.yaml
echo "ok  regenerated witness-manifest.yaml matches the committed copy"

echo
missing=$(python3 - <<'PY'
import witness_set as ws
_, missing = ws.load_witnesses()
print(",".join(missing))
PY
)
if [ -n "$missing" ]; then
  echo "=========================================================================="
  echo "GAP (not a failure): real-infrastructure witnesses not yet committed:"
  echo "  $missing"
  echo "The COTS effort (.scratch/govern-what-you-dont-control/) was named as the"
  echo "source for real captures of these six workloads (spec.md, 'The corpus';"
  echo ".scratch/computed-semver/issues/03-what-is-the-corpus.md). None exist as"
  echo "committed fixtures anywhere in this repo or the hub repo yet. Drop a real"
  echo "Pod manifest at computed-semver/corpus/witnesses/real/<name>.yaml for each"
  echo "and this gate picks it up automatically -- no code change needed."
  echo "=========================================================================="
fi

echo
if ! command -v kyverno >/dev/null; then
  echo "SKIP (step 5): kyverno CLI not found -- cannot prove the require-nonroot"
  echo "satisfied probe passes real admission (the _CONTAINER_BOOL_RE regression)"
else
  echo "== 5. the require-nonroot 'satisfied' probe passes real admission (regression guard for _CONTAINER_BOOL_RE) =="
  pod_file="$(mktemp)"
  trap 'rm -f "$pod_file"' EXIT
  python3 - "$pod_file" <<'PY'
import sys
from pathlib import Path
import yaml
import corpus_generator as cg

version = "1.0.0"
subject_dir = cg._materialize_subject(version)
preds = [
    p for p in cg.predicates(subject_dir)
    if p.policy == "require-nonroot.yaml" and p.location == "validations"
]
if len(preds) != 1:
    sys.exit(f"expected exactly 1 require-nonroot validation predicate, got {preds}")
pred = preds[0]

pod = cg._base_pod()
cg._set_label(pod, cg.PIN_LABEL, version)  # must claim 1.0.0 or the policy's
                                            # own matchConditions skips it
cg.probe_for(pred).satisfied(pod)
Path(sys.argv[1]).write_text(yaml.safe_dump(pod))
PY
  # ../distribution, not distribution -- same sibling-directory note as
  # verify-corpus-generator.sh's step 3.
  policy=../distribution/policies/v1.0.0/require-nonroot.yaml
  [ -f "$policy" ] || { echo "FAIL: policy file not found at $policy"; exit 1; }
  out=$(kyverno apply "$policy" --resource "$pod_file" 2>&1) || true
  if echo "$out" | grep -qi "^Error:"; then
    echo "FAIL: kyverno choked on the require-nonroot satisfied probe pod:"
    echo "$out"
    exit 1
  fi
  if ! echo "$out" | grep -qE "pass: [1-9][0-9]*, fail: 0"; then
    echo "FAIL: the require-nonroot satisfied probe pod did not cleanly PASS real"
    echo "admission -- this is exactly the _CONTAINER_BOOL_RE regression (a"
    echo "'satisfied' probe that writes into the wrong securityContext):"
    echo "$out"
    exit 1
  fi
  echo "ok  the require-nonroot satisfied probe pod passes real admission under kyverno"
fi

echo
echo "PASS: witness_set selfcheck ok, missing-shape gate passes against the "
echo "committed corpus, witness manifest regenerates byte-identical"
