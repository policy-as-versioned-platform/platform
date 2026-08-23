#!/usr/bin/env bash
# verify-cut-release-tags.sh -- ticket cs-13's offline twin for cut-release.yml.
# Exercises the SAME scripts the workflow calls (.github/scripts/cut-release-*)
# against a real scratch git repo and a real local "remote", so the ordering
# and atomicity guarantees are proven, not just asserted in a comment.
#
# CUT_RELEASE_TEST_MODE=1 swaps gitsign for a plain annotated tag inside
# cut-release-create-tags.sh -- signing itself is CI-only (this estate's
# rule: only CI holds the signing identity; spec.md "Module shape"). No
# cluster, no gitsign binary, no network.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scripts="$here/.github/scripts"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
say() { echo; echo "== $* =="; }

export CUT_RELEASE_TEST_MODE=1

# a bare "remote" and a working clone, so `git push` really pushes
git init --bare -q "$scratch/remote.git"
git init -q -b main "$scratch/work"
cd "$scratch/work"
git config user.email test@example.invalid
git config user.name test
git remote add origin "$scratch/remote.git"
echo one >file.txt && git add file.txt && git commit -q -m one
git push -q origin HEAD:refs/heads/main

remote_tags() { git ls-remote --tags origin | awk '{print $2}' | grep -v '\^{}$' | sed 's#refs/tags/##' | sort; }

say "1. single-tag legacy form still works"
VERSION_INPUT="v1.0.0" MESSAGE_INPUT="first" TAGS_INPUT="" \
  python3 "$scripts/cut-release-normalize.py" >tags.json
[ "$(jq -c . tags.json)" = '[{"tag":"v1.0.0","message":"first"}]' ] ||
  fail "single-tag normalize produced: $(cat tags.json)"
"$scripts/cut-release-refuse-existing.sh" tags.json
"$scripts/cut-release-create-tags.sh" tags.json
"$scripts/cut-release-push.sh" tags.json origin
[ "$(remote_tags)" = "v1.0.0" ] || fail "expected only v1.0.0 on remote, got: $(remote_tags)"
echo "ok: v1.0.0 pushed"

say "2. multi-tag dispatch cuts every tag off the same commit"
git commit -q --allow-empty -m two
head=$(git rev-parse HEAD)
VERSION_INPUT="" MESSAGE_INPUT="" \
  TAGS_INPUT='[{"tag":"v1.0.1","message":"a"},{"tag":"v2.0.0","message":"b"}]' \
  python3 "$scripts/cut-release-normalize.py" >tags.json
"$scripts/cut-release-refuse-existing.sh" tags.json
"$scripts/cut-release-create-tags.sh" tags.json
"$scripts/cut-release-push.sh" tags.json origin
for t in v1.0.1 v2.0.0; do
  remote_tags | grep -qx "$t" || fail "expected $t on remote after multi-tag push"
  same=$(git rev-parse "refs/tags/$t^{commit}")
  [ "$same" = "$head" ] || fail "$t should be on $head, is on $same"
done
echo "ok: v1.0.1 and v2.0.0 both landed on the same commit ($head)"

say "3. existing-tag refusal fires for EVERY tag before ANY tag is created"
VERSION_INPUT="" MESSAGE_INPUT="" \
  TAGS_INPUT='[{"tag":"v3.0.0","message":"c"},{"tag":"v1.0.0","message":"already exists"}]' \
  python3 "$scripts/cut-release-normalize.py" >tags.json
if "$scripts/cut-release-refuse-existing.sh" tags.json 2>refuse.err; then
  fail "refusal should have failed: v1.0.0 already exists"
fi
grep -q "v1.0.0 already exists" refuse.err || fail "wrong refusal message: $(cat refuse.err)"
git rev-parse "refs/tags/v3.0.0" >/dev/null 2>&1 &&
  fail "v3.0.0 must not exist locally -- refusal must run before any tag is created"
echo "ok: v1.0.0 collision refused, v3.0.0 (listed first) never got created"

say "4. a failed push leaves nothing on the remote (atomicity)"
# put v9.0.0 on the remote only (simulating a race with another dispatch),
# then try to push it again as part of a two-tag batch. The non-fast-forward
# tag update must reject the WHOLE atomic push, not just that one ref.
git tag -a v9.0.0 -m "pre-existing on remote only, simulating a race"
git push -q origin v9.0.0
git tag -d v9.0.0 >/dev/null # drop locally: this test targets the push layer, not the refuse layer
VERSION_INPUT="" MESSAGE_INPUT="" \
  TAGS_INPUT='[{"tag":"v8.0.0","message":"d"},{"tag":"v9.0.0","message":"e"}]' \
  python3 "$scripts/cut-release-normalize.py" >tags.json
"$scripts/cut-release-create-tags.sh" tags.json
if "$scripts/cut-release-push.sh" tags.json origin 2>push.err; then
  fail "atomic push should have failed: v9.0.0 already exists on the remote at a different object"
fi
remote_tags | grep -qx "v8.0.0" &&
  fail "atomic push must not have landed v8.0.0 when v9.0.0 in the same batch was rejected"
echo "ok: atomic push rejected the whole batch, v8.0.0 did not land alone"

say "5. \`version\`+\`tags\` together is refused, not silently merged"
if VERSION_INPUT="v5.0.0" MESSAGE_INPUT="m" TAGS_INPUT='[{"tag":"v6.0.0","message":"n"}]' \
  python3 "$scripts/cut-release-normalize.py" >both.out 2>both.err; then
  fail "should have refused version+tags together"
fi
grep -q "either .tags. or .version." both.err || fail "wrong error: $(cat both.err)"
echo "ok: mixed dispatch refused"

say "6. cs-27: every mis-shaped policy tag is refused here, before any tag exists -- not silently ungated"
for bad in 'Policy/v3.0.0' 'POLICY/v3.0.0' 'policy/V3.0.0' 'policy//v3.0.0' ' policy/v3.0.0' 'policy/v3.0.0 ' 'policy/v3.0'; do
  if VERSION_INPUT="" MESSAGE_INPUT="" \
    TAGS_INPUT="$(jq -nc --arg t "$bad" '[{"tag":$t,"message":"m"}]')" \
    python3 "$scripts/cut-release-normalize.py" >bad.out 2>bad.err; then
    fail "normalize should have refused mis-shaped tag $(printf '%q' "$bad"), got: $(cat bad.out)"
  fi
  grep -q "not a legal shape" bad.err || fail "wrong error for $(printf '%q' "$bad"): $(cat bad.err)"
done
echo "ok: every case/slash/whitespace variant of a policy tag refused before any tag was created"

echo
echo "PASS: single-tag legacy form works, multi-tag dispatch cuts every tag"
echo "on the same commit, the existing-tag refusal runs for every tag before"
echo "any tag is created, a failed atomic push leaves nothing on the"
echo "remote, and a mis-shaped policy tag (wrong case, stray slash or"
echo "whitespace) is refused at normalize time -- it can never reach"
echo "cut-release-gate.py's skip branch and get pushed ungated."
