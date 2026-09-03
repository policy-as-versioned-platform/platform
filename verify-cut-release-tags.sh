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

say "7. ticket 43: a DEGRADED publish's prerelease tag is a legal shape, and sorts below the clean number"
# The suffix is the whole point of ticket 18 Answer 1: the declared BASE
# number is untouched and the degraded release sorts BELOW the clean one, so
# no consumer ever treats a degraded publish as the newer version.
VERSION_INPUT="" MESSAGE_INPUT="" \
  TAGS_INPUT='[{"tag":"policy/v4.0.1-quarantine.1","message":"degraded"}]' \
  python3 "$scripts/cut-release-normalize.py" >tags.json ||
  fail "normalize refused a legal degraded policy tag: $(cat tags.json)"
[ "$(jq -r '.[0].tag' tags.json)" = "policy/v4.0.1-quarantine.1" ] ||
  fail "normalize mangled the degraded tag: $(cat tags.json)"
# ...and the ordering, through the SAME parser the gate, the tag history and
# every window sort use -- not a second copy that could disagree with it.
python3 - "$here" <<'PYEOF' || fail "prerelease ordering is wrong"
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "computed-semver"))
from comparison_window import parse_semver
order = sorted(["4.0.1", "4.0.1-quarantine.1", "4.0.0", "4.0.1-quarantine.2"], key=parse_semver)
assert order == ["4.0.0", "4.0.1-quarantine.1", "4.0.1-quarantine.2", "4.0.1"], order
print("ok: 4.0.0 < 4.0.1-quarantine.1 < 4.0.1-quarantine.2 < 4.0.1")
PYEOF
# the shape check still bites: a suffix on the platform's OWN line is not a
# legal tag (nothing gates that line, so nothing there can degrade), and an
# empty suffix is not a prerelease.
for bad in 'v1.0.0-quarantine.1' 'policy/v4.0.1-' 'policy/v4.0.1-.1'; do
  if VERSION_INPUT="" MESSAGE_INPUT="" \
    TAGS_INPUT="$(jq -nc --arg t "$bad" '[{"tag":$t,"message":"m"}]')" \
    python3 "$scripts/cut-release-normalize.py" >bad.out 2>bad.err; then
    fail "normalize should have refused $(printf '%q' "$bad")"
  fi
  grep -q "not a legal shape" bad.err || fail "wrong error for $(printf '%q' "$bad"): $(cat bad.err)"
done
echo "ok: policy/v4.0.1-quarantine.1 accepted and ordered below policy/v4.0.1; a suffix on the platform's own line refused"

say "8. ticket 53: the branch lands with the tags, in the same atomic push -- or neither does"
# 2026-08-31: the push carried the tags and left the branch behind, so the
# signed evidence commit the workflow had just made was reachable only from
# the tag. main lost the bundle, v2.0.0 inherited the hole, three adopters
# refused. This case is the twin of that day: commit "evidence" on the branch,
# push, and require the remote's refs/heads/main to be the tagged commit.
remote_main() { git ls-remote origin refs/heads/main | awk '{print $1}'; }
before=$(remote_main)
echo "evidence" >evidence.json && git add evidence.json && git commit -q -m "signed evidence (stand-in)"
head=$(git rev-parse HEAD)
[ "$before" != "$head" ] || fail "test setup: the remote branch must be behind the local commit"
VERSION_INPUT="" MESSAGE_INPUT="" \
  TAGS_INPUT='[{"tag":"v10.0.0","message":"evidence goes with the tag"}]' \
  python3 "$scripts/cut-release-normalize.py" >tags.json
"$scripts/cut-release-refuse-existing.sh" tags.json
"$scripts/cut-release-create-tags.sh" tags.json
"$scripts/cut-release-push.sh" tags.json origin
remote_tags | grep -qx "v10.0.0" || fail "v10.0.0 did not land on the remote"
[ "$(remote_main)" = "$head" ] ||
  fail "remote refs/heads/main is $(remote_main), not the tagged commit $head: the branch was left behind (the 2026-08-31 defect)"
[ "$(git rev-parse 'refs/tags/v10.0.0^{commit}')" = "$head" ] || fail "v10.0.0 is not on $head"
echo "ok: refs/heads/main on the remote moved to $head, the same commit v10.0.0 points at"

# ...and when the push is rejected, the branch does not move either: the
# atomicity promise covers the branch, not only the tags. Same race shape as
# case 4 -- a tag already on the remote at a different object.
git tag -a v12.0.0 -m "pre-existing on remote only, simulating a race"
git push -q origin v12.0.0
git tag -d v12.0.0 >/dev/null
git commit -q --allow-empty -m "evidence that must not land alone"
[ "$(git rev-parse HEAD)" != "$head" ] || fail "test setup: HEAD should have moved"
VERSION_INPUT="" MESSAGE_INPUT="" \
  TAGS_INPUT='[{"tag":"v11.0.0","message":"f"},{"tag":"v12.0.0","message":"g"}]' \
  python3 "$scripts/cut-release-normalize.py" >tags.json
"$scripts/cut-release-create-tags.sh" tags.json
if "$scripts/cut-release-push.sh" tags.json origin 2>push.err; then
  fail "atomic push should have failed: v12.0.0 already exists on the remote at a different object"
fi
remote_tags | grep -qx "v11.0.0" && fail "v11.0.0 must not have landed when v12.0.0 was rejected"
[ "$(remote_main)" = "$head" ] ||
  fail "remote refs/heads/main moved to $(remote_main) although the push was rejected: the branch escaped the atomic transaction"
echo "ok: rejected push moved neither the tags nor refs/heads/main (still $head)"

# ...and a detached HEAD is refused before anything is pushed, rather than
# guessed at: the evidence belongs on a named branch or nowhere.
git checkout -q --detach
if "$scripts/cut-release-push.sh" tags.json origin 2>push.err; then
  git checkout -q main
  fail "a detached HEAD should have been refused, not pushed"
fi
git checkout -q main
grep -q "detached HEAD" push.err || fail "wrong refusal for a detached HEAD: $(cat push.err)"
echo "ok: a detached HEAD is refused, nothing pushed"

echo
echo "PASS: single-tag legacy form works, multi-tag dispatch cuts every tag"
echo "on the same commit, the existing-tag refusal runs for every tag before"
echo "any tag is created, a failed atomic push leaves nothing on the"
echo "remote, and a mis-shaped policy tag (wrong case, stray slash or"
echo "whitespace) is refused at normalize time -- it can never reach"
echo "cut-release-gate.py's skip branch and get pushed ungated; and a degraded"
echo "publish's prerelease tag (ticket 43) normalizes cleanly and sorts BELOW"
echo "the clean number through the one shared parser; and the branch carrying"
echo "the signed evidence lands in the same atomic push as the tags, or not at"
echo "all (ticket 53)."
