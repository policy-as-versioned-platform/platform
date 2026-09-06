#!/usr/bin/env bash
# Eco-system ticket 34. The handbook is a compose-time render, and this is the check that says so.
#
# ADR-0007's last-mile section (confirmed 2026-09-06, ticket 80) names this script by name:
# "verify-fresh.sh (render-at-tag equals committed render) becomes the truth-surface script,
# gradable offline, with the end-to-end verify.sh retired beside it".
#
# WHAT IT MEASURES, AND AGAINST WHAT. The subject is one adopter's composed artefact AS SERVED at
# a git ref -- read with `git ls-tree`/`git show` at that ref, never from a working tree that
# happens to sit beside it. The operation is `handbook.py render <dir> --ref <ref>`: re-render the
# page from those served bytes and compare it, byte for byte, with the `composed/HANDBOOK.md` the
# same ref serves. A page that says anything the artefact does not cannot survive that comparison.
# Nothing about the FILE EXISTING is graded: an existing HANDBOOK.md that does not re-render is
# exactly the failure this exists to catch.
#
# TWO MODES.
#   verify-fresh.sh <adopter-dir> <ref>   grade that adopter at that ref
#   verify-fresh.sh                       no adopter named: run the tool's own proofs
#
# The no-argument mode is what the truth surface discovers and runs. It deliberately reads NO
# adopter: NORTH-STAR §2 forbids the publisher reading an institution's repository, and this script
# ships in the publisher's tree. It proves the TOOL instead, over planted git repositories built
# here: a fresh render passes, a tampered page fails, a tampered ARTEFACT under an untouched page
# fails, a ref with no artefact cannot be looked at, and the whole thing goes could-not-look rather
# than green when git is unreachable. The estate-wide read of the three real adopters is the hub's
# verify/handbook/verify-handbook-is-a-compose-time-render.sh, which is where an adopter's
# repository may be read from.
#
# Exit 0 observed true; 1 observed false; 3 could not look, reason on the last line (ADR-0020).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/../lib.sh"      # skip(), selfcheck_absent()
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "SKIP: no $PY on PATH to run handbook.py with"; exit 3; }
"$PY" -c 'import yaml' 2>/dev/null || { echo "SKIP: $PY cannot import yaml, which handbook.py needs"; exit 3; }

# ---------------------------------------------------------------- one adopter, one ref
grade_one() {
  local dir="$1" ref="$2" tmp rc
  command -v git >/dev/null 2>&1 || { echo "SKIP: git is not on PATH, so no ref can be read"; return 3; }
  [ -d "$dir" ] || { echo "SKIP: $dir is not a directory"; return 3; }
  git -C "$dir" rev-parse --verify --quiet "$ref^{commit}" >/dev/null 2>&1 \
    || { echo "SKIP: $dir has no ref $ref to read the served artefact at"; return 3; }
  git -C "$dir" cat-file -e "$ref:composed/HANDBOOK.md" 2>/dev/null \
    || { echo "SKIP: $ref of $dir serves no composed/HANDBOOK.md"; return 3; }

  tmp="$(mktemp -d)"
  "$PY" "$HERE/handbook.py" render "$dir" --ref "$ref" >"$tmp/rendered.md" 2>"$tmp/err"; rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: re-rendering $ref of $dir from its own served artefact refused: $(tail -1 "$tmp/err")"
    rm -rf "$tmp"; return 1
  fi
  git -C "$dir" show "$ref:composed/HANDBOOK.md" >"$tmp/served.md" 2>/dev/null
  if cmp -s "$tmp/rendered.md" "$tmp/served.md"; then
    echo "  ok   $dir@$ref: the served handbook is byte-identical to a re-render of the served artefact ($(wc -c <"$tmp/served.md" | tr -d ' ') bytes)"
    rm -rf "$tmp"; return 0
  fi
  echo "STALE: $dir@$ref: composed/HANDBOOK.md is NOT what its own composed artefact renders to"
  diff "$tmp/served.md" "$tmp/rendered.md" | head -20
  rm -rf "$tmp"; return 1
}

if [ "$#" -ge 1 ]; then
  ref="${2:-HEAD}"
  grade_one "$1" "$ref"; rc=$?
  case "$rc" in
    0) echo "PASS: $1 at $ref serves a handbook that is a pure re-render of the artefact served at the same ref";;
    3) : ;;   # grade_one already printed the SKIP line
    *) echo "FAIL: $1 at $ref does not serve a fresh handbook";;
  esac
  exit "$rc"
fi

# ---------------------------------------------------------------- the tool's own proofs
# git is the instrument the whole check is built on, so the could-not-look branch is RUN here on a
# machine that has it (ADR-0020's second note, ticket 76): with git unreachable this script must
# exit 3 with a SKIP last line, never 0 and never a red.
selfcheck_absent "$HERE/verify-fresh.sh" git

command -v git >/dev/null 2>&1 || { echo "SKIP: git is not on PATH, so no planted ref can be built"; exit 3; }

say "1. the render seam's own tests (pure, clock-free, biting, refusing what it cannot derive)"
"$PY" "$HERE/handbook.py" --selfcheck || fail "handbook.py --selfcheck"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
REPO="$WORK/adopter"
mkdir -p "$REPO"
"$PY" - "$HERE" "$REPO" <<'PY' || fail "could not plant an artefact to grade"
import json, sys, importlib.util
from pathlib import Path
here, repo = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("handbook", here / "handbook.py")
hb = importlib.util.module_from_spec(spec); spec.loader.exec_module(hb)
files, evidence = hb._fixture()
files[hb.EVIDENCE_PATH] = json.dumps(evidence, indent=2)
for rel, text in files.items():
    p = repo / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
(repo / hb.HANDBOOK_PATH).write_text(hb.render(files, evidence))
PY
git -C "$REPO" init -q -b main
# The planted repository must not inherit the RUNNER's git configuration: a developer machine may
# force-sign every tag and run a global pre-commit hook, and neither has anything to do with what
# is being graded. `git commit` and `git tag` here are only a way to make a ref exist.
mkdir -p "$WORK/no-hooks"
git -C "$REPO" config core.hooksPath "$WORK/no-hooks"
git -C "$REPO" config commit.gpgsign false
git -C "$REPO" config tag.gpgSign false
git -C "$REPO" config tag.forceSignAnnotated false
git -C "$REPO" config user.name t
git -C "$REPO" config user.email t@t.invalid
git -C "$REPO" add -A
git -C "$REPO" commit -qm "planted artefact and its render"
git -C "$REPO" tag planted-v1

say "2. the render committed beside its artefact is fresh at the tag that carries both"
grade_one "$REPO" planted-v1 || fail "a freshly rendered handbook graded stale"

say "3. a hand-edited page over an untouched artefact is STALE (the lie with a nicer font)"
printf '\nThe estate has no holes and everything is fine.\n' >>"$REPO/composed/HANDBOOK.md"
git -C "$REPO" add -A
git -C "$REPO" commit -qm "hand-edit the page"
git -C "$REPO" tag planted-v2
out="$(grade_one "$REPO" planted-v2)"; rc=$?
[ "$rc" = 1 ] && grep -q '^STALE:' <<<"$out" \
  || { echo "FAIL: a hand-edited handbook graded $rc, not 1: $out"; exit 1; }
echo "  ok   a sentence added by hand is caught at the tag"

say "4. a moved ARTEFACT under an untouched page is STALE too (the page went stale, not wrong)"
git -C "$REPO" checkout -q planted-v1 -- composed/HANDBOOK.md
"$PY" - "$REPO" <<'PY' || fail "could not move the planted artefact"
import json, sys
from pathlib import Path
p = Path(sys.argv[1]) / "composed" / "evidence.json"
doc = json.loads(p.read_text())
doc["prices"][0]["amount"] = 999999.0
p.write_text(json.dumps(doc, indent=2))
PY
git -C "$REPO" add -A
git -C "$REPO" commit -qm "move the price, leave the page"
git -C "$REPO" tag planted-v3
out="$(grade_one "$REPO" planted-v3)"; rc=$?
[ "$rc" = 1 ] && grep -q '^STALE:' <<<"$out" \
  || { echo "FAIL: a moved artefact under an unmoved page graded $rc, not 1: $out"; exit 1; }
echo "  ok   a price that moved without the page is caught at the tag"

say "5. a ref that serves no artefact is a could-not-look, never a pass and never a red"
git -C "$REPO" rm -rq composed
git -C "$REPO" commit -qm "no artefact here"
git -C "$REPO" tag planted-v4
out="$(grade_one "$REPO" planted-v4)"; rc=$?
[ "$rc" = 3 ] && grep -q '^SKIP:' <<<"$out" \
  || { echo "FAIL: a ref with no artefact graded $rc, not 3: $out"; exit 1; }
echo "  ok   a ref with no handbook exits 3"

echo "PASS: verify-fresh.sh grades render-at-ref against the page served at the same ref: a fresh render passes, a hand-edited page fails, an artefact that moved under an unmoved page fails, a ref with no artefact exits 3, and git being unreachable exits 3"
