#!/usr/bin/env bash
# Beat: the composition seam (policy-composition tickets 12-15; eco-system
# ticket 38). ADR-0012 (self-signed, pinned SHA) / ADR-0013 (baselines,
# control ids) / ADR-0014 (the governed namespace) / ADR-0016 (kind-aware
# render, the resolver key) / ADR-0017 (claim ownership) / ADR-0018 (the
# Namespace manifest is the governed declaration) / ADR-0020 (a missing
# behaviour is priced; only a missing instrument refuses). Since ticket 38 a
# new hole, a widened baseline and a new ungoverned namespace are PRICED
# deltas, and the selfcheck proves they compose rather than refuse.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"
# The estate this seam composes against is the directory holding the eight
# clones. Named explicitly so a nested worktree of the platform clone
# (`.estate-clone/platform/.work/<ticket>`) still finds it.
export PAVC_ESTATE_CLONE="${PAVC_ESTATE_CLONE:-$(cd "$HERE/../.." && pwd)}"

say "1. composition.py's own asserts (compose, render faithfulness, verify, the CLI, priced deltas, the one remaining refusal)"
python3 "$HERE/composition.py" --selfcheck || fail "composition.py --selfcheck"

say "1b. the three refusals ticket 38 deleted are gone from the source, and no new one took their place"
python3 - "$HERE/composition.py" <<'PY' || fail "a deleted refusal kind is still emitted by composition.py"
import re, sys
src = open(sys.argv[1]).read().split("\ndef selfcheck()", 1)[0]
# A refusal dict carries needs_composition; a deltas[] entry of the same
# name does not -- that is the whole point of the change.
refusal_kinds = {m.group(1) for m in re.finditer(r'"kind":\s*"([a-z-]+)"', src)
                 if "needs_composition" in src[m.end():m.end() + 400]}
gone = {"new-hole", "baseline-widening", "new-ungoverned-namespace"}
still = sorted(refusal_kinds & gone)
if still:
    print(f"still emitted as a refusal: {still}"); sys.exit(1)
print("refusal kinds emitted:", ", ".join(sorted(refusal_kinds)))
PY

say "2. the header's pinned parent contains the policy versions the set renders"
# The 2026-08-29 review: composed/HEADER.yaml named platform 1.1.1 at 58ef9c57
# while the set rendered v4.0.0, a tree that commit does not contain -- and
# nothing graded the pair. composition.py now computes it as a limit on every
# run; this is where it is read. A `commit` that carries the rendered versions
# can only exist once cut-release.yml has cut the tag in Actions (hard rule 3),
# so an open limit is a could-not-look naming the tag it waits for, never a 0.
# Through PAVC_ESTATE_CLONE, not `$HERE/../..`: a `..` under a symlinked
# nested worktree resolves physically to `.work/`, where no adopter lives.
ADOPTER="${ADOPTER:-$PAVC_ESTATE_CLONE/driftwood}"
if [ ! -d "$ADOPTER" ]; then
  echo "SKIP: no adopter tree at $ADOPTER to compose, so the pin/render pair cannot be read"
  exit 3
fi
OPEN="$(python3 - "$HERE" "$ADOPTER" <<'PY'
import importlib.util, sys
from pathlib import Path
here, adopter = Path(sys.argv[1]), Path(sys.argv[2])
import yaml
spec = importlib.util.spec_from_file_location("composition", here / "composition.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
party_doc = yaml.safe_load((adopter / "party.yaml").read_text())
doc, _ = mod.compose(adopter, mod._default_parent_trees(party_doc, adopter.parent))
lim = next(l for l in doc["limits"] if l["name"] == "pinned-parent-lacks-rendered-versions")
print(lim["detail"] if lim["status"] == "open" else "")
PY
)" || fail "could not compose $ADOPTER to read its pin/render pair"
if [ -n "$OPEN" ]; then
  # The waited-on tag is NAMED BY THE LIMIT, not hardcoded here. It said
  # `policy/v4.0.0` from 2026-08-29 until 2026-09-04, and by then 4.0.0 had
  # been cut and the pin had moved -- the sentence had gone stale while still
  # reading as current, which is the failure mode this project cares about. The
  # subject today is 5.0.0 (ticket 63, declared and not yet cut); tomorrow it is
  # whatever the array declares ahead of the adopter's pin.
  echo "SKIP: $OPEN -- the commit that carries these trees is not on the real remote until cut-release.yml cuts the corresponding policy/v<version> tag in Actions and the adopter's platform-pin.yaml moves with it (ticket 64 moves the pin and recomposes)"
  exit 3
fi
say "   every rendered policy version is present at the pinned parent commit"

say "PASS: the composition seam holds"
