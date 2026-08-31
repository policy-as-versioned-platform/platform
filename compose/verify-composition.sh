#!/usr/bin/env bash
# Beat: the composition seam (policy-composition tickets 12-15). ADR-0012
# (self-signed, pinned SHA) / ADR-0013 (baselines, control ids, holes) /
# ADR-0014 (the governed namespace) / ADR-0016 (kind-aware render, the
# resolver key) / ADR-0017 (claim ownership) / ADR-0018 (the Namespace
# manifest is the governed declaration).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"

say "1. composition.py's own asserts (compose, render faithfulness, verify, the CLI, refusal)"
python3 "$HERE/composition.py" --selfcheck || fail "composition.py --selfcheck"

say "2. the header's pinned parent contains the policy versions the set renders"
# The 2026-08-29 review: composed/HEADER.yaml named platform 1.1.1 at 58ef9c57
# while the set rendered v4.0.0, a tree that commit does not contain -- and
# nothing graded the pair. composition.py now computes it as a limit on every
# run; this is where it is read. A `commit` that carries the rendered versions
# can only exist once cut-release.yml has cut the tag in Actions (hard rule 3),
# so an open limit is a could-not-look naming the tag it waits for, never a 0.
ADOPTER="${ADOPTER:-$HERE/../../driftwood}"
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
  echo "SKIP: $OPEN -- the commit that carries these trees is not on the real remote until cut-release.yml cuts policy/v4.0.0 in Actions and the adopter's platform-pin.yaml moves with it"
  exit 3
fi
say "   every rendered policy version is present at the pinned parent commit"

say "PASS: the composition seam holds"
