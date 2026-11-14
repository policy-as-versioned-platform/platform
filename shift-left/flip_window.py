#!/usr/bin/env python3
"""flip_window.py -- which versions file the Audit->Deny flip beat checks against.

Prints one path on stdout, for ci-check.py's --versions-file:

  * distribution/versions.yaml, the served array, when it declares two or more
    major lines. A target there has a +/-1 neighbour to flip against.
  * shift-left/fixtures/flip-window.yaml, the planted two-line window, when the
    served array declares fewer. Then it also prints one NOTHING-TO-FLIP line
    on stderr naming the served array's versions, so no caller can mistake the
    planted window for the served one.

verify-shift-left.sh (the release gate) and wargamer/propose-policy-pr.sh both
ask this one place, so the two cannot choose different windows.
"""
from __future__ import annotations

import importlib.util
import sys
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
DISTRIBUTION = HERE.parent / "distribution"
SERVED = DISTRIBUTION / "versions.yaml"
PLANTED = HERE / "fixtures" / "flip-window.yaml"


def _versions():
    spec = importlib.util.spec_from_file_location(
        "render_orphan_guard", DISTRIBUTION / "render-orphan-guard.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.versions


def choose(served: Path = SERVED, planted: Path = PLANTED) -> tuple[Path, str | None]:
    """(versions file, NOTHING-TO-FLIP reason or None)."""
    declared = _versions()(served)
    majors = {v.split(".")[0] for v in declared}
    if len(majors) >= 2:
        # A neighbour can tighten the cage without changing the ValidatingPolicy
        # verdict this historical flip fixture exercises (tickets 158/159).
        # Ask the public shift-left CLI whether this fixture observes a flip.
        # A plain target failure or unavailable instrument stays on the served
        # path and remains red; only an observed all-pass gets the planted proof.
        observed = subprocess.run([
            sys.executable, str(HERE / "ci-check.py"),
            "--resource", str(HERE / "fixtures/workload-flip.yaml"),
            "--versions-file", str(served),
            "--engine-declaration", str(HERE / "fixtures/engine/kyverno.yaml"),
        ], capture_output=True, text=True)
        if observed.returncode != 0:
            return served, None
        return planted, (
            f"NOTHING-TO-FLIP: the historical flip fixture was observed compliant across "
            f"{served.relative_to(HERE.parent)} ({' '.join(declared)}). The cage changes "
            f"need not narrow that fixture's validation verdict. The flip proof runs "
            f"against {planted.relative_to(HERE.parent)}, which is not served."
        )
    return planted, (
        f"NOTHING-TO-FLIP: {served.relative_to(HERE.parent)} declares "
        f"{len(majors)} major line(s) ({' '.join(declared) or 'none'}), so no served "
        f"target has a +/-1 neighbour. The flip beat runs against the planted window "
        f"{planted.relative_to(HERE.parent)}, which is not served."
    )


def main() -> int:
    path, reason = choose()
    if reason:
        print(reason, file=sys.stderr)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
