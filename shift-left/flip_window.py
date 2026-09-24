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
        return served, None
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
