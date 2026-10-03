#!/usr/bin/env python3
"""ci-check.py — the shift-left CI check (ticket 12).

An institution dev's PR ships a workload manifest that CLAIMS a policy
version (the `policy-as-versioned.dev/policy-version` label — the same
version array contract distribution/versions.yaml renders live). This check:

  1. resolves the target's supported version WINDOW — target ±1 major line, off the SAME
     declared array distribution/versions.yaml owns (no second source of
     truth: reuses render-orphan-guard.py's `versions()`),
  2. runs the REAL `kyverno apply` for every policy in that window against the
     workload, offline (no cluster, no flux-operator) -- with the workload's
     version label rewritten to each window version in turn, because every
     policy self-scopes on that label and would otherwise skip the workload.

`kyverno apply` reports the CEL verdict (pass/fail) independent of whether
`spec.validationActions` says Audit or Deny — Audit only changes what a LIVE
cluster does with a fail (report vs block). So a workload that fails here
would be denied the moment its target version's Audit->Deny promotion PR
lands (ADR-0006: promotion is editorial, never a timer) — this check catches
that flip BEFORE merge, not at deploy.

THE ENGINE (eco-system ticket 148, hub ADR-0033 point 7). Each line in the window runs only on
an engine that line supports. The engine is the adopter's own declaration,
`gitops/engine/kyverno.yaml` at the top of the git repository the resource belongs to, or the
file `--engine-declaration` names; `engine/declaration.py` reads it. A line supports the engines
its own element of the versions file lists in `tested_engines`, read by the engine grader's own
rule (computed-semver/engine_compatibility.py). A line in the window that does not list the
declared engine is reported by name as an UNSUPPORTED PAIRING. It is not run, so it is neither a
compile error nor a pass. The kyverno CLI on PATH must report the declared version before any
line runs, or the check could not look.

Exit codes:
    0  the target line ran and passed, and every other line that ran passed. An unsupported
       neighbour is named, and it does not change this.
    1  a line that ran would deny the workload.
    3  could not look: no declared engine, a declaration that does not read, a CLI that
       reports another version, or a target line that does not support the declared engine.
       An adopter whose own target line does not load on its engine has no measured answer.

Usage:
    ci-check.py --resource path/to/workload.yaml
    ci-check.py --resource path/to/workload.yaml --target 4.0.0   # override the label
    ci-check.py --resource path/to/workload.yaml --engine-declaration path/to/kyverno.yaml
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DISTRIBUTION = HERE.parent / "distribution"
LABEL = "policy-as-versioned.dev/policy-version"
COULD_NOT_LOOK = 3


def _load(name: str, path: Path):
    """A module of this platform tree, by path (several carry hyphens or share a name)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_orphan_guard = _load("render_orphan_guard", DISTRIBUTION / "render-orphan-guard.py")
# render-orphan-guard.py's `versions()` and `elements()` -- the one array, reused.
versions = _orphan_guard.versions
elements = _orphan_guard.elements
# Eco-system ticket 148: the one reader of an adopter's engine declaration (shared with
# compose/composition.py), and the engine grader's own reading of a line's `tested_engines`.
declaration = _load("engine_declaration_reader", HERE.parent / "engine" / "declaration.py")
supported_engines = _load("engine_compatibility_rule",
                          HERE.parent / "computed-semver" / "engine_compatibility.py").declared_engines


def target_version(resource: Path, override: str | None) -> str | None:
    """The version the workload claims — None if unversioned (out of scope)."""
    if override:
        return override
    import yaml

    docs = [d for d in yaml.safe_load_all(resource.read_text()) if d]
    claimed = {d.get("metadata", {}).get("labels", {}).get(LABEL) for d in docs}
    claimed.discard(None)
    if not claimed:
        return None
    if len(claimed) > 1:
        raise SystemExit(f"resource file claims multiple versions {claimed}; pass --target")
    return claimed.pop()


def skew_window(target: str, declared: list[str]) -> list[str]:
    """Target ±1 MAJOR line off the declared array, sorted by semver: every
    declared version whose major is the target's own, the nearest lower
    major, or the nearest higher major. Measured by semver distance, never
    by array position -- a patch release inserted next to the target
    (2.0.1 between 2.0.0 and 3.0.0) must not push 3.0.0 out of 2.0.0's
    window, because a workload pinned at 2.0.0 can still be moved onto
    3.0.0's pin, and that is the flip this check exists to catch."""
    key = lambda v: tuple(int(p) for p in v.split("."))
    ordered = sorted(declared, key=key)
    if target not in ordered:
        raise SystemExit(
            f"policy-version {target!r} is not in the platform-declared array {ordered} "
            "(orphan) -- nothing to shift-left check against"
        )
    majors = sorted({key(v)[0] for v in ordered})
    i = majors.index(key(target)[0])
    lines = set(majors[max(0, i - 1) : i + 2])
    return [v for v in ordered if key(v)[0] in lines]


def policy_files(version: str) -> list[Path]:
    d = DISTRIBUTION / "policies" / f"v{version}"
    files = sorted(p for p in d.glob("*.yaml") if p.name != "kustomization.yaml")
    if not files:
        raise SystemExit(f"no policy files under {d}")
    return files


def pinned_to(resource: Path, version: str, out_dir: Path) -> Path:
    """A copy of the workload with its version label rewritten to `version`.
    Every policy self-scopes on that label (matchConditions, so versions
    coexist in one cluster), so a workload labelled 2.0.0 is simply skipped
    by 3.0.0's rules. The window question is "what if this workload were
    moved onto the neighbour's pin?" -- so ask it with the neighbour's pin."""
    import yaml

    docs = [d for d in yaml.safe_load_all(resource.read_text()) if d]
    for d in docs:
        labels = d.get("metadata", {}).get("labels", {})
        if LABEL in labels:
            labels[LABEL] = version
    out = out_dir / f"{resource.stem}@{version}.yaml"
    out.write_text(yaml.safe_dump_all(docs))
    return out


def kyverno_apply(policies: list[Path], resource: Path) -> tuple[bool, str]:
    cmd = ["kyverno", "apply", *[str(p) for p in policies], "--resource", str(resource)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0, proc.stdout + proc.stderr


def declaration_for(resource: Path) -> tuple[Path | None, str]:
    """(the declaration file for the repository `resource` belongs to, how it was found). The
    repository is the resource's own git top level: an adopter's CI checks its repository out
    beside the platform's, so a workload under `driftwood/` belongs to driftwood's declaration."""
    try:
        top = subprocess.run(["git", "-C", str(resource.resolve().parent), "rev-parse",
                              "--show-toplevel"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None, f"{resource} is in no git repository, so no {declaration.FILE} belongs to it"
    root = Path(top.stdout.strip())
    return root / declaration.FILE, f"the top of {root.name}, the repository {resource} belongs to"


def cli_version() -> str | None:
    """The version the kyverno CLI on PATH reports, or None when it reports none."""
    try:
        out = subprocess.run(["kyverno", "version"], capture_output=True, text=True).stdout
    except OSError:
        return None
    found = re.search(r"^Version:\s*v?(\d+\.\d+\.\d+)\s*$", out, re.MULTILINE)
    return found.group(1) if found else None


def line_support(versions_file: Path) -> dict[str, tuple[list[str] | None, str | None]]:
    """{version: (the engines its element lists, or None with the reason it supports none)}."""
    return {str(e.get("version")): supported_engines(e.get("tested_engines"))
            for e in elements(versions_file) if isinstance(e, dict)}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--resource", required=True, type=Path, help="workload manifest to check")
    ap.add_argument("--target", help="override the version read off the resource's label")
    ap.add_argument("--versions-file", type=Path, default=DISTRIBUTION / "versions.yaml")
    ap.add_argument("--engine-declaration", type=Path, default=None,
                    help="the adopter's gitops/engine/kyverno.yaml (default: the one at the top "
                         "of the git repository the resource belongs to)")
    args = ap.parse_args(argv)

    declared = versions(args.versions_file)
    target = target_version(args.resource, args.target)
    if target is None:
        print(f"{args.resource}: unversioned (no {LABEL} label) -- out of scope, pass")
        return 0

    window = skew_window(target, declared)
    print(f"{args.resource}: targets {target}, checking supported window {window}")

    # Eco-system ticket 148: the engine the adopter declares, and which lines support it.
    if args.engine_declaration is not None:
        where, found = args.engine_declaration, f"--engine-declaration {args.engine_declaration}"
    else:
        where, found = declaration_for(args.resource)
    try:
        engine = declaration.read(where) if where is not None else None
    except declaration.Malformed as exc:
        print(f"COULD NOT LOOK: {exc} ({found}); no line runs on an engine nobody can read")
        return COULD_NOT_LOOK
    if engine is None:
        for v in window:
            print(f"UNSUPPORTED PAIRING @ v{v}: no engine is declared ({found} carries no "
                  f"{declaration.FILE}); not run, so neither a compile error nor a pass")
        print(f"\nshift-left: COULD NOT LOOK -- {args.resource} belongs to no declared engine, so no "
              f"line in its window {window} was run (hub ADR-0033 point 7)")
        return COULD_NOT_LOOK
    print(f"declared engine: kyverno {engine['version']} (read from {where}, {found})")
    support = line_support(args.versions_file)
    runnable, unsupported = [], []
    for v in window:
        listed, why = support.get(v, (None, "has no element in the versions file"))
        if listed is not None and engine["version"] in listed:
            runnable.append(v)
            continue
        unsupported.append(v)
        print(f"UNSUPPORTED PAIRING @ v{v}: kyverno {engine['version']} is not a supported engine "
              f"of v{v} ({f'tested_engines {listed}' if listed is not None else why}); not run, "
              f"so neither a compile error nor a pass")
    if runnable:
        reported = cli_version()
        if reported != engine["version"]:
            print(f"COULD NOT LOOK: the kyverno CLI on PATH reports {reported or 'no version'}, and "
                  f"the declared engine is {engine['version']}; a line run on another engine would "
                  f"measure a pairing nobody declared")
            return COULD_NOT_LOOK

    failed = False
    pins = Path(tempfile.mkdtemp(prefix="shift-left-"))
    for v in runnable:
        policies = policy_files(v)
        ok, output = kyverno_apply(policies, pinned_to(args.resource, v, pins))
        print(f"--- kyverno apply @ v{v} ---")
        print(output.strip())
        if not ok:
            failed = True
            flip = " (Audit->Deny flip: passes today's Audit, would be denied on promotion)" if v != target else ""
            print(f"FAIL @ v{v}{flip}")

    not_checked = (f"; unsupported pairing(s), not run and not passed: "
                   f"{', '.join('v' + v for v in unsupported)}" if unsupported else "")
    if failed:
        print(f"\nshift-left: {args.resource} would be denied somewhere in its supported window "
              f"{window} on kyverno {engine['version']}{not_checked}")
        return 1
    if target in unsupported:
        print(f"\nshift-left: COULD NOT LOOK -- {args.resource} targets v{target}, which does not "
              f"support the declared kyverno {engine['version']}, so its own line was not run"
              f"{not_checked}")
        return COULD_NOT_LOOK
    print(f"\nshift-left: {args.resource} is compliant on kyverno {engine['version']} across the "
          f"line(s) of its window that support it {runnable}{not_checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
