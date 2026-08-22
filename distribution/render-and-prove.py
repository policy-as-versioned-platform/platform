#!/usr/bin/env python3
"""render-and-prove.py -- ticket cs-17: the shared render-and-prove step that
`graded/up.sh` and `posture/up.sh` both call (one script, not two copies of
the same ~25 lines -- a future change to the proof only has one place to
land).

Renders each version distribution/versions.yaml declares (ticket 12's
renderer, render-version-tree.py) into a scratch workdir seeded with a COPY
of the REAL committed distribution/policies/v<version>/ tree -- never a
synthetic empty directory -- so the render is grounded in actual repo state,
not compared only against itself.

"write_tree()'s disk output equals render_tree()'s in-memory output" is NOT
the proof that matters here -- that's the SAME function calling itself, and
is already covered by render-version-tree.py's own --selfcheck
(distribution/verify-render-version-tree.sh, ticket 12). The proof here is
that `kubectl kustomize` -- the REAL, independent builder flux-operator's
Kustomization controller actually runs, not render-version-tree.py judging
itself -- can build the rendered tree, and that its output carries every
mandatory member by name.

Honesty note: distribution/policies/v<version>/kustomization.yaml's
`resources:` list, as committed at HEAD, does not yet name the graded/
posture members -- folding them into the pinned path is the repair
release's job (ticket cs-15, spec.md "The repair release" step 1, not
landed as of this script). This script reproduces that fold-in inside the
scratch workdir only (it never touches the real, tracked kustomization.yaml)
so the proof below is of the tree the ResourceSet would deliver once cs-15
lands -- and the printed status says exactly that, rather than claiming
today's committed Kustomization already delivers it.

versions() comes from render-orphan-guard.py -- the one array, reused (see
that module's docstring: "There is exactly one array... neither
hand-maintains an allow-list, so the runnable-version set cannot drift").

Usage:
    render-and-prove.py <repo-root> <workdir>

Leaves, per declared version, <workdir>/v<version>/*.yaml -- ready for the
caller's `kubectl apply -f` loop -- and <workdir>/versions.txt.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


def _load(repo: Path, name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, repo / "distribution" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _set_resources(kustomization: Path, resources: list[str]) -> None:
    doc = yaml.safe_load(kustomization.read_text()) or {
        "apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization"}
    doc["resources"] = resources
    kustomization.write_text(yaml.safe_dump(doc, sort_keys=False))


def render_and_prove(repo: Path, work: Path) -> list[str]:
    rog = _load(repo, "render_orphan_guard", "render-orphan-guard.py")
    rvt = _load(repo, "render_version_tree", "render-version-tree.py")

    declared = rog.versions(repo / "distribution" / "versions.yaml")

    for v in declared:
        real = repo / "distribution" / "policies" / f"v{v}"
        target = work / f"v{v}"
        committed = (sorted(p.name for p in real.glob("*.yaml") if p.name != "kustomization.yaml")
                     if real.exists() else [])
        if real.exists():
            shutil.copytree(real, target)
        else:
            target.mkdir(parents=True)

        # write_tree() refuses to overwrite a file already present, so this
        # can never silently paper over the renderer disagreeing with
        # something already committed.
        rvt.write_tree(v, target)

        rendered = sorted(
            p.name for p in target.glob("*.yaml")
            if p.name != "kustomization.yaml" and p.name not in committed)

        print(f"  note v{v}: distribution/policies/v{v}/kustomization.yaml, as committed at HEAD, "
              f"names only {committed or '[]'} -- {rendered} are folded into this scratch copy's "
              "resources: list to simulate the repair release (ticket cs-15, not yet landed) that "
              "ships them for real")
        _set_resources(target / "kustomization.yaml", sorted(committed + rendered))

        built = subprocess.run(["kubectl", "kustomize", str(target)], capture_output=True, text=True)
        if built.returncode != 0:
            sys.exit(f"v{v}: kubectl kustomize -- the SAME builder flux-operator's Kustomization "
                      f"controller runs -- refused the rendered tree:\n{built.stderr}")
        built_names = {d["metadata"]["name"] for d in yaml.safe_load_all(built.stdout) if d}
        expect = {d["metadata"]["name"]
                  for text in rvt.render_tree(v).values()
                  for d in yaml.safe_load_all(text) if d}
        missing = expect - built_names
        if missing:
            sys.exit(f"v{v}: kubectl kustomize's real build is missing mandatory members {missing}")
        print(f"  ok   v{v}: kubectl kustomize -- the real, independent builder -- built the "
              f"simulated tree and delivered every mandatory member: {sorted(expect)}")

    (work / "versions.txt").write_text("\n".join(declared) + "\n")
    return declared


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.exit(__doc__)
    render_and_prove(Path(argv[1]), Path(argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
