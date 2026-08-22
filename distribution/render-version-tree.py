#!/usr/bin/env python3
"""render-version-tree.py -- ticket cs-12: render the mandatory members into a
version tree.

One authoring copy of each claim-wide policy stays under `graded/policies/`
and `posture/policies/`. This renderer emits the PER-VERSION copies that
`distribution/policies/v<version>/` actually ships -- the same pattern
`require-nonroot-1-0-0` already establishes by hand. A human must not be able
to omit one, so a renderer writes all seven every time:

    cage-tier, cage-netpol, stamp-posture, posture-trust-boundary,
    cage-baseline, cage-restricted, cage-quarantine  (the three PriorityClasses)

A version is four coordinated edits, not a directory: the directory, the
versioned `metadata.name`, the `policy-version` label, and a `matchConditions`
self-scope appended to whatever conditions the authoring copy already carries.
Self-scope lives in `matchConditions`, never `matchConstraints.objectSelector`
-- Kyverno flattens objectSelector into one shared webhook configuration, and
last-reconciled-wins silently breaks multi-version coexistence. Every emitted
policy file carries that reasoning as a comment (see OBJECTSELECTOR_BAN).

cage-tier's own dial table names PriorityClasses by their UNVERSIONED base
name ('cage-baseline', ...); this renderer rewrites those references to the
versioned names emitted alongside it, so each version's cage-tier only ever
names PriorityClasses that exist in the same tree.

Follows `render-orphan-guard.py`'s shape: a pure "offline twin"
(`render_tree`, no disk I/O) and a "live path" (`write_tree`, actually writes
the tree a release commits) that `--selfcheck` proves agree. Unlike the
orphan-guard -- which ranges the WHOLE version array into one file -- this
renderer takes exactly one version and writes exactly one tree: rendering
every tree on every run and failing on any diff would freeze the dial table
forever (spec.md, "Pinned delivery and rendering"). `write_tree` also refuses
to touch a directory that already holds any of these files: once a tree is
rendered and committed it is released, and the renderer never re-renders a
released tree.

The orphan-guard itself is OUT OF SCOPE here (it is the aggregate over the
array and cannot self-scope to one claim) -- ticket 22 gives it the
`platform-machinery` identity.

Usage:
    render-version-tree.py <version> [--out DIR]   # write the tree for <version>
    render-version-tree.py --selfcheck              # runnable asserts
"""
from __future__ import annotations

import copy
import sys
import tempfile
from pathlib import Path

import yaml

YAML_KWARGS = dict(sort_keys=False, allow_unicode=True, width=4096)

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
GRADED = REPO / "graded" / "policies"
POSTURE = REPO / "posture" / "policies"

LABEL_VERSION = "policy-as-versioned.dev/policy-version"

OBJECTSELECTOR_BAN = (
    "# Self-scopes via matchConditions on the policy-version label -- NOT\n"
    "# matchConstraints.objectSelector, which Kyverno flattens into one shared\n"
    "# ValidatingWebhookConfiguration (last-reconciled-wins) and silently breaks\n"
    "# multi-version coexistence.\n"
)

# The four claim-wide admission policies rendered as-is (kind + self-scope),
# and the three PriorityClasses (renamed only -- they have no matchConditions,
# they are not admission policies).
ADMISSION_SOURCES = [
    (GRADED / "cage-tier.yaml", "cage-tier.yaml"),
    (GRADED / "cage-netpol.yaml", "cage-netpol.yaml"),
    (POSTURE / "stamp-posture.yaml", "stamp-posture.yaml"),
    (POSTURE / "posture-trust-boundary.yaml", "posture-trust-boundary.yaml"),
]
PRIORITYCLASSES_SOURCE = GRADED / "priorityclasses.yaml"


def slug(version: str) -> str:
    """'1.0.0' -> '1-0-0', the require-nonroot-1-0-0 convention."""
    return version.replace(".", "-")


def _load_one(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _load_all(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text()) if d]


def _versioned_name(obj: dict, version: str) -> dict:
    """Deep-copy obj with metadata.name and the policy-version label rewritten."""
    obj = copy.deepcopy(obj)
    obj["metadata"]["name"] = f"{obj['metadata']['name']}-{slug(version)}"
    obj["metadata"].setdefault("labels", {})[LABEL_VERSION] = version
    return obj


def _self_scope(obj: dict, version: str) -> None:
    """Append (never replace) a matchConditions entry pinning this copy to
    pods that claim exactly `version` -- ANDed with whatever conditions the
    authoring copy already carries."""
    obj["spec"].setdefault("matchConditions", []).append({
        "name": "only-this-policy-version",
        "expression": f"object.metadata.?labels['{LABEL_VERSION}'].orValue('') == '{version}'",
    })


def render_tree(version: str) -> dict[str, str]:
    """The offline twin: a pure function, version -> {filename: yaml text}.
    No disk I/O -- verify-*.sh and --selfcheck use this without touching the
    real distribution/policies/ tree."""
    out: dict[str, str] = {}

    # PriorityClasses first, so cage-tier's dial table can name their
    # versioned names.
    pc_rename: dict[str, str] = {}
    rendered_pcs = []
    for pc in _load_all(PRIORITYCLASSES_SOURCE):
        base_name = pc["metadata"]["name"]
        versioned = _versioned_name(pc, version)
        pc_rename[base_name] = versioned["metadata"]["name"]
        rendered_pcs.append(versioned)
    out["priorityclasses.yaml"] = yaml.safe_dump_all(rendered_pcs, **YAML_KWARGS)

    for src, fname in ADMISSION_SOURCES:
        obj = _versioned_name(_load_one(src), version)
        _self_scope(obj, version)
        text = yaml.safe_dump(obj, **YAML_KWARGS)
        if fname == "cage-tier.yaml":
            # cage-tier names its own PriorityClasses -- rewrite the dial
            # table's 'pc':'<base>' entries to the versioned names emitted
            # above, so this version's cage only ever names PriorityClasses
            # that exist in this same tree.
            for base_name, versioned_name in pc_rename.items():
                text = text.replace(f"'pc':'{base_name}'", f"'pc':'{versioned_name}'")
        out[fname] = OBJECTSELECTOR_BAN + text

    return out


def write_tree(version: str, target: Path) -> None:
    """The live path: actually writes the rendered tree to disk -- what a
    release commits. Refuses to overwrite a tree that already has any of
    these files: a released tree is frozen, and this renders only the tree
    being cut, never a tree already released."""
    tree = render_tree(version)
    collisions = sorted(f for f in tree if (target / f).exists())
    if collisions:
        raise SystemExit(
            f"refusing to render into {target}: {collisions} already present. "
            "This renders only the tree being cut -- it never re-renders an "
            "already-released tree."
        )
    target.mkdir(parents=True, exist_ok=True)
    for fname, text in tree.items():
        (target / fname).write_text(text)


def selfcheck() -> None:
    v = "9.9.9-selfcheck"
    sv = slug(v)

    # the offline twin is deterministic
    tree_a, tree_b = render_tree(v), render_tree(v)
    assert tree_a == tree_b, "render_tree is not deterministic"
    assert set(tree_a) == {
        "priorityclasses.yaml", "cage-tier.yaml", "cage-netpol.yaml",
        "stamp-posture.yaml", "posture-trust-boundary.yaml",
    }, sorted(tree_a)

    # all seven mandatory members present (4 single-doc files + 3 PriorityClasses)
    doc_count = sum(len(_load_all_text(t)) for t in tree_a.values())
    assert doc_count == 7, f"expected 7 mandatory members, rendered {doc_count}"

    admission_files = ["cage-tier.yaml", "cage-netpol.yaml", "stamp-posture.yaml", "posture-trust-boundary.yaml"]
    for fname in admission_files:
        obj = yaml.safe_load(tree_a[fname])
        assert obj["metadata"]["name"].endswith(f"-{sv}"), obj["metadata"]["name"]
        assert obj["metadata"]["labels"][LABEL_VERSION] == v
        conds = obj["spec"]["matchConditions"]
        assert any(
            c["name"] == "only-this-policy-version" and c["expression"].endswith(f"== '{v}'")
            for c in conds
        ), f"{fname}: no self-scope matchConditions entry for {v}"
        assert "objectSelector" not in yaml.safe_dump(obj), f"{fname}: objectSelector leaked in"
        assert tree_a[fname].startswith(OBJECTSELECTOR_BAN), f"{fname}: missing the objectSelector-ban comment"

    pcs = _load_all_text(tree_a["priorityclasses.yaml"])
    assert len(pcs) == 3
    pc_names = {p["metadata"]["name"] for p in pcs}
    assert pc_names == {f"cage-baseline-{sv}", f"cage-restricted-{sv}", f"cage-quarantine-{sv}"}, pc_names

    # cage-tier names its own (versioned) PriorityClasses, and no unversioned
    # base name leaks through
    cage_tier = yaml.safe_load(tree_a["cage-tier.yaml"])
    dial_expr = next(v_ for v_ in cage_tier["spec"]["variables"] if v_["name"] == "dial")["expression"]
    for name in pc_names:
        assert name in dial_expr, f"cage-tier's dial table does not name its own PriorityClass {name}"
    for base_name in ("cage-baseline", "cage-restricted", "cage-quarantine"):
        assert f"'pc':'{base_name}'" not in dial_expr, f"un-rewritten base PriorityClass name {base_name} leaked into cage-tier"

    # live path vs offline twin: actually write to disk, read back, and they
    # must be byte-identical -- and re-rendering the same (now populated)
    # tree must refuse, never silently re-render a released tree.
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / f"v{v}"
        write_tree(v, target)
        for fname, text in tree_a.items():
            on_disk = (target / fname).read_text()
            assert on_disk == text, f"{fname}: live path disagrees with the offline twin"
        try:
            write_tree(v, target)
        except SystemExit:
            pass
        else:
            raise AssertionError("write_tree re-rendered an already-rendered tree instead of refusing")

    # the authoring copies are read-only inputs -- untouched by any of the above
    assert "'pc':'cage-baseline'" in (GRADED / "cage-tier.yaml").read_text(), \
        "authoring copy of cage-tier.yaml must stay unversioned (verify-graded.sh reads it)"

    print(
        "selfcheck ok: 7 mandatory members rendered for a named version; "
        "versioned names/labels/self-scope; cage-tier names its own "
        "PriorityClasses; live path == offline twin; re-render of a rendered "
        "tree refused; authoring copies untouched"
    )


def _load_all_text(text: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(text) if d]


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0
    if not args:
        print(__doc__)
        return 1
    version = args[0]
    out = None
    if len(args) >= 3 and args[1] == "--out":
        out = Path(args[2])
    target = out or (HERE / "policies" / f"v{version}")
    write_tree(version, target)
    print(f"rendered 7 mandatory members for {version} into {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
