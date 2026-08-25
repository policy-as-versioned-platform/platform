#!/usr/bin/env python3
"""composition.py -- the seam (policy-composition tickets 12-15). ADR-0012, ADR-0013,
ADR-0014, ADR-0016, ADR-0017, ADR-0018.

One entry point, `compose()`. It takes an adopter repo state plus its pinned
parent trees and gives back two things: the evidence document, as a
dictionary, and the rendered composed artefact, as a mapping of path to file
content. Every later ticket in this effort (16-18: pricing/threat
re-pricing, the proposer, wiring into CI) adds a field or a refusal
*through this seam and nothing else* -- see spec.md, "Testing Decisions",
"One seam".

TICKET 13 adds three structural refusals and a caging path, all inside this
same compose():

  * SPLIT DIAMOND -- two edges in the adopter's own `inherits` reaching the
    same (party, kind) at two different versions. "Every path from the
    adopter to one parent must resolve to one version" (spec.md,
    Resolution). This estate has no second data source recording a further
    parent's own pin today (`platform` ships no `party.yaml`), so the only
    real route to a diamond is two direct edges -- which is exactly what
    "every path ... must resolve to one version" also covers, and is what
    is checked here. A fixture is what proves it; the real estate has none.
  * CROSS-PARTY RULE CONFLICT -- two `implementations` parents supplying the
    same (family, name, version) with different content. Never merged,
    never last-wins: refused, naming both sources and both contents. Proved
    only inside one publisher today (the estate pins exactly one
    `implementations` party) -- a fixture with two exercises it, and the
    document's `limits[]` says so on every run via the two-publisher count.
  * RESTATEMENT OF A NON-VALIDATING MEMBER -- `overlay.restate` names an
    inherited member with no strictness ladder (a `MutatingPolicy` or a
    `GeneratingPolicy`). Refused; there is nothing to compare on (ADR-0016).
  * RESTATEMENT ON A `ValidatingPolicy` -- a stricter action (higher on
    `Audit < Deny`) is accepted, and the rendered member carries the
    restated action. A weaker action is never an override and never an
    exemption: it is a DECLARED INABILITY, priced by the estate's own
    `graded/cage.py` against that party's own appetite band
    (`risk/appetite.json`), reusing the estate's engine exactly as it
    stands. The rendered member keeps the INHERITED action -- the composed
    artefact carries no tier and no tier floor; only the proposer (ADR-0015)
    ever turns a tier, later, in its own PR.

What ticket 12's compose() does, precisely:

  1. Loads the adopter's party artefact (ticket 11) and runs its existing
     `check()` -- schema, pinned-tag agreement, baseline mirror. A party
     artefact that does not check out is a refusal before anything else runs;
     there is nothing safe to compose from it (mirrors party_artefact.py's
     own "a structurally invalid document can't be checked any further").
  2. Resolves every declared parent to a commit SHA. `controls` and
     `implementations` are pinned by a Flux GitRepository in this estate --
     the SHA is the one Renovate already wrote to `spec.ref.commit`, read
     straight off disk, never re-derived (ADR-0012: "the resolved git commit
     SHA Renovate already pins", not a freshly invented digest). `pricing`
     and `threat` have no Flux pin anywhere in this estate (ticket 11's
     README says so plainly): resolved instead by reading the party
     directly -- `git log` on the version-scoped subdirectory of the
     party's own clone (ico's `schema/v1/`, platform's
     `feeds/threat-register/v1/`), falling back to a content digest for a
     party tree that is not a git repo at all (a test fixture).
  3. Loads every member of every kind (`ValidatingPolicy`, `MutatingPolicy`,
     `GeneratingPolicy`) from each `implementations` parent, for every
     policy version the parent's own version array currently declares live.
     Keyed on the identity family plus the name with its version suffix
     stripped -- NOT on (family, version), which is the prototype's bug
     ADR-0016 names: `graded-enforcement` alone covers `cage-tier` and
     `cage-netpol`, so keying on the family drops one silently. The
     `platform-machinery` orphan guard loads through the parent's own
     offline twin (`render-orphan-guard.py`), under the platform tag as a
     second numbering axis, never forced onto the policy-version axis.
  4. Renders every loaded member back down: the whole inherited body, plus
     one `composed-for` label and two provenance annotations
     (`inherited-from`, `source-path`) -- exactly what the prototype's
     `render()`/`render_is_faithful()` already proved, except `spec.
     validationActions` is now written ONLY onto a `ValidatingPolicy`
     (the prototype's other named defect: it wrote that field onto every
     kind, inventing a field the Kyverno schema does not have on a mutate
     or a generate).
  5. Writes one advisory header, once, separate from the per-rule
     annotations: the composed marker, each parent's resolved SHA (once
     each, not once per version), the selected baseline name, and the
     governed namespace names read off the adopter's own `Namespace`
     manifests. Hole and ungoverned-namespace lists join the header in
     tickets 14/15.

What this ticket's compose() deliberately does NOT do, because the tickets
that own it come later: no baseline/hole resolution, no governed-namespace
refusal, no pricing/threat re-pricing beyond what ticket 13's own caging
path needs. Nothing in the real estate exercises the diamond or the
cross-party conflict paths yet either (spec.md, "Further Notes": "no
restatement fires... no second publisher is pinned") -- the rule is written
before the first case, and fixtures are what prove it fires.

TICKET 14 adds baseline coverage, control claims and holes, still inside
this same compose():

  * The selected baseline resolves BY NAME against the `controls` parent's
    real published profiles (`catalog/BASELINE_VERSIONS.json`, ticket 09),
    walking nested controls so an enhancement like `ac-6.10` is found. An
    id absent from the catalogue -- a claimed control-id, or an adopter's
    `overlay.controls` addition -- is a HARD FAILURE (`unknown-control-id`),
    never a hole; exact-string, no case-fold, no prefix-strip (ADR-0013).
  * CONTROL CLAIMS merge over every party that ships a member: every
    `implementations` parent's own `oscal/component-definition.json`, and
    -- new this ticket -- the adopter's own, next to the party artefact it
    signs (ADR-0017). This is also the first ticket to load `overlay.add`
    at all: it was declared in ticket 11's schema but never wired into
    compose(), and "an adopter claim... fills it" has no route without it.
  * A control counts as COVERED the instant any claim exists for it, valid
    or not -- "no claim", not "no valid claim" (spec.md) -- so a DANGLING
    claim (the policy it names is shipped by nobody composed) or a claim
    AGAINST ANOTHER PARTY'S POLICY (ADR-0017) both still close a hole while
    separately refusing on their own account. The real `platform`
    component-definition carries two dangling claims today
    (`ac-6`->`may-run-root-if-attested`, `cm-6`->`require-policy-version`,
    ticket 10's own named, still-open defect) -- composition now catches
    them, so the real estate's own composition REFUSES, for real, today.
  * HOLES compare against the last signed composed artefact's own header
    (`_previous_header()`): a NEW hole refuses and names it, a RECORDED one
    does not, a hole that closes since prints so. `None` (no committed
    header at all) is the bootstrap case -- the first composition ever
    records every hole and refuses on none (spec.md). The real estate's
    first composition records exactly 285.
  * A control that LEAVES the selected set refuses, no exceptions
    (`check_selected_set`); a named-baseline WIDENING (MODERATE->HIGH
    shape) refuses too, with no override (`check_baseline_widening`) --
    narrowing is left entirely to the removed-control check so the two
    never double-fire on one change.
  * The header gains `holes` (the still-open recorded set) and
    `selected-controls` (the full resolved set) -- what the NEXT run
    compares against.

TICKET 15 adds the governed-namespace lint, the exact new/recorded/closed
shape ticket 14's holes already use, applied to a different signal:

  * A `Namespace` manifest in the adopter's own repo that carries the
    `institution` label and not `governed: "true"` is UNGOVERNED
    (`ungoverned_namespaces`) -- ADR-0014's silence hole moved up one level
    (ADR-0018). A Namespace with no `institution` label at all is
    infrastructure and is ignored entirely.
  * `compute_ungoverned` compares the current ungoverned set against the
    last signed composed artefact's own recorded set
    (`_previous_header`'s `ungoverned-namespaces`): a NEW one refuses and
    names it, a RECORDED one does not, and one that gains the label since
    prints CLOSED. `None` (no committed header at all) is the same
    bootstrap case ticket 14 uses -- the first composition ever records
    every ungoverned namespace and refuses on none.
  * The header gains `ungoverned-namespaces` (the still-open recorded set),
    next to `holes`. The composed artefact still carries no namespace list
    as a declaration -- the governed set stays advisory only, exactly as
    ticket 12 left it. Nothing in the rendered per-member files ever reads
    either namespace set.

TICKET 16 adds pricing and threat re-pricing, still inside this same
compose() -- ADR-0006, ADR-0010, ADR-0015:

  * Every declared `pricing` and `threat` edge is priced twice, through the
    estate's OWN machinery and no other: the `ico` penalty schema through
    `ico`'s own converter (`schema/to_fair_scenario.py build`, the fixed
    `uk-gdpr`/`lower-tier` entry -- spec.md's own acceptance wording), the
    threat feed through `platform/feeds/to_fair_scenario.py`, reusing
    `_threat_scenario` exactly as ticket 13's caging path already calls it.
    No second risk engine, no second appetite store (`_appetite_tolerance`,
    `_cage_engine`, both already ticket 13's).
  * "Old" is the version the LAST SIGNED composed artefact's own header
    recorded for that (party, kind) -- the same `_previous_header` ticket
    14/15 already read, one more field of it. No prior header, or no prior
    edge of that kind at all, means nothing to compare a bump against yet:
    old and new both price at THIS run's version, which is a real, honest
    "no move" -- not a skipped computation. This runs every time, not only
    when a version actually moved: "for each party it prints the old
    price, the new price, the old tier and the proposed tier" (spec.md) is
    unconditional; whether the two prices differ is a separate fact the
    `changed` field carries.
  * `select_tier` can return `"deny"`, and the `cage-tier` MutatingPolicy
    coerces any label value it does not recognise to `baseline` -- ADR-0015
    names the consequence: a merged `tier: deny` label would invert the
    proposal in silence. A proposed `deny` is therefore marked
    `proposed_as: "issue"` here; every other tier is `"label"`. This is the
    mark, not the act -- composition itself opens nothing, ticket 17 wires
    the proposer that reads this mark and opens the right kind of thing.
  * Pricing touches NO rendered file. `render_member`/the members loop
    never sees a pricing or threat edge at all -- they carry no rule, by
    construction (spec.md: "the last two supply no rule and are never
    asked for one") -- so a price move changes `prices[]` and the header's
    `parents[]` entry for that one edge, and nothing else composition
    renders.
  * No wall clock anywhere in this module. Both converters this section
    calls take no `--as-of` at all (`ico`'s `build` and the feeds module's
    `threat` subcommand); an `eol` parent kind does not exist in the party
    artefact schema, so composition never has occasion to pass one. ADR-
    0006/ADR-0010's line stays exactly where the earlier tickets already
    drew it: a feed may re-price, and it may never apply -- nothing here
    ever reads `datetime.now()` or a scheduler of any kind.

Usage:
    composition.py compose <adopter-dir> [--estate-clone DIR] [--out DIR]
    composition.py verify <adopter-dir> [--estate-clone DIR]
    composition.py --selfcheck
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PLATFORM_DIR = HERE.parent
ESTATE_CLONE = PLATFORM_DIR.parent
DEFAULT_ESTATE_CLONE = ESTATE_CLONE

sys.path.insert(0, str(PLATFORM_DIR / "party"))
import party_artefact  # noqa: E402

ADMISSION_KINDS = ("ValidatingPolicy", "MutatingPolicy", "GeneratingPolicy")
VERSION_SUFFIX = re.compile(r"-\d+-\d+-\d+$")

# The whole strictness ladder (ADR-0016: a ValidatingPolicy concept and
# nothing else). A restatement is accepted only when it does not decrease.
STRICTNESS = {"Audit": 0, "Deny": 1}

LABEL_FAMILY = "policy-as-versioned.dev/policy"
LABEL_VERSION = "policy-as-versioned.dev/policy-version"
COMPOSED_FOR = "policy-as-versioned.dev/composed-for"
PROVENANCE_INHERITED = "policy-as-versioned.dev/inherited-from"
PROVENANCE_SOURCE = "policy-as-versioned.dev/source-path"
GOVERNED_LABEL = "policy-as-versioned.dev/governed"
INSTITUTION_LABEL = "policy-as-versioned.dev/institution"

# Where an unpinned parent kind's version lives inside the PARTY'S OWN clone
# -- ticket 11's forward note: "the seam/resolver (ticket 12) must resolve
# them by reading the party directly (ico's schema/v1/, platform's
# feeds/threat-register/v1/), not via a GitRepository."
UNPINNED_VERSION_SUBDIR: dict[str, tuple[str, ...]] = {
    "pricing": ("schema", "{version}"),
    "threat": ("feeds", "threat-register", "{version}"),
}

YAML_KWARGS = dict(sort_keys=False, allow_unicode=True, width=4096)

HEADER_COMMENT = (
    "# advisory header -- policy-as-versioned.dev/composed (ticket 12; ADR-0012).\n"
    "# Never read by Kyverno. Strip this file and every other file in this\n"
    "# tree is what the engine reads (per-rule composed-for/inherited-from/\n"
    "# source-path annotations are the same story, one level down).\n"
)


class Refused(Exception):
    """A reason composition cannot even start. Turned into outcome:refused,
    never a crash and never a silent pass."""


# --------------------------------------------------------------------------
# 1. resolving parents to a commit SHA
# --------------------------------------------------------------------------


def resolve_sha(party: str, kind: str, version: str, adopter_dir: Path, tree_path: Path) -> str:
    """The commit SHA a parent edge resolves to. `controls`/`implementations`
    read the SHA Renovate already wrote into the adopter's own Flux pin
    (ADR-0012: reused, never re-derived). `pricing`/`threat` have no such
    pin in this estate, so they resolve by reading the party's own tree."""
    pin_rel = party_artefact.PIN_FILES.get((party, kind))
    if pin_rel is not None:
        docs = [d for d in yaml.safe_load_all((adopter_dir / pin_rel).read_text()) if isinstance(d, dict)]
        gitrepo = next((d for d in docs if d.get("kind") == "GitRepository"), None)
        if gitrepo is None:
            raise Refused(f"{pin_rel}: no GitRepository document found")
        commit = gitrepo.get("spec", {}).get("ref", {}).get("commit")
        if not commit:
            raise Refused(f"{pin_rel}: spec.ref.commit is not set")
        return commit
    return _resolve_unpinned_sha(tree_path, kind, version)


def _resolve_unpinned_sha(tree_path: Path, kind: str, version: str) -> str:
    parts = UNPINNED_VERSION_SUBDIR.get(kind)
    version_dir = tree_path.joinpath(*(p.format(version=version) for p in parts)) if parts else None
    if (tree_path / ".git").exists():
        cmd = ["git", "-C", str(tree_path), "log", "-1", "--format=%H"]
        if version_dir is not None and version_dir.is_dir():
            cmd += ["--", str(version_dir.relative_to(tree_path))]
        result = subprocess.run(cmd, capture_output=True, text=True)
        sha = result.stdout.strip()
        if result.returncode == 0 and sha:
            return sha
    # ponytail: not a git repo (a test fixture), or git found no history for
    # the path -- a deterministic content digest stands in. Advisory
    # metadata only; never compared against a real git object. Upgrade path:
    # none needed unless a real non-git party tree turns up.
    digest_root = version_dir if version_dir is not None and version_dir.is_dir() else tree_path
    h = hashlib.sha256()
    # __pycache__ is excluded: load_implementations() dynamically imports
    # this same tree's render-orphan-guard.py, which writes a .pyc cache
    # file to disk as a side effect the FIRST time it runs in a process.
    # Without this exclusion the digest of an unpinned tree is not stable
    # across repeated calls in one process (found by ticket 14's verify()
    # round-trip, which is the first caller to compose() the same
    # non-git fixture tree twice) -- it is a bytecode-cache byproduct, not
    # tree content.
    for f in sorted(p for p in digest_root.rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts):
        h.update(f.read_bytes())
    return h.hexdigest()


# --------------------------------------------------------------------------
# 2. loading every member of every kind from an implementations parent
# --------------------------------------------------------------------------


def _version_array(root: Path) -> list[dict]:
    doc = yaml.safe_load((root / "distribution" / "versions.yaml").read_text())
    return doc["spec"]["inputs"][0]["versions"]


def load_implementations(root: Path) -> tuple[dict[str, dict[tuple[str, str], dict]], dict]:
    """Every admission member of every live policy version, keyed within
    each version on (identity family, name with its version stripped) --
    ADR-0016's fix for the prototype's (family, version) key, which drops a
    second member of one family in silence. Plus the orphan guard, rendered
    through the parent's own offline twin under a second numbering axis."""
    live = [v["version"] for v in _version_array(root)]
    members_by_version: dict[str, dict[tuple[str, str], dict]] = {}

    for version in live:
        tree_dir = root / "distribution" / "policies" / f"v{version}"
        members: dict[tuple[str, str], dict] = {}
        for path in sorted(tree_dir.glob("*.yaml")):
            if path.name in ("kustomization.yaml",):
                continue
            for doc in yaml.safe_load_all(path.read_text()):
                if not isinstance(doc, dict) or doc.get("kind") not in ADMISSION_KINDS:
                    continue  # PriorityClasses are dials, not admission.
                labels = (doc.get("metadata") or {}).get("labels") or {}
                family = labels.get(LABEL_FAMILY, "(none)")
                base = VERSION_SUFFIX.sub("", doc["metadata"]["name"])
                action = None
                if doc["kind"] == "ValidatingPolicy":
                    action = (doc.get("spec", {}).get("validationActions") or ["Audit"])[0]
                members[(family, base)] = {
                    "kind": doc["kind"], "doc": doc, "action": action,
                    "path": str(path.relative_to(root)),
                }
        members_by_version[version] = members

    return members_by_version, _load_guard(root)


def load_overlay_add(party_doc: dict) -> dict[tuple[str, str, str], dict]:
    """Every `overlay.add` entry -- a member the adopter ships itself,
    keyed like a parent's own members: (version, identity family, name
    with its version suffix stripped). Each entry is `{"version": ...,
    "manifest": <a full admission-kind document>}`. Versioned with the
    composed artefact itself: no separate semver axis, no separate pin
    (ADR-0017 consequences: "Shipping a member adds no obligation ADR-0012
    did not already impose")."""
    out: dict[tuple[str, str, str], dict] = {}
    for i, item in enumerate(party_doc.get("overlay", {}).get("add", []) or []):
        doc = item["manifest"]
        if doc.get("kind") not in ADMISSION_KINDS:
            continue
        labels = (doc.get("metadata") or {}).get("labels") or {}
        family = labels.get(LABEL_FAMILY, "(none)")
        base = VERSION_SUFFIX.sub("", doc["metadata"]["name"])
        action = None
        if doc["kind"] == "ValidatingPolicy":
            action = (doc.get("spec", {}).get("validationActions") or ["Audit"])[0]
        out[(item["version"], family, base)] = {
            "kind": doc["kind"], "doc": doc, "action": action,
            "path": f"party.yaml overlay.add[{i}]",
        }
    return out


def _load_guard(root: Path) -> dict:
    rog_path = root / "distribution" / "render-orphan-guard.py"
    spec = importlib.util.spec_from_file_location("render_orphan_guard", rog_path)
    twin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(twin)
    guard_doc = twin.orphan_guard(twin.versions(root / "distribution" / "versions.yaml"))
    return {
        "kind": guard_doc["kind"], "doc": guard_doc,
        "path": "distribution/versions.yaml (rendered from the array)",
    }


# --------------------------------------------------------------------------
# 3. render: the hard constraint -- source-level only, flat, advisory-only additions
# --------------------------------------------------------------------------


def render_member(source_doc: dict, action: str | None, adopter_party: str,
                   source_ref: str, source_path: str) -> dict:
    """The whole inherited body, carried unchanged, plus one composed-for
    label and two provenance annotations. `action` is written to
    `spec.validationActions` ONLY on a ValidatingPolicy -- a MutatingPolicy
    and a GeneratingPolicy have no such field, and inventing one produces a
    manifest the Kyverno CRD schema refuses (the prototype's other named
    defect, ADR-0016)."""
    doc = copy.deepcopy(source_doc)
    if doc.get("kind") == "ValidatingPolicy" and action is not None:
        doc.setdefault("spec", {})["validationActions"] = [action]
    md = doc.setdefault("metadata", {})
    md.setdefault("labels", {})[COMPOSED_FOR] = adopter_party
    md.setdefault("annotations", {}).update({
        PROVENANCE_INHERITED: source_ref,
        PROVENANCE_SOURCE: source_path,
    })
    return doc


def strip_provenance(doc: dict) -> dict:
    """The inverse of render_member's advisory additions. Strip these and
    what remains must equal the committed source file, byte for byte after
    parsing -- the hard constraint `render_is_faithful` asserts."""
    doc = copy.deepcopy(doc)
    md = doc.get("metadata", {})
    labels = md.get("labels") or {}
    labels.pop(COMPOSED_FOR, None)
    if labels:
        md["labels"] = labels
    else:
        md.pop("labels", None)
    annotations = md.get("annotations") or {}
    for key in (PROVENANCE_INHERITED, PROVENANCE_SOURCE):
        annotations.pop(key, None)
    if annotations:
        md["annotations"] = annotations
    else:
        md.pop("annotations", None)
    return doc


def render_is_faithful(rendered_doc: dict, source_doc: dict) -> bool:
    return strip_provenance(rendered_doc) == source_doc


# --------------------------------------------------------------------------
# 4. governed namespaces (advisory metadata) and the governed-namespace lint
#    (ticket 15; ADR-0014, ADR-0018)
# --------------------------------------------------------------------------


def governed_namespaces(adopter_dir: Path) -> list[str]:
    names: set[str] = set()
    for path in sorted(adopter_dir.rglob("*.yaml")):
        if ".git" in path.parts or "composed" in path.parts:
            continue
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text()) if isinstance(d, dict)]
        except yaml.YAMLError:
            continue
        for doc in docs:
            if doc.get("kind") != "Namespace":
                continue
            labels = (doc.get("metadata") or {}).get("labels") or {}
            if labels.get(GOVERNED_LABEL) == "true":
                names.add(doc["metadata"]["name"])
    return sorted(names)


def ungoverned_namespaces(adopter_dir: Path) -> list[str]:
    """Every Namespace manifest in the adopter's own repo that carries the
    `institution` label and not `governed: "true"` -- ADR-0014's silence
    hole moved up one level (ADR-0018): such a namespace can exempt every
    workload inside it by omission, the same way an unclaimed hole does. A
    Namespace with no `institution` label at all is infrastructure, not a
    candidate, and is ignored entirely -- this is the same walk
    `governed_namespaces` does, over the same files, just the other label."""
    names: set[str] = set()
    for path in sorted(adopter_dir.rglob("*.yaml")):
        if ".git" in path.parts or "composed" in path.parts:
            continue
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text()) if isinstance(d, dict)]
        except yaml.YAMLError:
            continue
        for doc in docs:
            if doc.get("kind") != "Namespace":
                continue
            labels = (doc.get("metadata") or {}).get("labels") or {}
            if INSTITUTION_LABEL in labels and labels.get(GOVERNED_LABEL) != "true":
                names.add(doc["metadata"]["name"])
    return sorted(names)


def compute_ungoverned(current: set[str], prev_ids: set[str] | None) -> tuple[list[dict], list[dict]]:
    """ungoverned[] entries (new/recorded/closed) and the refusals a NEW
    ungoverned namespace produces -- "the rule is the hole rule" (ticket 15):
    the exact new/recorded/closed shape and the exact bootstrap rule
    compute_holes already uses. prev_ids is None on the FIRST composition
    ever -- nothing yet to compare a namespace as new against, so "the first
    composition records three ungoverned namespaces and refuses on none"
    (spec.md) applies here too."""
    entries: list[dict] = []
    refusals: list[dict] = []
    for name in sorted(current):
        if prev_ids is None or name in prev_ids:
            entries.append({"namespace": name, "status": "recorded"})
        else:
            entries.append({"namespace": name, "status": "new"})
            refusals.append({
                "kind": "new-ungoverned-namespace", "subject": name,
                "detail": f"{name} carries the institution label and not governed: \"true\", "
                          f"and it is not in the last signed composed artefact's recorded "
                          f"ungoverned set -- a namespace cannot exempt every workload in it "
                          f"by omission (ADR-0014, ADR-0018)",
                "needs_composition": True,
            })
    if prev_ids is not None:
        for name in sorted(prev_ids - current):
            entries.append({"namespace": name, "status": "closed"})
    return entries, refusals


# --------------------------------------------------------------------------
# 5. structural refusals: the split diamond, and the cross-party conflict
#    (ticket 13, spec.md "Resolution")
# --------------------------------------------------------------------------


def check_diamonds(edges: list[dict]) -> list[dict]:
    """"Every path from the adopter to one parent must resolve to one
    version" (spec.md, Resolution). Two edges in the adopter's own
    `inherits` reaching the same (party, kind) at two different versions is
    refused, naming both edges -- never picked silently. This estate has no
    further data source recording a *second-hop* parent's own pin (`platform`
    ships no `party.yaml` of its own), so the diamond this estate can
    actually manifest today is two direct edges; that is also the literal
    reading of "a path ... resolve to one version", so no transitive walk is
    invented for a case nothing here can produce yet."""
    by_parent: dict[tuple[str, str], dict[str, list[dict]]] = {}
    for edge in edges:
        by_parent.setdefault((edge["party"], edge["kind"]), {}) \
            .setdefault(edge["version"], []).append(edge)
    refusals = []
    for (party, kind), by_version in sorted(by_parent.items()):
        if len(by_version) > 1:
            routes = "; ".join(f"{v}: {edges!r}" for v, edges in sorted(by_version.items()))
            refusals.append({
                "kind": "split-diamond",
                "subject": f"{party}/{kind}",
                "detail": f"{party} ({kind}) is inherited at {len(by_version)} versions "
                          f"through {sum(len(e) for e in by_version.values())} edges -> {routes}",
                "needs_composition": True,
            })
    return refusals


# --------------------------------------------------------------------------
# 6. restatement and caging (ticket 13, spec.md "Restatement and caging")
# --------------------------------------------------------------------------


def _appetite_tolerance(party: str) -> float | None:
    """REAL. `risk/appetite.json` lives in this same repo (platform) and is
    the single source of truth for a party's tolerance in GBP/year -- read
    directly rather than through `risk/enforce.py`'s `tolerance_for`, which
    calls `sys.exit` on a missing org; a missing band here is a composition
    refusal, never a process exit."""
    data = json.loads((PLATFORM_DIR / "risk" / "appetite.json").read_text())
    org = data.get("orgs", {}).get(party)
    return float(org["tolerance"]) if org else None


def _load_scenario(rel_path: str) -> dict:
    """A restate entry's own `scenario`, resolved against this repo
    (platform) -- the same convention the prototype used for its named
    scenario (`policy/scenarios/driftwood-root-residual.json`)."""
    return json.loads((PLATFORM_DIR / rel_path).read_text())


def _threat_scenario(feed_version: str, party: str) -> dict:
    """REAL. Falls back to the pinned threat feed, through the estate's own
    converter, when a restate entry names no scenario of its own."""
    result = subprocess.run(
        [sys.executable, str(PLATFORM_DIR / "feeds" / "to_fair_scenario.py"), "threat",
         str(PLATFORM_DIR / "feeds" / "threat-register" / feed_version / "register.json"), party],
        capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def _cage_engine():
    """Import the estate's REAL £ engine rather than modelling it again --
    graded/cage.py lives in this same repo (platform)."""
    sys.path.insert(0, str(PLATFORM_DIR / "graded"))
    import cage  # noqa: E402
    return cage


def _previous_header(adopter_dir: Path) -> dict | None:
    """The last signed composed artefact's own advisory header, if one is
    already committed -- the comparison point ticket 14's holes, selected
    control set and baseline name read (spec.md, "The composed artefact":
    the header carries "the recorded hole ids"). None means this is the
    FIRST composition ever, and spec.md's bootstrap rule applies: "the
    first composition records every hole and refuses on none", because
    there is nothing yet to compare a hole or a removed control against."""
    path = adopter_dir / "composed" / "HEADER.yaml"
    if not path.exists():
        return None
    text = path.read_text()
    if text.startswith(HEADER_COMMENT):
        text = text[len(HEADER_COMMENT):]
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def _previous_cages(adopter_dir: Path) -> list[dict]:
    """The last signed composed artefact's own cages[], if one is already
    committed -- the comparison point `changed` reads (same "new/recorded"
    shape holes and ungoverned namespaces use in tickets 14/15, one field
    simplified to a boolean since a cage carries no status ladder)."""
    prev = adopter_dir / "composed" / "evidence.json"
    if not prev.exists():
        return []
    try:
        return json.loads(prev.read_text()).get("cages", [])
    except (OSError, json.JSONDecodeError):
        return []


def apply_restatements(party_doc: dict, merged: dict, parents: list[dict],
                        adopter_dir: Path) -> tuple[list[dict], list[dict], list[dict]]:
    """Every `overlay.restate` entry against the merged member set. Returns
    (restatements, refusals, cages). Mutates `merged` in place: an accepted
    (stricter) restatement overwrites the rendered action; a weaker one does
    NOT -- the rendered file keeps the inherited action, and the residual is
    priced instead (spec.md: "The rendered action stays the inherited
    one... The composed artefact carries no tier and no tier floor")."""
    restatements: list[dict] = []
    refusals: list[dict] = []
    cages: list[dict] = []
    adopter_party = party_doc["party"]
    threat_pin = next((p["version"] for p in parents if p["kind"] == "threat"), None)
    previous_cages = _previous_cages(adopter_dir)

    for r in party_doc.get("overlay", {}).get("restate", []) or []:
        name, version, action = r["name"], r["version"], r["action"]
        match = next(((k, m) for k, m in merged.items() if k[2] == name and k[0] == version), None)
        if match is None:
            continue  # names nothing this composition resolved; ticket 14 owns dangling claims
        key, meta = match
        family = key[1]
        rule = f"{family}/{name}@{version}"

        if meta["kind"] != "ValidatingPolicy":
            refusals.append({
                "kind": "restatement-of-non-validating",
                "subject": rule,
                "detail": f"{rule} is a {meta['kind']}; a restatement applies to a "
                          f"ValidatingPolicy and to nothing else, because only a "
                          f"ValidatingPolicy carries the Audit<Deny strictness ladder "
                          f"a restatement compares on (ADR-0016)",
                "needs_composition": True,
            })
            continue

        inherited_action = meta["action"]
        accepted = STRICTNESS[action] >= STRICTNESS[inherited_action]
        restatements.append({
            "rule": rule, "inherited_action": inherited_action,
            "restated_action": action, "outcome": "accepted" if accepted else "caged",
        })
        if accepted:
            merged[key] = dict(meta, action=action)
            continue

        # Weaker. Never an override, never an exemption (CONTEXT.md
        # "Exemption"): a declared inability, priced against THIS party's
        # own appetite band by the estate's own cage engine. merged[key] is
        # left untouched, so the render below still carries inherited_action.
        band = _appetite_tolerance(adopter_party)
        if band is None:
            refusals.append({
                "kind": "no-appetite-band", "subject": adopter_party,
                "detail": f"{adopter_party} has no declared risk appetite in "
                          f"risk/appetite.json, so its residual on {rule} cannot be priced",
                "needs_composition": True,
            })
            continue

        scenario_rel = r.get("scenario")
        if scenario_rel:
            scenario, priced_from = _load_scenario(scenario_rel), scenario_rel
        elif threat_pin is not None:
            scenario, priced_from = _threat_scenario(threat_pin, adopter_party), \
                f"threat-register {threat_pin}"
        else:
            refusals.append({
                "kind": "unpriceable-inability", "subject": rule,
                "detail": f"{adopter_party} declared an inability on {rule} with no "
                          f"scenario of its own, and inherits no threat parent to price "
                          f"it from",
                "needs_composition": True,
            })
            continue

        decision = _cage_engine().select(scenario, adopter_party, band, mode="warn")
        tier = decision["tier"]
        prior = next((c for c in previous_cages
                      if c.get("party") == adopter_party and c.get("rule") == rule), None)
        cages.append({
            "party": adopter_party, "rule": rule, "band": band,
            "residual": decision.get("tcor", {}).get("residual", decision.get("uncaged_residual")),
            "tier": tier, "action": decision["action"], "priced_from": priced_from,
            "changed": prior is None or prior.get("tier") != tier,
        })
    return restatements, refusals, cages


# --------------------------------------------------------------------------
# 7. baseline coverage, control claims and holes (ticket 14; ADR-0013, ADR-0017)
# --------------------------------------------------------------------------

# A party's own OSCAL component-definition -- the platform layout ADR-0013
# already fixed (ticket 10). The ADOPTER's own claims live NEXT TO the
# party artefact it signs (ADR-0017: "in its own repo, next to the party
# artefact it signs"), i.e. directly in adopter_dir, no subdirectory.
PARENT_CLAIMS_PATH = ("oscal", "component-definition.json")
ADOPTER_CLAIMS_FILE = "component-definition.json"


def _catalog_ids(nist_root: Path) -> set[str]:
    """Every control id the controls parent's catalogue carries, walking
    nested (enhancement) controls so `ac-6.10` is found by a group-level
    scan -- the same walk as nist/scripts/verify_baselines.py and
    platform/oscal/lint_claims.py's catalog_control_ids(). Duplicated on
    purpose: each reader stays self-contained (lint_claims.py's own
    docstring names this convention)."""
    catalog_dir = nist_root / "catalog"
    meta = json.loads((catalog_dir / "CATALOG_VERSION.json").read_text())
    catalog_doc = json.loads((catalog_dir / meta["file"]).read_bytes())
    ids: set[str] = set()

    def walk(controls):
        for c in controls:
            ids.add(c["id"])
            walk(c.get("controls", []))

    for group in catalog_doc["catalog"].get("groups", []):
        walk(group.get("controls", []))
    return ids


def _baseline_ids(nist_root: Path, name: str) -> set[str] | None:
    """The bare control ids a named OSCAL baseline profile selects, exact-
    string off `with-ids` (ADR-0013). None means the controls parent
    publishes no baseline of this name -- "a missing baseline file" is a
    lint finding (spec.md), not something only composition could see."""
    meta_path = nist_root / "catalog" / "BASELINE_VERSIONS.json"
    if not meta_path.exists():
        return None
    meta = json.loads(meta_path.read_text())
    entry = meta.get("baselines", {}).get(name)
    if entry is None:
        return None
    profile_doc = json.loads((nist_root / "catalog" / entry["file"]).read_bytes())
    return set(profile_doc["profile"]["imports"][0]["include-controls"][0]["with-ids"])


def _load_claims(comp_def_path: Path) -> list[tuple[str, str]]:
    """(control-id, claimed policy name) for every Check_Id prop in one
    OSCAL component-definition -- the same read as oscal/lint_claims.py's
    claimed_policy_names(), duplicated so this reader stays self-contained
    too. [] when the party ships no such file (an adopter need not)."""
    if not comp_def_path.exists():
        return []
    comp_def = json.loads(comp_def_path.read_text())
    out: list[tuple[str, str]] = []
    for comp in comp_def["component-definition"]["components"]:
        for ci in comp.get("control-implementations", []):
            for ir in ci.get("implemented-requirements", []):
                control = ir["control-id"]
                for p in ir.get("props", []):
                    if p.get("name") == "Check_Id":
                        out.append((control, p["value"]))
    return out


def _unknown_id_refusals(ids: list[str], catalog_ids: set[str], subject_prefix: str) -> list[dict]:
    """An id absent from the catalogue, exact-string -- no case-fold, no
    prefix-strip (ADR-0013): a hard failure, never a hole. A plain lint of
    the id against the catalogue would also catch this, so
    needs_composition is False (spec.md: "a prefixed id... are lint
    findings")."""
    return [{
        "kind": "unknown-control-id",
        "subject": f"{subject_prefix}: {cid}",
        "detail": f"{cid!r} is absent from the catalogue -- exact-string resolution finds no "
                  f"case-folded or prefix-stripped match, and an unknown id is a hard failure, "
                  f"not a hole (ADR-0013)",
        "needs_composition": False,
    } for cid in sorted(dict.fromkeys(ids)) if cid not in catalog_ids]


def resolve_claims(all_claims: list[tuple[str, str, str]], policy_owner: dict[str, str],
                    catalog_ids: set[str]) -> tuple[set[str], list[dict]]:
    """Every (control_id, policy_name, claiming_party) triple, resolved two
    ways:

      * the claimed policy must be shipped by SOME composed party, else a
        DANGLING claim (ADR-0013's exact-string id rule catches an unknown
        control id the same way) -- both are lint findings a per-party
        check would also catch on its own (oscal/lint_claims.py already
        does, for platform's), so needs_composition is False;
      * it must be shipped by the SAME party that claims it, else the
        claim is against ANOTHER party's policy (ADR-0017: "a control
        claim belongs to whoever ships the implementation") -- telling
        whose policy it is needs the whole composed set, so
        needs_composition is True.

    A control counts as COVERED -- not a hole -- the moment ANY claim
    exists for it, valid or not: "a baseline control with no claim is a
    hole" (spec.md) says no claim, not no VALID claim. A dangling or
    cross-party claim is its own refusal, orthogonal to hole counting."""
    covered: set[str] = set()
    refusals: list[dict] = []
    for control_id, policy_name, claiming_party in all_claims:
        covered.add(control_id)
        refusals += _unknown_id_refusals([control_id], catalog_ids,
                                          f"{claiming_party} component-definition")
        if control_id not in catalog_ids:
            continue
        owner = policy_owner.get(policy_name)
        if owner is None:
            refusals.append({
                "kind": "dangling-claim",
                "subject": f"{claiming_party}: {control_id} -> {policy_name}",
                "detail": f"{claiming_party}'s component-definition claims {control_id} is "
                          f"evidenced by {policy_name!r}, but no composed member of any kind "
                          f"carries that name",
                "needs_composition": False,
            })
        elif owner != claiming_party:
            refusals.append({
                "kind": "claim-against-another-partys-policy",
                "subject": f"{claiming_party}: {control_id} -> {policy_name}",
                "detail": f"{claiming_party} claims {control_id} is evidenced by "
                          f"{policy_name!r}, which {owner} ships, not {claiming_party} -- a "
                          f"control claim belongs to whoever ships the implementation "
                          f"(ADR-0017)",
                "needs_composition": True,
            })
    return covered, refusals


def compute_holes(selected_set: set[str], covered: set[str],
                   prev_hole_ids: set[str] | None) -> tuple[list[dict], list[dict]]:
    """holes[] entries (new/recorded/closed) and the refusals a NEW hole
    produces. prev_hole_ids is None on the FIRST composition ever -- there
    is nothing yet to compare a hole as new against, so spec.md's bootstrap
    rule applies: "the first composition records every hole and refuses on
    none"."""
    holes = sorted(selected_set - covered)
    entries: list[dict] = []
    refusals: list[dict] = []
    for cid in holes:
        if prev_hole_ids is None or cid in prev_hole_ids:
            entries.append({"control_id": cid, "status": "recorded"})
        else:
            entries.append({"control_id": cid, "status": "new"})
            refusals.append({
                "kind": "new-hole", "subject": cid,
                "detail": f"{cid} is in the selected baseline and no claim covers it, and it "
                          f"is not in the last signed composed artefact's recorded hole list "
                          f"-- a new hole refuses (ADR-0013)",
                "needs_composition": True,
            })
    if prev_hole_ids is not None:
        for cid in sorted((prev_hole_ids & selected_set) - set(holes)):
            entries.append({"control_id": cid, "status": "closed"})
    return entries, refusals


def check_selected_set(selected_set: set[str], prev_selected: set[str] | None) -> list[dict]:
    """A control leaving the selected set is refused, no exceptions:
    "a removal is refused... the composition compares the selected set
    against the last signed composed artefact's selected set and refuses
    on any control that left" (spec.md). None means the first composition
    -- nothing to compare against yet."""
    if prev_selected is None:
        return []
    return [{
        "kind": "removed-control", "subject": cid,
        "detail": f"{cid} was in the last signed composed artefact's selected control set and "
                  f"is absent now -- a control may be added, never removed (ADR-0013)",
        "needs_composition": True,
    } for cid in sorted(prev_selected - selected_set)]


def check_baseline_widening(baseline_ids: set[str], prev_baseline_ids: set[str] | None,
                             prev_name: str | None, name: str) -> list[dict]:
    """A named-baseline change that only ADDS controls still refuses, with
    no override: "a baseline widening refused with no override, so that
    MODERATE to HIGH is a reviewed decision and never a quiet edit"
    (spec.md). A change that drops a control is caught by
    check_selected_set above instead -- this fires only when nothing left,
    so a narrowing isn't double-counted here."""
    if prev_baseline_ids is None or prev_name == name or not (baseline_ids > prev_baseline_ids):
        return []
    return [{
        "kind": "baseline-widening", "subject": f"{prev_name} -> {name}",
        "detail": f"{prev_name} -> {name} adds {len(baseline_ids - prev_baseline_ids)} "
                  f"control(s) at once; a baseline widening is a reviewed decision and has no "
                  f"override (ADR-0013)",
        "needs_composition": True,
    }]


# --------------------------------------------------------------------------
# 8. pricing and threat re-pricing (ticket 16; ADR-0006, ADR-0010, ADR-0015)
# --------------------------------------------------------------------------

# The one regime/violation-type this composition re-prices through ico's own
# converter -- "the uncaged exposure on the uk-gdpr lower-tier entry"
# (spec.md's own acceptance wording, and the prototype's own section 9).
# WHICH regimes actually apply to which workload is a separate, still-open
# gap this composition does not decide -- see ico's own to_fair_scenario.py
# docstring. This re-prices the one entry named, nothing more.
ICO_REGIME = "uk-gdpr"
ICO_VIOLATION_TYPE = "lower-tier"

# select_tier()'s bottom rung. TIERS (graded/cage.py) holds only the three
# real dial presets, and the cage-tier MutatingPolicy coerces any OTHER
# label value to "baseline" -- so a merged `tier: deny` label would invert
# the proposal in silence (ADR-0015). A proposed deny is marked as an issue
# subject here; every other tier is a real label value.
DENY_TIER = "deny"


def _ico_scenario(ico_root: Path, version: str) -> dict:
    """REAL. ico's own converter, `build`, against its own
    <version>/penalty-schema.json -- the same subprocess convention
    `_threat_scenario` above already uses for the threat parent."""
    result = subprocess.run(
        [sys.executable, str(ico_root / "schema" / "to_fair_scenario.py"), "build",
         str(ico_root / "schema" / version / "penalty-schema.json"),
         ICO_REGIME, ICO_VIOLATION_TYPE],
        capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def _previous_parent_version(prev_header: dict | None, party: str, kind: str) -> str | None:
    """The version a pricing/threat parent was pinned to in the LAST SIGNED
    composed artefact's own header -- the "old" half of a price move. None
    on the first composition ever, or when the prior header never recorded
    an edge of this (party, kind) at all -- both mean there is nothing yet
    to compare a bump against."""
    if prev_header is None:
        return None
    return next((p["version"] for p in prev_header.get("parents", [])
                 if p["party"] == party and p["kind"] == kind), None)


def price_parent(edge: dict, adopter_party: str, tolerance: float, ico_root: Path | None,
                  prev_version: str | None) -> dict:
    """One prices[] entry for one pricing/threat edge: priced at the OLD
    version (the last signed artefact's recorded pin, or -- with nothing
    to compare -- this run's own version, which prices as an honest "no
    move") and at the NEW version (this run's resolved pin), both through
    the estate's own £ engine and appetite band, never a second one.
    `ico_root` is unused for a `threat` edge -- `_threat_scenario` always
    reads the threat feed out of THIS repo (`platform`), because `threat`'s
    only party in this estate is `platform` itself, exactly as ticket 13's
    caging path already assumes."""
    party, kind, new_version = edge["party"], edge["kind"], edge["version"]
    old_version = prev_version if prev_version is not None else new_version

    if kind == "pricing":
        old_sc, new_sc = _ico_scenario(ico_root, old_version), _ico_scenario(ico_root, new_version)
    else:  # "threat"
        old_sc = _threat_scenario(old_version, adopter_party)
        new_sc = _threat_scenario(new_version, adopter_party)

    cage = _cage_engine()
    old = cage.select(old_sc, adopter_party, tolerance, mode="warn")
    new = cage.select(new_sc, adopter_party, tolerance, mode="warn")
    return {
        "source": party, "kind": kind,
        "old_version": old_version, "new_version": new_version,
        "old_price": old["uncaged_residual"], "new_price": new["uncaged_residual"],
        "old_tier": old["tier"], "proposed_tier": new["tier"],
        "changed": old["tier"] != new["tier"],
        "proposed_as": "issue" if new["tier"] == DENY_TIER else "label",
    }


def compute_prices(edges: list[dict], adopter_party: str, tolerance: float | None,
                    parent_trees: dict[str, Path], prev_header: dict | None) -> list[dict]:
    """prices[] -- one entry per declared pricing/threat edge. Computed
    EVERY run, not only when a version actually moved: "for each party it
    prints the old price, the new price, the old tier and the proposed
    tier" (spec.md) is unconditional, and "a price move that changes no
    tier prints as no change" is what the `changed` field on each entry
    says, not a reason to skip printing. `tolerance` is None only when the
    adopter has no declared appetite band at all -- the same case
    `apply_restatements` already refuses on when a caging actually needs
    one; pricing prints nothing for that party rather than raise a second,
    redundant refusal for the identical missing band."""
    if tolerance is None:
        return []
    prices: list[dict] = []
    for edge in edges:
        if edge["kind"] not in ("pricing", "threat"):
            continue
        ico_root = Path(parent_trees[edge["party"]]) if edge["kind"] == "pricing" else None
        prev_version = _previous_parent_version(prev_header, edge["party"], edge["kind"])
        prices.append(price_parent(edge, adopter_party, tolerance, ico_root, prev_version))
    return prices


# --------------------------------------------------------------------------
# the seam
# --------------------------------------------------------------------------


def _refused(errors: list[str]) -> dict:
    return {
        "outcome": "refused",
        "party_artefact_errors": list(errors),
        "parents": [],
        "members": [],
        "refusals": [],
        "restatements": [],
        "cages": [],
        "holes": [],
        "ungoverned": [],
        "prices": [],
        "limits": [],
    }


def compose(adopter_dir: Path, parent_trees: dict[str, Path]) -> tuple[dict, dict[str, str]]:
    """The one entry point. Takes the adopter repo state (a directory) and
    the pinned parent trees (party name -> that party's directory). Returns
    the evidence document as a dict and the rendered composed artefact as a
    mapping of path (relative to `adopter_dir`) to file content. Writes
    nothing to disk -- that is the CLI's job."""
    adopter_dir = Path(adopter_dir)
    party_yaml = adopter_dir / "party.yaml"
    if not party_yaml.exists():
        return _refused([f"{party_yaml} does not exist"]), {}

    check_result = party_artefact.check(party_yaml, adopter_dir)
    if check_result["errors"]:
        # A party artefact that does not check out cannot be composed from --
        # there is nothing safe to read a resolved parent from (mirrors
        # party_artefact.check()'s own "can't be checked any further").
        return _refused(check_result["errors"]), {}

    party_doc = yaml.safe_load(party_yaml.read_text())
    adopter_party = party_doc["party"]
    edges = party_doc.get("inherits", []) or []

    parents: list[dict] = []
    missing: list[str] = []
    for edge in edges:
        party, kind, version = edge["party"], edge["kind"], edge["version"]
        tree = parent_trees.get(party)
        if tree is None or not Path(tree).is_dir():
            missing.append(f"{party}/{kind}@{version}: no parent tree provided")
            continue
        try:
            sha = resolve_sha(party, kind, version, adopter_dir, Path(tree))
        except Refused as e:
            missing.append(f"{party}/{kind}@{version}: {e}")
            continue
        parents.append({"party": party, "kind": kind, "version": version, "sha": sha})
    if missing:
        return _refused(missing), {}

    refusals: list[dict] = check_diamonds(edges)

    # Merge every implementations parent's members into one set, keyed on
    # (version, family, name). Two sources supplying the same key with
    # different content is refused -- never merged, never last-wins
    # (spec.md, Resolution) -- and dropped from the composed set entirely,
    # because there is no principled way to pick one.
    merged: dict[tuple[str, str, str], dict] = {}
    conflicting_keys: set[tuple[str, str, str]] = set()
    implementations_parties: set[str] = set()
    guard: dict | None = None
    # (control_id, claimed policy name, claiming party) -- every OSCAL
    # control claim composition can see: each implementations parent's own
    # (ADR-0017: a claim belongs to whoever ships the implementation), plus
    # the adopter's own, gathered below the loop.
    claims: list[tuple[str, str, str]] = []

    for edge in edges:
        if edge["kind"] != "implementations":
            continue
        impl_party, impl_version = edge["party"], edge["version"]
        implementations_parties.add(impl_party)
        impl_sha = next(p["sha"] for p in parents
                         if p["party"] == impl_party and p["kind"] == "implementations")
        impl_root = Path(parent_trees[impl_party])
        members_by_version, this_guard = load_implementations(impl_root)
        source_ref = f"{impl_party}@{impl_version}"

        for control_id, policy_name in _load_claims(impl_root.joinpath(*PARENT_CLAIMS_PATH)):
            claims.append((control_id, policy_name, impl_party))

        for version, members in sorted(members_by_version.items()):
            for (family, base), meta in sorted(members.items()):
                key = (version, family, base)
                prior = merged.get(key)
                if prior is not None and prior["doc"] != meta["doc"]:
                    refusals.append({
                        "kind": "rule-conflict",
                        "subject": f"{family}/{base}@{version}",
                        "detail": (
                            f"{prior['source_ref']} and {source_ref} both supply "
                            f"{family}/{base}@{version} with different content -- "
                            f"{prior['source_ref']}: {json.dumps(prior['doc'], sort_keys=True)} "
                            f"vs {source_ref}: {json.dumps(meta['doc'], sort_keys=True)}"
                        ),
                        "needs_composition": True,
                    })
                    conflicting_keys.add(key)
                    merged.pop(key, None)
                    continue
                if key in conflicting_keys:
                    continue
                merged[key] = dict(meta, source_party=impl_party, source_sha=impl_sha,
                                    source_ref=source_ref)

        if guard is None:
            guard = dict(this_guard, source_party=impl_party, source_sha=impl_sha,
                         source_ref=source_ref)

    # The adopter's own overlay members -- shipped by the adopter, not any
    # parent (ADR-0017). A key already supplied by a parent is left alone;
    # a genuinely new (version, family, name) is a new member, not a
    # restatement (ADR-0016's own consequence: "It is a new member, not a
    # restatement").
    for key, meta in load_overlay_add(party_doc).items():
        merged.setdefault(key, dict(meta, source_party=adopter_party, source_sha=None,
                                     source_ref=f"{adopter_party} (overlay)"))

    # The adopter's own control claims -- next to the party artefact it
    # signs (ADR-0017), never mixed with a parent's.
    for control_id, policy_name in _load_claims(adopter_dir / ADOPTER_CLAIMS_FILE):
        claims.append((control_id, policy_name, adopter_party))

    limits = [{
        "name": "two-publisher-conflict",
        "detail": "the cross-party rule-conflict path above is only exercised in the real "
                   "estate once a second implementations publisher is pinned",
        "count": len(implementations_parties),
        "status": "closed" if len(implementations_parties) >= 2 else "open",
    }]

    restatements, restate_refusals, cages = apply_restatements(party_doc, merged, parents, adopter_dir)
    refusals += restate_refusals

    # -----------------------------------------------------------------
    # ticket 14: baseline coverage, control claims and holes
    # -----------------------------------------------------------------

    policy_owner: dict[str, str] = {}
    for (_version, _family, base), meta in merged.items():
        policy_owner.setdefault(base, meta["source_party"])

    controls_edge = next((e for e in edges if e["kind"] == "controls"), None)
    nist_root: Path | None = None
    catalog_ids: set[str] = set()
    baseline_ids: set[str] = set()
    baseline_name = party_doc["baseline"]
    if controls_edge is None:
        refusals.append({
            "kind": "no-controls-parent", "subject": adopter_party,
            "detail": f"{adopter_party} declares no controls parent, so its selected "
                      f"baseline {baseline_name!r} cannot be resolved against a catalogue",
            "needs_composition": True,
        })
    else:
        nist_root = Path(parent_trees[controls_edge["party"]])
        catalog_ids = _catalog_ids(nist_root)
        resolved = _baseline_ids(nist_root, baseline_name)
        if resolved is None:
            refusals.append({
                "kind": "missing-baseline-file", "subject": baseline_name,
                "detail": f"{controls_edge['party']} publishes no baseline named "
                          f"{baseline_name!r}",
                "needs_composition": False,
            })
        else:
            baseline_ids = resolved

    added_controls = party_doc.get("overlay", {}).get("controls", []) or []
    refusals += _unknown_id_refusals(added_controls, catalog_ids, f"{adopter_party} overlay.controls")
    selected_set = baseline_ids | {c for c in added_controls if c in catalog_ids}

    covered, claim_refusals = resolve_claims(claims, policy_owner, catalog_ids)
    refusals += claim_refusals

    prev_header = _previous_header(adopter_dir)
    prev_hole_ids = set(prev_header.get("holes", [])) if prev_header is not None else None
    prev_selected = set(prev_header.get("selected-controls", [])) if prev_header is not None else None
    prev_baseline_name = prev_header.get("baseline") if prev_header is not None else None
    prev_baseline_ids = (
        _baseline_ids(nist_root, prev_baseline_name)
        if prev_header is not None and nist_root is not None and prev_baseline_name
        else None
    )
    prev_ungoverned_ids = (
        set(prev_header.get("ungoverned-namespaces", [])) if prev_header is not None else None
    )

    hole_entries, hole_refusals = compute_holes(selected_set, covered, prev_hole_ids)
    refusals += hole_refusals
    refusals += check_selected_set(selected_set, prev_selected)
    refusals += check_baseline_widening(baseline_ids, prev_baseline_ids, prev_baseline_name, baseline_name)

    # -----------------------------------------------------------------
    # ticket 15: the governed namespace lint
    # -----------------------------------------------------------------
    ungoverned_entries, ungoverned_refusals = compute_ungoverned(
        set(ungoverned_namespaces(adopter_dir)), prev_ungoverned_ids)
    refusals += ungoverned_refusals

    # -----------------------------------------------------------------
    # ticket 16: pricing and threat parents re-price, and never apply
    # -----------------------------------------------------------------
    prices = compute_prices(edges, adopter_party, _appetite_tolerance(adopter_party),
                             parent_trees, prev_header)

    members_evidence: list[dict] = []
    rendered: dict[str, str] = {}

    for (version, family, base), meta in sorted(merged.items()):
        doc = render_member(meta["doc"], meta["action"], adopter_party, meta["source_ref"], meta["path"])
        # The member's own identity, not its source path's basename -- an
        # overlay.add member has no real on-disk file to name (ticket 14).
        # Equivalent for every parent-sourced member today: each is shipped
        # at exactly "<base>.yaml".
        filename = f"{base}.yaml"
        out_path = f"composed/policies/v{version}/{filename}"
        rendered[out_path] = yaml.safe_dump(doc, **YAML_KWARGS)
        members_evidence.append({
            "family": family, "name": base, "kind": meta["kind"], "version": version,
            "source_party": meta["source_party"], "source_sha": meta["source_sha"],
            "action": meta["action"],
        })

    if guard is not None:
        guard_doc = render_member(guard["doc"], None, adopter_party, guard["source_ref"], guard["path"])
        rendered["composed/orphan-guard.yaml"] = yaml.safe_dump(guard_doc, **YAML_KWARGS)
        members_evidence.append({
            "family": "platform-machinery", "name": "policy-version-orphan-guard",
            "kind": guard["kind"], "version": None,
            "source_party": guard["source_party"], "source_sha": guard["source_sha"], "action": None,
        })

    # The recorded hole ids -- open (new + recorded), never closed ones --
    # are what the NEXT run's compute_holes() compares against. A closed
    # hole drops out of the recorded set: if it becomes a hole again later
    # it is "new" again, not "recorded" (spec.md names no reopened case).
    recorded_hole_ids = sorted(e["control_id"] for e in hole_entries if e["status"] != "closed")
    # Same shape: the recorded (open) set the NEXT run compares against.
    # A closed namespace drops out -- if it goes ungoverned again later it
    # is "new" again, not "recorded" (compute_ungoverned names no reopened
    # case, matching compute_holes).
    recorded_ungoverned = sorted(e["namespace"] for e in ungoverned_entries if e["status"] != "closed")

    header = {
        "policy-as-versioned.dev/composed": True,
        "parents": parents,
        "baseline": baseline_name,
        "governed-namespaces": governed_namespaces(adopter_dir),
        "holes": recorded_hole_ids,
        "selected-controls": sorted(selected_set),
        "ungoverned-namespaces": recorded_ungoverned,
    }
    rendered["composed/HEADER.yaml"] = HEADER_COMMENT + yaml.safe_dump(header, **YAML_KWARGS)

    document = {
        "outcome": "refused" if refusals else "composed",
        "party_artefact_errors": [],
        "parents": parents,
        "members": members_evidence,
        "refusals": refusals,
        "restatements": restatements,
        "cages": cages,
        "holes": hole_entries,
        "ungoverned": ungoverned_entries,
        "prices": prices,
        "limits": limits,
    }
    return document, rendered


def verify(adopter_dir: Path, parent_trees: dict[str, Path]) -> tuple[bool, list[str]]:
    """Re-renders from a fresh resolution of the same parent trees and
    compares byte-for-byte against whatever is already committed under
    `adopter_dir`. A verifier runs this with parent_trees checked out at the
    exact SHAs the committed HEADER.yaml records (that checkout is the
    verifier's job, not this function's)."""
    adopter_dir = Path(adopter_dir)
    document, rendered = compose(adopter_dir, parent_trees)
    if document["outcome"] != "composed":
        return False, [f"re-composition refused: {document['party_artefact_errors']} "
                        f"{document.get('refusals', [])}"]
    mismatches: list[str] = []
    for rel_path, content in rendered.items():
        committed = adopter_dir / rel_path
        if not committed.exists():
            mismatches.append(f"{rel_path}: not committed on disk")
        elif committed.read_text() != content:
            mismatches.append(f"{rel_path}: committed content differs from the re-render")
    composed_dir = adopter_dir / "composed"
    if composed_dir.is_dir():
        for path in composed_dir.rglob("*.yaml"):
            rel = str(path.relative_to(adopter_dir))
            if rel not in rendered:
                mismatches.append(f"{rel}: committed but no longer produced by a re-render")
    return (not mismatches), mismatches


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _default_parent_trees(party_doc: dict, estate_clone: Path) -> dict[str, Path]:
    names = {edge["party"] for edge in (party_doc.get("inherits", []) or [])}
    return {name: estate_clone / name for name in names}


def cmd_compose(adopter_dir: Path, estate_clone: Path, out_dir: Path | None) -> int:
    party_yaml = adopter_dir / "party.yaml"
    party_doc = yaml.safe_load(party_yaml.read_text()) if party_yaml.exists() else {}
    parent_trees = _default_parent_trees(party_doc, estate_clone)
    document, rendered = compose(adopter_dir, parent_trees)
    print(json.dumps(document, indent=2))
    if document["outcome"] == "composed":
        out_dir = out_dir or adopter_dir
        for rel_path, content in rendered.items():
            target = out_dir / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        (out_dir / "composed" / "evidence.json").write_text(json.dumps(document, indent=2))
        return 0
    return 1


def cmd_verify(adopter_dir: Path, estate_clone: Path) -> int:
    party_yaml = adopter_dir / "party.yaml"
    if not party_yaml.exists():
        print(f"REFUSED: {party_yaml} does not exist", file=sys.stderr)
        return 1
    party_doc = yaml.safe_load(party_yaml.read_text())
    parent_trees = _default_parent_trees(party_doc, estate_clone)
    ok, mismatches = verify(adopter_dir, parent_trees)
    if ok:
        print("OK: composed artefact re-renders byte-for-byte from the recorded parent SHAs")
        return 0
    for m in mismatches:
        print(f"MISMATCH: {m}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        # composition.py ships inside platform's own repo, so `platform` is
        # always present here -- what can genuinely be missing is the rest
        # of the estate this module composes AGAINST (driftwood, nist, ico),
        # which only exists once clone-estate.sh has run.
        missing = [name for name in ("driftwood", "nist", "ico")
                   if not (DEFAULT_ESTATE_CLONE / name).is_dir()]
        if missing:
            print(f"SKIP: .estate-clone/{{{','.join(missing)}}} absent. Run ./clone-estate.sh first.")
            return 0
        selfcheck()
        return 0

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("compose", "verify"):
        c = sub.add_parser(name)
        c.add_argument("adopter_dir", type=Path)
        c.add_argument("--estate-clone", type=Path, default=DEFAULT_ESTATE_CLONE)
        if name == "compose":
            c.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv[1:])

    if args.cmd == "compose":
        return cmd_compose(args.adopter_dir, args.estate_clone, args.out)
    if args.cmd == "verify":
        return cmd_verify(args.adopter_dir, args.estate_clone)
    return 2


# --------------------------------------------------------------------------
# selfcheck -- every acceptance criterion, against real files on disk
# --------------------------------------------------------------------------


def _real_parent_trees() -> dict[str, Path]:
    return {name: DEFAULT_ESTATE_CLONE / name for name in ("platform", "nist", "ico")}


def _adopter_copy(name: str, dest: Path) -> Path:
    """Copy a real adopter's committed tree (party.yaml + gitops/) into a
    scratch directory, so a fixture can edit party.yaml's overlay without
    touching the real repo, and without re-deriving party_artefact.check()'s
    own checks against real pin files and the real baseline mirror."""
    src = DEFAULT_ESTATE_CLONE / name
    work = dest / name
    work.mkdir(parents=True)
    (work / "party.yaml").write_text((src / "party.yaml").read_text())
    shutil.copytree(src / "gitops", work / "gitops")
    return work


def _with_restate(work: Path, restate: list[dict]) -> None:
    doc = yaml.safe_load((work / "party.yaml").read_text())
    doc["overlay"]["restate"] = restate
    (work / "party.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _bump_parent_version(work: Path, party: str, kind: str, version: str) -> None:
    """Ticket 16's own fixture primitive: edit ONE declared edge's pinned
    version in place, leaving every other edge untouched -- the "a pricing
    or threat parent bumps" scenario, the same edit a real Renovate PR
    would make to `party.yaml`."""
    doc = yaml.safe_load((work / "party.yaml").read_text())
    for edge in doc["inherits"]:
        if edge["party"] == party and edge["kind"] == kind:
            edge["version"] = version
    (work / "party.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _write_baseline_configmap(work: Path, baseline: str) -> None:
    (work / "gitops" / "apps").mkdir(parents=True, exist_ok=True)
    doc = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": "x-nist-pin", "namespace": "x"},
           "data": {"baselineName": baseline}}
    (work / "gitops" / "apps" / "nist-pin-configmap.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


# ---- ticket 14 fixtures: a small, CLEAN synthetic estate (no dangling
# claims of its own), used wherever a test needs an outcome that can
# actually reach "composed" -- the real estate cannot today, because
# platform's own two dangling claims (ticket 10's named, still-open defect)
# refuse every real composition regardless of holes. ----

KNOWN_DANGLING_PLATFORM_CLAIMS = 2  # ac-6->may-run-root-if-attested, cm-6->require-policy-version


def _assert_only_known_dangling(refusals: list[dict], context: str) -> None:
    """Every real driftwood/tuppence/ludlow composition carries exactly
    platform's two known-dangling claims (ticket 10 named them; ticket 14
    is what now makes composition itself see them) and nothing else --
    proof that composition adds no OTHER refusal for a party artefact that
    otherwise checks out."""
    others = [r for r in refusals if r["kind"] != "dangling-claim"]
    assert not others, (context, others)
    assert len(refusals) == KNOWN_DANGLING_PLATFORM_CLAIMS, (context, refusals)


def _write_fixture_catalog(nist_root: Path) -> None:
    """aa-1 (with a nested enhancement aa-1.1), aa-2, aa-3, bb-1. Three
    named baselines: SMALL={aa-1,aa-1.1,aa-2}, BIG=SMALL plus aa-3 (a
    strict superset, for the widening refusal), TINY={aa-1} (a strict
    subset, for the removed-control refusal)."""
    catalog_dir = nist_root / "catalog"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    catalog_doc = {"catalog": {"uuid": "f" * 8, "groups": [{"id": "fam", "controls": [
        {"id": "aa-1", "controls": [{"id": "aa-1.1"}]},
        {"id": "aa-2"}, {"id": "aa-3"}, {"id": "bb-1"},
    ]}]}}
    (catalog_dir / "catalog.json").write_text(json.dumps(catalog_doc))
    (catalog_dir / "CATALOG_VERSION.json").write_text(json.dumps({"file": "catalog.json"}))

    def profile(ids):
        return {"profile": {"imports": [{"href": "catalog.json",
                 "include-controls": [{"with-ids": ids}]}]}}

    (catalog_dir / "small.json").write_text(json.dumps(profile(["aa-1", "aa-1.1", "aa-2"])))
    (catalog_dir / "big.json").write_text(json.dumps(profile(["aa-1", "aa-1.1", "aa-2", "aa-3"])))
    (catalog_dir / "tiny.json").write_text(json.dumps(profile(["aa-1"])))
    (catalog_dir / "BASELINE_VERSIONS.json").write_text(json.dumps({"baselines": {
        "SMALL": {"file": "small.json"}, "BIG": {"file": "big.json"}, "TINY": {"file": "tiny.json"},
    }}))


def _write_fixture_platform(root: Path, real_platform: Path, claims: list[tuple[str, str]]) -> None:
    """One clean ValidatingPolicy member, "member-a", plus whatever
    (control_id, policy_name) claims the caller wants in its own
    component-definition.json -- deliberately separate from the real
    platform's own two dangling claims, so a hole/claim test here isn't
    muddied by an unrelated, already-covered defect."""
    _write_versions_yaml(root, [{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "e" * 40}])
    shutil.copy(real_platform / "distribution" / "render-orphan-guard.py",
                root / "distribution" / "render-orphan-guard.py")
    _write_admission_doc(root / "distribution" / "policies" / "v1.0.0" / "member-a.yaml",
                          "ValidatingPolicy", "member-a-1-0-0", "fam-a", "1.0.0",
                          validation_actions=["Audit"])
    _write_component_definition(root / "oscal" / "component-definition.json", claims)


def _write_component_definition(path: Path, claims: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    comp_def = {"component-definition": {"components": [{"control-implementations": [{
        "implemented-requirements": [
            {"control-id": control_id, "props": [{"name": "Check_Id", "value": policy_name}]}
            for control_id, policy_name in claims
        ],
    }]}]}}
    path.write_text(json.dumps(comp_def))


def _write_fixture_ico(root: Path, real_ico: Path) -> None:
    """A fixture `ico` parent tree: the real converter script (`schema/
    to_fair_scenario.py`, copied unchanged -- same fixture convention
    `_write_fixture_platform` already uses for `render-orphan-guard.py`)
    against two fixture `schema/v{1,2}/penalty-schema.json` bands. Ticket
    16's crossing case needs an appetite band the bump actually crosses,
    and no real band anywhere in the estate straddles one on either real
    bump (spec.md's own Testing Decisions: the pricing call itself is not
    a sanctioned seam to assert on directly) -- so the LM band moves here,
    in a fixture parent tree, and the crossing is proved through
    `compose()` against a real adopter's real GBP tolerance, the only
    sanctioned seam."""
    def band(version: str, lo: float, hi: float) -> None:
        doc = {
            "schema_version": version, "published_by": "fixture-ico",
            "regimes": {ICO_REGIME: {
                "authority": "fixture", "statute": "fixture", "currency": "GBP",
                "violation_types": {ICO_VIOLATION_TYPE: {
                    "formula": {"type": "per_violation_tier", "min_gbp": lo, "max_gbp": hi},
                }},
            }},
        }
        d = root / "schema" / version
        d.mkdir(parents=True, exist_ok=True)
        (d / "penalty-schema.json").write_text(json.dumps(doc))

    (root / "schema").mkdir(parents=True, exist_ok=True)
    shutil.copy(real_ico / "schema" / "to_fair_scenario.py", root / "schema" / "to_fair_scenario.py")
    band("v1", 100_000, 400_000)  # ALE ~GBP541k -> quarantine residual ~GBP43.3k: over driftwood's GBP40k -> deny
    band("v2", 50_000, 250_000)   # ALE ~GBP324k -> quarantine residual ~GBP26.0k: under driftwood's GBP40k -> quarantine


def _write_fixture_adopter(work: Path, baseline: str, controls_add: list[str] | None = None,
                            add: list[dict] | None = None, own_claims: list[tuple[str, str]] | None = None,
                            nist_party: str = "fixture-nist", impl_party: str = "fixture-platform") -> None:
    party_doc = {
        "party": "fixture-adopter14", "roles": ["adopter"], "baseline": baseline,
        "inherits": [
            {"party": nist_party, "kind": "controls", "version": "1.0.0"},
            {"party": impl_party, "kind": "implementations", "version": "1.0.0"},
        ],
        "overlay": {"add": add or [], "restate": [], "controls": controls_add or []},
    }
    work.mkdir(parents=True, exist_ok=True)
    (work / "party.yaml").write_text(yaml.safe_dump(party_doc, sort_keys=False))
    _write_baseline_configmap(work, baseline)
    if own_claims:
        _write_component_definition(work / ADOPTER_CLAIMS_FILE, own_claims)


def _write_namespace(work: Path, name: str, *, institution: bool = True, governed: bool = False) -> None:
    """A `Namespace` manifest with only the labels the caller asks for --
    ticket 15's own fixture primitive, mirroring the real
    `<adopter>/gitops/apps/namespace.yaml` shape but named per-namespace so
    a test can add several under one adopter tree."""
    labels: dict[str, str] = {}
    if institution:
        labels[INSTITUTION_LABEL] = name
    if governed:
        labels[GOVERNED_LABEL] = "true"
    doc = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}}
    (work / "gitops" / "apps").mkdir(parents=True, exist_ok=True)
    (work / "gitops" / "apps" / f"namespace-{name}.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _commit_header(work: Path, rendered: dict[str, str]) -> None:
    """What `cmd_compose` does for HEADER.yaml alone -- write the just-
    composed header so the NEXT compose() call in the same test reads it
    back as `_previous_header`."""
    (work / "composed").mkdir(exist_ok=True)
    (work / "composed" / "HEADER.yaml").write_text(rendered["composed/HEADER.yaml"])


def selfcheck() -> None:
    driftwood = DEFAULT_ESTATE_CLONE / "driftwood"
    parent_trees = _real_parent_trees()

    document, rendered = compose(driftwood, parent_trees)
    assert document["party_artefact_errors"] == []
    # ticket 14: the real platform component-definition carries two claims
    # against a policy that does not exist anywhere (ticket 10 already
    # named them; fixing them is that repo's job). Composition now catches
    # them itself, so the real estate REFUSES today -- exactly the "reaches
    # the adopter as a refused pull request" spec.md opens with.
    assert document["outcome"] == "refused", document
    _assert_only_known_dangling(document["refusals"], "real driftwood")
    print("OK compose(): the real driftwood composes against its real pinned parents; the "
          "only refusals present are platform's own two known-dangling claims")

    assert {"outcome", "parents", "members", "refusals", "restatements", "cages",
            "holes", "ungoverned", "prices", "limits"} <= document.keys(), document.keys()
    print("OK document: carries outcome, parents[], members[], refusals[], restatements[], "
          "cages[], holes[], ungoverned[], prices[], limits[]")

    # --- prices[] is populated on the real driftwood's first-ever composition
    # too, with nothing to compare a bump against yet (an honest "no move") ---
    assert len(document["prices"]) == 2, document["prices"]  # pricing + threat, both declared
    assert {p["kind"] for p in document["prices"]} == {"pricing", "threat"}
    for p in document["prices"]:
        assert p["old_version"] == p["new_version"], p  # nothing committed yet to bump against
        assert p["changed"] is False, p
    print("OK prices[]: computed on the real driftwood's very first composition too, with no "
          "prior signed artefact to compare a bump against -- old and new both price at this "
          "run's own pin, an honest 'no move'")

    # --- ticket 13: the two-publisher limit prints OPEN at one publisher ---
    limit = next(l for l in document["limits"] if l["name"] == "two-publisher-conflict")
    assert limit["count"] == 1 and limit["status"] == "open", limit
    assert document["restatements"] == [] and document["cages"] == []
    print("OK limits[]: the two-publisher-conflict limit prints open at driftwood's one "
          "pinned implementations publisher")

    declared_kinds = {e["kind"] for e in yaml.safe_load(
        (driftwood / "party.yaml").read_text())["inherits"]}
    assert declared_kinds == {"controls", "implementations", "pricing", "threat"}
    assert len(document["parents"]) == 4
    for parent in document["parents"]:
        assert parent["sha"], parent
    print("OK parents[]: all four declared parent kinds resolve to a non-empty SHA")

    # --- two members of one family at one version both survive resolution ---
    members_by_version, guard = load_implementations(parent_trees["platform"])
    live_version = sorted(members_by_version)[-1]
    at_version = members_by_version[live_version]
    assert ("graded-enforcement", "cage-tier") in at_version, at_version.keys()
    assert ("graded-enforcement", "cage-netpol") in at_version, at_version.keys()
    print("OK load_implementations: cage-tier and cage-netpol, one family, one version, both survive "
          "(ADR-0016's fix for the prototype's (family, version) key)")

    # a dedicated synthetic fixture, not just the estate's own luck
    with tempfile.TemporaryDirectory() as td:
        fixture_root = Path(td) / "fixture-platform"
        _write_versions_yaml(fixture_root, [{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "f" * 40}])
        shutil.copy(parent_trees["platform"] / "distribution" / "render-orphan-guard.py",
                    fixture_root / "distribution" / "render-orphan-guard.py")
        tree = fixture_root / "distribution" / "policies" / "v1.0.0"
        _write_admission_doc(tree / "member-a.yaml", "ValidatingPolicy", "member-a-1-0-0",
                              "one-family", "1.0.0", validation_actions=["Audit"])
        _write_admission_doc(tree / "member-b.yaml", "MutatingPolicy", "member-b-1-0-0",
                              "one-family", "1.0.0")
        fixture_members, _ = load_implementations(fixture_root)
        assert ("one-family", "member-a") in fixture_members["1.0.0"]
        assert ("one-family", "member-b") in fixture_members["1.0.0"]
    print("OK load_implementations: a dedicated fixture, two members of one family at one version, "
          "both keys present")

    # --- render faithfulness across the whole live implementations set ---
    faithful_count = 0
    for version, members in members_by_version.items():
        for (family, base), meta in members.items():
            out_path = f"composed/policies/v{version}/{Path(meta['path']).name}"
            rendered_doc = yaml.safe_load(rendered[out_path])
            assert render_is_faithful(rendered_doc, meta["doc"]), (family, base, version)
            faithful_count += 1
    assert faithful_count == sum(len(m) for m in members_by_version.values())
    print(f"OK render_is_faithful: every member of every live version ({faithful_count} total) "
          "renders back byte-identical after the header is stripped")

    # --- no validationActions written onto a mutate or a generate ---
    mutating_or_generating = 0
    for path, text in rendered.items():
        if path.startswith("composed/policies/") and ("cage-tier.yaml" in path or "cage-netpol.yaml" in path):
            assert "validationActions" not in text, path
            mutating_or_generating += 1
    assert mutating_or_generating > 0
    print("OK render_member: no validationActions field written onto cage-tier (Mutating) "
          "or cage-netpol (Generating)")

    # --- orphan guard composes under the platform tag, matches the offline twin ---
    guard_rendered = yaml.safe_load(rendered["composed/orphan-guard.yaml"])
    assert render_is_faithful(guard_rendered, guard["doc"])
    guard_member = next(m for m in document["members"] if m["name"] == "policy-version-orphan-guard")
    assert guard_member["family"] == "platform-machinery"
    assert guard_member["version"] is None
    print("OK orphan guard: composes under the platform tag (no policy-version), "
          "renders back to the offline twin's output")

    # --- the header ---
    header = yaml.safe_load(rendered["composed/HEADER.yaml"])
    assert header["policy-as-versioned.dev/composed"] is True
    assert len(header["parents"]) == 4
    assert all(p["sha"] for p in header["parents"])
    assert header["baseline"] == "MODERATE"
    assert header["governed-namespaces"] == ["driftwood"]
    # ticket 14: the estate starts at 285 recorded holes and refuses on
    # none of them (spec.md's bootstrap rule -- nothing is committed for
    # the real estate yet, so this IS the first composition every time).
    assert len(document["holes"]) == 285, len(document["holes"])
    assert all(h["status"] == "recorded" for h in document["holes"])
    assert {h["control_id"] for h in document["holes"]} == set(header["holes"])
    assert "ac-6.10" in {h["control_id"] for h in document["holes"]}
    assert "ac-6" not in {h["control_id"] for h in document["holes"]}  # claimed (even if dangling)
    assert "cm-6" not in {h["control_id"] for h in document["holes"]}  # claimed (even if dangling)
    assert len(header["selected-controls"]) == 287  # MODERATE
    print("OK HEADER.yaml/holes[]: the real estate's first composition records 285 holes, all "
          "recorded (none new, none refused), ac-6.10 found by walking nested controls, and "
          "ac-6/cm-6 are covered (a claim exists, even the dangling one)")

    # ticket 15: real driftwood's own Namespace manifest already carries
    # BOTH labels (ticket 11 landed it labelled from the start) -- so the
    # real estate has zero ungoverned namespaces to record or refuse on.
    assert document["ungoverned"] == [], document["ungoverned"]
    assert header["ungoverned-namespaces"] == [], header["ungoverned-namespaces"]
    print("OK ungoverned[]: real driftwood's own namespace already carries governed: \"true\", "
          "so composition records zero ungoverned namespaces")

    # --- verify mode + CLI wrapper: a CLEAN fixture, since the real estate
    # cannot reach outcome=="composed" today (platform's two dangling
    # claims always refuse it) -- see _assert_only_known_dangling above.
    # verify()/cmd_compose only ever run against an artefact that DID reach
    # "composed", so a clean fixture is what actually exercises them. ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write_fixture_catalog(root / "fixture-nist")
        _write_fixture_platform(root / "fixture-platform", parent_trees["platform"],
                                 claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": root / "fixture-nist", "fixture-platform": root / "fixture-platform"}

        work = root / "fixture-adopter14"
        _write_fixture_adopter(work, "SMALL")
        clean_doc, work_rendered = compose(work, fixture_trees)
        assert clean_doc["outcome"] == "composed", clean_doc
        for rel, content in work_rendered.items():
            target = work / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        ok, mismatches = verify(work, fixture_trees)
        assert ok, mismatches
        print("OK verify(): a freshly composed and committed tree re-renders clean")

        (work / "composed" / "orphan-guard.yaml").write_text("kind: Tampered\n")
        ok, mismatches = verify(work, fixture_trees)
        assert not ok and mismatches, mismatches
        print("OK verify(): a tampered committed file is caught as a byte-for-byte mismatch")

    # --- CLI wrapper: writes files, prints the document, exits non-zero on refusal ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write_fixture_catalog(root / "fixture-nist")
        _write_fixture_platform(root / "fixture-platform", parent_trees["platform"],
                                 claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": root / "fixture-nist", "fixture-platform": root / "fixture-platform"}
        # cmd_compose resolves parent trees from --estate-clone by NAME, so
        # the fixture parties live directly under root, matching that layout.
        out = root / "fixture-adopter14"
        _write_fixture_adopter(out, "SMALL")
        rc = cmd_compose(out, root, out)
        assert rc == 0, (rc, (out / "party.yaml").read_text())
        assert (out / "composed" / "HEADER.yaml").exists()
        assert (out / "composed" / "evidence.json").exists()
    print("OK cmd_compose: writes the rendered files and the evidence document, exits 0 on success")

    # --- and against the real estate, cmd_compose exits non-zero today,
    # for the known reason and nothing else (ticket 14's own honesty:
    # composition now genuinely blocks the real driftwood's pull request) ---
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "cli-out"
        out.mkdir()
        (out / "party.yaml").write_text((driftwood / "party.yaml").read_text())
        shutil.copytree(driftwood / "gitops", out / "gitops")
        rc = cmd_compose(out, DEFAULT_ESTATE_CLONE, out)
        assert rc == 1
        assert not (out / "composed").exists()
    print("OK cmd_compose: against the real estate, exits 1 today for platform's two known-"
          "dangling claims, and writes nothing -- composition genuinely blocks the pull "
          "request spec.md opens with")

    # --- refusal: a structurally invalid party artefact never composes, CLI exits non-zero ---
    with tempfile.TemporaryDirectory() as td:
        broken = Path(td) / "broken-adopter"
        broken.mkdir()
        bad_doc = {"party": "broken", "roles": ["adopter"], "baseline": "MODERATE",
                   "inherits": [], "overlay": {"add": [], "restate": []}}
        del bad_doc["roles"]  # missing required field
        (broken / "party.yaml").write_text(yaml.safe_dump(bad_doc))
        doc, files = compose(broken, {})
        assert doc["outcome"] == "refused"
        assert doc["party_artefact_errors"]
        assert files == {}
        rc = cmd_compose(broken, DEFAULT_ESTATE_CLONE, broken)
        assert rc == 1
        assert not (broken / "composed").exists()
    print("OK compose()/cmd_compose: a party artefact that doesn't check out refuses, "
          "renders nothing, and the CLI exits non-zero")

    # ======================================================================
    # ticket 13: structural refusals, restatement, and caging
    # ======================================================================

    # --- a split diamond refuses and names both edges ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        doc = yaml.safe_load((work / "party.yaml").read_text())
        # ico/pricing carries no Flux pin (party_artefact.check_tags only
        # NOTES it), so a second declared version here can't also trip the
        # unrelated tag-mismatch refusal -- this is the diamond, isolated.
        doc["inherits"].append({"party": "ico", "kind": "pricing", "version": "v2"})
        (work / "party.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
        document, files = compose(work, parent_trees)
        assert document["outcome"] == "refused", document
        diamond = [r for r in document["refusals"] if r["kind"] == "split-diamond"]
        assert len(diamond) == 1, document["refusals"]
        assert diamond[0]["subject"] == "ico/pricing", diamond[0]
        assert "v1" in diamond[0]["detail"] and "v2" in diamond[0]["detail"], diamond[0]
        assert diamond[0]["needs_composition"] is True
    print("OK check_diamonds: two edges to ico/pricing at two versions refuse, naming both")

    # --- two sources for one rule with different content refuse, naming both;
    #     the two-publisher limit closes ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for name, action in (("impl-a", "Audit"), ("impl-b", "Deny")):
            fx = root / name
            _write_versions_yaml(fx, [{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "c" * 40}])
            shutil.copy(parent_trees["platform"] / "distribution" / "render-orphan-guard.py",
                        fx / "distribution" / "render-orphan-guard.py")
            _write_admission_doc(fx / "distribution" / "policies" / "v1.0.0" / "dup-member.yaml",
                                  "ValidatingPolicy", "dup-member-1-0-0", "dup-family", "1.0.0",
                                  validation_actions=[action])
        work = root / "fixture-adopter"
        work.mkdir()
        fixture_doc = {
            "party": "fixture-adopter", "roles": ["adopter"], "baseline": "MODERATE",
            "inherits": [
                {"party": "impl-a", "kind": "implementations", "version": "1.0.0"},
                {"party": "impl-b", "kind": "implementations", "version": "1.0.0"},
            ],
            "overlay": {"add": [], "restate": []},
        }
        (work / "party.yaml").write_text(yaml.safe_dump(fixture_doc, sort_keys=False))
        _write_baseline_configmap(work, "MODERATE")
        document, files = compose(work, {"impl-a": root / "impl-a", "impl-b": root / "impl-b"})
        assert document["outcome"] == "refused", document
        conflicts = [r for r in document["refusals"] if r["kind"] == "rule-conflict"]
        assert len(conflicts) == 1, document["refusals"]
        assert conflicts[0]["subject"] == "dup-family/dup-member@1.0.0", conflicts[0]
        assert "impl-a@1.0.0" in conflicts[0]["detail"] and "impl-b@1.0.0" in conflicts[0]["detail"]
        assert "Audit" in conflicts[0]["detail"] and "Deny" in conflicts[0]["detail"]
        assert conflicts[0]["needs_composition"] is True
        assert not any("dup-member.yaml" in p for p in files), files.keys()
        two_pub = next(l for l in document["limits"] if l["name"] == "two-publisher-conflict")
        assert two_pub["count"] == 2 and two_pub["status"] == "closed", two_pub
    print("OK rule-conflict: two implementations publishers on one key with different "
          "content refuse, naming both sources and both contents, never merged; the "
          "two-publisher limit prints closed at two")

    # --- a restatement of a mutate refuses (ADR-0016) ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        _with_restate(work, [{"name": "cage-tier", "version": "2.0.0", "action": "Deny"}])
        document, files = compose(work, parent_trees)
        assert document["outcome"] == "refused", document
        mutate_refusals = [r for r in document["refusals"] if r["kind"] == "restatement-of-non-validating"]
        assert len(mutate_refusals) == 1, document["refusals"]
        assert mutate_refusals[0]["subject"] == "graded-enforcement/cage-tier@2.0.0"
        assert mutate_refusals[0]["needs_composition"] is True
        assert document["restatements"] == [], document["restatements"]
    print("OK restatement-of-non-validating: restating cage-tier (a MutatingPolicy) refuses")

    # --- a stricter restatement is accepted and the rendered file carries it ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        _with_restate(work, [{"name": "require-nonroot", "version": "2.0.0", "action": "Deny"}])
        document, files = compose(work, parent_trees)
        assert document["outcome"] == "refused", document  # platform's known-dangling claims only
        _assert_only_known_dangling(document["refusals"], "stricter restatement")
        r = next(r for r in document["restatements"]
                 if r["rule"] == "require-nonroot/require-nonroot@2.0.0")
        assert r["inherited_action"] == "Audit" and r["restated_action"] == "Deny"
        assert r["outcome"] == "accepted", r
        rendered_doc = yaml.safe_load(files["composed/policies/v2.0.0/require-nonroot.yaml"])
        assert rendered_doc["spec"]["validationActions"] == ["Deny"], rendered_doc
    print("OK restatement accepted: Audit -> Deny is stricter, and the rendered file carries "
          "the restated Deny")

    # --- a weaker restatement is caged; the rendered file keeps the inherited action;
    #     the same weaker restatement prices three parties to the prototype's table ---
    scenario_rel = "policy/scenarios/driftwood-root-residual.json"
    assert (PLATFORM_DIR / scenario_rel).exists(), scenario_rel
    tiers: dict[str, str] = {}
    last_files: dict[str, str] = {}
    for org, expected_tier in (("driftwood", "baseline"), ("tuppence", "baseline"),
                                ("ludlow", "quarantine")):
        with tempfile.TemporaryDirectory() as td:
            work = _adopter_copy(org, Path(td))
            _with_restate(work, [{
                "name": "posture-trust-boundary", "version": "2.0.0", "action": "Audit",
                "scenario": scenario_rel, "why": "needs CAP_NET_RAW; cannot meet condition C",
            }])
            document, files = compose(work, parent_trees)
            # a caged inability adds no refusal of its own -- the only
            # refusals present are platform's known-dangling claims
            assert document["outcome"] == "refused", document
            _assert_only_known_dangling(document["refusals"], f"weaker restatement ({org})")
            r = next(r for r in document["restatements"]
                     if r["rule"] == "posture/posture-trust-boundary@2.0.0")
            assert r["inherited_action"] == "Deny" and r["restated_action"] == "Audit"
            assert r["outcome"] == "caged", r
            cage_entry = next(c for c in document["cages"]
                               if c["rule"] == "posture/posture-trust-boundary@2.0.0")
            assert cage_entry["party"] == org
            tiers[org] = cage_entry["tier"]
            assert cage_entry["tier"] == expected_tier, (org, cage_entry)
            rendered_doc = yaml.safe_load(files["composed/policies/v2.0.0/posture-trust-boundary.yaml"])
            assert rendered_doc["spec"]["validationActions"] == ["Deny"], rendered_doc  # stays inherited
            last_files = files
    print(f"OK cages[]: a weaker restatement is caged against each party's own appetite band, "
          f"the rendered file keeps the inherited Deny, and the same declared inability prices "
          f"three parties to the prototype's table: {tiers}")

    # --- no tier and no tier floor appears anywhere composition itself writes ---
    # (cage-tier.yaml's OWN inherited body legitimately reads posture.acme.io/tier
    # off the workload at admission time -- that is the runtime dial-selection
    # mechanism this composition carries unchanged, not a declared verdict. What
    # must never appear is composition's OWN advisory additions -- the header and
    # the policy-as-versioned.dev/* labels/annotations render_member writes --
    # naming a tier or a tier floor.)
    header = yaml.safe_load(last_files["composed/HEADER.yaml"])
    assert "tier" not in header and "cages" not in header, header
    for path, text in last_files.items():
        if not path.endswith(".yaml"):
            continue
        for doc in yaml.safe_load_all(text):
            if not isinstance(doc, dict):
                continue
            md = doc.get("metadata") or {}
            # Exact-key: composition's own three added keys (COMPOSED_FOR,
            # PROVENANCE_INHERITED, PROVENANCE_SOURCE) are never a tier field.
            # A substring check would false-positive on cage-tier's own
            # legitimate source-path value ("...cage-tier.yaml" contains
            # "tier" as a member NAME, not a declared verdict).
            for section in (md.get("annotations") or {}, md.get("labels") or {}):
                assert "posture.acme.io/tier" not in (section or {}), (path, section)
    print("OK no tier and no tier floor appears anywhere in what composition itself writes -- "
          "only the proposer (ADR-0015) ever turns one, later, in its own PR")

    # --- refusals[] carries needs_composition on every entry, across every kind seen above ---
    for r in diamond + conflicts + mutate_refusals:
        assert "needs_composition" in r and isinstance(r["needs_composition"], bool), r
    print("OK refusals[]: needs_composition is present on every entry "
          "(split-diamond, rule-conflict, restatement-of-non-validating)")

    # ======================================================================
    # ticket 14: baseline coverage, control claims and holes
    # ======================================================================

    # --- the baseline resolver: exact-string, walks nested controls; a
    # prefixed or upper-case id is a hard failure, not a hole ---
    with tempfile.TemporaryDirectory() as td:
        nist_root = Path(td) / "fixture-nist"
        _write_fixture_catalog(nist_root)
        assert _catalog_ids(nist_root) == {"aa-1", "aa-1.1", "aa-2", "aa-3", "bb-1"}
        assert _baseline_ids(nist_root, "SMALL") == {"aa-1", "aa-1.1", "aa-2"}
        assert _baseline_ids(nist_root, "NONEXISTENT") is None
        print("OK _catalog_ids/_baseline_ids: SMALL resolves by name, exact-string, and the "
              "nested enhancement aa-1.1 is found by walking; an unpublished name resolves None")

        platform_root = Path(td) / "fixture-platform"
        _write_fixture_platform(platform_root, parent_trees["platform"], claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": nist_root, "fixture-platform": platform_root}

        # A prefixed/upper-case addition: a hard failure, not a hole. Never
        # enters the selected set (no ghost hole for a string that names no
        # real control), and needs_composition is False -- a plain lint of
        # the id against the catalogue would also catch it.
        work = Path(td) / "bad-ids"
        _write_fixture_adopter(work, "SMALL", controls_add=["AA-1", "fam:aa-2"])
        doc, _ = compose(work, fixture_trees)
        assert doc["outcome"] == "refused", doc
        bad_ids = [r for r in doc["refusals"] if r["kind"] == "unknown-control-id"]
        assert {r["needs_composition"] for r in bad_ids} == {False}, bad_ids
        assert any("AA-1" in r["subject"] for r in bad_ids), bad_ids
        assert any("fam:aa-2" in r["subject"] for r in bad_ids), bad_ids
        assert "AA-1" not in {h["control_id"] for h in doc["holes"]}  # never even considered a hole
        print("OK unknown-control-id: an upper-case id and a prefixed id both refuse as hard "
              "failures (needs_composition False), and are never counted as a hole")

        # --- first composition: holes recorded, refuses on none; claims
        # merge across the parent AND the adopter's own component-definition ---
        base = Path(td) / "run1"
        _write_fixture_adopter(base, "SMALL")
        doc1, rendered1 = compose(base, fixture_trees)
        assert doc1["outcome"] == "composed", doc1
        assert {h["control_id"]: h["status"] for h in doc1["holes"]} == {
            "aa-1.1": "recorded", "aa-2": "recorded"}
        _commit_header(base, rendered1)
        print("OK compute_holes: a first composition (nothing committed yet) records every "
              "hole and refuses on none")

        # --- a second composition with one NEW hole refuses, naming it ---
        added = Path(td) / "run2-new-hole"
        shutil.copytree(base, added)
        doc_added = yaml.safe_load((added / "party.yaml").read_text())
        doc_added["overlay"]["controls"] = ["aa-3"]
        (added / "party.yaml").write_text(yaml.safe_dump(doc_added, sort_keys=False))
        doc2, _ = compose(added, fixture_trees)
        assert doc2["outcome"] == "refused", doc2
        new_holes = [r for r in doc2["refusals"] if r["kind"] == "new-hole"]
        assert len(new_holes) == 1 and new_holes[0]["subject"] == "aa-3", doc2["refusals"]
        assert new_holes[0]["needs_composition"] is True
        assert {"control_id": "aa-1.1", "status": "recorded"} in doc2["holes"]
        print("OK compute_holes: a second composition with one new hole refuses and names it "
              "(aa-3, added via overlay.controls, an adopter-added control with no claim yet)")

        # --- the SAME added control, but filled in the same run by the
        # adopter's own claim against its own overlay.add member: never
        # becomes a hole at all, and claims merge across every party ---
        filled = Path(td) / "run2-adopter-fills"
        shutil.copytree(base, filled)
        own_member = {
            "apiVersion": "policies.kyverno.io/v1alpha1", "kind": "ValidatingPolicy",
            "metadata": {"name": "own-policy-1-0-0", "labels": {LABEL_FAMILY: "own-fam"}},
            "spec": {"validationActions": ["Audit"]},
        }
        doc_filled = yaml.safe_load((filled / "party.yaml").read_text())
        doc_filled["overlay"]["controls"] = ["aa-3"]
        doc_filled["overlay"]["add"] = [{"version": "1.0.0", "manifest": own_member}]
        (filled / "party.yaml").write_text(yaml.safe_dump(doc_filled, sort_keys=False))
        _write_component_definition(filled / ADOPTER_CLAIMS_FILE, [("aa-3", "own-policy")])
        doc3, files3 = compose(filled, fixture_trees)
        assert doc3["outcome"] == "composed", doc3
        assert "aa-3" not in {h["control_id"] for h in doc3["holes"]}, doc3["holes"]
        assert "composed/policies/v1.0.0/own-policy.yaml" in files3, files3.keys()
        print("OK resolve_claims: an adopter-added control refuses as a new hole when unfilled "
              "(above), and an adopter claim in its own component-definition -- against its own "
              "overlay.add member -- fills it in the same run, so it is never even a hole")

        # --- a hole filled ACROSS runs marks it closed ---
        closes = Path(td) / "run2-closes"
        shutil.copytree(base, closes)
        doc_closes = yaml.safe_load((closes / "party.yaml").read_text())
        doc_closes["overlay"]["add"] = [{"version": "1.0.0", "manifest": own_member}]
        (closes / "party.yaml").write_text(yaml.safe_dump(doc_closes, sort_keys=False))
        _write_component_definition(closes / ADOPTER_CLAIMS_FILE, [("aa-1.1", "own-policy")])
        doc4, _ = compose(closes, fixture_trees)
        assert doc4["outcome"] == "composed", doc4
        assert {"control_id": "aa-1.1", "status": "closed"} in doc4["holes"], doc4["holes"]
        assert {"control_id": "aa-2", "status": "recorded"} in doc4["holes"], doc4["holes"]
        print("OK compute_holes: a second composition with a hole filled (aa-1.1, by an "
              "adopter claim added since the last signed artefact) marks it closed")

        # --- a removed control refuses ---
        shrunk = Path(td) / "run2-removed"
        shutil.copytree(base, shrunk)
        doc_shrunk = yaml.safe_load((shrunk / "party.yaml").read_text())
        doc_shrunk["baseline"] = "TINY"  # {aa-1} -- drops aa-1.1 and aa-2
        (shrunk / "party.yaml").write_text(yaml.safe_dump(doc_shrunk, sort_keys=False))
        _write_baseline_configmap(shrunk, "TINY")
        doc5, _ = compose(shrunk, fixture_trees)
        assert doc5["outcome"] == "refused", doc5
        removed = [r for r in doc5["refusals"] if r["kind"] == "removed-control"]
        assert {r["subject"] for r in removed} == {"aa-1.1", "aa-2"}, doc5["refusals"]
        assert all(r["needs_composition"] is True for r in removed)
        print("OK check_selected_set: TINY drops aa-1.1 and aa-2 from SMALL's selected set, and "
              "a removed control refuses, naming both")

        # --- a widened baseline refuses, with no override ---
        widened = Path(td) / "run2-widened"
        shutil.copytree(base, widened)
        doc_widened = yaml.safe_load((widened / "party.yaml").read_text())
        doc_widened["baseline"] = "BIG"  # SMALL plus aa-3 -- a strict superset
        (widened / "party.yaml").write_text(yaml.safe_dump(doc_widened, sort_keys=False))
        _write_baseline_configmap(widened, "BIG")
        doc6, _ = compose(widened, fixture_trees)
        assert doc6["outcome"] == "refused", doc6
        widening = [r for r in doc6["refusals"] if r["kind"] == "baseline-widening"]
        assert len(widening) == 1 and widening[0]["subject"] == "SMALL -> BIG", doc6["refusals"]
        assert widening[0]["needs_composition"] is True
        removed_on_widen = [r for r in doc6["refusals"] if r["kind"] == "removed-control"]
        assert removed_on_widen == [], doc6["refusals"]  # nothing left; only widening fires
        print("OK check_baseline_widening: SMALL -> BIG refuses with no override, and does not "
              "also fire as a removal (nothing left the selected set)")

        # --- an adopter claim against a PARENT's policy refuses ---
        cross = Path(td) / "run2-cross-party-claim"
        shutil.copytree(base, cross)
        _write_component_definition(cross / ADOPTER_CLAIMS_FILE, [("aa-2", "member-a")])
        doc7, _ = compose(cross, fixture_trees)
        assert doc7["outcome"] == "refused", doc7
        cross_refusals = [r for r in doc7["refusals"] if r["kind"] == "claim-against-another-partys-policy"]
        assert len(cross_refusals) == 1, doc7["refusals"]
        assert "aa-2" in cross_refusals[0]["subject"] and "member-a" in cross_refusals[0]["subject"]
        assert cross_refusals[0]["needs_composition"] is True
        # aa-2 still counts as COVERED -- a claim exists, invalid or not
        # (spec.md: "no claim", not "no valid claim") -- so it closes as a
        # hole even though the claim that closed it is itself refused.
        assert {"control_id": "aa-2", "status": "closed"} in doc7["holes"], doc7["holes"]
        print("OK resolve_claims: an adopter claim against fixture-platform's own member-a "
              "refuses (ADR-0017) -- 'fixture-adopter14 claims aa-2 is evidenced by "
              "\"member-a\", which fixture-platform ships, not fixture-adopter14' -- and still "
              "counts as coverage (a claim exists), orthogonal to the claim's own validity")

    # --- and against the real estate: a claim whose policy exists nowhere
    # refuses with needs_composition False, naming the two dangling
    # platform claims today (ticket 14's own acceptance wording) ---
    real_doc, _ = compose(driftwood, parent_trees)
    dangling = [r for r in real_doc["refusals"] if r["kind"] == "dangling-claim"]
    assert len(dangling) == 2, real_doc["refusals"]
    assert all(r["needs_composition"] is False for r in dangling)
    assert any("ac-6" in r["subject"] and "may-run-root-if-attested" in r["subject"] for r in dangling)
    assert any("cm-6" in r["subject"] and "require-policy-version" in r["subject"] for r in dangling)
    print("OK resolve_claims: the real platform component-definition's two dangling claims "
          "(ac-6->may-run-root-if-attested, cm-6->require-policy-version) refuse with "
          "needs_composition False, named exactly")

    # --- the header carries the recorded hole ids (asserted against the
    # real estate's first composition, above: "OK HEADER.yaml/holes[]").
    # Stripping it is a no-op on every other rendered file: HEADER.yaml is
    # its own separate file, and "holes"/"selected-controls" appear
    # nowhere else in what composition renders. ---
    for path, text in rendered.items():
        if path == "composed/HEADER.yaml":
            continue
        assert '"holes"' not in text and "holes:" not in text, path
        assert "selected-controls" not in text, path
    print("OK HEADER.yaml: 'holes' and 'selected-controls' live only in the advisory header -- "
          "stripping it leaves every other rendered file unchanged")

    # ======================================================================
    # ticket 15: the governed namespace lint
    # ======================================================================
    with tempfile.TemporaryDirectory() as td:
        nist_root = Path(td) / "fixture-nist"
        _write_fixture_catalog(nist_root)
        platform_root = Path(td) / "fixture-platform"
        _write_fixture_platform(platform_root, parent_trees["platform"], claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": nist_root, "fixture-platform": platform_root}

        # --- a namespace with no institution label is ignored entirely ---
        ignored = Path(td) / "ignored"
        _write_fixture_adopter(ignored, "SMALL")
        _write_namespace(ignored, "infra", institution=False, governed=False)
        assert ungoverned_namespaces(ignored) == []
        doc0, _ = compose(ignored, fixture_trees)
        assert doc0["outcome"] == "composed", doc0
        assert doc0["ungoverned"] == [], doc0["ungoverned"]
        print("OK ungoverned_namespaces: a Namespace with no institution label is ignored "
              "entirely, never entering the ungoverned set")

        # --- bootstrap: the FIRST composition (nothing committed yet)
        # records a pre-existing ungoverned namespace and refuses on none --
        # same bootstrap rule compute_holes already uses (spec.md, Further
        # Notes: "the first composition records ... three ungoverned "
        # namespaces and refuses on none") ---
        base = Path(td) / "run1"
        _write_fixture_adopter(base, "SMALL")
        _write_namespace(base, "acme", institution=True, governed=False)
        doc1, rendered1 = compose(base, fixture_trees)
        assert doc1["outcome"] == "composed", doc1
        assert doc1["ungoverned"] == [{"namespace": "acme", "status": "recorded"}], doc1["ungoverned"]
        _commit_header(base, rendered1)
        print("OK compute_ungoverned: a first composition (nothing committed yet) records a "
              "pre-existing ungoverned namespace and refuses on none")

        # --- an unchanged second run: still recorded, still no refusal ---
        again = Path(td) / "run1-again"
        shutil.copytree(base, again)
        doc2, _ = compose(again, fixture_trees)
        assert doc2["outcome"] == "composed", doc2
        assert doc2["ungoverned"] == [{"namespace": "acme", "status": "recorded"}], doc2["ungoverned"]
        print("OK compute_ungoverned: a recorded ungoverned namespace records and does not refuse")

        # --- it gains the label since the last signed artefact: closed ---
        labelled = Path(td) / "run1-labelled"
        shutil.copytree(base, labelled)
        _write_namespace(labelled, "acme", institution=True, governed=True)
        doc3, _ = compose(labelled, fixture_trees)
        assert doc3["outcome"] == "composed", doc3
        assert doc3["ungoverned"] == [{"namespace": "acme", "status": "closed"}], doc3["ungoverned"]
        print("OK compute_ungoverned: a namespace that gains the label prints as closed")

        # --- a genuinely NEW ungoverned namespace (absent from the last
        # signed artefact, which recorded none) refuses and names it ---
        clean_base = Path(td) / "run2"
        _write_fixture_adopter(clean_base, "SMALL")
        doc4, rendered4 = compose(clean_base, fixture_trees)
        assert doc4["outcome"] == "composed", doc4
        assert doc4["ungoverned"] == [], doc4["ungoverned"]
        _commit_header(clean_base, rendered4)

        new_ns = Path(td) / "run2-new"
        shutil.copytree(clean_base, new_ns)
        _write_namespace(new_ns, "acme", institution=True, governed=False)
        doc5, _ = compose(new_ns, fixture_trees)
        assert doc5["outcome"] == "refused", doc5
        new_refusals = [r for r in doc5["refusals"] if r["kind"] == "new-ungoverned-namespace"]
        assert len(new_refusals) == 1 and new_refusals[0]["subject"] == "acme", doc5["refusals"]
        assert new_refusals[0]["needs_composition"] is True
        assert {"namespace": "acme", "status": "new"} in doc5["ungoverned"], doc5["ungoverned"]
        print("OK compute_ungoverned: a new ungoverned namespace (absent from the last signed "
              "artefact) refuses and names it")

        # --- the header carries the recorded ungoverned set, and stripping
        # it leaves every other rendered file unchanged; nothing in the
        # per-member files ever reads either namespace set ---
        header1 = yaml.safe_load(rendered1["composed/HEADER.yaml"])
        assert header1["ungoverned-namespaces"] == ["acme"], header1["ungoverned-namespaces"]
        for path, text in rendered1.items():
            if path == "composed/HEADER.yaml":
                continue
            assert "ungoverned" not in text, path
            assert GOVERNED_LABEL not in text, path
            assert "acme" not in text, path
        print("OK HEADER.yaml: carries the recorded ungoverned namespaces, and stripping it "
              "leaves every other rendered file unchanged -- nothing composition renders reads "
              "either namespace set")

    # ======================================================================
    # ticket 16: pricing and threat parents re-price, and never apply
    # ======================================================================

    # --- an ico penalty-schema bump (v1 -> v2) moves the uncaged exposure
    # on uk-gdpr/lower-tier through ico's own converter; on driftwood's
    # real band both versions land on the same tier, so the document
    # prints no change; no rendered file changes on the price move ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        doc0, rendered0 = compose(work, parent_trees)
        _assert_only_known_dangling(doc0["refusals"], "ico bump, before")
        _commit_header(work, rendered0)
        _bump_parent_version(work, "ico", "pricing", "v2")
        doc1, files1 = compose(work, parent_trees)
        _assert_only_known_dangling(doc1["refusals"], "ico bump, after")
        price = next(p for p in doc1["prices"] if p["kind"] == "pricing")
        assert price["source"] == "ico", price
        assert price["old_version"] == "v1" and price["new_version"] == "v2", price
        assert price["old_price"] != price["new_price"], price
        assert price["old_tier"] == price["proposed_tier"] == "deny", price
        assert price["changed"] is False, price
        assert price["proposed_as"] == "issue", price  # deny: an issue subject, never a label
        for path, content in rendered0.items():
            if path == "composed/HEADER.yaml":
                continue
            assert files1[path] == content, path
        assert files1.keys() == rendered0.keys(), (files1.keys(), rendered0.keys())
    print("OK prices[]: an ico penalty-schema bump (v1 -> v2) moves the uncaged uk-gdpr/lower-"
          "tier exposure through ico's own converter; on driftwood's real band both versions "
          "land on deny, so the document prints no tier change, marked as an issue subject "
          "never a label; no rendered file changes -- a byte comparison proves it")

    # --- a threat-register bump (v1 -> v2) moves tuppence's exposure
    # through the feeds module; same real-band 'no change' shape ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("tuppence", Path(td))
        doc0, rendered0 = compose(work, parent_trees)
        _assert_only_known_dangling(doc0["refusals"], "threat bump, before")
        _commit_header(work, rendered0)
        _bump_parent_version(work, "platform", "threat", "v2")
        doc1, files1 = compose(work, parent_trees)
        _assert_only_known_dangling(doc1["refusals"], "threat bump, after")
        price = next(p for p in doc1["prices"] if p["kind"] == "threat")
        assert price["source"] == "platform", price
        assert price["old_version"] == "v1" and price["new_version"] == "v2", price
        assert price["old_price"] != price["new_price"], price  # v2 raises tuppence's LEF
        assert price["old_tier"] == price["proposed_tier"] == "deny", price
        assert price["changed"] is False, price
        for path, content in rendered0.items():
            if path == "composed/HEADER.yaml":
                continue
            assert files1[path] == content, path
    print("OK prices[]: a threat-register bump (v1 -> v2) moves tuppence's exposure through the "
          "feeds module; on the real band both versions land on deny, no tier change; no "
          "rendered file changes")

    # --- a fixture band that a bump crosses prints a proposed tier, and
    # the mark flips from 'label' (a real tier) as soon as it stops being
    # deny -- proved through compose(), the only sanctioned seam (spec.md's
    # own Testing Decisions names the pricing call off-limits to assert on
    # directly), since no real appetite band anywhere in the estate
    # actually straddles a boundary on either real price move above (the
    # prototype's own honest finding, reproduced: the wiring moves, the
    # real-band outcome does not). Only ico's own tree is fixtured -- the
    # bump crosses driftwood's real GBP40,000 tolerance, not a fixture one ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        fixture_ico = Path(td) / "fixture-ico"
        _write_fixture_ico(fixture_ico, parent_trees["ico"])
        crossing_parents = dict(parent_trees, ico=fixture_ico)

        doc0, rendered0 = compose(work, crossing_parents)
        _assert_only_known_dangling(doc0["refusals"], "crossing fixture, before")
        _commit_header(work, rendered0)
        _bump_parent_version(work, "ico", "pricing", "v2")
        doc1, files1 = compose(work, crossing_parents)
        _assert_only_known_dangling(doc1["refusals"], "crossing fixture, after")
        price = next(p for p in doc1["prices"] if p["kind"] == "pricing")
        assert price["old_version"] == "v1" and price["new_version"] == "v2", price
        assert price["old_tier"] == "deny", price
        assert price["proposed_tier"] == "quarantine", price
        assert price["changed"] is True, price
        assert price["proposed_as"] == "label", price  # quarantine is a real label value
        for path, content in rendered0.items():
            if path == "composed/HEADER.yaml":
                continue
            assert files1[path] == content, path
        assert files1.keys() == rendered0.keys(), (files1.keys(), rendered0.keys())
    print("OK prices[]: a fixture ico band (v1->v2) that crosses driftwood's real GBP40,000 "
          "tolerance prints a proposed tier through compose() (deny -> quarantine, "
          "changed=True), marked as a label; no rendered file changes")

    # --- no scheduler, no wall-clock read anywhere in composition.py
    # itself, except through an explicit --as-of passed to the feeds
    # module (spec.md's own acceptance wording) -- neither converter this
    # section calls even takes one: ico's build and the feeds module's
    # threat subcommand are both timeless, and an "eol" parent kind does
    # not exist in the party artefact schema at all ---
    # Import statements in the real, load-bearing code above selfcheck(),
    # not prose or this very check's own forbidden-token list (both would
    # otherwise match themselves) -- composition.py never gained the
    # CAPABILITY to read a clock or a scheduler at all.
    own_source = Path(__file__).read_text().split("\ndef selfcheck()", 1)[0]
    forbidden_imports = ("import datetime", "from datetime", "import time",
                          "import sched", "import croniter")
    hits = [tok for tok in forbidden_imports if tok in own_source]
    assert not hits, hits
    print("OK composition.py itself calls no scheduler and reads no wall clock of its own")

    print(
        "\nselfcheck ok: one seam composes the real driftwood against its real pinned parents; "
        "every member of every live version renders back byte-identical after the header is "
        "stripped; two members of one family at one version both survive (real estate and a "
        "dedicated fixture); no validationActions leaks onto a mutate or a generate; the orphan "
        "guard composes under the platform tag and matches its own offline twin; the header "
        "carries the composed marker, every parent SHA once, the baseline and the governed "
        "namespace names; verify() catches a byte-for-byte drift; the CLI writes files and "
        "exits non-zero on a refusal; a split diamond and a cross-party rule conflict refuse, "
        "naming both edges/sources/contents; a restatement of a mutate refuses; a stricter "
        "restatement is accepted and rendered; a weaker restatement is caged against the "
        "estate's real cage engine and appetite bands, rendering the inherited action and "
        "pricing driftwood/tuppence/ludlow to the prototype's own baseline/baseline/quarantine "
        "table; no tier ever appears in the rendered artefact; the two-publisher limit prints "
        "open at one and closed at two; every refusal carries needs_composition. TICKET 14: the "
        "baseline resolves by name exact-string, walking nested controls (ac-6.10 found); a "
        "prefixed or upper-case id is a hard failure, not a hole; the real estate's first "
        "composition records 285 holes and refuses on none, but DOES refuse on platform's own "
        "two dangling claims (ac-6->may-run-root-if-attested, cm-6->require-policy-version), "
        "needs_composition False; a new hole refuses and names it; a closed hole is marked so; "
        "an adopter-added control refuses unfilled and is filled by the adopter's own claim "
        "against its own overlay.add member; a removed control and a widened baseline both "
        "refuse with no override; a claim against a parent's policy refuses; and the header "
        "carries the recorded hole ids and the selected control set, in a file that strips away "
        "clean. TICKET 15: a Namespace with no institution label is ignored entirely; the first "
        "composition records a pre-existing ungoverned namespace and refuses on none; a "
        "recorded one records and does not refuse; one that gains the governed label prints as "
        "closed; a genuinely new one refuses and names it; and the header carries the recorded "
        "ungoverned set, in a file that strips away clean, with neither namespace set ever read "
        "by anything composition renders. TICKET 16: an ico penalty-schema bump and a threat-"
        "register bump each move the priced exposure through the estate's own converters, "
        "printing old/new price and old/proposed tier every run; on the real bands neither "
        "changes a tier; a fixture band that a bump crosses prints a proposed tier; a proposed "
        "deny is marked as an issue subject and never a label value; no rendered file ever "
        "changes on a price move; and composition itself reads no wall clock and calls no "
        "scheduler."
    )


def _write_versions_yaml(root: Path, versions: list[dict]) -> None:
    (root / "distribution").mkdir(parents=True, exist_ok=True)
    doc = {
        "apiVersion": "fluxcd.controlplane.io/v1", "kind": "ResourceSet",
        "metadata": {"name": "policy-versions", "namespace": "flux-system"},
        "spec": {"inputs": [{"versions": versions}], "resourcesTemplate": ""},
    }
    (root / "distribution" / "versions.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _write_admission_doc(path: Path, kind: str, name: str, family: str, version: str,
                          validation_actions: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "apiVersion": "policies.kyverno.io/v1alpha1", "kind": kind,
        "metadata": {"name": name, "labels": {
            LABEL_FAMILY: family, LABEL_VERSION: version,
        }},
        "spec": {},
    }
    if validation_actions is not None:
        doc["spec"]["validationActions"] = validation_actions
    path.write_text(yaml.safe_dump(doc, sort_keys=False))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
