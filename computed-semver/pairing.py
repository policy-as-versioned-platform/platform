#!/usr/bin/env python3
"""pairing.py -- ticket cs-22: pairing rules and the `platform-machinery` class.

The gate pairs an old policy with its new counterpart correctly, and refuses
when it cannot -- a wrong pairing produces a confident wrong bump. This module
is that pairing layer: it parses the YAML (never a text diff -- comments are
not part of a parsed document, so a comment-only change is invisible to it by
construction) and pairs old/new bodies on the tuple of IDENTITY FAMILY (the
`policy-as-versioned.dev/policy` label -- "graded-enforcement" and "posture"
each already group several different unversioned-by-filename policies, see
graded/policies/cage-netpol.yaml and priorityclasses.yaml, both
"graded-enforcement") and the policy's `metadata.name` with its version slug
stripped -- never by filename, which cannot tell two members of the same
family apart when they land in differently-named files (the deliberate
before/after case in `selfcheck` proves this: two family members swap which
file they live in between old and new, and still pair correctly).

Three structural rules `check_pairing` enforces, refusing and naming the file
the moment any is violated:

  1. Movement traced to an UNVERSIONED member fails. A member's identity
     label only ever names a FAMILY, never a version -- the actual version
     pin is the separate `policy-as-versioned.dev/policy-version` label
     render-version-tree.py stamps on every rendered copy. A member that
     shows real content movement (not just a version-literal artifact, rule
     3 below) but carries no version pin at all is exactly ticket 15's
     finding: five policies that stayed claim-wide instead of being folded
     into the pinned path, discovered only because their movement had
     nowhere legitimate to register. This rule is what keeps that from
     recurring.

     ONE declared exception: `platform-machinery` (see below). Everything
     else that shows movement must carry a version pin or the gate refuses.

     Scope, disclosed: this rule only engages once the identity LABEL is in
     use somewhere in the comparison (`old_members + new_members` carries at
     least one non-None identity). gate.py's own historical rederivation
     tests (ticket cs-18/19/21's selfcheck) replay the REAL pre-repair
     v1.0.0/v2.0.0/v2.0.1 release line verbatim -- byte-identical bodies that
     predate the identity/version label scheme entirely, carrying no label
     of any kind on either side. That comparison is Track 1/2's job alone
     (rederive_bumps.py / cage_engine.py, both already ticket-owned and
     already correct for it) -- retroactively demanding a label scheme on a
     real historical tag this project never stamped would not catch a new
     bug, it would just make an already-settled rederivation refuse. A
     REPO STATE that mixes ANY labeled member with an unlabeled one -- the
     actual shape of ticket 15's finding, a partial migration -- still hits
     the rule on the unlabeled member, exactly as intended.

  2. `platform-machinery` IS a class, recognised by that identity label like
     any other family -- never a name-based exclusion (a `if name ==
     "policy-version-orphan-guard"` special case would let the next
     machinery object with a typo'd name, or an identity nobody bothered to
     set, slip straight through the rule above). It is legitimately
     unversioned because the platform release TAG numbers it, not a
     per-policy version label -- render-orphan-guard.py's emitted policy
     carries the identity and nothing else changes for it here.
     `selfcheck` proves the class, not the name: a member carrying the
     `platform-machinery` identity under an arbitrary file/policy name
     passes, and a DIFFERENT member with no identity label at all --
     including one that LOOKS like machinery -- still fails, so the class
     is not a by-name escape hatch.

  3. Two versioned trees that declare the SAME version for the same member
     but disagree on content fails. A version, once claimed, is supposed to
     be one frozen body -- this is the direct, disclosed shape of ticket 15's
     step 3 ("fold the second v1.0.0 tree into the distribution line"): the
     real historical release line once had two DIFFERENT v1.0.0 trees.

Rules compare as a SET -- `matchConditions[].expression` union
`validations[].expression`, order dropped. A version-literal-only
difference (the self-scope `matchConditions` entry render-version-tree.py
appends names the version literal by construction, so it always differs
character-for-character between any two versions) is normalised away before
the set comparison decides "did anything real change" -- when normalising
makes the two sides equal, the pair is reported UNPROVEN, never guessed at
either way (spec.md, "the gate does not guess").

Usage:
    pairing.py --selfcheck
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import corpus_generator  # cs-19: already imports render-version-tree.py by path

HERE = Path(__file__).resolve().parent

IDENTITY_LABEL = "policy-as-versioned.dev/policy"
VERSION_LABEL = "policy-as-versioned.dev/policy-version"
PLATFORM_MACHINERY = "platform-machinery"

# spec.md, "Coverage and evidence": "Coverage is defined over predicate
# expressions only, which means matchConditions and validations." Only kinds
# that can carry either are members this module tracks; a PriorityClass (no
# matchConditions/validations of its own) is out of this module's scope.
KNOWN_KINDS = {"ValidatingPolicy", "MutatingPolicy"}


@dataclass(frozen=True)
class Member:
    identity: str | None
    base_name: str
    version: str | None
    file: Path
    rules: frozenset[str]


def strip_version(name: str, version: str | None) -> str:
    """'require-nonroot-1-0-0' + '1.0.0' -> 'require-nonroot'. An unversioned
    name (no version label) is returned unchanged -- it never carried a slug
    suffix to strip."""
    if not version:
        return name
    suffix = "-" + version.replace(".", "-")
    return name[: -len(suffix)] if name.endswith(suffix) else name


def _rules(body: dict) -> frozenset[str]:
    """matchConditions + validations expressions -- spec.md's own coverage
    vocabulary ("predicate expressions only, which means matchConditions and
    validations") -- PLUS `variables[].expression`: "the dial map inside the
    tier policy is a policy body" (this ticket's own text), and cage-tier.yaml
    (a MutatingPolicy) carries its entire dial table as ONE variable
    expression, never a validation -- a MutatingPolicy has none."""
    spec = body.get("spec") or {}
    exprs = [c["expression"] for c in (spec.get("matchConditions") or []) if "expression" in c]
    exprs += [v["expression"] for v in (spec.get("validations") or []) if "expression" in v]
    exprs += [v["expression"] for v in (spec.get("variables") or []) if "expression" in v]
    return frozenset(exprs)


def parse_tree(directory: Path) -> list[Member]:
    """Every ValidatingPolicy/MutatingPolicy document under `directory`,
    parsed as YAML (yaml.safe_load_all -- multi-document files, e.g. three
    PriorityClass docs sharing one file, are walked correctly; comments are
    simply not part of the parsed structure, so a comment-only change is
    invisible here by construction, never by a text-diff special case).
    Non-policy documents (`versions.yaml`'s bare `{versions: [...]}`, a
    Kustomization, a PriorityClass) are skipped, not guessed at -- the
    version array's OWN comparison is a different rule (spec.md, "The array
    decides which bodies run"; ticket cs-24's job, not this module's)."""
    members: list[Member] = []
    for f in sorted(directory.rglob("*.yaml")):
        for body in yaml.safe_load_all(f.read_text()):
            if not body or "metadata" not in body or body.get("kind") not in KNOWN_KINDS:
                continue
            name = body["metadata"].get("name")
            if not name:
                continue
            labels = body["metadata"].get("labels") or {}
            identity = labels.get(IDENTITY_LABEL)
            version = labels.get(VERSION_LABEL)
            members.append(Member(
                identity=identity,
                base_name=strip_version(name, version),
                version=version,
                file=f,
                rules=_rules(body),
            ))
    return members


def _normalize(expr: str, version: str | None) -> str:
    """Strips a known version literal out of a CEL expression string so a
    self-scope matchConditions entry (which always names the version) does
    not read as a real change by itself."""
    return expr.replace(f"'{version}'", "'<version>'") if version else expr


def _status(old: Member | None, new: Member | None) -> str:
    """'none' | 'unproven' | 'moved'. Never a text diff -- always the parsed
    rule SET, order dropped (frozenset), on each side."""
    if old is None or new is None:
        return "moved"  # existence itself changed -- always real movement
    if old.rules == new.rules:
        return "none"
    norm_old = {_normalize(e, old.version) for e in old.rules}
    norm_new = {_normalize(e, new.version) for e in new.rules}
    return "unproven" if norm_old == norm_new else "moved"


@dataclass
class PairingResult:
    ok: bool
    reason: str | None
    statuses: dict[tuple[str | None, str], str] = field(default_factory=dict)
    unproven: list[tuple[str | None, str]] = field(default_factory=list)


def check_pairing(old_dir: Path, new_dir: Path) -> PairingResult:
    """Pairs every member of `old_dir` and `new_dir` on (identity family,
    name with its version stripped) and enforces the three structural rules
    named in the module docstring, in order, refusing on the first one
    violated and naming the file. Returns ok=True with every pair's status
    (and the 'unproven' subset) when nothing refuses."""
    old_members, new_members = parse_tree(old_dir), parse_tree(new_dir)
    old_by_key = {(m.identity, m.base_name): m for m in old_members}
    new_by_key = {(m.identity, m.base_name): m for m in new_members}
    keys = sorted(set(old_by_key) | set(new_by_key), key=lambda k: (k[0] or "", k[1]))

    # See the module docstring's rule 1: the unversioned-member rule only
    # engages once the identity scheme is in use somewhere in THIS
    # comparison -- a wholly-unlabeled legacy pair predates it entirely.
    identity_scheme_in_use = any(m.identity is not None for m in old_members + new_members)

    statuses: dict[tuple[str | None, str], str] = {}
    unproven: list[tuple[str | None, str]] = []
    for key in keys:
        old_m, new_m = old_by_key.get(key), new_by_key.get(key)
        status = _status(old_m, new_m)
        statuses[key] = status
        if status == "unproven":
            unproven.append(key)
            continue
        if status != "moved":
            continue

        identity, base_name = key

        # Rule 3: same declared version, disagreeing content.
        if old_m and new_m and old_m.version is not None and old_m.version == new_m.version:
            return PairingResult(
                False,
                f"{identity or '(no identity)'}/{base_name}: old and new both declare "
                f"version {old_m.version!r} but disagree on content "
                f"({old_m.file} vs {new_m.file})",
                statuses, unproven,
            )

        # Rules 1 + 2: movement on an unversioned, non-platform-machinery member.
        version = (new_m.version if new_m else None) or (old_m.version if old_m else None)
        file_ref = new_m.file if new_m else old_m.file
        if identity_scheme_in_use and version is None and identity != PLATFORM_MACHINERY:
            return PairingResult(
                False,
                f"movement traced to an unversioned policy: {file_ref} "
                f"(identity={identity!r}) -- give it a '{VERSION_LABEL}' label "
                f"or the '{PLATFORM_MACHINERY}' identity",
                statuses, unproven,
            )

    return PairingResult(True, None, statuses, unproven)


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

def _policy_yaml(name: str, identity: str | None, version: str | None,
                  validations: list[str], comment: str = "") -> str:
    labels = {}
    if identity is not None:
        labels[IDENTITY_LABEL] = identity
    if version is not None:
        labels[VERSION_LABEL] = version
    body = {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "ValidatingPolicy",
        "metadata": {"name": name, "labels": labels},
        "spec": {
            "validationActions": ["Deny"],
            "matchConditions": (
                [{"name": "only-this-policy-version",
                  "expression": f"object.metadata.?labels['{VERSION_LABEL}'].orValue('') == '{version}'"}]
                if version else []
            ),
            "validations": [{"expression": e, "message": "m"} for e in validations],
        },
    }
    text = yaml.safe_dump(body, sort_keys=False)
    return (comment + "\n" + text) if comment else text


def selfcheck() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        # 1+4. Parse the YAML, never diff text: a comment-only change (the
        #      ticket's own headline case -- "19 of the 30 changed lines are
        #      comments") classifies as no movement. Comments are simply not
        #      part of the parsed structure.
        old_dir, new_dir = td / "comment-old", td / "comment-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "p.yaml").write_text(_policy_yaml(
            "p-1-0-0", "posture", "1.0.0", ["object.spec.x == 1"],
            comment="# old commentary, several lines\n# explaining nothing behavioural"))
        (new_dir / "p.yaml").write_text(_policy_yaml(
            "p-1-0-0", "posture", "1.0.0", ["object.spec.x == 1"],
            comment="# completely rewritten commentary\n# still nothing behavioural\n# a third line"))
        r = check_pairing(old_dir, new_dir)
        assert r.ok, r.reason
        assert r.statuses[("posture", "p")] == "none", r.statuses

        # 2. Pairing uses (identity, name-with-version-stripped) -- proven by
        #    a deliberate case a FILENAME pairing cannot solve: two members
        #    of the SAME family swap which file they live in between old and
        #    new (family "graded-enforcement" mirrors cage-tier/cage-netpol
        #    genuinely sharing one identity, per graded/policies/*.yaml).
        old_dir, new_dir = td / "swap-old", td / "swap-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "one.yaml").write_text(_policy_yaml(
            "alpha-1-0-0", "graded-enforcement", "1.0.0", ["a == 1"]))
        (old_dir / "two.yaml").write_text(_policy_yaml(
            "beta-1-0-0", "graded-enforcement", "1.0.0", ["b == 1"]))
        (new_dir / "three.yaml").write_text(_policy_yaml(  # alpha, but a DIFFERENT filename
            "alpha-2-0-0", "graded-enforcement", "2.0.0", ["a == 2"]))  # real content change
        (new_dir / "four.yaml").write_text(_policy_yaml(  # beta, also a different filename
            "beta-2-0-0", "graded-enforcement", "2.0.0", ["b == 1"]))  # unchanged
        r = check_pairing(old_dir, new_dir)
        assert r.ok, r.reason
        assert r.statuses[("graded-enforcement", "alpha")] == "moved", r.statuses
        # beta's own content never moved -- only its self-scope's version
        # literal did (1.0.0 -> 2.0.0), same as any other version bump, so
        # it normalises to "unproven", never "moved" -- and, critically,
        # never alpha's "moved" verdict: the two are never crossed.
        assert r.statuses[("graded-enforcement", "beta")] == "unproven", r.statuses

        # 3. Rules compare as a SET -- reordering matchConditions/validations
        #    changes nothing.
        old_dir, new_dir = td / "set-old", td / "set-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "p.yaml").write_text(_policy_yaml(
            "p-1-0-0", "posture", "1.0.0", ["a == 1", "b == 2", "c == 3"]))
        (new_dir / "p.yaml").write_text(_policy_yaml(
            "p-1-0-0", "posture", "1.0.0", ["c == 3", "a == 1", "b == 2"]))  # reordered only
        r = check_pairing(old_dir, new_dir)
        assert r.ok and r.statuses[("posture", "p")] == "none", (r.reason, r.statuses)

        # 5. A version-literal-only difference (self-scope condition names
        #    the version, nothing else moves) is UNPROVEN, never guessed.
        old_dir, new_dir = td / "lit-old", td / "lit-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "p.yaml").write_text(_policy_yaml(
            "p-1-0-0", "posture", "1.0.0", ["x == 1"]))
        (new_dir / "p.yaml").write_text(_policy_yaml(
            "p-2-0-0", "posture", "2.0.0", ["x == 1"]))  # only the version pin moved
        r = check_pairing(old_dir, new_dir)
        assert r.ok, r.reason
        assert r.statuses[("posture", "p")] == "unproven", r.statuses
        assert ("posture", "p") in r.unproven, r.unproven

        # 6. Movement on an UNVERSIONED member fails and names the file --
        #    only once the identity scheme is in use SOMEWHERE in the
        #    comparison (a labeled sibling, mirroring ticket 15's actual
        #    partial-migration shape).
        old_dir, new_dir = td / "unversioned-old", td / "unversioned-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "labeled.yaml").write_text(_policy_yaml(
            "labeled-1-0-0", "posture", "1.0.0", ["x == 1"]))
        (new_dir / "labeled.yaml").write_text(_policy_yaml(
            "labeled-1-0-0", "posture", "1.0.0", ["x == 1"]))  # unchanged, not the offender
        (old_dir / "rogue.yaml").write_text(_policy_yaml(
            "rogue", None, None, ["y == 1"]))  # no identity, no version
        (new_dir / "rogue.yaml").write_text(_policy_yaml(
            "rogue", None, None, ["y == 2"]))  # real content movement, still unversioned
        r = check_pairing(old_dir, new_dir)
        assert not r.ok
        assert "rogue.yaml" in r.reason, r.reason
        assert "unversioned" in r.reason, r.reason

        # ... and a wholly-unlabeled legacy comparison (identity scheme not
        # in use ANYWHERE -- the real pre-repair release line's own shape)
        # is not this rule's job at all: it passes here, exactly as ticket
        # cs-18/19/21's own historical rederivation selfcheck relies on.
        old_dir, new_dir = td / "legacy-old", td / "legacy-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "legacy.yaml").write_text(_policy_yaml("legacy", None, None, ["z == 1"]))
        (new_dir / "legacy.yaml").write_text(_policy_yaml("legacy", None, None, ["z == 2"]))
        r = check_pairing(old_dir, new_dir)
        assert r.ok, r.reason

        # 7+8. `platform-machinery` is a CLASS (recognised by the label),
        #      never a by-name exclusion. A member under an arbitrary name
        #      carrying the identity passes unversioned; a DIFFERENT member
        #      that merely LOOKS like machinery but carries no identity at
        #      all still fails -- the class is not a by-name escape.
        old_dir, new_dir = td / "machinery-old", td / "machinery-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "labeled.yaml").write_text(_policy_yaml(
            "labeled-1-0-0", "posture", "1.0.0", ["x == 1"]))
        (new_dir / "labeled.yaml").write_text(_policy_yaml(
            "labeled-1-0-0", "posture", "1.0.0", ["x == 1"]))
        (old_dir / "whatever-name.yaml").write_text(_policy_yaml(
            "whatever-name", PLATFORM_MACHINERY, None, ["'1.0.0' in allowed"]))
        (new_dir / "whatever-name.yaml").write_text(_policy_yaml(
            "whatever-name", PLATFORM_MACHINERY, None, ["'1.0.0' in allowed", "'2.0.0' in allowed"]))
        r = check_pairing(old_dir, new_dir)
        assert r.ok, r.reason  # real movement, but numbered by the platform tag -- not a fail
        assert r.statuses[(PLATFORM_MACHINERY, "whatever-name")] == "moved", r.statuses

        (old_dir / "new-machinery-object.yaml").write_text(_policy_yaml(
            "new-machinery-object", None, None, ["'1.0.0' in allowed"]))  # no identity at all
        (new_dir / "new-machinery-object.yaml").write_text(_policy_yaml(
            "new-machinery-object", None, None, ["'1.0.0' in allowed", "'2.0.0' in allowed"]))
        r2 = check_pairing(old_dir, new_dir)
        assert not r2.ok
        assert "new-machinery-object.yaml" in r2.reason, r2.reason  # no by-name escape

        # 9. Two versioned trees declaring the SAME version with different
        #    content fails -- ticket 15's own real finding (two different
        #    v1.0.0 trees).
        old_dir, new_dir = td / "conflict-old", td / "conflict-new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "p.yaml").write_text(_policy_yaml(
            "p-1-0-0", "posture", "1.0.0", ["x == 1"]))
        (new_dir / "p.yaml").write_text(_policy_yaml(
            "p-1-0-0", "posture", "1.0.0", ["x == 999"]))  # same version, real disagreement
        r = check_pairing(old_dir, new_dir)
        assert not r.ok
        assert "1.0.0" in r.reason and "disagree" in r.reason, r.reason

        # 10. render-orphan-guard.py's emitted policy carries the
        #     platform-machinery identity for real (not a hand-built fixture).
        og = corpus_generator._orphan_guard
        rendered = og.orphan_guard(["1.0.0", "2.0.0"])
        assert rendered["metadata"]["labels"][IDENTITY_LABEL] == PLATFORM_MACHINERY, rendered["metadata"]

        # 11. The real graded/policies/cage-tier.yaml, rendered through the
        #     real ticket-cs-12 renderer at two versions, one with a
        #     tightened baseline dial -- pairs cleanly (properly versioned,
        #     real content movement, no rule tripped) AND classifies MAJOR
        #     through cage_engine.py (ticket cs-21, untouched, reused
        #     directly). This is the ticket's own required before/after
        #     proof, run end to end rather than merely asserted.
        import cage_engine
        vt = corpus_generator._version_tree
        old_dir, new_dir = td / "dial-old", td / "dial-new"
        old_dir.mkdir(); new_dir.mkdir()
        tree_old = vt.render_tree("1.0.0")
        tree_new = vt.render_tree("2.0.0")
        (old_dir / "cage-tier.yaml").write_text(tree_old["cage-tier.yaml"])
        (new_dir / "cage-tier.yaml").write_text(
            tree_new["cage-tier.yaml"].replace("'cpu':'500m'", "'cpu':'250m'"))  # baseline tightened
        assert "'cpu':'250m'" in (new_dir / "cage-tier.yaml").read_text()  # the edit actually landed

        r = check_pairing(old_dir, new_dir)
        assert r.ok, r.reason  # a real, properly-versioned pair -- nothing structural to refuse
        assert r.statuses[("graded-enforcement", "cage-tier")] == "moved", r.statuses

        pods_dir = td / "dial-pods"
        pods_dir.mkdir()
        (pods_dir / "claimant.yaml").write_text(yaml.safe_dump({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "claimant", "labels": {VERSION_LABEL: "2.0.0"}},
            "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]},
        }))
        result = cage_engine.classify_repo(old_dir, new_dir, [pods_dir / "claimant.yaml"])
        assert result.computed_bump == "major", result.computed_bump
        cage_movement = next(m for m in result.movement if m.policy == "cage-tier.yaml")
        assert cage_movement.verdict == "major", cage_movement
        assert "claimant" in cage_movement.entries, cage_movement.entries

    print(
        "selfcheck ok: parses YAML, never a text diff -- a comment-only change "
        "is no movement; pairing uses (identity, name-with-version-stripped), "
        "proven by two family members swapping filenames between old and new; "
        "rules compare as a set, order dropped; a version-literal-only "
        "difference is unproven, not guessed; movement on an unversioned "
        "member fails and names the file, once the identity scheme is in use "
        "anywhere in the comparison -- a wholly-unlabeled legacy comparison "
        "(gate.py's own historical rederivation) is untouched; "
        "platform-machinery is a class recognised by its label under an "
        "arbitrary name, never a by-name exclusion, and a different unlabeled "
        "machinery-shaped object still fails; two trees declaring the same "
        "version with different content fails; render-orphan-guard.py's "
        "emitted policy carries the platform-machinery identity for real; "
        "the real graded cage-tier.yaml, rendered at two versions with a "
        "tightened baseline dial, pairs cleanly and classifies major through "
        "cage_engine.py end to end"
    )


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
