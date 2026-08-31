#!/usr/bin/env python3
"""release_integrity.py -- ticket cs-26: the four extra gate rules.

Four independent, structural refusals that close four ways a release could
fool the gate about what it is actually shipping (spec.md, "The four extra
gate rules"). None of them is a bump class -- the number stays honest, or
the release is refused.

  1. `frozen_tree_refusal`      -- a PRIOR version's HEAD copy must equal
     what its git TAG actually contains. Reads the tag with
     `git show <tag>:<path>`, never trusts a HEAD copy on its own -- a hand
     edit to an already-released tree would otherwise fool the gate about
     what that version means (comparison_window.py's own docstring names
     this as exactly this ticket's job, out of its scope).
  2. `rerender_refusal`         -- the tree BEING CUT must equal what ticket
     12's renderer (render-version-tree.py) would produce right now.
     Regenerates, diffs, refuses on any difference -- for the version being
     cut ONLY. Re-rendering every tree on every run would freeze the dial
     table for ever (render-version-tree.py's own docstring); a renderer
     defect therefore surfaces here as a refusal, never as a second seam.
  3. `mandatory_members_refusal` -- a literal SET comparison: every member
     name ticket 12's renderer would emit for a version (never a second,
     hand-maintained list) must be present in that version's tree. Fires
     even when rule 2 would not catch it standalone (e.g. run against this
     module directly, or a caller that only wants the cheap existence
     check) -- one of the eight mandatory members quietly deleted, but
     everything else byte-identical, is exactly the case a pure diff
     buries in the noise of "there IS a difference" without naming which
     enforcement surface vanished.
  4. `empty_commit_refusal`     -- every element of the version array
     (distribution/versions.yaml's `spec.inputs[0].versions`) must carry a
     non-empty `commit`. Both real elements carry `commit: ""` today
     (ticket 15 fills them); without this rule the field silently empties
     again on the next hand-edited element.

Every function returns a refusal-reason string naming exactly what it
refused and why, or `None` when that rule is satisfied. `refusal()` runs all
four in order and returns the first hit. `gate.py` wires this in through
`RepoState.release` (optional, defaults to None -- no regression for any
RepoState that doesn't set it).

Usage:
    release_integrity.py --selfcheck
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

import corpus_generator  # reuses corpus_generator._version_tree -- render_tree
                          # is ticket 12's, never re-implemented here.

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


@dataclass
class ReleaseIntegrity:
    """The four rules' inputs, bundled -- optional on `RepoState` (defaults
    to None there), so every RepoState built by tickets 18-24 keeps working
    with no regression; only a caller that wires this runs these four
    checks.

    `git_repo`       -- the real git repository whose tags anchor already-
                         released versions.
    `policies_dir`   -- e.g. distribution/policies: one v<version>/
                         subdirectory per released (or being-cut) version.
    `prior_versions` -- {version: tag} for every version already released
                         BEFORE the one being cut. The version being cut
                         itself has no tag yet -- the gate runs before
                         `git tag` (spec.md's own release diagram) -- so it
                         is checked by rules 2/3 (regenerate/diff, mandatory
                         members), never by rule 1.
    `version_array`  -- distribution/versions.yaml's raw
                         `spec.inputs[0].versions` elements, `commit` field
                         and all (render-orphan-guard.py's `elements()`,
                         reused -- never re-parsed here).
    """
    git_repo: Path
    policies_dir: Path
    prior_versions: dict[str, str]
    version_array: list[dict]


def frozen_tree_refusal(git_repo: Path, version: str, tag: str, tree_dir: Path) -> str | None:
    """Rule 1. Every file under `tree_dir` (a prior version's real on-disk
    tree) must be byte-identical to what `git show <tag>:<path>` returns for
    the same relative path -- reads the tag, never trusts the HEAD copy on
    its own. Refuses naming the tag and every file that differs, is missing
    from HEAD, or is missing from the tag."""
    if not tree_dir.exists():
        return (
            f"frozen-tree check refused: released version {version}'s tree "
            f"{tree_dir} does not exist at HEAD, but tag {tag!r} exists to "
            f"compare it against"
        )
    rel_root = tree_dir.relative_to(git_repo)
    head_files = {
        p.relative_to(tree_dir).as_posix(): p.read_bytes()
        for p in sorted(tree_dir.rglob("*")) if p.is_file()
    }

    listing = subprocess.run(
        ["git", "-C", str(git_repo), "ls-tree", "-r", "--name-only", tag, "--", str(rel_root)],
        capture_output=True, text=True,
    )
    if listing.returncode != 0 or not listing.stdout.strip():
        return (
            f"frozen-tree check refused: could not read tag {tag!r} for released "
            f"version {version} ({listing.stderr.strip() or 'tag or path not found'}) "
            f"-- prior versions are read from their tag, never from a HEAD copy"
        )

    tag_files: dict[str, bytes] = {}
    for line in listing.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        rel = Path(line).relative_to(rel_root).as_posix()
        show = subprocess.run(
            ["git", "-C", str(git_repo), "show", f"{tag}:{line}"],
            capture_output=True,
        )
        if show.returncode != 0:
            return (
                f"frozen-tree check refused: tag {tag!r} claims {line!r} but "
                f"`git show` could not read it for released version {version}"
            )
        tag_files[rel] = show.stdout

    mismatched = sorted(
        rel for rel in (set(head_files) | set(tag_files))
        if head_files.get(rel) != tag_files.get(rel)
    )
    if mismatched:
        return (
            f"frozen-tree check refused: HEAD copy of released version {version} "
            f"differs from what tag {tag!r} actually contains, in {mismatched} -- "
            f"prior versions are read from their tag, never from a HEAD copy"
        )
    return None


def rerender_refusal(declared: str, tree_dir: Path) -> str | None:
    """Rule 2. Regenerates ticket 12's `render_tree(declared)` and diffs it
    against what is actually on disk at `tree_dir`, for the same filenames
    only -- refuses on any difference. Renders and checks ONLY `declared`;
    an already-released tree is never re-rendered here (rule 1's job)."""
    expected = corpus_generator._version_tree.render_tree(declared)
    mismatched = []
    for fname, text in expected.items():
        actual_path = tree_dir / fname
        if not actual_path.exists():
            mismatched.append(f"{fname} (missing)")
        elif actual_path.read_text() != text:
            mismatched.append(fname)
    if mismatched:
        return (
            f"re-render check refused: the tree being cut for {declared} does not "
            f"match ticket 12's renderer output, in {mismatched} -- the tree being "
            f"cut is regenerated and diffed, never hand-edited"
        )
    return None


def mandatory_members_refusal(declared: str, tree_dir: Path) -> str | None:
    """Rule 3. A literal set comparison: every member name
    `render_tree(declared)` would emit (ticket 12's eight mandatory members
    -- never a second, hand-maintained list) must be present, by
    `metadata.name`, somewhere in `tree_dir`. Independent of rule 2's byte
    diff: this fires even when a document is missing but every OTHER byte on
    disk is untouched."""
    expected_names: set[str] = set()
    for text in corpus_generator._version_tree.render_tree(declared).values():
        for doc in yaml.safe_load_all(text):
            if doc:
                expected_names.add(doc["metadata"]["name"])

    actual_names: set[str] = set()
    if tree_dir.exists():
        for f in tree_dir.glob("*.yaml"):
            for doc in yaml.safe_load_all(f.read_text()):
                if doc and isinstance(doc, dict) and "metadata" in doc:
                    name = doc["metadata"].get("name")
                    if name:
                        actual_names.add(name)

    missing = sorted(expected_names - actual_names)
    if missing:
        return (
            f"enforcement-surface check refused: version {declared} is missing "
            f"mandatory member(s) {missing} -- a release cannot drop any of "
            f"ticket 12's eight mandatory members from a version"
        )
    return None


def empty_commit_refusal(version_array: list[dict]) -> str | None:
    """Rule 4. Every element of the version array must carry a non-empty
    `commit`. Names every offending version."""
    empty = [e.get("version", "?") for e in version_array if not e.get("commit")]
    if empty:
        return (
            f"empty-commit check refused: version array element(s) {empty} carry "
            f"an empty `commit` field"
        )
    return None


def _declared_tag(release: ReleaseIntegrity, declared: str) -> str | None:
    """The tag this repo has ALREADY cut for `declared`, or None if it has
    not been cut yet. Read from the version array's own `tag` field (never a
    second naming convention), then confirmed against real git tags."""
    tag = next((e.get("tag") for e in release.version_array
                if e.get("version") == declared and e.get("tag")), None)
    if not tag:
        return None
    r = subprocess.run(["git", "-C", str(release.git_repo), "tag", "-l", tag],
                       capture_output=True, text=True)
    return tag if r.returncode == 0 and r.stdout.strip() else None


def refusal(release: ReleaseIntegrity, declared: str) -> str | None:
    """Runs all four rules, in order, against `declared`. Returns the first
    refusal reason, or None when all four pass. The order carries no
    priority claim -- a sufficiently broken release could trip more than
    one; the caller (gate.py) sees the first."""
    for version, tag in sorted(release.prior_versions.items()):
        r = frozen_tree_refusal(release.git_repo, version, tag, release.policies_dir / f"v{version}")
        if r is not None:
            return r

    declared_tree = release.policies_dir / f"v{declared}"
    already_cut = _declared_tag(release, declared)
    if already_cut:
        # `declared` has ALREADY been tagged, so its tree is FROZEN and rules 2
        # and 3 -- which regenerate the tree being cut from TODAY's authoring
        # copies -- are the wrong question for it (rule 2's own docstring: "an
        # already-released tree is never re-rendered here (rule 1's job)"). The
        # authoring copies move forward on every real policy change (a changed
        # body is a NEW version, never an edit to a released one -- ticket 26
        # moved them for the first time), so re-rendering a released version
        # against them refuses a release that already happened. Rule 1 is the
        # question for a frozen tree, and `declared` is never in
        # `prior_versions` (that map is the versions BEFORE the one being cut),
        # so it is asked here.
        r = frozen_tree_refusal(release.git_repo, declared, already_cut, declared_tree)
        if r is not None:
            return r
    else:
        r = rerender_refusal(declared, declared_tree)
        if r is not None:
            return r
        r = mandatory_members_refusal(declared, declared_tree)
        if r is not None:
            return r

    return empty_commit_refusal(release.version_array)


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                    env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                         "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                         "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})


def selfcheck() -> None:
    # ---- rule 1: frozen-tree, a REAL git repo, a REAL tag, a REAL hand edit ----
    repo = Path(tempfile.mkdtemp())
    _git(repo, "init", "-q")
    tree = repo / "distribution" / "policies" / "v1.0.0"
    tree.mkdir(parents=True)
    (tree / "cage-tier.yaml").write_text("kind: ValidatingPolicy\nmetadata: {name: cage-tier-1-0-0}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "release 1.0.0")
    _git(repo, "tag", "policy/v1.0.0")

    # before: HEAD == tag -> no refusal
    before = frozen_tree_refusal(repo, "1.0.0", "policy/v1.0.0", tree)
    assert before is None, before

    # after: a hand edit at HEAD, tag untouched -> refuses, names the tag and the file
    (tree / "cage-tier.yaml").write_text("kind: ValidatingPolicy\nmetadata: {name: HAND-EDITED}\n")
    after = frozen_tree_refusal(repo, "1.0.0", "policy/v1.0.0", tree)
    assert after is not None, "hand-edited HEAD copy did not refuse"
    assert "1.0.0" in after and "policy/v1.0.0" in after and "cage-tier.yaml" in after, after

    # a tag that doesn't exist at all also refuses, rather than silently
    # falling back to trusting HEAD
    missing_tag = frozen_tree_refusal(repo, "9.9.9", "policy/v9.9.9-nonexistent", tree)
    assert missing_tag is not None and "9.9.9-nonexistent" in missing_tag, missing_tag

    # ---- rule 2: re-render only the tree being cut ----
    with tempfile.TemporaryDirectory() as td:
        good = Path(td) / "v9.9.9"
        for fname, text in corpus_generator._version_tree.render_tree("9.9.9").items():
            good.mkdir(parents=True, exist_ok=True)
            (good / fname).write_text(text)
        assert rerender_refusal("9.9.9", good) is None

        # hand-edit ONE mandatory member -> refuses and names it
        (good / "cage-netpol.yaml").write_text("hand-edited, not the renderer's output\n")
        broken = rerender_refusal("9.9.9", good)
        assert broken is not None and "cage-netpol.yaml" in broken, broken

        # a whole missing file also refuses
        missing = Path(td) / "v9.9.8"
        missing.mkdir()
        (missing / "cage-tier.yaml").write_text(
            corpus_generator._version_tree.render_tree("9.9.8")["cage-tier.yaml"])
        r = rerender_refusal("9.9.8", missing)
        assert r is not None and "missing" in r, r

    # ---- rule 3: mandatory-member removal, a literal set comparison ----
    with tempfile.TemporaryDirectory() as td:
        full = Path(td) / "v8.8.8"
        full.mkdir()
        for fname, text in corpus_generator._version_tree.render_tree("8.8.8").items():
            (full / fname).write_text(text)
        assert mandatory_members_refusal("8.8.8", full) is None

        # delete one of the PriorityClass documents FROM WITHIN the file (not
        # the whole file) -- proves this is a document-level set comparison,
        # not just "does the file exist". Four of them since ticket 26 added
        # the `isolated` rung's cage-isolated class.
        docs = [d for d in yaml.safe_load_all((full / "priorityclasses.yaml").read_text()) if d]
        assert len(docs) == 4, [d["metadata"]["name"] for d in docs]
        (full / "priorityclasses.yaml").write_text(yaml.safe_dump_all(docs[:-1], sort_keys=False))
        removed_name = docs[-1]["metadata"]["name"]
        r = mandatory_members_refusal("8.8.8", full)
        assert r is not None and removed_name in r, (r, removed_name)

        # a version whose tree doesn't exist at all is trivially missing
        # every member, not a crash
        r2 = mandatory_members_refusal("7.7.7", Path(td) / "does-not-exist")
        assert r2 is not None and "cage-tier" in r2, r2

    # ---- rule 4: empty commit ----
    filled = [
        {"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "abc123"},
        {"version": "2.0.0", "tag": "policy/v2.0.0", "commit": "def456"},
    ]
    assert empty_commit_refusal(filled) is None

    emptied = [
        {"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "abc123"},
        {"version": "2.0.0", "tag": "policy/v2.0.0", "commit": ""},
    ]
    r = empty_commit_refusal(emptied)
    assert r is not None and "2.0.0" in r and "1.0.0" not in r, r

    # ---- refusal(): all four wired together, order proven ----
    good_repo = Path(tempfile.mkdtemp())
    _git(good_repo, "init", "-q")
    good_policies = good_repo / "distribution" / "policies"
    v1 = good_policies / "v1.0.0"
    v1.mkdir(parents=True)
    for fname, text in corpus_generator._version_tree.render_tree("1.0.0").items():
        (v1 / fname).write_text(text)
    _git(good_repo, "add", "-A")
    _git(good_repo, "commit", "-q", "-m", "release 1.0.0")
    _git(good_repo, "tag", "policy/v1.0.0")

    v2 = good_policies / "v2.0.0"
    v2.mkdir(parents=True)
    for fname, text in corpus_generator._version_tree.render_tree("2.0.0").items():
        (v2 / fname).write_text(text)

    clean = ReleaseIntegrity(
        git_repo=good_repo, policies_dir=good_policies,
        prior_versions={"1.0.0": "policy/v1.0.0"},
        version_array=[{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "abc"}],
    )
    assert refusal(clean, "2.0.0") is None, refusal(clean, "2.0.0")

    # break each rule in turn against a fresh copy of the same clean setup,
    # proving each is independently reachable through refusal()

    # rule 1 via refusal(): hand-edit the ALREADY-RELEASED 1.0.0 tree
    (v1 / "cage-netpol.yaml").write_text("hand-edited\n")
    r = refusal(clean, "2.0.0")
    assert r is not None and "1.0.0" in r and "policy/v1.0.0" in r, r
    for fname, text in corpus_generator._version_tree.render_tree("1.0.0").items():
        (v1 / fname).write_text(text)  # restore
    assert refusal(clean, "2.0.0") is None

    # rule 2 via refusal(): hand-edit the tree BEING CUT (2.0.0)
    (v2 / "stamp-posture.yaml").write_text("hand-edited\n")
    r = refusal(clean, "2.0.0")
    assert r is not None and "stamp-posture.yaml" in r, r
    for fname, text in corpus_generator._version_tree.render_tree("2.0.0").items():
        (v2 / fname).write_text(text)  # restore
    assert refusal(clean, "2.0.0") is None

    # rule 3 via refusal(): drop a mandatory member from the tree being cut
    (v2 / "cage-tier.yaml").unlink()
    r = refusal(clean, "2.0.0")
    assert r is not None and "cage-tier" in r.lower(), r
    (v2 / "cage-tier.yaml").write_text(corpus_generator._version_tree.render_tree("2.0.0")["cage-tier.yaml"])
    assert refusal(clean, "2.0.0") is None

    # rule 4 via refusal(): empty the (already-released) array element's commit
    dirty_array = ReleaseIntegrity(
        git_repo=clean.git_repo, policies_dir=clean.policies_dir,
        prior_versions=clean.prior_versions,
        version_array=[{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": ""}],
    )
    r = refusal(dirty_array, "2.0.0")
    assert r is not None and "1.0.0" in r and "commit" in r, r

    print(
        "selfcheck ok: rule 1 refuses a hand-edited HEAD copy of a released "
        "tree against its real tag, and refuses a missing tag rather than "
        "trusting HEAD; rule 2 refuses the tree being cut differing from "
        "ticket 12's renderer output, naming the file, missing files included; "
        "rule 3 refuses a mandatory member deleted from inside an otherwise "
        "untouched file, naming it, via a literal set comparison against "
        "render_tree's own output; rule 4 refuses an empty `commit` field and "
        "names only the offending version; refusal() wires all four together "
        "and each is independently reachable through it"
    )


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
