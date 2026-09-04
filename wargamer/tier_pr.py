#!/usr/bin/env python3
"""tier_pr.py -- the proposer's last step (ticket 17; ADR-0015, ADR-0022).
Turns a bounded cage-tier proposal (wargamer.py + proposer_bounds.py) into a
REAL, opened artefact: a pull request editing `posture.acme.io/tier` on the
adopter's GOVERNED NAMESPACE MANIFEST -- the manifest carrying
`policy-as-versioned.dev/governed: "true"`, found by reading the adopter's
own repo, never by a path this module knows.

ADR-0022 moved the declaration: the tier is declared on the governed
Namespace and `cage-tier` renders it onto every pod through
`namespaceObject`. The pod label is an OUTPUT, clobbered at every
admission. A proposal against `deploy/pod.yaml` therefore changed NOTHING
once merged, which is what this module used to open (fixed 2026-08-28).

**There is no issue branch any more.** ADR-0015's "a proposed `deny` opens
an issue instead of a label PR" is dead: under ADR-0022 the bottom rung is
`isolated` -- a real, running, unreachable cage -- so there is no tier that
cannot travel as a declaration, nothing is ever denied, and EVERY proposal
this module lands is a pull request a human merges.

Unlike propose-policy-pr.sh and driftwood/scripts/bump-nist-pin.sh -- which
render the diff and stop, propose-never-dispose, on purpose -- this script
is the one place in the estate that actually commits, pushes and opens.
"The last step lands" (spec.md). The safety property does not change: this
module still exposes no merge()/approve()/dispose(), the same structural
guarantee wargamer.py and proposer_bounds.py already assert, and every
proposal it lands still rides the ordinary PR-gate + human-review rails
every other artefact in this estate rides. Nothing here decides WHETHER to
propose -- that is proposer_bounds.py's job, upstream of this module.

Runs in the ADOPTER's own repo, on the adopter's own GH_TOKEN, through its
pinned `platform` dependency -- the same shape shift-left.yml already uses
for the version cross-check gate (ADR-0015: "same-repo credential").

Dedupe: `wargamer.propose()`'s own branch name IS the key. A second run
resets that branch to the current base and force-pushes a single fresh
commit reflecting the current £ (never accumulates history), then updates
the already-open PR in place rather than opening a second one. A rejection
is that PR closed unmerged: the ledger is DERIVED from it (ADR-0024), and
the HTML-comment marker in the PR body carries the curve hash and the
selection-policy version the proposal was priced under.

Usage:
    tier_pr.py run --adopter-dir <path> --evidence <evidence.json> \\
        --org <party> [--base main] \\
        [--rejections <derived-ledger.json>] [--dry-run]
    tier_pr.py selfcheck
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "honesty"))
import wargamer          # noqa: E402  propose() shapes what gets landed
import proposer_bounds   # noqa: E402  decides WHETHER to land it
import rejection_ledger  # noqa: E402  derives the ledger those bounds read

# ADR-0022: the tier is declared on the governed Namespace, next to the
# governed label, on the same signed object. `cage-tier` reads it through
# `namespaceObject`; the pod label is that render's output.
GOVERNED_LABEL = "policy-as-versioned.dev/governed"
TIER_LABEL = "posture.acme.io/tier"

_KIND_NAMESPACE = re.compile(r"""^kind:\s*["']?Namespace["']?\s*$""")
_GOVERNED_TRUE = re.compile(
    r"""^(\s*)policy-as-versioned\.dev/governed:\s*["']?true["']?\s*$""")
_TIER_LINE = re.compile(r"""^(\s*)posture\.acme\.io/tier:\s*\S.*$""")
_TIER_VALUE = re.compile(r"""^\s*posture\.acme\.io/tier:\s*["']?([^"'\s#]+)""")
_OVERLAY_FLOOR = re.compile(r"""^\s+floor:\s*["']?([^"'\s#]+)""")


# --------------------------------------------------------------------------
# finding the declaration -- by the governed label, never by a path
# --------------------------------------------------------------------------
def governed_namespace_span(text: str) -> tuple[int, int] | None:
    """The (start, end) line span of the YAML document in `text` that is a
    Namespace AND carries `governed: "true"`, or None. Document-scoped so a
    multi-document file (tuppence/reset/workloads.yaml declares an
    ungoverned Namespace beside its workloads) is read a document at a
    time, not as one blob."""
    lines = text.splitlines(keepends=True)
    starts, ends, cur = [], [], 0
    for i, line in enumerate(lines):
        if line.rstrip() == "---":
            starts.append(cur)
            ends.append(i)
            cur = i + 1
    starts.append(cur)
    ends.append(len(lines))
    for start, end in zip(starts, ends):
        doc = lines[start:end]
        if any(_KIND_NAMESPACE.match(x) for x in doc) and \
                any(_GOVERNED_TRUE.match(x) for x in doc):
            return start, end
    return None


def _candidate_manifests(adopter_dir: Path) -> list[Path]:
    """The manifests a declaration could live in: the COMMITTED ones where the
    adopter directory is a git clone -- an ignored scratch tree (`.work/`) is
    not a signed declaration and a PR could not carry it -- and everything on
    disk where it is not, which is the `--dry-run`-against-a-throwaway-copy
    case verify/e2e/step3 runs."""
    listed = _git("ls-files", "-z", "--", "*.yaml", "*.yml",
                  cwd=adopter_dir, check=False, capture=True)
    if listed.returncode == 0:
        return [adopter_dir / rel for rel in listed.stdout.split("\0") if rel]
    return [p for p in sorted(adopter_dir.rglob("*.y*ml"))
            if not {".git", "__pycache__"} & set(p.parts)]


def find_governed_namespaces(adopter_dir: Path) -> list[Path]:
    """Every manifest in the adopter's own repo that declares a governed
    Namespace. The proposer knows no path: `gitops/apps/namespace.yaml` is
    where all three adopters happen to keep it today, and an adopter that
    moves it is still proposed against.

    ponytail: a line-level read, not a YAML parse -- a GitHub runner is not
    promised pyyaml (the same reason rejection-decay.yaml is read by hand).
    Upgrade to yaml.safe_load_all if a declaration ever needs anchors."""
    hits = []
    for path in _candidate_manifests(adopter_dir):
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        if governed_namespace_span(text):
            hits.append(path)
    return hits


def declared_tier(text: str) -> str | None:
    """The `posture.acme.io/tier` the governed Namespace document in `text`
    declares today, or None where it declares none (which ADR-0022 renders as
    `isolated`). Read from the Namespace, never from a price line's `old_tier`:
    the line records what a regime priced last time, the Namespace records what
    the party signed (ticket 78)."""
    span = governed_namespace_span(text)
    if span is None:
        return None
    lines = text.splitlines()
    for i in range(*span):
        found = _TIER_VALUE.match(lines[i])
        if found:
            return found.group(1)
    return None


def read_overlay_floor(party_yaml: Path) -> str | None:
    """`overlay.floor` from the party artefact, or None. The one tighten-only
    floor an adopter may declare (ADR-0022); selection clamps up to it.

    ponytail: a line-level read of the top-level `overlay:` block, for the same
    reason the rest of this module reads YAML by hand (a runner is not promised
    pyyaml). A floor nested any deeper than `overlay:` -> `  floor:` is not a
    shape party_artefact.py's schema admits."""
    if not party_yaml.exists():
        return None
    in_overlay = False
    for line in party_yaml.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if not line[0].isspace():
            in_overlay = line.split(":", 1)[0].strip() == "overlay"
            continue
        if in_overlay:
            found = _OVERLAY_FLOOR.match(line)
            if found:
                return found.group(1)
    return None


# --------------------------------------------------------------------------
# propose-never-dispose, read off the argv this module BUILDS
# --------------------------------------------------------------------------
# An attribute name is not what disposes of a pull request; a `gh` verb is. The
# selfcheck used to assert only that no `merge`/`approve`/`dispose` attribute
# existed on this module, and a single
# `_gh("pr", "merge", "--squash", "--admin", branch, repo=repo)` appended to
# `_open_or_update_pr` passed every one of those assertions and printed "The
# war-gamer proposes; a human disposes." underneath it (found 2026-08-29).
# propose-tier.yml already grants the `contents: write` + `pull-requests: write`
# that call needs, so nothing else would have stopped it either.
#
# ponytail: string constants in positional arguments and in a list/tuple
# literal, plus the one REST shape (`.../merge`) that carries the verb in a URL
# rather than in an argument. A verb assembled at run time --
# `_gh("pr", verb)` -- is not matched, and a credential that cannot merge is the
# upgrade path (a GitHub App token with `pull_requests: write` and no
# `contents: write` makes the refusal the server's). What is bought here is that
# the ordinary way to write the call -- literally, the way the plant below
# writes it -- is refused at selfcheck rather than at review.
DISPOSING_ARGS = frozenset({
    "merge", "--merge", "--squash", "--rebase", "--admin", "--auto",
    "approve", "--approve", "close", "--delete-branch",
})
# Matched against string CONSTANTS in the tree, never against the raw text: a
# comment saying the words is not a call making them, and a text-level scan
# flagged this file's own explanation of itself.
_MERGE_ENDPOINT = re.compile(r"/merges?/?$")


def disposing_calls(source: str) -> list[str]:
    """Every call in `source` that would dispose of a pull request rather than
    propose one, as `line N: [argv]` strings. Empty is the property."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and _MERGE_ENDPOINT.search(node.value):
            found.append(f"line {node.lineno} names a /merge REST endpoint: {node.value!r}")
        if not isinstance(node, ast.Call):
            continue
        argv = [a.value for a in node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        argv += [e.value for a in node.args if isinstance(a, (ast.List, ast.Tuple))
                 for e in a.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if not argv:
            continue
        # The verb is usually its own argument (`"pr", "merge"`), and in the REST shape it is the
        # last segment of a path (`"repos/o/r/pulls/1/merge"`), which is the same disposal wearing
        # a URL.
        verbs = set(argv) | {a.rsplit("/", 1)[-1] for a in argv if "/" in a}
        if (DISPOSING_ARGS & verbs) and ({"pr", "api", "review"} & set(argv)):
            found.append(f"line {node.lineno} builds a disposing gh command: {argv}")
    return found


# The plant. Kept beside the scanner rather than in a fixture file, so that
# "the guard bites" is asserted by the same commit that could weaken it, and so
# that a reader can see exactly what shape is being refused.
PLANTED_DISPOSAL = '''
def _open_or_update_pr(p, base, repo):
    number = _gh("pr", "create", "--head", p["branch"], "--base", base, repo=repo)
    _gh("pr", "merge", "--squash", "--admin", p["branch"], repo=repo)
    _gh("api", "--method", "PUT", "repos/o/r/pulls/1/merge")
    return number
'''


# --------------------------------------------------------------------------
# the text edit -- a line edit, not a YAML re-dump (render-faithfulness
# ethos, applied to the Namespace declaration instead of a composed policy)
# --------------------------------------------------------------------------
def apply_tier_declaration(text: str, tier: str) -> tuple[str, bool]:
    """Set `posture.acme.io/tier` inside the governed Namespace document of
    `text` -- updated where it is already declared, inserted right after the
    governed label where it is not. Every other byte of the file, comments
    included, is untouched.

    ponytail: a line edit inside the governed document's span, so the
    Namespace's own commentary survives a re-tune. A trailing `# comment` on
    the tier line itself does not. Upgrade to a round-tripping YAML editor
    (ruamel) only if an adopter ever needs one."""
    span = governed_namespace_span(text)
    if span is None:
        return text, False
    start, end = span
    lines = text.splitlines(keepends=True)
    for i in range(start, end):
        found = _TIER_LINE.match(lines[i])
        if found:
            lines[i] = f'{found.group(1)}{TIER_LABEL}: "{tier}"\n'
            return "".join(lines), True
    for i in range(start, end):
        found = _GOVERNED_TRUE.match(lines[i])
        if found:
            lines.insert(i + 1, f'{found.group(1)}{TIER_LABEL}: "{tier}"\n')
            return "".join(lines), True
    return text, False


# --------------------------------------------------------------------------
# git / gh -- thin subprocess wrappers, so a test can stub `gh` via PATH
# --------------------------------------------------------------------------
def _run(cmd: list[str], cwd: Path | None = None, check: bool = True, capture: bool = False):
    return subprocess.run(cmd, cwd=cwd, check=check,
                           capture_output=capture, text=True)


def _git(*args: str, cwd: Path, check: bool = True, capture: bool = False):
    return _run(["git", *args], cwd=cwd, check=check, capture=capture)


def _gh(*args: str, repo: str | None = None, capture: bool = True):
    # `--repo` explicit, never cwd-detected -- the same convention
    # shift-left.yml already uses for every `gh` call (`--repo
    # "${{ github.repository }}"`), so this runs identically whether or not
    # the working directory `gh` would otherwise infer from is a git repo.
    extra = ["--repo", repo] if repo else []
    return _run(["gh", *args, *extra], capture=capture)


def _existing_pr_number(branch: str, repo: str | None) -> str:
    out = _gh("pr", "list", "--head", branch, "--state", "open",
              "--json", "number", "-q", ".[0].number", repo=repo).stdout.strip()
    return out


def _open_or_update_pr(p: dict, base: str, repo: str | None) -> dict:
    body = _pr_body(p)
    number = _existing_pr_number(p["branch"], repo)
    if number:
        _gh("pr", "edit", number, "--title", p["title"], "--body", body, repo=repo)
        return {"action": "updated", "number": number}
    out = _gh("pr", "create", "--head", p["branch"], "--base", base,
              "--title", p["title"], "--body", body, repo=repo)
    return {"action": "created", "url": out.stdout.strip()}


def _money(price: dict, field: str) -> str:
    value = price.get(field)
    if not isinstance(value, (int, float)):
        return "unpriced"
    return f"{value:,.2f} {price.get('currency') or '???'}"


def _party_paragraph(p: dict) -> str:
    """The party-level selection, spelled out for the reviewer (ticket 78):
    which lines priced what, which was strictest, whether the floor clamped,
    what the Namespace declared, and that this proposer only tightens."""
    sel = p.get("party_selection")
    if not sel:
        return ""
    lines = ", ".join(f"{k} -> `{v}`" for k, v in sorted(sel["lines"].items())) or "none"
    floor = f"`{sel['floor']}`" if sel.get("floor") else "none declared"
    clamped = " (the floor clamped the write up)" if sel.get("clamped_to_floor") else ""
    current = f"`{sel['current']}`" if sel.get("current") else \
        f"nothing (`{wargamer.FAIL_CLOSED}` by default, ADR-0022)"
    return (
        f"**Party selection (tighten-only, ADR-0022):** one Namespace carries one tier for "
        f"every pod in it, so the declaration is the **strictest** `proposed_tier` across "
        f"this party's priced lines -- {lines} -- clamped to the declared floor ({floor}){clamped}. "
        f"The Namespace declared {current}. This proposal writes `{sel['tier']}`, which is "
        f"tighter. The proposer never writes a looser tier: a loosening would need the "
        f"party's aggregate residual and a body that argues it, and this proposer does not "
        f"yet ask that question (ticket 78).\n\n"
    )


def _pr_body(p: dict) -> str:
    c = p["change"]
    price = p.get("price") or {}
    line_move = ""
    if c.get("line_from") is not None and (c["line_from"], c["line_to"]) != (c["from"], c["to"]):
        line_move = (f" The line itself moved `{c['line_from']}` -> `{c['line_to']}`; the "
                     f"declaration moves to the party's tier (below).")
    return (
        f"{p.get('ledger_marker', '')}\n\n"
        f"Proposed by the war-gamer's cage-tier drift (ADR-0015, ADR-0022). "
        f"**What moved:** `{c['label']}` on `{p.get('manifest', 'the governed Namespace')}` "
        f"-- the governed Namespace declaration, not a pod label -- "
        f"`{c['from']}` -> `{c['to']}`. `cage-tier` renders that onto every pod in the "
        f"namespace through `namespaceObject`, so the pod label follows this merge and "
        f"cannot be set anywhere else.{line_move}\n\n"
        f"**The price that moved it:** {price.get('source', '?')}/{price.get('kind', '?')} "
        f"{_money(price, 'from')} -> {_money(price, 'to')} "
        f"under the `{price.get('perspective', p.get('org', '?'))}` perspective.\n\n"
        f"{_party_paragraph(p)}"
        f"**Priced under:** selection policy `{p.get('policy_version') or 'none published'}`, "
        f"curve `{p.get('curve_hash') or 'none published'}`.\n\n"
        f"Evidence: {json.dumps(p['from_evidence'], sort_keys=True)}\n\n"
        f"{p.get('as_of_note', '')}\n\n"
        f"Closing this PR without merging is the rejection: the ledger is DERIVED "
        f"from closed-unmerged PRs on this branch, so no file records your no "
        f"(ADR-0024). The marker at the top carries the curve hash and the "
        f"selection-policy version this proposal was priced under -- a later "
        f"proposal priced under a different one is a NEW question and will be "
        f"raised again.\n\n"
        f"Never merged by this proposer -- opened for human review only."
    ).strip()


# --------------------------------------------------------------------------
# landing one proposal
# --------------------------------------------------------------------------
def _land(p: dict, adopter_dir: Path, ns_path: Path, base: str, dry_run: bool,
          repo: str | None) -> dict:
    result = {"branch": p["branch"], "proposal_kind": p["proposal_kind"],
              "manifest": str(ns_path.relative_to(adopter_dir))}
    p["manifest"] = result["manifest"]

    text = ns_path.read_text()
    new_text, changed = apply_tier_declaration(text, p["change"]["to"])
    if not changed:
        result["error"] = (f"{ns_path} no longer declares a governed Namespace "
                            f"-- nothing to land")
        return result
    if dry_run:
        result["landed"] = "dry-run"
        result["diff"] = new_text
        return result

    _git("fetch", "origin", base, cwd=adopter_dir)
    # Reset the branch to the current base every run: a single fresh commit
    # reflecting THIS run's £, never a growing history -- the reviewer sees
    # the current price, not an accumulating diff (spec.md: "a second run
    # force-pushes the same branch, so the reviewer sees the current £").
    _git("checkout", "-q", "-B", p["branch"], f"origin/{base}", cwd=adopter_dir)
    # Re-read AFTER the checkout: the edit must land on what `base` declares
    # today, not on whatever the working tree happened to be on.
    on_base = ns_path.read_text()
    new_text, changed = apply_tier_declaration(on_base, p["change"]["to"])
    if not changed:
        _git("checkout", "-q", base, cwd=adopter_dir)
        result["error"] = (f"{ns_path} declares no governed Namespace on origin/{base} "
                            f"-- nothing to land")
        return result
    # ...and tighten-only is re-judged against what origin/base declares NOW,
    # not what the working tree declared when run() folded the party: a
    # declaration that moved under this run must not be loosened by it.
    if not _tightens(declared_tier(on_base), p["change"]["to"]):
        _git("checkout", "-q", base, cwd=adopter_dir)
        result.update(held="tighten-only", current_tier=declared_tier(on_base),
                      party_tier=p["change"]["to"],
                      why=f"origin/{base} declares {declared_tier(on_base)!r}; "
                          f"{p['change']['to']!r} does not tighten it")
        return result
    rel = ns_path.relative_to(adopter_dir)
    ns_path.write_text(new_text)
    _git("add", str(rel), cwd=adopter_dir)
    diff = _git("diff", "--cached", "--quiet", cwd=adopter_dir, check=False)
    if diff.returncode != 0:
        _git("commit", "-q", "-m", p["title"], cwd=adopter_dir)
    _git("push", "--force", "origin", f"HEAD:refs/heads/{p['branch']}", cwd=adopter_dir)
    result["landed"] = _open_or_update_pr(p, base, repo)
    _git("checkout", "-q", base, cwd=adopter_dir)
    return result


def _tightens(current: str | None, tier: str) -> bool:
    """Would writing `tier` tighten a Namespace that declares `current`? The
    same rule wargamer.select_party_tier() folds with, applied once more at the
    moment of the write. None declared is `isolated` by default, and only the
    explicit `isolated` line may be written over it."""
    ladder = wargamer.LADDER
    if tier not in ladder or (current is not None and current not in ladder):
        return False
    if current is None:
        return tier == wargamer.FAIL_CLOSED
    return ladder.index(tier) > ladder.index(current)


def run(adopter_dir: Path, evidence_path: Path, org: str,
        rejections_path: Path | None, base: str = "main", dry_run: bool = False,
        repo: str | None = None, as_of: str | None = None) -> list[dict]:
    """The whole beat: load ticket 16's prices[] from the adopter's own
    committed evidence.json, bound them (proposer_bounds.py, unchanged),
    and land whatever survives -- always a pull request against the
    adopter's own governed Namespace declaration, found by its governed
    label. Nothing here decides WHETHER to propose. `repo` defaults to
    the `GITHUB_REPOSITORY` Actions gives every run for free; pass it
    explicitly for a local/offline run (selfcheck does).

    Bounds ONLY `wargame_cage_tier()`'s own rows -- deliberately never the
    general `wargamer.wargame()`/`proposer_bounds.dispositions()`, which
    default to the war-gamer's OWN demo enforcement/scenario fixture
    (`collect()`'s hardcoded feed files) when no `intel` is passed. Calling
    that here would silently propose a canned policy-body PR alongside the
    real cage-tier one on every real adopter run, and let it compete for
    the same RATE_LIMIT budget -- a fixture leaking into production. See
    `proposer_bounds.py`'s own selfcheck (3b) for the identical choice."""
    if not evidence_path.exists():
        # ticket 18 wires composition into the adopter's own CI and commits
        # composed/evidence.json on success; until that PR has landed once,
        # there is nothing yet for this proposer to read. Not an error --
        # the same "nothing to propose" shape propose-policy-pr.sh already
        # prints when a run finds no drift.
        print(f"note: {evidence_path} not found -- nothing composed yet, nothing to propose",
              file=sys.stderr)
        return []
    evidence = json.loads(evidence_path.read_text())
    prices = evidence.get("prices", [])
    repo = repo or os.environ.get("GITHUB_REPOSITORY")

    # The declaration is found, never known: the manifest carrying
    # `policy-as-versioned.dev/governed: "true"` on a Namespace, wherever the
    # adopter keeps it (ADR-0022). Two of them is an ambiguity this proposer
    # refuses to guess at -- it says which two and lands nothing.
    ns_hits = find_governed_namespaces(adopter_dir)
    ns_error = None
    if not ns_hits:
        ns_error = (f"no manifest under {adopter_dir} declares a Namespace with "
                    f'{GOVERNED_LABEL}: "true" -- there is no tier declaration to propose against')
    elif len(ns_hits) > 1:
        ns_error = (f"{len(ns_hits)} governed Namespace manifests under {adopter_dir} "
                    f"({', '.join(str(h.relative_to(adopter_dir)) for h in ns_hits)}) -- "
                    f"which one carries this party's tier is not this proposer's guess to make")

    # The selection is over the PARTY, not the price line (ticket 78; ADR-0022):
    # the strictest proposed_tier across prices[], clamped to the party's own
    # overlay.floor, and never looser than what the governed Namespace declares
    # today. A line still drifts on its own -- that is the question the ledger
    # keys on -- but what gets WRITTEN is the party's tier, and when that tier
    # does not tighten the declaration nothing is written at all.
    selection = None
    if prices and not ns_error:
        current = declared_tier(ns_hits[0].read_text())
        floor = read_overlay_floor(adopter_dir / "party.yaml")
        try:
            selection = wargamer.select_party_tier(prices, current=current, floor=floor)
        except ValueError as e:
            ns_error = f"missing instrument: {e}"
    rows = wargamer.wargame_cage_tier(prices, org, selection=selection) if prices else []
    if selection and selection["held"]:
        print(f"note: proposer holds -- {selection['basis']}", file=sys.stderr)
        return [{"branch": wargamer.propose(row)["branch"],
                 "proposal_kind": "pull_request", "held": "tighten-only",
                 "line": row["control"], "line_tier": row["price"].get("proposed_tier"),
                 "party_tier": selection["tier"], "current_tier": selection["current"],
                 "why": selection["basis"]}
                for row in rows if row["drift"]]

    # The ledger is DERIVED from closed-unmerged PRs on this repo's own dedupe
    # branches (ADR-0024). Offline it comes back empty AND SAYS SO on STDERR.
    # stdout is the proposal-document stream `--dry-run` writes and readers
    # json.loads, so a human note there breaks the contract (caught live by
    # verify/e2e/step3, 2026-08-28). --
    # a proposer that cannot see the rejections must not silently suppress and
    # must not silently propose. `--rejections` stays as an override for a
    # ledger derived once and reused (the workflow derives it inline instead).
    shape = rejection_ledger.fingerprint(prices)
    today = {proposer_bounds._key(row): shape for row in rows}
    if rejections_path:
        rejections = json.loads(rejections_path.read_text())
        print(f"note: rejection ledger read from {rejections_path}", file=sys.stderr)
    else:
        rejections, ledger_note = rejection_ledger.derive(repo, today)
        print(f"note: {ledger_note}", file=sys.stderr)

    disp = proposer_bounds.bound(rows, rejections)
    landed = []
    for d in disp:
        p = d["proposal"]
        if not p:
            continue
        p["ledger_marker"] = rejection_ledger.marker(d["key"], shape["curve_hash"],
                                                     shape["policy_version"])
        price = p.get("price") or {}
        p["org"] = org
        # The marker (the dedupe key's shape) stays the fingerprint and only the
        # fingerprint. These two are the human-readable half of the body, so they
        # fall back to the priced entry's own fields when no twin line published.
        p["curve_hash"] = shape["curve_hash"] or price.get("curve_hash") or ""
        p["policy_version"] = shape["policy_version"] or price.get("policy_version") or ""
        if ns_error:
            landed.append({"branch": p["branch"], "proposal_kind": p["proposal_kind"],
                           "error": ns_error})
            continue
        if as_of:
            p["as_of_note"] = (f"Re-composed and priced at **{as_of}** by the daily clock "
                               f"(ADR-0024): a date-driven band crossing with no new tag is "
                               f"a proposal trigger, and the clock committed nothing.")
        landed.append(_land(p, adopter_dir, ns_hits[0], base, dry_run, repo))
    return landed


# --------------------------------------------------------------------------
# selfcheck -- offline: a real local bare-repo "remote" (same pattern
# platform/verify-cut-release-tags.sh already uses) + a stub `gh` on PATH
# capturing its own invocations, so no live GitHub/network is needed.
# --------------------------------------------------------------------------
def selfcheck() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        remote = tmp / "remote.git"
        work = tmp / "work"
        _run(["git", "init", "--bare", "-q", str(remote)])
        _run(["git", "init", "-q", "-b", "main", str(work)])
        _git("config", "user.email", "test@example.invalid", cwd=work)
        _git("config", "user.name", "test", cwd=work)
        _git("remote", "add", "origin", str(remote), cwd=work)
        # The declaration: the governed Namespace manifest, in the exact shape
        # (block labels, comments, an already-declared tier) the three adopters
        # keep in gitops/apps/namespace.yaml.
        ns = work / "gitops" / "apps" / "namespace.yaml"
        ns.parent.mkdir(parents=True)
        ns.write_text(
            'apiVersion: v1\n'
            'kind: Namespace\n'
            'metadata:\n'
            '  name: driftwood\n'
            '  labels:\n'
            '    app.kubernetes.io/part-of: driftwood\n'
            '    # the governed declaration -- the tier is declared next to it\n'
            '    policy-as-versioned.dev/governed: "true"\n'
            '    posture.acme.io/tier: "baseline"\n'
        )
        # The pod manifest the proposer USED to edit: still here, and it must
        # come out byte-identical -- the pod label is cage-tier's output.
        workload = work / "deploy" / "pod.yaml"
        workload.parent.mkdir(parents=True)
        workload.write_text(
            'apiVersion: v1\n'
            'kind: Pod\n'
            'metadata: { name: checkout-svc, labels: '
            '{ "policy-as-versioned.dev/policy-version": "2.0.0" } }\n'
        )
        # An ungoverned Namespace in a multi-document file: the discovery must
        # not mistake it for the declaration (tuppence/reset/workloads.yaml).
        (work / "reset.yaml").write_text(
            'apiVersion: v1\n'
            'kind: Namespace\n'
            'metadata: { name: driftwood-reset }\n'
            '---\n'
            'apiVersion: v1\n'
            'kind: ConfigMap\n'
            'metadata: { name: notes, labels: { "policy-as-versioned.dev/governed": "true" } }\n'
        )
        (work / "other.txt").write_text("untouched\n")
        _git("add", "-A", cwd=work)
        _git("commit", "-q", "-m", "seed", cwd=work)
        _git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=work)

        gh_log = tmp / "gh.log"
        gh_state = tmp / "gh_state.json"
        gh_state.write_text(json.dumps({"pr": None, "issue": None, "closed": []}))
        stub_dir = tmp / "bin"
        stub_dir.mkdir()
        _write_gh_stub(stub_dir / "gh", gh_log, gh_state)
        env = dict(os.environ)
        env["PATH"] = f"{stub_dir}{os.pathsep}{env['PATH']}"

        evidence = tmp / "evidence.json"
        label_proposal_prices = [{
            "source": "ico", "kind": "pricing", "old_version": "v1", "new_version": "v2",
            "old_price": 1_000, "new_price": 90_000, "currency": "GBP",
            "perspective": "driftwood", "policy_version": "1.2.0",
            "curve_hash": "sha256:a-curve",
            "old_tier": "baseline", "proposed_tier": "quarantine",
            "changed": True, "proposed_as": "label",
        }]
        # A price still carrying the retired `proposed_as: "issue"` flag AND a
        # tier that used to be `deny`: ADR-0022 killed both, and this must land
        # as an ordinary pull request against the declaration like any other.
        legacy_issue_prices = [{
            "source": "platform", "kind": "threat", "old_version": "v1", "new_version": "v2",
            "old_price": 1_000, "new_price": 9_000_000, "currency": "GBP",
            "perspective": "driftwood",
            "old_tier": "quarantine", "proposed_tier": "isolated",
            "changed": True, "proposed_as": "issue",
        }]
        branch = "wargamer/retune-tier-driftwood-cage-tier-ico-pricing"

        # --- 1. a proposal opens a PR editing the GOVERNED NAMESPACE
        #     declaration -- and never the pod label, which is an output ---
        evidence.write_text(json.dumps({"prices": label_proposal_prices}))
        landed = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                org="driftwood",
                                rejections_path=None, base="main", dry_run=False)
        assert len(landed) == 1, landed
        assert landed[0]["proposal_kind"] == "pull_request", landed
        assert landed[0]["manifest"] == "gitops/apps/namespace.yaml", \
            ("the proposal must target the manifest carrying the governed label, "
             "found by reading it", landed)
        assert landed[0]["landed"]["action"] == "created", landed
        calls = _read_log(gh_log)
        assert any(c[:2] == ["pr", "create"] for c in calls), calls
        assert not any(c[0] == "issue" for c in calls), \
            ("the issue branch is dead -- no proposal may touch an issue", calls)
        body = next(c for c in calls if c[:2] == ["pr", "create"])
        body = body[body.index("--body") + 1]
        for expected in ("gitops/apps/namespace.yaml", "baseline", "quarantine",
                         "1,000.00 GBP", "90,000.00 GBP", "1.2.0", "sha256:a-curve"):
            assert expected in body, ("the PR body must say what moved, the price that "
                                      "moved it, the selection-policy version and the "
                                      f"curve hash -- {expected!r} missing", body)
        ns_on_branch = _git("show", f"{branch}:gitops/apps/namespace.yaml",
                             cwd=work, capture=True).stdout
        assert 'posture.acme.io/tier: "quarantine"' in ns_on_branch, ns_on_branch
        assert 'policy-as-versioned.dev/governed: "true"' in ns_on_branch, \
            "the governed label must survive the edit"
        assert "# the governed declaration" in ns_on_branch, \
            "the Namespace's own commentary must survive the edit"
        pod_on_branch = _git("show", f"{branch}:deploy/pod.yaml",
                              cwd=work, capture=True).stdout
        assert "posture.acme.io/tier" not in pod_on_branch, \
            ("the pod label is cage-tier's OUTPUT -- the proposer must never "
             "edit it (ADR-0022)", pod_on_branch)
        main_ns = _git("show", "main:gitops/apps/namespace.yaml", cwd=work, capture=True).stdout
        assert 'posture.acme.io/tier: "baseline"' in main_ns, \
            ("main must be untouched -- the edit lands only on the branch", main_ns)
        other_on_branch = _git("show", f"{branch}:other.txt", cwd=work, capture=True).stdout
        assert other_on_branch == "untouched\n", "only the declaration may change"

        # --- 2. a second run (price moved further) force-pushes the SAME
        #     branch and UPDATES the open PR, never opens a second one ---
        gh_log.write_text("")
        label_proposal_prices[0]["new_price"] = 200_000
        evidence.write_text(json.dumps({"prices": label_proposal_prices}))
        landed2 = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                 org="driftwood",
                                 rejections_path=None, base="main", dry_run=False)
        assert landed2[0]["branch"] == landed[0]["branch"], "dedupe key must be the branch name"
        assert landed2[0]["landed"]["action"] == "updated", landed2
        calls2 = _read_log(gh_log)
        assert not any(c[:2] == ["pr", "create"] for c in calls2), \
            ("a second run must never open a second PR", calls2)
        assert any(c[:2] == ["pr", "edit"] for c in calls2), calls2
        rev_count = _git("rev-list", "--count", "wargamer/retune-tier-driftwood-cage-tier-ico-pricing",
                          cwd=work, capture=True).stdout.strip()
        assert rev_count == "2", ("the branch must carry ONE fresh commit atop main "
                                   "every run, never an accumulating history", rev_count)

        # --- 3. the retired issue branch: a price still flagged
        #     `proposed_as: "issue"` opens a PULL REQUEST against the
        #     declaration, and no issue exists to open (ADR-0022) ---
        gh_log.write_text("")
        # a fresh question: the stub's "open PR" is the one from 1 and 2
        gh_state.write_text(json.dumps({**json.loads(gh_state.read_text()), "pr": None}))
        evidence.write_text(json.dumps({"prices": legacy_issue_prices}))
        landed3 = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                 org="driftwood",
                                 rejections_path=None, base="main", dry_run=False)
        assert len(landed3) == 1, landed3
        assert landed3[0]["proposal_kind"] == "pull_request", landed3
        assert landed3[0]["manifest"] == "gitops/apps/namespace.yaml", landed3
        calls3 = _read_log(gh_log)
        assert any(c[:2] == ["pr", "create"] for c in calls3), calls3
        assert not any(c[0] == "issue" for c in calls3), \
            ("ADR-0015's issue branch is removed: every proposal is a PR", calls3)
        ns3 = _git("show", f"{landed3[0]['branch']}:gitops/apps/namespace.yaml",
                    cwd=work, capture=True).stdout
        assert 'posture.acme.io/tier: "isolated"' in ns3, ns3

        # --- 4. the DERIVED rejection ledger (ADR-0024): a PR a human closed
        #     without merging suppresses the same question, and only that
        #     question. Nothing is committed anywhere that records the no ---
        import datetime as _dt
        ledger_key = "driftwood/cage-tier/ico-pricing"
        shape = rejection_ledger.fingerprint(label_proposal_prices)
        closed_yesterday = (_dt.datetime.now(_dt.timezone.utc)
                            - _dt.timedelta(days=1)).isoformat().replace("+00:00", "Z")

        def _closed(curve, policy):
            return [{"number": 7, "headRefName": "wargamer/retune-tier-driftwood-cage-tier-ico-pricing",
                      "mergedAt": None, "closedAt": closed_yesterday,
                      "body": rejection_ledger.marker(ledger_key, curve, policy)}]

        state = json.loads(gh_state.read_text())
        state["closed"] = _closed(shape["curve_hash"], shape["policy_version"])
        state["pr"] = None
        gh_state.write_text(json.dumps(state))
        gh_log.write_text("")
        evidence.write_text(json.dumps({"prices": label_proposal_prices}))
        suppressed = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                    org="driftwood",
                                    rejections_path=None, base="main", dry_run=False)
        assert suppressed == [], ("yesterday's rejection must suppress today's "
                                   "identical proposal", suppressed)
        assert not _read_log(gh_log) or not any(
            c[:2] == ["pr", "create"] for c in _read_log(gh_log)), _read_log(gh_log)

        # ...and a rejection priced under a DIFFERENT curve does not count: a
        # new GBP is a new question (ticket 10 Q5).
        state["closed"] = _closed("sha256:a-different-curve", shape["policy_version"])
        gh_state.write_text(json.dumps(state))
        gh_log.write_text("")
        reraised = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                  org="driftwood",
                                  rejections_path=None, base="main", dry_run=False)
        assert len(reraised) == 1, ("a rejection under another curve must not "
                                     "silence this one", reraised)
        assert any(c[:2] == ["pr", "create"] for c in _read_log(gh_log)), _read_log(gh_log)

        # --- 4b. the proposer can only TIGHTEN (ticket 78; ADR-0022). The
        #     selection is over the PARTY, not the price line: a per-line
        #     crossing on a party whose declaration is already `isolated`
        #     (driftwood's threat-register line, baseline -> restricted, beside
        #     two lines that already select isolated) must write NOTHING --
        #     no branch, no commit, no PR -- and say why. ---
        def _declare(tier_line: str | None) -> None:
            ns.write_text(
                'apiVersion: v1\n'
                'kind: Namespace\n'
                'metadata:\n'
                '  name: driftwood\n'
                '  labels:\n'
                '    app.kubernetes.io/part-of: driftwood\n'
                '    # the governed declaration -- the tier is declared next to it\n'
                '    policy-as-versioned.dev/governed: "true"\n'
                + (f'    posture.acme.io/tier: "{tier_line}"\n' if tier_line else '')
            )
            _git("add", "-A", cwd=work)
            _git("commit", "-q", "-m", f"declare {tier_line}", cwd=work)
            _git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=work)

        def _line(source, kind, old_tier, new_tier, changed, old_price=1_000, new_price=90_000):
            return {"source": source, "kind": kind, "old_version": "v1", "new_version": "v2",
                    "old_price": old_price, "new_price": new_price, "currency": "GBP",
                    "perspective": "driftwood", "old_tier": old_tier, "proposed_tier": new_tier,
                    "changed": changed, "proposed_as": "label"}

        def _fresh():
            state = json.loads(gh_state.read_text())
            state["pr"] = None
            state["closed"] = []
            gh_state.write_text(json.dumps(state))
            gh_log.write_text("")

        _git("checkout", "-q", "main", cwd=work)
        _declare("isolated")
        _fresh()
        crossing_on_isolated = [
            _line("feeds", "feed", "baseline", "restricted", True),        # the crossing
            _line("ico", "feed", "isolated", "isolated", False),           # already isolated
            _line("twin", "twin", "isolated", "isolated", False),          # already isolated
        ]
        evidence.write_text(json.dumps({"prices": crossing_on_isolated}))
        held = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                             org="driftwood", rejections_path=None, base="main",
                             dry_run=False)
        assert len(held) == 1 and held[0].get("held") == "tighten-only", \
            ("a per-line crossing on a party declared isolated must be HELD, not landed", held)
        assert "landed" not in held[0] and "error" not in held[0], held
        assert held[0]["party_tier"] == "isolated" and held[0]["current_tier"] == "isolated", held
        assert held[0]["line_tier"] == "restricted", held
        assert not any(c[:2] == ["pr", "create"] for c in _read_log(gh_log)), \
            ("nothing looser may be proposed -- no PR", _read_log(gh_log))
        feeds_branch = "wargamer/retune-tier-driftwood-cage-tier-feeds-feed"
        no_branch = _git("show-ref", "--verify", "--quiet", f"refs/heads/{feeds_branch}",
                         cwd=work, check=False)
        assert no_branch.returncode != 0, "a held proposal must create no branch"
        main_ns = _git("show", "main:gitops/apps/namespace.yaml", cwd=work, capture=True).stdout
        assert 'posture.acme.io/tier: "isolated"' in main_ns, main_ns

        # --- 4c. strictest line wins: the crossing line prices `restricted`,
        #     a sibling line already prices `quarantine`, the declaration says
        #     `baseline` -- the write is `quarantine`, the party's strictest,
        #     never the crossing line's own tier, and the body says so. ---
        _declare("baseline")
        _fresh()
        evidence.write_text(json.dumps({"prices": [
            _line("feeds", "feed", "baseline", "restricted", True),
            _line("ico", "feed", "quarantine", "quarantine", False),
        ]}))
        strict = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                               org="driftwood", rejections_path=None, base="main",
                               dry_run=False)
        assert len(strict) == 1 and strict[0]["landed"]["action"] == "created", strict
        ns_strict = _git("show", f"{feeds_branch}:gitops/apps/namespace.yaml",
                         cwd=work, capture=True).stdout
        assert 'posture.acme.io/tier: "quarantine"' in ns_strict, \
            ("the party's strictest line must be written, not the crossing line's", ns_strict)
        body = next(c for c in _read_log(gh_log) if c[:2] == ["pr", "create"])
        body = body[body.index("--body") + 1]
        assert "strictest" in body and "`baseline` -> `quarantine`" in body, \
            ("the PR body must say the write is the party's strictest line", body)
        assert "feeds/feed" in body and "ico/feed" in body, body

        # --- 4d. the floor clamps: one crossing line prices `restricted`, the
        #     party's own overlay.floor is `quarantine` -- the write is the
        #     floor (ADR-0022: selection clamps up to the floor). ---
        _fresh()
        (work / "party.yaml").write_text(
            'party: driftwood\n'
            'roles: [risk-bearer, adopter]\n'
            'overlay:\n'
            '  add: []\n'
            '  restate: []\n'
            '  floor: quarantine\n'
            'publishes: []\n'
        )
        _git("add", "-A", cwd=work)
        _git("commit", "-q", "-m", "declare a floor", cwd=work)
        _git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=work)
        evidence.write_text(json.dumps({"prices": [
            _line("feeds", "feed", "baseline", "restricted", True),
        ]}))
        floored = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                org="driftwood", rejections_path=None, base="main",
                                dry_run=False)
        assert len(floored) == 1 and floored[0]["landed"]["action"] == "created", floored
        ns_floor = _git("show", f"{feeds_branch}:gitops/apps/namespace.yaml",
                        cwd=work, capture=True).stdout
        assert 'posture.acme.io/tier: "quarantine"' in ns_floor, \
            ("the declared floor must clamp the write up", ns_floor)
        (work / "party.yaml").unlink()
        _git("add", "-A", cwd=work)
        _git("commit", "-q", "-m", "drop the floor", cwd=work)
        _git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=work)

        # --- 4e. the current declaration is read from the Namespace, not from
        #     the price line's `old_tier`: the line says it moved from
        #     `baseline`, the Namespace already declares `quarantine`, the line
        #     lands at `restricted` -- looser than what is declared, so HELD. ---
        _declare("quarantine")
        _fresh()
        evidence.write_text(json.dumps({"prices": [
            _line("feeds", "feed", "baseline", "restricted", True),
        ]}))
        stale = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                              org="driftwood", rejections_path=None, base="main",
                              dry_run=False)
        assert len(stale) == 1 and stale[0].get("held") == "tighten-only", stale
        assert stale[0]["current_tier"] == "quarantine", stale
        # ...and the same line on a Namespace declared `baseline` lands, as a
        # proposal from `baseline` (what is declared) to `restricted`.
        _declare("baseline")
        _fresh()
        moved = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                              org="driftwood", rejections_path=None, base="main",
                              dry_run=False)
        assert len(moved) == 1 and moved[0]["landed"]["action"] == "created", moved
        assert 'posture.acme.io/tier: "restricted"' in _git(
            "show", f"{feeds_branch}:gitops/apps/namespace.yaml", cwd=work, capture=True).stdout

        # --- 5. structural safety: this module has no way to merge/dispose,
        #     and no way to open an issue either ---
        me = sys.modules[__name__]
        for banned in ("merge", "approve", "dispose", "auto_merge",
                       "_open_or_update_issue", "_issue_body"):
            assert not callable(getattr(me, banned, None)), \
                f"tier_pr must expose no {banned}()"

        # Attribute names are not what disposes of a pull request; `gh` verbs are. So read the
        # argv this module BUILDS (see `disposing_calls` above for what that does and does not
        # buy), and -- because a scanner that has only ever seen clean source cannot tell
        # "correct" from "always says nothing" -- PLANT the disposal and require it to be caught.
        source = Path(__file__).read_text()
        # The plant lives in this module's own text as a string constant, so it must not be
        # parsed as if it were code: check it separately, then check the rest.
        assert PLANTED_DISPOSAL in source, "the planted-disposal fixture is not in this file"
        planted = disposing_calls(PLANTED_DISPOSAL)
        assert len(planted) == 3, ("the plant must be caught -- twice on argv, once on the "
                                   "REST endpoint it names", planted)
        assert any("--squash" in hit for hit in planted), planted
        assert any("/merge REST endpoint" in hit for hit in planted), planted
        # A pr CREATE in the same plant is not a disposal, so the scanner is not just shouting
        # at every gh call it sees.
        assert not disposing_calls('_gh("pr", "create", "--head", b, "--base", base)')

        real = disposing_calls(source.replace(PLANTED_DISPOSAL, ""))
        assert not real, (real, "the war-gamer proposes and a human disposes (ADR-0015)")

    print(
        "ok  a proposal opens a PR editing posture.acme.io/tier on the GOVERNED NAMESPACE "
        "manifest found by its governed label (comments and the governed label survive; the "
        "pod label, an output, is untouched; main untouched; everything else byte-identical), "
        "and its body names the manifest, the move, the price that moved it, the "
        "selection-policy version and the curve hash; a second run force-pushes the SAME "
        "branch (1 fresh commit, not 2) and UPDATES the open PR, never opens a second one; "
        "a price still flagged proposed_as=issue opens a PULL REQUEST -- no issue path "
        "exists any more (ADR-0022); yesterday's closed-unmerged PR SUPPRESSES the identical "
        "proposal while one priced under another curve does not (the ledger is derived, "
        "nothing records the no); the proposer can only TIGHTEN (ticket 78): a per-line "
        "crossing on a party declared isolated lands nothing (no branch, no PR), the party's "
        "strictest priced line is what gets written and the body says so, the declared "
        "overlay.floor clamps the write up, and the current tier is read off the Namespace "
        "(a line landing looser than the declaration is held); no merge()/approve()/dispose() "
        "anywhere in this module, and no DISPOSING GH CALL either -- the argv this module "
        "builds is read, a planted `_gh(\"pr\", \"merge\", \"--squash\", \"--admin\", ...)` and "
        "a planted /merge REST path are both caught, and a `gh pr create` is not."
    )


def _run_with_env(fn, env, **kwargs):
    """Run `fn` with the stub `gh` first on PATH, restoring afterwards --
    subprocess.run reads os.environ at call time, so this is enough without
    threading env through every _git/_gh call above."""
    old = os.environ.get("PATH")
    os.environ["PATH"] = env["PATH"]
    try:
        return fn(**kwargs)
    finally:
        if old is not None:
            os.environ["PATH"] = old


def _read_log(path: Path) -> list[list[str]]:
    if not path.exists() or not path.read_text().strip():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _write_gh_stub(path: Path, log_path: Path, state_path: Path) -> None:
    # A tiny stateful stub: `pr create`/`issue create` mint a number the
    # very next `pr list`/`issue list` call will find, so the dedupe path
    # (list -> create-or-edit) is exercised for real, offline.
    path.write_text(f"""#!/usr/bin/env python3
import json, sys
log_path = {str(log_path)!r}
state_path = {str(state_path)!r}
argv = sys.argv[1:]
with open(log_path, "a") as fh:
    fh.write(json.dumps(argv) + "\\n")
state = json.load(open(state_path))
kind = argv[0] if argv else ""
if kind == "pr" and argv[1] == "list" and "closed" in argv:
    print(json.dumps(state.get("closed", [])))
elif kind == "pr" and argv[1] == "list":
    print(state["pr"] or "")
elif kind == "pr" and argv[1] == "create":
    state["pr"] = "1"
    json.dump(state, open(state_path, "w"))
    print("https://example.invalid/pr/1")
elif kind == "pr" and argv[1] == "edit":
    pass
elif kind == "issue" and argv[1] == "list":
    print(state["issue"] or "")
elif kind == "issue" and argv[1] == "create":
    state["issue"] = "1"
    json.dump(state, open(state_path, "w"))
    print("https://example.invalid/issue/1")
elif kind == "issue" and argv[1] == "edit":
    pass
""")
    path.chmod(0o755)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "selfcheck":
        selfcheck()
        return 0

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--adopter-dir", type=Path, required=True)
    r.add_argument("--evidence", type=Path, required=True)
    r.add_argument("--org", required=True)
    r.add_argument("--base", default="main")
    r.add_argument("--rejections", type=Path, default=None,
                   help="a pre-derived ledger; omit to derive it from closed PRs")
    r.add_argument("--as-of", default=None,
                   help="the date this run re-composed at, recorded in the PR body")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--repo", default=None, help="owner/repo; defaults to $GITHUB_REPOSITORY")
    sub.add_parser("selfcheck")
    args = p.parse_args(argv[1:])

    if args.cmd == "selfcheck":
        selfcheck()
        return 0
    landed = run(args.adopter_dir, args.evidence, args.org,
                 args.rejections, base=args.base, dry_run=args.dry_run, repo=args.repo,
                 as_of=args.as_of)
    print(json.dumps(landed, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
