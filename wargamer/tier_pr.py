#!/usr/bin/env python3
"""tier_pr.py -- the proposer's last step (ticket 17; ADR-0015). Turns a
bounded cage-tier proposal (wargamer.py + proposer_bounds.py) into a REAL,
opened artefact: a pull request editing `posture.acme.io/tier` on the
adopter's committed workload manifest, or -- for a proposed `deny`, which
the `cage-tier` MutatingPolicy would coerce to `baseline` if it ever landed
as a label -- an issue instead. Never both, for the same proposal.

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
the already-open PR in place rather than opening a second one. An issue
proposal dedupes the same way, keyed by an HTML-comment marker in the issue
body (the same span-marker pattern driftwood's adopter-gate.py already uses
for the PR body).

Usage:
    tier_pr.py run --adopter-dir <path> --evidence <evidence.json> \\
        --workload <workload.yaml> --org <party> [--base main] \\
        [--rejections <derived-ledger.json>] [--dry-run]
    tier_pr.py selfcheck
"""
from __future__ import annotations

import argparse
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

# The exact matchCondition ../graded/policies/cage-tier.yaml itself gates
# on -- only a labels block that already claims a policy version is this
# policy's population, so only that block is a legal place to add the tier.
CLAIMS_LABEL = "policy-as-versioned.dev/policy-version"
TIER_LABEL = "posture.acme.io/tier"

# One flow-style `labels: { ... }` map, as driftwood/deploy/pod.yaml (and
# every other workload manifest fixture in this estate) writes it. A block-
# style workload manifest is out of scope here -- see apply_tier_label's own
# docstring for the upgrade path.
_LABELS_BLOCK = re.compile(r"labels:\s*\{([^{}]*)\}")
_TIER_KV = re.compile(r'"posture\.acme\.io/tier"\s*:\s*"[^"]*"')

ISSUE_MARKER = "<!-- wargamer:tier:{slug} -->"


# --------------------------------------------------------------------------
# the text edit -- a line edit, not a YAML re-dump (render-faithfulness
# ethos, applied to a workload manifest instead of a composed policy)
# --------------------------------------------------------------------------
def apply_tier_label(text: str, tier: str) -> tuple[str, bool]:
    """For every `labels: { ... }` flow map in `text` that already claims a
    policy version, set `posture.acme.io/tier` inside that SAME map --
    updated if present, inserted if absent. Every other byte of the file is
    untouched.

    ponytail: flow-style maps only (this estate's own convention, and the
    exact shape driftwood/deploy/pod.yaml, ludlow/deploy/pod.yaml and
    tuppence/deploy/pod.yaml all use). Upgrade to a block-style `labels:`
    walker if an adopter workload manifest ever ships that shape instead."""
    changed = False

    def _sub(m: re.Match) -> str:
        nonlocal changed
        body = m.group(1)
        if CLAIMS_LABEL not in body:
            return m.group(0)
        changed = True
        if _TIER_KV.search(body):
            new_body = _TIER_KV.sub(f'"{TIER_LABEL}": "{tier}"', body)
        else:
            trimmed = body.rstrip()
            sep = "" if trimmed.endswith(",") else ","
            new_body = f'{trimmed}{sep} "{TIER_LABEL}": "{tier}"'
        return f"labels: {{{new_body}}}"

    new_text = _LABELS_BLOCK.sub(_sub, text)
    return new_text, changed


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


def _pr_body(p: dict) -> str:
    c = p["change"]
    return (
        f"{p.get('ledger_marker', '')}\n\n"
        f"Proposed by the war-gamer's cage-tier drift (ADR-0015). "
        f"`{c['label']}`: `{c['from']}` -> `{c['to']}`.\n\n"
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


def _existing_issue_number(marker: str, repo: str | None) -> str:
    out = _gh("issue", "list", "--search", f'"{marker}" in:body', "--state", "open",
              "--json", "number", "-q", ".[0].number", repo=repo).stdout.strip()
    return out


def _issue_body(p: dict, marker: str) -> str:
    return (
        f"{marker}\n{p.get('ledger_marker', '')}\n\n"
        f"The war-gamer's cage-tier drift (ADR-0015) proposes `deny` for "
        f"{p['from_evidence']['source']}/{p['from_evidence']['kind']}. "
        f"`TIERS` holds only `baseline`/`restricted`/`quarantine`, and the "
        f"`cage-tier` MutatingPolicy coerces any unrecognised label value to "
        f"`baseline` -- so a merged `{TIER_LABEL}: deny` label would silently "
        f"INVERT this proposal. Opened as an issue instead of a label pull "
        f"request, on purpose.\n\n"
        f"Evidence: {json.dumps(p['from_evidence'], sort_keys=True)}\n\n"
        f"Never merged/closed by this proposer -- a human disposes."
    )


def _open_or_update_issue(p: dict, repo: str | None) -> dict:
    slug = p["branch"].rsplit("retune-tier-", 1)[-1]
    marker = ISSUE_MARKER.format(slug=slug)
    body = _issue_body(p, marker)
    number = _existing_issue_number(marker, repo)
    if number:
        _gh("issue", "edit", number, "--body", body, repo=repo)
        return {"action": "updated", "number": number}
    out = _gh("issue", "create", "--title", p["title"], "--body", body, repo=repo)
    return {"action": "created", "url": out.stdout.strip()}


# --------------------------------------------------------------------------
# landing one proposal
# --------------------------------------------------------------------------
def _land(p: dict, adopter_dir: Path, workload_path: Path, base: str, dry_run: bool,
          repo: str | None) -> dict:
    result = {"branch": p["branch"], "proposal_kind": p["proposal_kind"]}

    if p["proposal_kind"] == "issue":
        if dry_run:
            result["landed"] = "dry-run"
        else:
            result["landed"] = _open_or_update_issue(p, repo)
        return result

    if not workload_path.exists():
        result["error"] = f"workload manifest {workload_path} not found -- nothing to land"
        return result
    text = workload_path.read_text()
    new_text, changed = apply_tier_label(text, p["change"]["to"])
    if not changed:
        result["error"] = (f"no {CLAIMS_LABEL!r} labels block found in "
                            f"{workload_path} -- nothing to land")
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
    rel = workload_path.relative_to(adopter_dir)
    workload_path.write_text(new_text)
    _git("add", str(rel), cwd=adopter_dir)
    diff = _git("diff", "--cached", "--quiet", cwd=adopter_dir, check=False)
    if diff.returncode != 0:
        _git("commit", "-q", "-m", p["title"], cwd=adopter_dir)
    _git("push", "--force", "origin", f"HEAD:refs/heads/{p['branch']}", cwd=adopter_dir)
    result["landed"] = _open_or_update_pr(p, base, repo)
    _git("checkout", "-q", base, cwd=adopter_dir)
    return result


def run(adopter_dir: Path, evidence_path: Path, workload_path: Path, org: str,
        rejections_path: Path | None, base: str = "main", dry_run: bool = False,
        repo: str | None = None, as_of: str | None = None) -> list[dict]:
    """The whole beat: load ticket 16's prices[] from the adopter's own
    committed evidence.json, bound them (proposer_bounds.py, unchanged),
    and land whatever survives -- a PR or an issue, never both, per
    proposal. Nothing here decides WHETHER to propose. `repo` defaults to
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
    rows = wargamer.wargame_cage_tier(prices, org) if prices else []

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
        if as_of:
            p["as_of_note"] = (f"Re-composed and priced at **{as_of}** by the daily clock "
                               f"(ADR-0024): a date-driven band crossing with no new tag is "
                               f"a proposal trigger, and the clock committed nothing.")
        landed.append(_land(p, adopter_dir, workload_path, base, dry_run, repo))
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
        workload = work / "deploy" / "pod.yaml"
        workload.parent.mkdir(parents=True)
        workload.write_text(
            'apiVersion: v1\n'
            'kind: Pod\n'
            'metadata: { name: checkout-svc, labels: '
            '{ "policy-as-versioned.dev/policy-version": "2.0.0" } }\n'
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
            "old_price": 1_000, "new_price": 90_000,
            "old_tier": "baseline", "proposed_tier": "quarantine",
            "changed": True, "proposed_as": "label",
        }]
        deny_proposal_prices = [{
            "source": "platform", "kind": "threat", "old_version": "v1", "new_version": "v2",
            "old_price": 1_000, "new_price": 9_000_000,
            "old_tier": "quarantine", "proposed_tier": "deny",
            "changed": True, "proposed_as": "issue",
        }]

        # --- 1. a label proposal opens a PR editing the workload manifest line ---
        evidence.write_text(json.dumps({"prices": label_proposal_prices}))
        landed = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                workload_path=workload, org="driftwood",
                                rejections_path=None, base="main", dry_run=False)
        assert len(landed) == 1, landed
        assert landed[0]["proposal_kind"] == "pull_request", landed
        assert landed[0]["landed"]["action"] == "created", landed
        calls = _read_log(gh_log)
        assert any(c[:2] == ["pr", "create"] for c in calls), calls
        assert not any(c[:2] == ["issue", "create"] for c in calls), \
            ("a label proposal must never open an issue", calls)
        text_on_branch = _git("show", "wargamer/retune-tier-driftwood-cage-tier-ico-pricing:deploy/pod.yaml",
                               cwd=work, capture=True).stdout
        assert '"posture.acme.io/tier": "quarantine"' in text_on_branch, text_on_branch
        assert CLAIMS_LABEL in text_on_branch, "the original claim label must survive the edit"
        main_text = _git("show", "main:deploy/pod.yaml", cwd=work, capture=True).stdout
        assert "posture.acme.io/tier" not in main_text, \
            ("main must be untouched -- the edit lands only on the branch", main_text)
        other_on_branch = _git("show", "wargamer/retune-tier-driftwood-cage-tier-ico-pricing:other.txt",
                                cwd=work, capture=True).stdout
        assert other_on_branch == "untouched\n", "only the workload manifest may change"

        # --- 2. a second run (price moved further) force-pushes the SAME
        #     branch and UPDATES the open PR, never opens a second one ---
        gh_log.write_text("")
        label_proposal_prices[0]["new_price"] = 200_000
        evidence.write_text(json.dumps({"prices": label_proposal_prices}))
        landed2 = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                 workload_path=workload, org="driftwood",
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

        # --- 3. a proposed deny opens an issue, never a pull request ---
        gh_log.write_text("")
        evidence.write_text(json.dumps({"prices": deny_proposal_prices}))
        landed3 = _run_with_env(run, env, adopter_dir=work, evidence_path=evidence,
                                 workload_path=workload, org="driftwood",
                                 rejections_path=None, base="main", dry_run=False)
        assert len(landed3) == 1, landed3
        assert landed3[0]["proposal_kind"] == "issue", landed3
        calls3 = _read_log(gh_log)
        assert any(c[:2] == ["issue", "create"] for c in calls3), calls3
        assert not any(c[:2] == ["pr", "create"] for c in calls3), \
            ("a deny proposal must never open a pull request", calls3)

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
                                    workload_path=workload, org="driftwood",
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
                                  workload_path=workload, org="driftwood",
                                  rejections_path=None, base="main", dry_run=False)
        assert len(reraised) == 1, ("a rejection under another curve must not "
                                     "silence this one", reraised)
        assert any(c[:2] == ["pr", "create"] for c in _read_log(gh_log)), _read_log(gh_log)

        # --- 5. structural safety: this module has no way to merge/dispose ---
        me = sys.modules[__name__]
        for banned in ("merge", "approve", "dispose", "auto_merge"):
            assert not callable(getattr(me, banned, None)), \
                f"tier_pr must expose no {banned}()"

    print(
        "ok  a label proposal opens a PR editing posture.acme.io/tier on the workload "
        "manifest line (main untouched, everything else byte-identical); a second run "
        "force-pushes the SAME branch (1 fresh commit, not 2) and UPDATES the open PR, "
        "never opens a second one; a proposed deny opens an issue and never a PR; "
        "yesterday's closed-unmerged PR SUPPRESSES the identical proposal while one "
        "priced under another curve does not (the ledger is derived, nothing records "
        "the no); no merge()/approve()/dispose() anywhere in this module."
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
    r.add_argument("--workload", type=Path, required=True)
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
    landed = run(args.adopter_dir, args.evidence, args.workload, args.org,
                 args.rejections, base=args.base, dry_run=args.dry_run, repo=args.repo,
                 as_of=args.as_of)
    print(json.dumps(landed, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
