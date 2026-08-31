#!/usr/bin/env python3
"""cs-13: turn cut-release.yml's dispatch inputs into a normalized tags.json
list of {"tag": ..., "message": ...} entries.

Exactly one dispatch form is accepted:
  - single-tag (legacy, unchanged for existing callers): VERSION_INPUT + MESSAGE_INPUT
  - multi-tag (new): TAGS_INPUT, a JSON array of {"tag", "message"} objects

Reads from the environment (not argv/stdin containing raw `${{ inputs.* }}`
text) so the workflow can pass attacker-influenced input safely, via `env:`,
rather than interpolating it into a shell command line.

cs-27: every tag is also checked here against the only two legal shapes --
`v<semver>` (platform's own line, cs-07's subject) or `policy/v<semver>`
(cs-27's publisher-gate subject, cut-release-gate.py's own POLICY_TAG_RE).
This is the one seam every entry passes through before
cut-release-refuse-existing.sh, cut-release-gate.py, cut-release-create-tags.sh
and cut-release-push.sh ever see it, so it is the one place a shape check
closes the gap for all four: a tag that is neither shape -- wrong case,
extra/missing slash, leading/trailing whitespace, anything else -- fails the
whole dispatch here, before any tag exists, rather than silently falling
through cut-release-gate.py's `POLICY_TAG_RE.match` as "not this gate's
subject, skipped" and reaching `git tag`/`git push` with no gate run at all.
"""
import json
import os
import re
import sys

# Ticket 43 (18 Answer 1): a policy tag may carry a prerelease suffix --
# `policy/v4.0.1-quarantine.1` is what a DEGRADED publish is tagged. The
# platform's own `v<semver>` line takes no suffix: it is not gated, so
# nothing there can degrade.
TAG_RE = re.compile(r"^(v\d+\.\d+\.\d+|policy/v\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?)$")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    version = os.environ.get("VERSION_INPUT") or None
    message = os.environ.get("MESSAGE_INPUT") or None
    tags_raw = os.environ.get("TAGS_INPUT") or None

    if tags_raw:
        if version or message:
            fail("pass either `tags` or `version`+`message`, not both")
        try:
            entries = json.loads(tags_raw)
        except json.JSONDecodeError as e:
            fail(f"`tags` is not valid JSON: {e}")
            return
        if not isinstance(entries, list):
            fail("`tags` must be a JSON array")
            return
    else:
        if not version or not message:
            fail("no `tags` given -- `version` and `message` are both required for the single-tag form")
            return
        entries = [{"tag": version, "message": message}]

    if not entries:
        fail("`tags` must have at least one entry")
        return

    seen = set()
    for e in entries:
        if not isinstance(e, dict) or not e.get("tag") or not e.get("message"):
            fail(f"every entry needs both tag and message: {e}")
            return
        if not TAG_RE.match(e["tag"]):
            fail(f"tag {e['tag']!r} is not a legal shape -- must be exactly "
                 f"vX.Y.Z, policy/vX.Y.Z or policy/vX.Y.Z-<prerelease> "
                 f"(case-sensitive, no stray whitespace/slashes)")
            return
        if e["tag"] in seen:
            fail(f"tag {e['tag']} listed more than once in one dispatch")
            return
        seen.add(e["tag"])

    json.dump(entries, sys.stdout)


if __name__ == "__main__":
    main()
