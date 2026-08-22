#!/usr/bin/env python3
"""cs-13: turn cut-release.yml's dispatch inputs into a normalized tags.json
list of {"tag": ..., "message": ...} entries.

Exactly one dispatch form is accepted:
  - single-tag (legacy, unchanged for existing callers): VERSION_INPUT + MESSAGE_INPUT
  - multi-tag (new): TAGS_INPUT, a JSON array of {"tag", "message"} objects

Reads from the environment (not argv/stdin containing raw `${{ inputs.* }}`
text) so the workflow can pass attacker-influenced input safely, via `env:`,
rather than interpolating it into a shell command line.
"""
import json
import os
import sys


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
        if e["tag"] in seen:
            fail(f"tag {e['tag']} listed more than once in one dispatch")
            return
        seen.add(e["tag"])

    json.dump(entries, sys.stdout)


if __name__ == "__main__":
    main()
