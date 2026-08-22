#!/usr/bin/env bash
# verify-release-integrity.sh -- ticket cs-26. The four extra gate rules'
# own selfcheck: a real git repo, a real tag, and a real hand edit prove each
# of the four refusals actually fires (frozen-tree, re-render, mandatory-
# member, empty-commit) -- not just that the happy path stays green. No
# kyverno CLI needed: these four rules read git and YAML only.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

python3 release_integrity.py --selfcheck
