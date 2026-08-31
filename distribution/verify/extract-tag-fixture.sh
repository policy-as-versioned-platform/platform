#!/usr/bin/env bash
# Re-derive the offline proof's material from this repo's own signed tags.
#
# `testdata/<tag>.tag` is a byte-for-byte `git cat-file tag` dump of a REAL
# gitsign-signed tag cut by this repo's cut-release.yml. It is committed so the
# proof runs in a clone with no tags fetched and with no network. It is
# derived, never hand-written: verify-source-verification.sh re-runs this and
# diffs whenever the tag is present locally, so the fixture cannot drift away
# from the tag it claims to be.
#
#   ./extract-tag-fixture.sh                 # refresh every fixture that exists
#   ./extract-tag-fixture.sh policy/v4.0.0   # add one
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
mkdir -p "$here/testdata"

tags=("$@")
if [ ${#tags[@]} -eq 0 ]; then
  for f in "$here"/testdata/*.tag; do
    [ -e "$f" ] || continue
    # filename <prefix>-<rest> maps back to tag <prefix>/<rest>. ponytail:
    # first dash only, which is every tag shape this estate cuts; a tag with a
    # dash inside the version needs the argument form above.
    tags+=("$(basename "$f" .tag | sed 's|-|/|')")
  done
fi

for tag in "${tags[@]}"; do
  out="$here/testdata/$(echo "$tag" | tr '/' '-').tag"
  git -C "$repo" cat-file tag "$tag" > "$out"
  echo "wrote $out ($(wc -c < "$out") bytes)"
done
