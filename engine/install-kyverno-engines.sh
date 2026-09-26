#!/usr/bin/env bash
# install-kyverno-engines.sh <platform> <dest> -- one Kyverno CLI per row of the engine table.
#
# Eco-system ticket 146 items 1 and 6. For every row of engine/kyverno/engine-table.yaml this
# downloads the CLI archive for <platform> (darwin_arm64 or linux_x86_64), refuses it unless its
# sha256 is the row's, extracts the binary to <dest>/<version>/kyverno, and refuses the binary
# unless `kyverno version` reports the row's version. It prints one line per engine it installed.
#
# The grader takes the directory: `engine_compatibility.py --engine-dir <dest>`. Nothing here is
# put on PATH, so the CLI that other checks call is unchanged.
#
# A checksum mismatch, a download that fails or a binary that reports another version exits 1
# and names the row. There is no skip: an engine the table lists and this script cannot install
# is an engine the grader will then read as could-not-look, and saying why here is cheaper.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
platform="${1:?usage: install-kyverno-engines.sh <darwin_arm64|linux_x86_64> <dest>}"
dest="${2:?usage: install-kyverno-engines.sh <darwin_arm64|linux_x86_64> <dest>}"
case "$platform" in darwin_arm64|linux_x86_64) ;; *) echo "FAIL: unknown platform $platform" >&2; exit 2;; esac
if command -v sha256sum >/dev/null; then sha() { sha256sum "$1" | awk '{print $1}'; }
else sha() { shasum -a 256 "$1" | awk '{print $1}'; }; fi

rows="$(python3 "$HERE/engine_table.py" rows "$platform")"
[ -n "$rows" ] || { echo "FAIL: the engine table has no row" >&2; exit 1; }
mkdir -p "$dest"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
while read -r version url want; do
  curl -fsSL -o "$work/cli.tgz" "$url" || { echo "FAIL: $version: could not download $url" >&2; exit 1; }
  got="$(sha "$work/cli.tgz")"
  [ "$got" = "$want" ] || { echo "FAIL: $version: $url hashes to $got, the table says $want" >&2; exit 1; }
  mkdir -p "$dest/$version"
  tar -xzf "$work/cli.tgz" -C "$dest/$version" kyverno
  chmod +x "$dest/$version/kyverno"
  reported="$("$dest/$version/kyverno" version | sed -n 's/^Version: *v\{0,1\}\([0-9][0-9.]*\) *$/\1/p' | head -1)"
  [ "$reported" = "$version" ] || { echo "FAIL: $version: the binary reports '$reported'" >&2; exit 1; }
  echo "installed kyverno $version ($platform, archive sha256 $got) at $dest/$version/kyverno"
  rm -f "$work/cli.tgz"
done <<<"$rows"
