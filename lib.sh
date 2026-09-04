#!/usr/bin/env bash
# Shared by every verify-*.sh that looks at a live cluster. A live tail has
# exactly three outcomes: observed-true (PASS), observed-false (FAIL), or
# could-not-look (SKIP, exit 3). A script never claims what it did not observe
# and never FAILs because it could not look.
#
#   skip <reason>                  print "SKIP: <reason>", exit 3
#   substrate_ok <kind-cluster>    0 if docker works, the kind cluster is listed
#                                  and Flux is Ready there (every Kustomization
#                                  in flux-system Ready=True, at least one);
#                                  else 1 with the reason in $SUBSTRATE_REASON.
#   require_substrate <cluster>    substrate_ok or skip. Whole-script gate.
#   live_tail_skip <reason>        print the tail's SKIP line, record it so the
#                                  final PASS line names the unobserved tail.
#   selfcheck_absent <script> <tool>...
#                                  re-run <script> with <tool>... unreachable and
#                                  require exit 3 with a SKIP: last line, so the
#                                  could-not-look branch is observed, not assumed.
# Offline-proof scripts gate only their live tail: `if substrate_ok x; then
# ... else live_tail_skip "$SUBSTRATE_REASON"; fi`, then `pass_line "<claim>"`,
# which exits 3 (SKIP) if any tail was skipped, 0 only when every tail was observed.
skip() { echo "SKIP: $*"; exit 3; }

substrate_ok() {
  local c="$1" ready
  SUBSTRATE_REASON=""
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
    || { SUBSTRATE_REASON="docker is not reachable"; return 1; }
  command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx "$c" \
    || { SUBSTRATE_REASON="kind cluster '$c' is not listed by kind get clusters"; return 1; }
  ready="$(timeout 30 kubectl --context "kind-$c" -n flux-system get kustomization \
    -o jsonpath='{range .items[*]}{.metadata.name}={.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null)" \
    || { SUBSTRATE_REASON="cannot list Flux kustomizations on kind-$c"; return 1; }
  [ -n "$ready" ] || { SUBSTRATE_REASON="Flux has no Kustomization in flux-system on kind-$c"; return 1; }
  grep -v '=True$' <<<"$ready" | grep -q . \
    && { SUBSTRATE_REASON="Flux not Ready on kind-$c: $(grep -v '=True$' <<<"$ready" | tr '\n' ' ')"; return 1; }
  return 0
}

require_substrate() { substrate_ok "$1" || skip "$SUBSTRATE_REASON"; }

LIVE_TAIL_SKIPPED=""
live_tail_skip() { echo "SKIP (live tail): $*"; LIVE_TAIL_SKIPPED="$*"; }

# pass_line <claim>: the final line. Exit 0 only when every tail was observed;
# a skipped tail makes the script's outcome SKIP (exit 3), never PASS.
pass_line() {
  if [ -n "$LIVE_TAIL_SKIPPED" ]; then echo "SKIP: offline proof holds; live tail could not look: $LIVE_TAIL_SKIPPED — $*"; exit 3; fi
  echo "PASS: $*"
}

# selfcheck_absent <script> <tool>...  (ecosystem ticket 76, "every green rests on an
# observation"). A script's could-not-look branch only runs on a machine that lacks the
# instrument, so on every machine that has it the branch is untested and can rot back to
# `exit 0` -- which verify-all.sh grades PASS, a green on an absence. This runs the branch:
# it re-executes <script> with <tool>... unreachable and requires exit 3 with a "SKIP: "
# last line. The tools are hidden by rebuilding each PATH directory that holds one as a farm
# of symlinks to its other entries, so the neighbours stay reachable (homebrew's python3,
# with pyyaml, lives in the same directory as kyverno and cosign).
#
# Prints one ok line and returns 0 when the branch holds; prints FAIL and exits 1 when it
# does not. A no-op inside the child re-run. Callers cd to their own directory first and
# pass "$PWD/${BASH_SOURCE##*/}" so the child re-runs the same file.
selfcheck_absent() {
  local script="$1"; shift
  [ -z "${PAV_SELFCHECK_CHILD:-}" ] || return 0
  local names="$*" hidden=" $* " farm sub dir f keep="" out rc=0 last
  farm="$(mktemp -d)"
  local IFS=:
  for dir in $PATH; do
    sub=""
    for f in "$@"; do if [ -x "$dir/$f" ]; then sub=hide; fi; done
    if [ "$sub" = hide ]; then
      sub="$farm/$(printf '%s' "$dir" | tr / _)"
      mkdir -p "$sub"
      for f in "$dir"/*; do
        case "$hidden" in *" ${f##*/} "*) ;; *) ln -s "$f" "$sub/" 2>/dev/null || true ;; esac
      done
      keep="${keep:+$keep:}$sub"
    else
      keep="${keep:+$keep:}$dir"
    fi
  done
  IFS=$' \t\n'
  out="$(PAV_SELFCHECK_CHILD=1 PATH="$keep" "${BASH:-bash}" "$script" 2>&1)" || rc=$?
  rm -rf "$farm"
  last="$(printf '%s\n' "$out" | tail -1)"
  case "$rc:$last" in
    3:SKIP:*) echo "  ok   selfcheck: with $names unreachable this script exits 3 and its last line is SKIP:" ;;
    *) echo "FAIL: selfcheck: with $names unreachable ${script##*/} exited $rc (want 3), last line: ${last:0:120}"
       exit 1 ;;
  esac
}
