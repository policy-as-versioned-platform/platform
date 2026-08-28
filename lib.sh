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
# Offline-proof scripts gate only their live tail: `if substrate_ok x; then
# ... else live_tail_skip "$SUBSTRATE_REASON"; fi`, then `pass_line "<claim>"`.
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

# pass_line <claim>: the final line. Names the live tail as unobserved when it was.
pass_line() {
  if [ -n "$LIVE_TAIL_SKIPPED" ]; then echo "PASS (offline proof only; live tail SKIP: $LIVE_TAIL_SKIPPED): $*"
  else echo "PASS: $*"; fi
}
