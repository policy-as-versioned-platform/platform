#!/usr/bin/env bash
# diagnose.sh: what a red run needs in its log. Called by up.sh and proof.sh; it never fails.
k() { kubectl --context kind-loop "$@"; }
k get pods,networkpolicy -A -o wide || true
k get mutatingpolicies.policies.kyverno.io,generatingpolicies.policies.kyverno.io \
  -o jsonpath='{range .items[*]}{.kind}/{.metadata.name} {.status}{"\n"}{end}' || true
