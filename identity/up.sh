#!/usr/bin/env bash
# Idempotent bring-up of the identity substrate (SPIRE + Istio + OpenBao) onto
# the EXISTING driftwood KinD cluster, delivered as inherited platform machinery
# via Flux HelmReleases. Re-runnable at a venue. Never creates/deletes a cluster.
#
# Drives everything through Flux's helm-controller (installed by driftwood/up.sh),
# so the HelmRelease YAML is the single source of truth — no duplicated helm flags.
# Every reconcile is `timeout`-bounded: nothing hangs; a slow image pull just
# means "re-run up.sh", it never blocks the tour.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTX="${CTX:-kind-driftwood}"
KAPPLY() { kubectl --context "$CTX" apply -f "$@"; }
RECON()  { timeout 300 flux --context "$CTX" reconcile helmrelease -n "$1" "$2" || \
             echo "  (reconcile of $2 not finished within timeout — safe to re-run up.sh)"; }
say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

for c in kubectl flux; do command -v "$c" >/dev/null || { echo "MISSING cli: $c" >&2; exit 1; }; done
kubectl --context "$CTX" version >/dev/null 2>&1 || { echo "driftwood cluster not reachable ($CTX); run estate/driftwood/scripts/up.sh first" >&2; exit 1; }
flux check --context "$CTX" >/dev/null 2>&1 || { echo "Flux not installed on $CTX; run driftwood/up.sh first" >&2; exit 1; }

say "namespaces"
KAPPLY "$HERE/namespaces.yaml"

say "SPIRE (server + agent + controller-manager + csi + oidc)"
KAPPLY "$HERE/spire/helmrelease.yaml"
RECON spire-system spire-crds
RECON spire-system spire

# The agent caches the trust bundle in its data dir and PREFERS that cache over
# the freshly-projected `spire-bundle` ConfigMap. The chart backs that data dir
# with an emptyDir, so the cache survives every container restart but not pod
# recreation. If the server rotates its X509 CA while the agent is down, the
# cached bundle goes stale and the agent crashloops forever on
#   "x509svid: could not verify leaf certificate: certificate signed by unknown authority"
# — nothing re-reads the ConfigMap, so it never recovers on its own. Observed
# live on driftwood 2026-08-28 after an 8-day crashloop, which left every meshed
# sidecar without an SDS socket. Recreating the pod clears the cache.
# ponytail: blunt pod delete; the upstream fix is the agent falling back to
# trust_bundle_path when the cached bundle fails to verify the server.
say "SPIRE agent Ready (recreate if it is stuck on a stale cached trust bundle)"
DS_READY() { timeout 180 kubectl --context "$CTX" -n spire-system rollout status ds/spire-agent --timeout=150s; }
DS_READY || {
  echo "  spire-agent not Ready — deleting its pods to drop the cached trust bundle"
  kubectl --context "$CTX" -n spire-system delete pod -l app.kubernetes.io/name=agent,app.kubernetes.io/instance=spire --wait=false || true
  DS_READY || echo "  (spire-agent still not Ready — safe to re-run up.sh)"
}

say "Istio, consuming SPIRE identity (SPIRE Workload API socket integration)"
KAPPLY "$HERE/istio/helmrelease.yaml"
RECON istio-system istio-base
RECON istio-system istiod

say "OpenBao (dev-mode secret plane)"
KAPPLY "$HERE/openbao/helmrelease.yaml"
RECON openbao openbao

# CRD-dependent objects — apply after the charts have registered their CRDs.
# Best-effort: if a CRD isn't up yet, re-running up.sh applies these cleanly.
say "identity config: base ClusterSPIFFEID, STRICT mTLS, OpenBao jwt seam"
KAPPLY "$HERE/spire/clusterspiffeid-mesh.yaml" || echo "  (ClusterSPIFFEID CRD not ready — re-run up.sh)"
KAPPLY "$HERE/istio/peerauthentication-strict.yaml" || echo "  (Istio CRDs not ready — re-run up.sh)"
KAPPLY "$HERE/openbao/jwt-auth.yaml"

say "mTLS proof workloads (ping -> pong, SPIFFE AuthorizationPolicy)"
KAPPLY "$HERE/demo-mtls/workloads.yaml"
KAPPLY "$HERE/demo-mtls/authorizationpolicy.yaml" || echo "  (Istio CRDs not ready — re-run up.sh)"

# A sidecar admitted while the SPIRE agent had no socket never recovers: the
# `spire` inject template mounts the CSI volume read-only over
# /var/run/secrets/workload-spiffe-uds, so when pilot-agent falls back to
# serving its own SDS there it gets EROFS, gives up after a few tries
# ("SDS grpc server could not be started"), and Envoy stays un-Ready for the
# life of the pod. Restart any demo Deployment that did not come Ready so it is
# re-admitted against a working agent.
for d in pong ping; do
  timeout 180 kubectl --context "$CTX" -n mesh-demo rollout status deploy/"$d" --timeout=150s || {
    echo "  $d has no Ready sidecar — restarting so it is re-admitted"
    kubectl --context "$CTX" -n mesh-demo rollout restart deploy/"$d" || true
    timeout 180 kubectl --context "$CTX" -n mesh-demo rollout status deploy/"$d" --timeout=150s \
      || echo "  ($d still not Ready — safe to re-run up.sh)"
  }
done

say "done. verify with estate/platform/identity/verify-identity.sh"
