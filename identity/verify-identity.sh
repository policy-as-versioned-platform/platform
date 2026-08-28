#!/usr/bin/env bash
# Assert the identity substrate holds together. Two layers:
#   OFFLINE (always) — every manifest parses, and the load-bearing wiring is
#     present: SPIRE is Istio's CA, mTLS is STRICT, authz matches SPIFFE
#     principals, OpenBao's jwt auth points at SPIRE's OIDC JWKS, and the
#     SPIRE agent socket is exposed for Envoy's SDS.
#   LIVE (only if the substrate is already up) — SPIRE/istiod/openbao pods
#     exist and ping reaches pong over SPIFFE mTLS. Bounded; skipped otherwise.
# Exits non-zero if any invariant the talk relies on is broken.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line: three outcomes per live tail
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== offline: structural invariants =="
python3 - "$HERE" <<'PY'
import sys, glob, os
try:
    import yaml
except ImportError:
    sys.exit("PyYAML not available; `pip install pyyaml` to run the offline check")
root = sys.argv[1]
docs = []
for f in glob.glob(os.path.join(root, "**", "*.yaml"), recursive=True):
    with open(f) as fh:
        for d in yaml.safe_load_all(fh):
            if d: docs.append((os.path.relpath(f, root), d))
assert docs, "no manifests parsed"

def find(kind, name=None):
    return [d for _, d in docs if d.get("kind") == kind and (name is None or d.get("metadata", {}).get("name") == name)]

fails = []
def check(cond, msg):
    if not cond: fails.append(msg)
    print(("  ok   " if cond else "  FAIL ") + msg)

# SPIRE stood up, with controller-manager + oidc + csi enabled.
spire = find("HelmRelease", "spire")
check(bool(spire), "SPIRE HelmRelease present")
v = spire[0]["spec"]["values"] if spire else {}
check(v.get("spire-server", {}).get("controllerManager", {}).get("enabled") is True,
      "spire-controller-manager enabled (renders ClusterSPIFFEID -> entries)")
check(v.get("spiffe-oidc-discovery-provider", {}).get("enabled") is True,
      "SPIRE OIDC Discovery Provider enabled (JWKS for OpenBao)")
check(v.get("spiffe-csi-driver", {}).get("enabled") is True,
      "spiffe-csi-driver enabled (mounts agent socket into meshed pods)")
td = v.get("global", {}).get("spire", {}).get("trustDomain")
check(td == "acme.internal", f"trust domain is the one estate root (acme.internal), got {td!r}")
agent_sock = v.get("spire-agent", {}).get("socketPath", "")
check(agent_sock.startswith("/run/spire/agent-sockets/"), f"agent socket exposed for Envoy SDS ({agent_sock})")

# Istio consumes SPIRE identity for WORKLOADS, but istiod still needs its own
# CA server to mint its control-plane/webhook serving cert (ticket 04). NOTE:
# global.caName is a no-op on Istio 1.24 (only ever consulted for
# GkeWorkloadCertificate) — it must stay deleted, not asserted. What actually
# makes SPIRE the mesh CA for workloads: sidecar injection mounts the SPIRE
# workload socket at Envoy's well-known SDS path (see istio/helmrelease.yaml
# and https://istio.io/latest/docs/ops/integrations/spire/).
istiod = find("HelmRelease", "istiod")
check(bool(istiod), "istiod HelmRelease present")
iv = istiod[0]["spec"]["values"] if istiod else {}
check("caName" not in iv.get("global", {}),
      "global.caName is absent (it's a no-op on Istio 1.24 and must not be reintroduced)")
check(iv.get("pilot", {}).get("env", {}).get("ENABLE_CA_SERVER") != "false",
      "istiod's own CA server is NOT disabled — it must mint its own webhook serving cert "
      "(ENABLE_CA_SERVER: false was the ticket-04 bug: no CA bundle ever loads, webhook fails "
      "\"tls: internal error\")")
check(iv.get("meshConfig", {}).get("trustDomain") == "acme.internal",
      "meshConfig.trustDomain matches SPIRE's trust domain (acme.internal, not the cluster.local default)")
spire_tmpl = iv.get("sidecarInjectorWebhook", {}).get("templates", {}).get("spire", "")
check("csi.spiffe.io" in spire_tmpl and "/run/secrets/workload-spiffe-uds" in spire_tmpl,
      "sidecar injection mounts the SPIRE workload socket at Envoy's SDS default path (this, not caName, makes SPIRE the mesh CA)")
check("spiffe.io/spire-managed-identity" in spire_tmpl,
      "spire injection template carries the spiffe.io/spire-managed-identity label block")

# STRICT mesh mTLS.
pa = find("PeerAuthentication", "default")
check(bool(pa) and pa[0]["spec"]["mtls"]["mode"] == "STRICT", "mesh-wide PeerAuthentication STRICT")

# Base identity template + authz on SPIFFE principals.
csid = find("ClusterSPIFFEID", "mesh-base")
check(bool(csid), "base ClusterSPIFFEID present")
tmpl = csid[0]["spec"]["spiffeIDTemplate"] if csid else ""
check("spiffe://" in tmpl and "TrustDomain" in tmpl, "SVID template derives a spiffe:// path from pod/ns/sa")
# ticket 11 (live-discovered): the spire chart scopes its controller-manager
# to className "<release-namespace>-<release-name>" and runs with "handle
# crs without class name: false" — a ClusterSPIFFEID with no className is
# never reconciled at all (no error, .status.stats stays empty forever).
# Confirmed live: this object minted zero registration entries since it was
# first applied; the chart's own same-shaped fallback CSID
# (<release>-default) was producing the base-identity SVIDs the estate had
# been crediting to this file.
check(csid[0]["spec"].get("className") not in (None, ""),
      "className set, so spire-controller-manager actually reconciles this object")
ap = find("AuthorizationPolicy", "pong-allow-ping")
check(bool(ap), "AuthorizationPolicy present")
prin = ap[0]["spec"]["rules"][0]["from"][0]["source"]["principals"] if ap else []
# Scheme-less: Istio's AuthorizationPolicy takes "<trustDomain>/ns/<ns>/sa/<sa>"
# and prepends "spiffe://" itself when building the Envoy RBAC matcher — a
# "spiffe://"-prefixed value here double-prefixes to an unmatchable principal
# (ticket 04/11 finding; https://istio.io/latest/docs/reference/config/security/authorization-policy/).
check(any(p.startswith("acme.internal/") for p in prin),
      f"authz admits by SPIFFE principal, not IP ({prin})")
check(not any(p.startswith("spiffe://") for p in prin),
      f"authz principal is scheme-less, not double-prefixed ({prin})")

# OpenBao running + jwt auth wired to SPIRE OIDC (the secret-plane seam).
check(bool(find("HelmRelease", "openbao")), "OpenBao HelmRelease present")
job = find("Job", "openbao-jwt-setup")
check(bool(job), "OpenBao jwt-auth setup Job present")
args = "".join(job[0]["spec"]["template"]["spec"]["containers"][0].get("args", [])) if job else ""
check("oidc_discovery_url" in args and "spire-spiffe-oidc-discovery-provider" in args,
      "OpenBao jwt auth points at SPIRE's OIDC Discovery Provider JWKS")
# ticket 32, live-discovered: this Job had been Failed for 27 days because the
# URL was http:// against a Service that publishes 443 only, so OpenBao's jwt
# method was never enabled while this script's PASS line claimed it was. The
# three facts that make it reachable, asserted so it cannot silently rot back:
check("https://" in args,
      "the discovery URL is https (the provider serves TLS on :8443; the Service publishes 443 only)")
check("spire-spiffe-oidc-discovery-provider.spire-system\"" in args
      or "spire-spiffe-oidc-discovery-provider.spire-system " in args,
      "the discovery host is <svc>.spire-system -- the ONLY name in both the provider's "
      "`domains` list and its serving cert's DNS SANs")
check("oidc_discovery_ca_pem" in args,
      "the SPIRE trust bundle is pinned as the CA (its cert chains to no public root)")
check(any(v.get("configMap", {}).get("name") == "spire-bundle"
          for v in (job[0]["spec"]["template"]["spec"].get("volumes") or [])) if job else False,
      "the Job mounts the spire-bundle ConfigMap (which is why it runs in spire-system)")

# The package: one directory, one version, one set of claims (ticket 32).
import json
pkg = os.path.join(root)
ver_file = os.path.join(pkg, "VERSION")
check(os.path.exists(ver_file), "the package carries its own VERSION")
version = open(ver_file).read().strip() if os.path.exists(ver_file) else ""
cdpath = os.path.join(pkg, "component-definition.json")
check(os.path.exists(cdpath), "the package carries OSCAL control claims (component-definition.json)")
if os.path.exists(cdpath) and version:
    cd = json.load(open(cdpath))["component-definition"]
    check(cd["metadata"]["version"] == version,
          f"claims and bits carry the SAME version ({version!r}) -- a package that versions "
          f"its claims separately is two packages wearing one name")
kpath = os.path.join(pkg, "kustomization.yaml")
check(os.path.exists(kpath), "the package declares its membership (kustomization.yaml)")
if os.path.exists(kpath):
    members = yaml.safe_load(open(kpath)).get("resources", [])
    for m in ["namespaces.yaml", "spire/helmrelease.yaml", "spire/clusterspiffeid-mesh.yaml",
              "istio/helmrelease.yaml", "openbao/helmrelease.yaml", "openbao/jwt-auth.yaml"]:
        check(m in members, f"package membership includes {m}")
    check(not any(m.startswith("demo-mtls") for m in members),
          "the ping->pong mTLS PROOF is not shipped as substrate")
    check(not any(m.startswith("federation") for m in members),
          "federation/ is not shipped wholesale -- each org applies its own file, not all four")

# The SVID path carries the cage tier (ticket 32 / ticket 12 answer 2). The
# posture ClusterSPIFFEID lives under ../posture/spire because posture/up.sh
# and posture/verify-posture-projection.sh load it from there; it is still a
# member of this package (see flux-pin.yaml) so its shape is asserted here.
ppath = os.path.normpath(os.path.join(root, "../posture/spire/clusterspiffeid-posture.yaml"))
if os.path.exists(ppath):
    with open(ppath) as fh:
        tmpl = next(d for d in yaml.safe_load_all(fh) if d)["spec"]["spiffeIDTemplate"]
    check("/cage/" in tmpl and tmpl.index("/posture/") < tmpl.index("/cage/") < tmpl.index("/ns/"),
          "SVID path is /posture/<version>/cage/<tier>/ns/<ns>/sa/<sa>")
    check('posture.acme.io/tier' in tmpl,
          "the tier segment reads the label cage-tier renders from the governed Namespace "
          "(one render, no second policy)")
    check('"isolated"' in tmpl,
          "a pod with no tier label falls closed to `isolated`, never to an empty segment "
          "and never to baseline")
else:
    fails.append("posture ClusterSPIFFEID not found at ../posture/spire/")
    print("  FAIL posture ClusterSPIFFEID not found at ../posture/spire/")

if fails:
    sys.exit(f"\n{len(fails)} invariant(s) broken")
print("  -- all offline invariants hold --")
PY

# Bonus: kubectl client-side schema check on core kinds (no cluster mutation).
if command -v kubectl >/dev/null; then
  echo "== offline: kubectl dry-run (core kinds) =="
  kubectl apply --dry-run=client -f "$HERE/namespaces.yaml" >/dev/null && echo "  ok   namespaces dry-run" || echo "  (dry-run needs a reachable cluster; skipped)"
fi

# LIVE proof — only if the substrate is already up; strictly bounded, never hangs.
# NOTE: every check below captures kubectl's output into a variable first,
# THEN greps/heads the variable — never `kubectl ... | grep -q ...` directly.
# `grep -q`/`head -N` exit as soon as they see a match/line, SIGPIPEing the
# still-writing kubectl on the other end of the pipe; under `pipefail` that
# turns a PASSING check into a coin-flip FAIL (found live, debugging this
# ticket's own new checks — a real, if minor, instance of the ticket-01 bug
# class: a gate whose failure meant nothing).
if ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" get ns spire-system >/dev/null 2>&1; then
  live_tail_skip "identity substrate not installed on $CTX (run identity/up.sh)"
else
  echo "== live: substrate + mTLS proof =="
  OUT=$(timeout 20 kubectl --context "$CTX" -n spire-system get pods 2>/dev/null)
  echo "$OUT" | grep -q spire && echo "  ok   SPIRE pods present" || fail "SPIRE pods not present"

  # "present" is not "working": this pod list read `spire-agent ... CrashLoopBackOff`
  # for eight days while every check below still passed, because the agent had
  # cached a trust bundle that the server's rotated CA no longer matched
  # (identity/up.sh now clears it). No agent means no Workload API socket, so
  # every meshed sidecar loses SDS. Assert the DaemonSet is actually Ready.
  READY=$(timeout 20 kubectl --context "$CTX" -n spire-system get ds spire-agent \
    -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}' 2>/dev/null)
  case "$READY" in
    0/*|/*|"") fail "spire-agent DaemonSet has no Ready pod ($READY) — no SPIFFE Workload API socket for Envoy SDS" ;;
    *) [ "${READY%%/*}" = "${READY##*/}" ] && echo "  ok   spire-agent DaemonSet fully Ready ($READY)" \
         || fail "spire-agent DaemonSet not fully Ready ($READY)" ;;
  esac

  # istiod comes up: not merely present (it ran 1/1 the whole time ticket 04's
  # bug was live) but with an available replica.
  AVAIL=$(timeout 20 kubectl --context "$CTX" -n istio-system get deploy istiod \
    -o jsonpath='{.status.availableReplicas}' 2>/dev/null)
  echo "$AVAIL" | grep -qE '^[1-9]' && echo "  ok   istiod has an available replica" || fail "istiod has no available replica"

  # the webhook serves: its caBundle must be populated. This is exactly what
  # ENABLE_CA_SERVER: false left empty ("Failed to load CA bundle: could not
  # decode pem" -> the webhook patch controller never wrote a caBundle here).
  CABUNDLE_LEN=$(timeout 20 kubectl --context "$CTX" get mutatingwebhookconfiguration istio-sidecar-injector \
    -o jsonpath='{.webhooks[0].clientConfig.caBundle}' 2>/dev/null | wc -c | tr -d ' ')
  [ "${CABUNDLE_LEN:-0}" -gt 100 ] && echo "  ok   sidecar-injector webhook has a populated caBundle (serves)" \
    || fail "sidecar-injector webhook caBundle is empty — it is not serving"

  OUT=$(timeout 20 kubectl --context "$CTX" -n openbao get pods 2>/dev/null)
  echo "$OUT" | grep -q openbao && echo "  ok   OpenBao present" || fail "OpenBao not present"

  # "present" is not "wired". For 27 days this script's PASS line said "OpenBao
  # trusts SPIRE JWKS" while the jwt-setup Job was Failed and `bao auth list`
  # showed nothing but token/ — the offline check above only ever proved the
  # Job's ARGS mentioned the right words. Observe the auth method itself.
  AUTHS=$(timeout 20 kubectl --context "$CTX" -n openbao exec openbao-0 -c openbao -- \
    sh -c 'BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root bao auth list' 2>/dev/null)
  echo "$AUTHS" | grep -q '^jwt/' \
    && echo "  ok   OpenBao's jwt auth method is ENABLED (bao auth list)" \
    || fail "OpenBao has no jwt auth method enabled — run identity/up.sh (dev-mode OpenBao is in-memory: a pod restart wipes it)"

  # ...and that it points at SPIRE, not at some other issuer. `status valid`
  # is OpenBao's own word for "I fetched and parsed that discovery document",
  # so this is the JWKS trust observed rather than asserted.
  JWTCFG=$(timeout 20 kubectl --context "$CTX" -n openbao exec openbao-0 -c openbao -- \
    sh -c 'BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root bao read auth/jwt/config' 2>/dev/null)
  echo "$JWTCFG" | grep -q 'oidc_discovery_url .*https://spire-spiffe-oidc-discovery-provider' \
    || fail "OpenBao's jwt auth is not configured against SPIRE's OIDC Discovery Provider: $(echo "$JWTCFG" | tr '\n' ' ')"
  # `status valid` is OpenBao's own word for "I fetched and parsed that discovery
  # document". Until 2026-08-28 this line PRINTED "(status valid)" while only the
  # configured URL string had been grepped -- the phrase was never read out of
  # the command's output at all. Read it.
  echo "$JWTCFG" | grep -qE '^status[[:space:]]+valid' \
    || fail "OpenBao's jwt auth points at SPIRE but its discovery status is not valid: $(echo "$JWTCFG" | grep -E '^status' || echo 'no status line at all')"
  echo "  ok   OpenBao's jwt auth resolves SPIRE's OIDC discovery document over TLS (bao itself reports status valid)"

  # A configured default_role that does not exist means nothing can ever log in.
  # Found live 2026-08-28: default_role was `posture`, the role was absent (the
  # Job that creates it had been Failed for hours), and this script was green.
  ROLE=$(echo "$JWTCFG" | awk '$1 == "default_role" { print $2 }')
  [ -n "$ROLE" ] && [ "$ROLE" != "n/a" ] \
    || fail "OpenBao's jwt auth declares no default_role, so no JWT-SVID can be exchanged for a token"
  timeout 20 kubectl --context "$CTX" -n openbao exec openbao-0 -c openbao -- \
    sh -c "BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root bao read auth/jwt/role/$ROLE" >/dev/null 2>&1 \
    || fail "OpenBao's jwt auth names default_role '$ROLE' and that role DOES NOT EXIST — the trust is configured but nothing can authenticate through it"
  echo "  ok   its default_role '$ROLE' really exists, so the trust is usable and not just configured"

  # A Failed setup Job must not sit under a green, even when its effect happens
  # to be present from an earlier run.
  JOBSTATE=$(timeout 20 kubectl --context "$CTX" -n openbao get job openbao-reset-role \
    -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || true)
  [ "$JOBSTATE" != "True" ] \
    || fail "the openbao-reset-role Job is Failed on $CTX — the role above is a leftover, not a reconciled fact"

  # The cage tier is really in the SVID path on this cluster, not just in the
  # file. A ClusterSPIFFEID the controller-manager never reconciled would leave
  # the old template live and nothing would say so (ticket 11's lesson).
  LIVETMPL=$(timeout 20 kubectl --context "$CTX" get clusterspiffeid posture \
    -o jsonpath='{.spec.spiffeIDTemplate}' 2>/dev/null)
  case "$LIVETMPL" in
    *"/cage/"*) echo "  ok   live posture ClusterSPIFFEID carries the /cage/<tier> segment" ;;
    "")         fail "no posture ClusterSPIFFEID on $CTX (run posture/up.sh)" ;;
    *)          fail "live posture ClusterSPIFFEID still has the pre-ticket-32 path: $LIVETMPL" ;;
  esac

  # a meshed pod schedules with a real SPIFFE SVID: the webhook must actually
  # have injected istio-proxy (2/2, not admission-only), and that proxy's own
  # workload cert must carry a spiffe://acme.internal/... SAN.
  PODS=$(timeout 20 kubectl --context "$CTX" -n mesh-demo get pod -l app=ping -o name 2>/dev/null)
  P=$(echo "$PODS" | head -1)
  if [ -n "$P" ]; then
    READY=$(timeout 20 kubectl --context "$CTX" -n mesh-demo get "$P" -o jsonpath='{.status.containerStatuses[?(@.name=="istio-proxy")].ready}' 2>/dev/null)
    [ "$READY" = "true" ] && echo "  ok   ping's istio-proxy sidecar is injected and Ready" \
      || fail "ping has no Ready istio-proxy sidecar — webhook did not inject"
    CERTS=$(timeout 20 kubectl --context "$CTX" -n mesh-demo exec "$P" -c istio-proxy -- pilot-agent request GET certs 2>/dev/null)
    echo "$CERTS" | grep -q 'spiffe://acme\.internal/ns/mesh-demo/sa/ping' && echo "  ok   ping's proxy holds a real SVID (spiffe://acme.internal/ns/mesh-demo/sa/ping)" \
      || fail "ping's proxy has no spiffe://acme.internal SVID"
    # ticket 04 found, ticket 11 fixed: authorizationpolicy.yaml's `principals`
    # is now scheme-less (see the offline check above), so Istio's own
    # "spiffe://" prepend renders a matchable principal and this call reaches.
    CODE=$(timeout 20 kubectl --context "$CTX" -n mesh-demo exec "$P" -c ping -- curl -sS -o /dev/null -w '%{http_code}' pong.mesh-demo/ 2>/dev/null)
    echo "$CODE" | grep -q 200 && echo "  ok   ping -> pong over SPIFFE mTLS (200)" || fail "ping -> pong over SPIFFE mTLS did not return 200"
  else
    # live_tail_skip, not a bare echo: a bare echo left LIVE_TAIL_SKIPPED empty,
    # so pass_line still printed PASS claiming "mTLS STRICT, authz by SPIFFE
    # principal" when ping->pong had never been run (review, 2026-08-28).
    live_tail_skip "no app=ping pod in mesh-demo on $CTX: the SVID + mTLS reach was not observed"
  fi
fi
# The claim names only what was observed. "OpenBao trusts SPIRE JWKS" used to
# be asserted from the Job's argument strings while the Job itself had been
# Failed for 27 days; it is now `bao auth list` plus `bao read auth/jwt/config`
# read off the running OpenBao. Federation is NOT in this line — no peer trust
# domain serves a bundle endpoint, and verify-federation.sh exits 3 saying so.
pass_line "SPIRE is Istio's CA, mTLS STRICT, authz by SPIFFE principal, the SVID path carries posture/<version>/cage/<tier>, and OpenBao's jwt auth is enabled against SPIRE's OIDC discovery over TLS"
