# The WAF sidecar cage-tier injects at every hardened rung (restricted,
# quarantine, isolated) is `ghcr.io/acme/coraza-waf:cage` -- a PLACEHOLDER for
# the estate's real Coraza sidecar (graded/README.md, "Calibration knobs").
# That repository does not exist, so until 2026-08-28 every pod in a hardened
# Namespace sat in ErrImagePull for ever: the cage was a refusal in effect,
# which NORTH-STAR §4 step 4 ("the workload keeps running") says it must never
# be. up.sh builds this stand-in under the placeholder's own name and loads it
# into the KinD node, so the sidecar the cage adds actually starts.
#
# Numeric USER is load-bearing: the cage writes runAsNonRoot: true on every
# container it injects, and the kubelet refuses an image whose USER is a name
# it cannot resolve to a uid.
#
# ponytail: a sleeping busybox is not a WAF -- it proves the cage runs, not
# that it inspects traffic. Swap the FROM for the real Coraza sidecar image
# when the estate has one; nothing else here changes.
FROM busybox:1.36
USER 65532
ENTRYPOINT ["sleep", "infinity"]
