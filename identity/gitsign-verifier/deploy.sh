#!/usr/bin/env bash
# Idempotent bring-up of the gitsign-verifier controller on a KinD cluster,
# plus the offline git server that gives its live tail real material: this
# repo's own gitsign-signed tag (policy/v3.0.0), fetched over smart HTTP
# inside the cluster -- not a stand-in. Same shape as
# ../../driftwood/scripts/up.sh's git-server step: build an image from a
# bare clone, kind-load it, apply, restart so the pod always serves what
# this run just built.
#
# Ticket 41 / verify-source-verification.sh section 10. Re-runnable.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"
TS="$HERE/testserver"
CLUSTER="${CLUSTER:-driftwood}"
CTX="kind-$CLUSTER"
WORK="$TS/.work"

command -v kind >/dev/null && command -v kubectl >/dev/null && command -v docker >/dev/null \
  || { echo "need kind, kubectl, docker on PATH" >&2; exit 1; }
kind get clusters | grep -qx "$CLUSTER" || { echo "no KinD cluster '$CLUSTER'" >&2; exit 1; }

echo "== building the tag-server image from this repo's own .git =="
rm -rf "$WORK"; mkdir -p "$WORK/ctx"
git -C "$PLATFORM" clone -q --bare "$PLATFORM" "$WORK/ctx/platform.git"
cp "$TS/Dockerfile" "$TS/lighttpd.conf" "$WORK/ctx/"
docker build -q -t gitsign-tag-server:local "$WORK/ctx" >/dev/null
kind load docker-image gitsign-tag-server:local --name "$CLUSTER"

echo "== applying the tag server =="
kubectl --context "$CTX" apply -f "$TS/deployment.yaml"
if kubectl --context "$CTX" -n flux-system get deploy gitsign-tag-server >/dev/null 2>&1; then
  kubectl --context "$CTX" -n flux-system rollout restart deploy/gitsign-tag-server
fi
kubectl --context "$CTX" -n flux-system rollout status deploy/gitsign-tag-server --timeout=120s

echo "== applying the gitsign-verifier controller package =="
# ponytail: a stock python:3.13-alpine image + `apk add git openssl` at pod
# start (see deployment.yaml) rather than a built image -- this controller is
# time-boxed to die at Flux #1068 and this estate cuts it no release train.
# Observed live 2026-08-31: KinD pods here reach the alpine mirrors fine, so
# this is not a network gap on this machine; `kind load docker-image` of the
# base is a belt-and-braces step so pod start never races a registry pull.
docker pull -q python:3.13-alpine@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d >/dev/null
# best-effort: kind's `ctr images import --all-platforms` chokes on this
# manifest list's non-host digests even though the host image is present and
# pods here have their own egress to pull it directly (observed 2026-08-31).
# Not fatal -- the node falls back to pulling it itself, which works.
kind load docker-image python:3.13-alpine@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d --name "$CLUSTER" \
  || echo "  (kind load of the base image failed; the node will pull it directly instead)"
kubectl --context "$CTX" apply -k "$HERE"
kubectl --context "$CTX" -n flux-system rollout restart deploy/gitsign-verifier 2>/dev/null || true
kubectl --context "$CTX" -n flux-system rollout status deploy/gitsign-verifier --timeout=120s

echo "== applying the watched GitRepository (real signed tag, real pins) =="
RE="$(sed -n 's/^  EXPECTED_IDENTITY_REGEXP: //p' "$PLATFORM/.github/workflows/release.yml")"
ISS="$(sed -n 's/^  EXPECTED_ISSUER: //p' "$PLATFORM/.github/workflows/release.yml")"
[ -n "$RE" ] && [ -n "$ISS" ] || { echo "release.yml carries no identity pins to read" >&2; exit 1; }
# python str.replace, not sed: RE is full of literal backslashes (\.) that a
# sed replacement string would reinterpret as escapes/backreferences.
RE="$RE" ISS="$ISS" python3 -c '
import os, pathlib
t = pathlib.Path(os.sys.argv[1]).read_text()
t = t.replace("%%IDENTITY_REGEXP%%", os.environ["RE"]).replace("%%ISSUER%%", os.environ["ISS"])
print(t)
' "$TS/gitrepository.yaml.tmpl" | kubectl --context "$CTX" apply -f -

echo "== done; the controller reconciles every INTERVAL (60s) =="
