#!/usr/bin/env bash
# cs-13: creates one signed annotated tag per entry in tags.json, all on the
# current HEAD. Runs after cut-release-refuse-existing.sh has already
# checked every tag in the list absent, so a failure partway through this
# step still leaves nothing pushed (push is a separate, later step).
#
# CUT_RELEASE_TEST_MODE=1 swaps gitsign for a plain unsigned annotated tag,
# so the offline twin (verify-cut-release-tags.sh) can exercise the same
# ordering/atomicity logic without a live Actions OIDC identity. Signing
# itself stays CI-only -- this estate's rule that only CI holds the signing
# identity (spec.md, "Module shape").
set -euo pipefail
tags_json="${1:?usage: cut-release-create-tags.sh <tags.json>}"

jq -c '.[]' "$tags_json" | while IFS= read -r entry; do
  tag=$(jq -r '.tag' <<<"$entry")
  message=$(jq -r '.message' <<<"$entry")
  if [ "${CUT_RELEASE_TEST_MODE:-}" = "1" ]; then
    git tag -a "${tag}" -m "${message}"
  else
    git -c gpg.format=x509 -c gpg.x509.program=gitsign \
      -c user.name="policy-as-versioned release bot" \
      -c user.email="releases@${GITHUB_REPOSITORY_OWNER}.invalid" \
      tag -s "${tag}" -m "${message}"
  fi
  echo "tagged ${tag}"
done
