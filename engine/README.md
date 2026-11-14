# platform/engine — the admission + fleet controllers

**Ticket 11.** Kyverno (ADR-0003's admission engine) and the ControlPlane
Flux Operator (ADR-0005's install/fleet layer), delivered as Flux
HelmReleases — the same pattern as `identity/` (spire, istio, openbao) and
`access/` (pomerium, dex). Neither was installed anywhere in the repo before
this ticket, even though `estate/driftwood/README.md` and
`estate/platform/distribution/README.md` both name them as prerequisites.

## What's here

| Piece | File | Role |
|---|---|---|
| Kyverno | `kyverno/helmrelease.yaml` | admission controller; installs the `policies.kyverno.io` CRD group (`ValidatingPolicy`, `MutatingPolicy`) every policy in this repo needs |
| Engine table | `kyverno/engine-table.yaml` | every Kyverno version the estate may run, with a sourced sha256 for each CLI archive, `install.yaml` and the Helm chart (hub ADR-0033, ticket 146). Read by `engine_table.py`; `install-kyverno-engines.sh <platform> <dest>` installs every row by checksum. A row supports nothing: a line supports the engines its own `tested_engines` lists |
| Declaration reader | `declaration.py` | reads an adopter's own `gitops/engine/kyverno.yaml`, the engine it declares (hub ADR-0033 point 2, tickets 147 and 148). `compose/composition.py` and `shift-left/ci-check.py` both read it here. An absent file is an undeclared engine; a present file that does not read raises `Malformed`, naming why. `from_table(version)` writes a well-formed declaration from the table's row, for fixtures |
| flux-operator | `flux-operator/helmrelease.yaml` | installs the `ResourceSet`/`FluxInstance` CRDs `estate/platform/distribution` needs; no `FluxInstance` is created, so the cluster's existing vanilla Flux install is untouched (ADR-0005 guardrail) |

## Ordering

Installed **before** the posture layer (`estate/platform/posture/`), which
ships `MutatingPolicy`/`ValidatingPolicy` objects that need Kyverno's CRDs to
exist first. See `estate/talk/up.sh`.

## Run it

```bash
estate/driftwood/scripts/up.sh      # cluster + Flux must exist first
estate/platform/engine/up.sh        # applies both HelmReleases, bounded reconciles
estate/platform/engine/verify-engine.sh
```
