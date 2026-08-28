# platform/graded — the graded enforcement envelope (tiers over dials)

**Ticket 10.** Beyond admit/deny. A workload that falls behind its policy version
is **not denied** — it keeps running, **caged by degree**. Kyverno **mutate +
generate** injects the cage; the £ (`cage.py`) picks *how hard*; the cage's
run-cost is booked to **TCoR**. **Deny is only the bottom rung** — reached when
even the tightest cage leaves a residual over the org's appetite band.

## What's here

| Piece | File | Role |
|---|---|---|
| The £ engine | `cage.py` | Named tiers → dials (deterministic); the £ picks the tier; emits the TCoR ledger line (residual + cost-of-controls). Reuses `../fair/fair.py` and `../risk/enforce.py`. |
| Cage (mutate) | `policies/cage-tier.yaml` | `MutatingPolicy`: every pod that claims a policy version is mutated into a cage — cpu/mem limits, eviction PriorityClass, and (restricted+) drop-ALL caps, read-only-fs, a WAF sidecar. A pod carrying `posture.acme.io/tier` gets that tier; one with no (or an unrecognized) tier defaults to `baseline`, the loosest tier — no uncaged state within that population. A pod claiming no policy version at all (system/COTS) is out of scope, unmatched. Never denies. |
| Per-tier reach (generate) | `policies/cage-netpol.yaml` | `GeneratingPolicy`: a caged non-baseline pod triggers ALL THREE restricting rungs' `NetworkPolicy` objects in its namespace at once, each selecting its own tier — so a tier move is a label change with nothing created or deleted in its path, and `synchronize` is off. Repaired 2026-08-28: with one policy per trigger and synchronize on, Kyverno's watcher deleted every `cage-reach-*` in every OTHER namespace whenever one caged pod was created anywhere. |
| Eviction priority | `policies/priorityclasses.yaml` | Three `PriorityClass`es below the default; tighter tier = evicted sooner under pressure. |
| Tests | `tests/` | `kyverno test` matrices: the cage is a **mutation** (cage present), not a deny; the generate emits the lockdown netpol. |
| Bring-up / verify | `up.sh`, `verify-graded.sh` | idempotent apply (no waits); offline proofs + bounded live tail. |

## Tiers over dials

PSS-style presets over the independent dials Kyverno injects. One table, held in
`cage.py` and mirrored by the Kyverno `dial` map (`verify-graded.sh` step 4 fails
on any drift):

| Tier | cpu / mem | drop caps | read-only fs | WAF sidecar | eviction | risk collapsed | run-cost £/yr |
|---|---|---|---|---|---|---|---|
| `baseline` | 500m / 256Mi | — | — | — | −10 | 30% | 500 |
| `restricted` | 250m / 128Mi | ALL | yes | light (100m) | −100 | 70% | 2,000 |
| `quarantine` | 100m / 64Mi | ALL | yes | heavy (250m) | −1000 | 92% | 6,000 |
| `isolated` | 100m / 64Mi | ALL | yes | heavy (250m) | first | 98% | 15,000 |
| `infra` | — | — | — | — | `system-cluster-critical` | — | — |

`isolated` is quarantine's dials plus **no reach at all** (no ingress, no egress) and
**first eviction** — a running, unreachable cage, the rung `deny` used to occupy
(ADR-0022). `infra` is declared by role on a Namespace manifest by a `platform`-role
party and is never selected by the price, so it is not on the selection ladder.
The `reduce`/`cost` figures for `isolated` are calibration knobs, marked as such in
`cage.py`. **Not yet served:** `graded/policies/cage-tier.yaml` still carries only the
first three rungs and its per-tier reach is still one flat egress lockdown, so
`verify-graded.sh` step 4 reports the drift; eco-system ticket 26 lands the Kyverno
half (dial map, `cage-isolated` PriorityClass, per-tier reach, and the unknown-tier
fallback flipping from `baseline` to `isolated`).

## The £ picks the tier (and TCoR)

A cage is a **priced partial-reduce on a retained risk**: it collapses part of the
behind-posture residual (R′ stays > 0) at a booked run-cost (C_cage > 0). The £
picks the **loosest** cage whose residual still fits the org's appetite band (read from
that org's OWN signed `party.yaml` `appetite.tolerance`; the platform-held
`../risk/appetite.json` fixture is retired, ADR-0021) — else `isolated`, the bottom
rung: quarantine's dials plus no reach at all and first eviction, a RUNNING cage,
never a Deny (ADR-0022). The selection is then clamped UP to the adopter's own
`overlay.floor`, never down.

```mermaid
flowchart TD
  B[Pod falls behind<br/>uncaged residual ALE] --> S{loosest tier whose<br/>residual ≤ appetite band?}
  S -->|baseline fits| C1[Cage: baseline<br/>TCoR = R′ + £500]
  S -->|needs restricted| C2[Cage: restricted<br/>TCoR = R′ + £2k]
  S -->|needs quarantine| C3[Cage: quarantine<br/>TCoR = R′ + £6k]
  S -->|even quarantine over-band| D[Cage: isolated<br/>no reach, evicted first<br/>TCoR = R′ + £15k]
  C1 --> F{below the adopter's<br/>overlay.floor?}
  C2 --> F
  C3 --> F
  D --> F
  F -->|yes| G[clamp UP to the floor<br/>tighten-only, never down]
  F -->|no| H[selected tier]
```

Same behind-posture workload, different appetite → different cage. Loose-appetite
**driftwood** (£40k band) cages it `baseline`; strict-appetite **ludlow** (£5k
band) cages the *same* workload `quarantine` — proportionality, tier edition
(reusing the appetite band that drives the Audit/Deny flip in `../risk`).

```bash
cage.py select scenarios/driftwood-behind-posture.json --org driftwood   # -> baseline, TCoR ~£23.7k
cage.py select scenarios/driftwood-behind-posture.json --org ludlow       # -> quarantine, TCoR ~£8.6k
cage.py dials restricted                                                   # the deterministic dial expansion
cage.py selfcheck                                                          # the assertions
```

## The cage, at admission

```mermaid
flowchart LR
  P[Pod create<br/>posture.acme.io/tier=restricted] --> MUT[MutatingPolicy cage-tier<br/>expand tier → dials]
  MUT --> P2[Caged pod<br/>limits + drop-ALL + ro-fs + WAF<br/>+ eviction PriorityClass<br/>label posture.acme.io/caged=true]
  P2 --> GEN[GeneratingPolicy cage-netpol]
  GEN --> NP[NetworkPolicy cage-egress-lockdown<br/>egress: DNS only]
```

The tier is set upstream by the £ / the currency controller (ticket 16) — never
self-asserted for a *loosening*: an unknown tier value falls through the map to
`baseline`, and `posture.acme.io/caged` is stamped by the policy, not the pod.
Least-privilege stays the floor for everyone via the versioned `require-*`
policies; this cage only *tightens* a workload that fell behind, and only a
workload that claims a policy version at all — see ticket 08 below.

## Run it

```bash
estate/driftwood/scripts/up.sh          # cluster + Flux
# Kyverno must be installed (ticket 03 / distribution path)
estate/platform/graded/up.sh
estate/platform/graded/verify-graded.sh
```

`verify-graded.sh` proves offline (no cluster) that the cage is a mutation not a
deny, the tier→dials expansion is deterministic and matches `cage.py`, an
in-currency pod (claims a version, no tier label) is caged into `baseline`
rather than left untouched, a pod claiming no version at all is skipped
outright, the generate emits the egress lockdown, and the eviction ordering
holds. If the policies are installed live it also server-dry-runs a
behind-posture pod and asserts it is *caged* (mutated), never denied.

### Every claiming workload is always caged (ticket 08)

There is no uncaged state *within the population that claims a policy version*.
A pod with a version claim but no `posture.acme.io/tier` label — the in-currency
population — is not skipped; it is mutated into `baseline`, the loosest tier,
the permissive default. `baseline` still stamps `cpu: 500m`, `mem: 256Mi` and a
`cage-baseline` PriorityClass onto every claiming pod that previously went
untouched, so **this is itself a major bump** under `CONTEXT.md`'s own semver
rule (verdict impact on currently-compliant workloads): a pod that cannot
schedule under those new limits is refused, where before it was admitted
clean. Release this change as a major version, not a patch. A tier value that
is missing *or* unrecognized both fall through to `baseline` — never to a
no-op skip, which would be the exemption `CONTEXT.md` bans.

**A pod that claims no policy version at all is a different population, and
this ticket does not touch it.** `cage-tier.yaml`'s `matchConditions` gate on
`policy-as-versioned.dev/policy-version` presence (the same convention
`../posture/policies/stamp-posture.yaml` uses) keeps kube-system, Kyverno's own
pods, Flux's controllers, cert-manager, and any COTS workload outside this
policy's reach — they are unmatched, not caged. Whether that permanently
unversioned population should also default to `baseline` is a real question,
genuinely left open and spun out to its own effort (ticket 02 answer #5), not
a decision this policy body has already made.

**Inside a GOVERNED Namespace that question is closed, and the answer is not
"uncaged".** Left open there it meant one omitted label bought a workload out of
the cage entirely: observed live on 2026-08-28, a claim-less pod ran in a
governed Namespace whose declared tier was `isolated` with no tier label, no
PriorityClass, no limits, no hardening and no reach cage, and it reached the API
server and the internet. `governed-namespace-requires-claim` was promoted from
`Audit` to `Deny` that day (`../distribution/render-governed-namespace-guard.py`,
ADR-0022, ADR-0014's own promotion path), and `graded/up.sh` now installs it and
the orphan guard on the cluster, because an offline-only proof of an admission
control is not a proof. That refusal is a missing INSTRUMENT (ADR-0020): the
claim is what selects which served version cages the pod. A pod that claims is
caged and priced, never refused.

## Calibration knobs

- **`TIERS` reduce/cost** in `cage.py` — the risk each cage collapses and its £/yr
  run-cost. Tune to real WAF/eviction telemetry; the demo values keep the ordering
  (tighter = more reduce *and* more cost) the selection relies on.
- **PriorityClass values** (`−10 / −100 / −1000`) — how aggressively each tier is
  evicted under node pressure. All below the default 0, `preemptionPolicy: Never`.
- **WAF image** `ghcr.io/acme/coraza-waf:cage` — placeholder for the estate's
  actual heavier-WAF sidecar.

## Boundaries (what this ticket does *not* do)

- **Ticket 16** — the **currency controller** decides *when* a workload has fallen
  behind and stamps the tier label post-admission. This ticket consumes that label;
  it does not compute currency.
- **Deny path** — the versioned `require-*` ValidatingPolicies (ticket 03) and the
  risk-tuned Audit→Deny flip (`../risk`) own the admit/deny rung. `cage.py` emits a
  `Deny` action when no cage fits, but the enforcement of it is those policies.
