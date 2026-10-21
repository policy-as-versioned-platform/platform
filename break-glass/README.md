# platform/break-glass — posture-gated human access, priced by £

**Scope,2026-10-17 (ecosystem ticket27).** This is an offline decision fixture,
not an observed live access-control integration. The actor identity/access plane
is shelved for this build (hub ticket90). The existing global assurance bands
are not a per-party mapping derived from `party.yaml`. Shared factor names and
decision constants now live in `../access/factors.py`; this engine no longer
imports the legacy static operation selector. The legacy selector is now retired: `access.py` only reports migration
guidance and exits3. Shelved caller scripts use this offline fixture instead;
no live actor probe or authentication integration is activated. Authentic
per-party bands remain outstanding, so ticket27 remains open.

**Optional party declaration,2026-10-21 (ticket27).** The offline CLI can now
read explicit `appetite.assurance_bands` from a party artefact with
`decide SCENARIO --party-yaml ADOPTER/party.yaml`. It does not derive three
cutoffs from the existing tolerance. This supplies the missing reader, not
actual bands for the three adopters or any live actor assurance.

**Ticket 19** (blocked by 06, 18). A risky operation — break-glass, or a `ludlow`
patient-data read — demands **current device posture** + **higher identity
assurance**, *proportional to the operation's £*. A stale or unattested device is
**caged** (read-only/scoped session) or **denied** — the harder the £, the less a
degraded device gets away with.

This is the included human/device decision fixture. The retired ticket18
selector used a static operation table and binary device input. This fixture
replaces those two choices:

1. **The bar is the £, not a table.** The op's FAIR scenario runs through
   `../fair/fair.py`; its `carried` £ (TVaR + risk load) picks the assurance band.
   Higher £ ⇒ a strictly stronger required set — the same money `../risk/enforce.py`
   uses to pick Audit vs Deny for workloads.
2. **Device posture has currency.** A device SVID is `fresh` (attested, in
   currency), `stale` (was attested, now aged out — the currency controller,
   ticket 16, has dropped the entry), or `none` (unmanaged laptop, never on the
   `acme.internal` root). Currency, not mere existence, decides the rung.

## What's here

| Piece | File | Role |
|---|---|---|
| The gate | `break-glass.py` | graded DENY / CAGE / STEP_UP / ALLOW by op-£ × device posture — the decision logic, with asserts |
| Assurance bands | `assurance-bands.json` | £ thresholds: `step_up_at` / `attest_at` / `no_cage_at` |
| Scenarios | `scenarios/*.json` | single-state FAIR triples: `driftwood-read` (T1) · `tuppence-write` (T2) · `driftwood-bulk-export` (T3-cage) · `ludlow-patient-data` (T3-deny) |
| Verify | `verify-break-glass.sh` | offline asserts + structural invariants (reuse, band ordering, per-scenario tier) |

No cluster resources of its own. Calling this engine from Pomerium forward-auth /
external-authz is a proposed integration, not something the included verifier
observes. The IAP wiring and live checks in `../access/` are shelved with the
actor identity plane; this verifier grades only the offline fixture.

## The gradient (proportional to £)

```mermaid
flowchart TD
  OP[Risky op<br/>FAIR scenario] -->|fair.py carried £| BAND{£ band?}
  BAND -->|< step_up_at| T1[Tier 1 — OIDC floor<br/>authenticated human]
  BAND -->|< attest_at| T2[Tier 2 — + WebAuthn<br/>phishing-resistant passkey]
  BAND -->|≥ attest_at| T3[Tier 3 — + attested device<br/>current device SVID]
  T3 --> POS{Device posture?}
  POS -->|fresh + passkey| ALLOW[ALLOW — full access]
  POS -->|fresh, no passkey| STEPUP[STEP_UP — prompt passkey]
  POS -->|stale, £ < no_cage_at| CAGE[CAGE — read-only/scoped session]
  POS -->|stale, £ ≥ no_cage_at| DENY1[DENY — read-only peek is the breach]
  POS -->|none / unmanaged| DENY2[DENY — no trust to cage]
```

| Op | carried £ | Tier | fresh+passkey | stale device | unmanaged |
|---|---|---|---|---|---|
| `driftwood-read` | ~£1.9k | 1 | ALLOW | ALLOW (irrelevant) | ALLOW |
| `tuppence-write` | ~£53k | 2 | ALLOW | ALLOW (device n/a) | STEP_UP if no passkey |
| `driftwood-bulk-export` | ~£535k | 3 | ALLOW | **CAGE** (read-only) | DENY |
| `ludlow-patient-data` | ~£2.4M | 3 | ALLOW | **DENY** | DENY |

The money-shot: the **same stale device** is *caged* on the £535k export but
*denied* on the £2.4M patient read — the response is proportional to the £, not a
fixed rule.

```bash
break-glass.py decide scenarios/ludlow-patient-data.json  --oidc --webauthn --device fresh   # ALLOW
break-glass.py decide scenarios/ludlow-patient-data.json  --oidc --webauthn --device stale    # DENY
break-glass.py decide scenarios/driftwood-bulk-export.json --oidc --webauthn --device stale    # CAGE
break-glass.py decide scenarios/tuppence-write.json        --oidc --device fresh                # STEP_UP
break-glass.py selfcheck                                                                        # the asserts
```

A stolen credential (no passkey, known human) is *stepped up*; a device out of
currency is *caged or denied by £*; an unmanaged laptop is *refused* — it cannot
be caged into trust it never had.

## Run it

```bash
estate/driftwood/scripts/up.sh          # cluster + Flux
estate/platform/identity/up.sh          # SPIRE / Istio / OpenBao substrate
estate/platform/access/up.sh            # Dex + Pomerium + device SVID (the plane this rides on)
estate/platform/break-glass/verify-break-glass.sh   # offline asserts (no cluster needed)
```

## Existing fixture inputs and limits

- **`assurance-bands.json`** — unchanged global `step_up_at` / `attest_at` /
  `no_cage_at` fixture thresholds in £/yr. The default and explicit `--bands`
  modes remain stdlib-only; alternate tables must be finite, nonnegative and
  ordered. There is no tolerance-to-cutoff formula or inferred multiplier.
- **`--party-yaml`** — uses the existing strict party parser and schema, then
  the captured same-party appetite interpretation. The optional closed
  `appetite.assurance_bands` object requires `currency: GBP` and explicit
  `step_up_at`, `attest_at`, `no_cage_at` numbers in GBP/year of carried loss.
  They must satisfy `0 <= step_up_at <= attest_at <= no_cage_at`; comparisons
  remain strictly `>`, so equality does not raise the assurance tier. The
  party's tolerance must also be a finite, nonnegative GBP amount, and the
  scenario's `org` must exactly equal the declared party. Missing policy is a
  named missing instrument, never a fallback to global fixture values.
  `--party-yaml` and `--bands` are mutually exclusive. Its `assurance_policy`
  output binds the party, resolved thresholds and SHA256 of the one raw party
  capture. That hash is provenance, **not signature verification**. Tag
  authentication belongs to the caller; this offline CLI performs none.
- **Scenario triples** — each op's `(min, mode, max)` loss magnitude is an
  estimate; a reassessment (as in `../risk/` ticket 06) can push an op across a
  band and change its required assurance, in a reviewable PR justified by the £.
- **Posture currency source** — `fresh`/`stale`/`none` is an explicit CLI input
  here. Reading it from a live device SVID belongs to the shelved actor lane;
  the offline verifier does not observe device attestation or renewal.

The registered verifier runs the new synthetic public CLI cases as well as
the old fixture checks. It names Python/PyYAML absence with exit3/SKIP; a CLI
input that cannot be interpreted refuses before emitting a priced decision.
No real adopter bands, financial amounts, empirical observations or actor
integration are supplied by these tests.
