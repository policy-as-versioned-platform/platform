# platform / party — the party artefact schema and check (ticket 11, widened by ticket 21)

One signed file per party declares that party: its name, its roles, its parents as
party+kind+version, what it publishes, its own size, appetite and reporting currency, its selected
baseline name (if it adopts), and an overlay. Promoted from the shape
`spikes/cs-06b-cross-party-composition/material/parties/*.yaml` proposed. See `CONTEXT.md`'s
*Party*, *Role* and *Baseline* entries,
[ADR-0012](../../docs/adr/0012-composed-artefact-self-signed-pinned-sha.md),
[ADR-0013](../../docs/adr/0013-regulator-publishes-baselines-adopter-selects.md) and
[ADR-0019](../../docs/adr/0019-one-feed-envelope-signed-by-the-tag.md).

This lives in `platform`, not in an adopter's own repo, because every adopter already pins
`platform` and calls its checks through that pin — the same "library, not a service" shape
`shift-left/ci-check.py` uses. The platform's own artefact is `../party.yaml`, one directory up,
checked by this same checker: the platform is a party like any other and is not exempt from the
format it ships.

## Shape

```yaml
party: driftwood
roles: [risk-bearer, adopter]  # publisher | risk-bearer | adopter | platform | insurer
baseline: MODERATE             # required only of a party that adopts
inherits:                      # the pin IS the subscription record (ADR-0019)
  - { party: platform, kind: implementations, version: "1.1.1" }
  - { party: nist,     kind: controls,        version: "1.1.0" }
  - { party: ico,      kind: feed, name: penalty-schema,  version: "v1", since: "2026-08-28" }
  - { party: feeds,    kind: feed, name: threat-register, version: "v1", since: "2026-08-28" }
publishes:                     # the discovery record; there is no central catalogue
  - { kind: feed, name: forward-intel, path: twin/forward-intel,
      payload_schema: twin/forward-intel/payload.schema.json, revoked: [] }
size:                          # signed, so the price is this party's and no fixture's
  turnover: { amount: 120000000, currency: GBP }
  customers: 400000
  data_subjects: 400000
  headcount: 900
  as_of: "2026-08-28"
appetite:
  tolerance: { amount: 40000, currency: GBP }
reporting_currency: GBP
overlay:
  add: []
  restate: []
  floor: restricted            # optional, tighten-only; 'infra' is not offered
```

`schema.json` is the single source of truth for the allowed roles (`publisher`, `risk-bearer`,
`adopter`, `platform`, `insurer`), the three parent kinds (`controls`, `implementations`, `feed`)
and the four floor tiers — `party_artefact.py` reads its enums from that file rather than
re-declaring them.

`pricing` and `threat` were separate parent kinds until ticket 21. Both are now `feed` with a free
`name`, so a new publisher ships a new feed with no platform change (ADR-0019 point 3).

## What's here

- **`schema.json`** — the structural shape above, as a JSON Schema draft-07 document.
- **`party_artefact.py`** — four checks, run in order:
  1. **schema** — the structural shape, against `schema.json`. A `feed` parent must name the feed;
     a `since` must be a real calendar date; `size` is all five fields or none, so a party is
     never priced against a default it did not sign; every amount carries its currency; a floor
     may not be `infra`.
  2. **tags** — a declared parent version must equal the tag the adopter's own Flux/Renovate files
     pin, for the two parent kinds this estate wires through Flux: `nist`/`controls`
     (`gitops/flux-system/gotk-sync-nist.yaml`) and `platform`/`implementations`
     (`gitops/platform/platform-pin.yaml`). A `feed` parent is pinned by a signed tag on the
     publisher repo, not by a Flux `GitRepository` — a feed carries prices, not rules, so nothing
     in `gitops/` reconciles it. The check names each feed parent as unchecked rather than
     silently skipping it; the tag itself is checked against the real remote by ticket 21's
     `verify-feed-contract.sh`.
  3. **baseline mirror** (adopters only) — the adopter's `nist` pin ConfigMap's `baselineName` key
     must equal the party artefact's own `baseline` field. The party artefact is the risk-bearing
     declaration; the ConfigMap only mirrors it (advisory, for humans and the OSCAL plumbing). A
     party that does not adopt selects no baseline and has no ConfigMap, so this is named as not
     run rather than passed.
  4. **publish capability** — two facts *observed off real files*, printed as `FACT:` lines:
     - `verification_key_present` — this party's `.github/workflows/release.yml` pins the gitsign
       identity it accepts (`EXPECTED_IDENTITY_REGEXP`). Under ADR-0012/0019/0023 the gitsign tag
       is the only signature, so the pinned identity *is* the verification key. This replaces the
       old `signing_key_present` flag, which reported whether a `feeds/keys` public key file
       existed — a detached-signature mechanism ADR-0023 (D3) retires. An unpinned identity is
       not verification, and reports false.
     - `can_publish` — the roles include `publisher` **and** a `.github/workflows/cut-release.yml`
       exists to cut the signed tag. A role on its own is a claim; the workflow is the capability.

     A party that advertises `publishes[]` it cannot publish is an **error**: discovery is the
     catalogue, so an entry with no release path is a promise the estate cannot keep.
- **`verify-party-artefact.sh`** — the runnable beat: the selfcheck, then the platform's own
  `party.yaml` through the real `check` subcommand, then an assertion that its `can_publish` is
  actually true. Offline; no exit-3 case.

## Run

```sh
python3 party_artefact.py check ../../driftwood/party.yaml --adopter-dir ../../driftwood
python3 party_artefact.py check ../party.yaml --adopter-dir ..   # the platform's own
python3 party_artefact.py --selfcheck      # runnable asserts
./verify-party-artefact.sh                  # the beat
```

An adopter's own `shift-left.yml` runs `check` on every pull request, against the `platform`
checkout it already has for `ci-check.py`/`adopter-gate.py`.
