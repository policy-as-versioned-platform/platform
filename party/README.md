# platform / party — the party artefact schema and check (ticket 11)

One signed file per party declares that party: its name, its roles, its parents as
party+kind+version, its selected baseline name, and an overlay with `add` and `restate` lists.
Promoted from the shape `spikes/cs-06b-cross-party-composition/material/parties/*.yaml` proposed.
See `CONTEXT.md`'s *Party*, *Role* and *Baseline* entries,
[ADR-0012](../../docs/adr/0012-composed-artefact-self-signed-pinned-sha.md) and
[ADR-0013](../../docs/adr/0013-regulator-publishes-baselines-adopter-selects.md).

This lives in `platform`, not in an adopter's own repo, because every adopter already pins
`platform` and calls its checks through that pin — the same "library, not a service" shape
`shift-left/ci-check.py` uses.

## Shape

```yaml
party: driftwood
roles: [risk-bearer, adopter]
baseline: MODERATE            # selected by name; may add, never remove
inherits:
  - { party: platform, kind: implementations, version: "0.1.0" }
  - { party: nist,     kind: controls,        version: "1.0.0" }
  - { party: ico,      kind: pricing,         version: "v1" }
  - { party: platform, kind: threat,          version: "v1" }
overlay:
  add: []
  restate: []
```

`schema.json` is the single source of truth for the allowed roles (`publisher`, `risk-bearer`,
`adopter`) and the four parent kinds (`controls`, `implementations`, `pricing`, `threat`) —
`party_artefact.py` reads its enums from that file rather than re-declaring them.

## What's here

- **`schema.json`** — the structural shape above, as a JSON Schema document.
- **`party_artefact.py`** — three checks, run in order:
  1. **schema** — the structural shape, against `schema.json`.
  2. **tags** — a declared parent version must equal the tag the adopter's own Flux/Renovate
     files pin, for the two parent kinds this estate actually wires through Flux today:
     `nist`/`controls` (`gitops/flux-system/gotk-sync-nist.yaml`) and
     `platform`/`implementations` (`gitops/platform/platform-pin.yaml`). `pricing` (`ico`) and
     `threat` (`platform`'s feeds) are real parent kinds ADR-0013's model requires, but neither is
     pinned by a Flux `GitRepository` anywhere in this estate — `ico` ships no git tags at all,
     and the threat register is a versioned subdirectory read out of the already-pinned
     `platform` checkout, not a second pin. The check names both as unchecked instead of silently
     skipping them or claiming a check that never ran.
  3. **baseline mirror** — the adopter's `nist` pin ConfigMap's `baselineName` key must equal the
     party artefact's own `baseline` field. The party artefact is the risk-bearing declaration;
     the ConfigMap only mirrors it (advisory, for humans and the OSCAL plumbing).
- **`verify-party-artefact.sh`** — the runnable beat: `party_artefact.py --selfcheck`.

## Run

```sh
python3 party_artefact.py check ../../driftwood/party.yaml --adopter-dir ../../driftwood
python3 party_artefact.py --selfcheck      # runnable asserts
./verify-party-artefact.sh                  # the beat
```

An adopter's own `shift-left.yml` runs `check` on every pull request, against the `platform`
checkout it already has for `ci-check.py`/`adopter-gate.py`.
