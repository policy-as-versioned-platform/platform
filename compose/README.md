# platform / compose — the composition seam (tickets 12-15)

One entry point, `compose()`, that takes an adopter repo state plus its pinned parent trees and
gives back the evidence document (a dict) and the rendered composed artefact (a mapping of path to
file content). Every later ticket in this effort (16-18) adds a field or a refusal *through this
seam and nothing else* — spec.md's "Testing Decisions", "One seam".

See `CONTEXT.md`'s *Composed artefact*, *Restatement*, *Baseline*, *Control claim* and *Governed
namespace* entries,
[ADR-0012](../../docs/adr/0012-composed-artefact-self-signed-pinned-sha.md) (self-signed, pinned
SHA), [ADR-0013](../../docs/adr/0013-regulator-publishes-baselines-adopter-selects.md) (baselines,
control ids, holes),
[ADR-0014](../../docs/adr/0014-unclaimed-is-caged-governed-namespace-requires-claim.md) (the
governed namespace, and the silence it closes),
[ADR-0016](../../docs/adr/0016-a-subclass-never-restates-a-mutate.md)
(kind-aware render, the family+name-stripped resolver key),
[ADR-0017](../../docs/adr/0017-a-control-claim-belongs-to-whoever-ships-the-implementation.md)
(who a claim belongs to, and an adopter's own addition) and
[ADR-0018](../../docs/adr/0018-the-namespace-manifest-is-the-governed-declaration.md) (the
Namespace manifest is the declaration; the composed artefact carries no namespace list).

This lives in `platform`, not in an adopter's own repo, for the same reason `party/` does: every
adopter already pins `platform` and calls through that pin.

## What this ticket's `compose()` does

1. Loads the adopter's `party.yaml` and runs `party/party_artefact.py`'s existing `check()`. A
   party artefact that doesn't check out refuses before anything else runs.
2. Resolves every declared parent to a commit SHA. `controls`/`implementations` read the SHA
   already recorded in the adopter's own Flux pin (`spec.ref.commit`), never re-derived. `pricing`
   and `threat` have no Flux pin in this estate, so they resolve by reading the party directly
   (`git log` on `ico`'s `schema/v1/`, `platform`'s `feeds/threat-register/v1/`).
3. Loads every `ValidatingPolicy`/`MutatingPolicy`/`GeneratingPolicy` member of every live policy
   version from each `implementations` parent, keyed on (identity family, name with its version
   suffix stripped) — not `(family, version)`, the prototype's bug. The orphan guard loads through
   the parent's own offline twin (`render-orphan-guard.py`), under the platform tag.
4. Renders every member back down: the whole inherited body, plus a `composed-for` label and
   `inherited-from`/`source-path` annotations. `spec.validationActions` is written only onto a
   `ValidatingPolicy` — the prototype's other named defect.
5. Writes one advisory header (`composed/HEADER.yaml`): the composed marker, each parent's
   resolved SHA once, the selected baseline name, the governed namespace names.

## What ticket 13 adds

- **Split diamond** — two of the adopter's own `inherits` edges reaching one `(party, kind)` at two
  versions. Refused, naming both edges. The real estate has no data source for a further-hop
  diamond (`platform` ships no `party.yaml`), so this fires only against a fixture today.
- **Cross-party rule conflict** — two `implementations` parents supplying one
  `(family, name, version)` with different content. Never merged, never last-wins: refused, naming
  both sources and both contents, and dropped from the composed set. The `limits[]` two-publisher
  count says whether this path is exercised (`open` at one pinned publisher, `closed` at two).
- **Restatement of a non-`ValidatingPolicy`** — `overlay.restate` naming a `MutatingPolicy` or
  `GeneratingPolicy` member. Refused (ADR-0016: no strictness ladder to compare on).
- **Restatement on a `ValidatingPolicy`** — a stricter action (`Audit`→`Deny`) is accepted and the
  rendered member carries it. A weaker action is never an override, never an exemption: it is a
  declared inability, priced by the estate's own `graded/cage.py` against that party's own signed
  `party.yaml` `appetite.tolerance` band. The rendered member keeps the INHERITED action — the composed artefact
  carries no tier and no tier floor; only the proposer (ADR-0015) ever turns one, later.

## What ticket 14 adds

- **Baseline resolution** — the party artefact's `baseline` name resolves against the `controls`
  parent's real published profiles (`catalog/BASELINE_VERSIONS.json`), walking nested controls so
  an enhancement like `ac-6.10` is found. An id absent from the catalogue — a claimed
  `control-id`, or an adopter's own `overlay.controls` addition — is a hard failure
  (`unknown-control-id`), never a hole: exact-string, no case-fold, no prefix-strip (ADR-0013).
- **Control claims merge over every party that ships a member**, including — for the first time —
  the adopter's own `component-definition.json`, next to the `party.yaml` it signs (ADR-0017).
  This is also the first ticket that loads `overlay.add` at all: it was declared in ticket 11's
  schema but never wired into `compose()`, and there is no other route by which an adopter's own
  claim can ever "fill" a hole, since it may never claim against a parent's policy.
- **A control counts as covered the instant any claim exists for it, valid or not** — spec.md says
  "no claim", not "no valid claim" — so a **dangling claim** (the named policy is shipped by
  nobody composed) or a claim **against another party's policy** (ADR-0017) both still close a
  hole while separately refusing on their own account (`needs_composition: false` and `true`
  respectively — the first is a plain per-party lint's own finding, the second needs the whole
  composed set to know whose policy it is).
- **Holes** compare against the *last signed composed artefact's own header*: a new hole refuses
  and names it, a recorded one does not, a closed one prints so. No committed header at all is the
  bootstrap case — the first composition ever records every hole and refuses on none.
- **A control that leaves the selected set refuses**, no exceptions — a narrowed named baseline
  included for free, since its dropped controls just show up as removed. **A named-baseline
  widening** (a MODERATE→HIGH shape: the new resolved set is a strict superset of the old) refuses
  too, with no override — kept separate from the removed-control check so the two never
  double-fire on one change.
- The header gains `holes` (the still-open recorded set) and `selected-controls` (the full
  resolved set) — what the *next* run compares against. The document gains `holes[]`.

**Found along the way:** the real `platform` component-definition carries two claims against a
policy that exists nowhere (`ac-6`→`may-run-root-if-attested`, `cm-6`→`require-policy-version`,
ticket 10's own named, still-open defect). Composition now catches them itself, so the real
estate's own composition **refuses today** — the driftwood/tuppence/ludlow pull request spec.md
opens with, made real. Fixing that defect stays `platform`'s job, not this seam's.

Out of scope here, because later tickets own it: pricing/threat re-pricing beyond what caging
itself needs.

## What ticket 15 adds

- **The governed-namespace lint** — every `Namespace` manifest in the adopter's own repo that
  carries the `institution` label and not `governed: "true"` is **ungoverned**
  (`ungoverned_namespaces`) — ADR-0014's silence hole moved up one level (ADR-0018). A namespace
  with no `institution` label at all is infrastructure and is ignored entirely.
- **The rule is the hole rule** (`compute_ungoverned`, the exact new/recorded/closed shape and
  bootstrap rule `compute_holes` already uses): compared against the *last signed composed
  artefact's own header*, a new one refuses and names it, a recorded one does not, one that gains
  the label since prints closed. No committed header at all is the bootstrap case — the first
  composition ever records every ungoverned namespace and refuses on none.
- The header gains `ungoverned-namespaces` (the still-open recorded set), next to `holes`. The
  document gains `ungoverned[]`. The composed artefact still carries no namespace list of its own
  — the governed set stays advisory metadata only, exactly as ticket 12 left it, and nothing
  composition renders ever reads either namespace set.

## What ticket 16 adds

- **Every declared `pricing` and `threat` edge is priced twice**, through the estate's own machinery
  and no other: the `ico` penalty schema through `ico`'s own converter (`schema/to_fair_scenario.py
  build`, the fixed `uk-gdpr`/`lower-tier` entry), the threat feed through `platform/feeds/
  to_fair_scenario.py`, reusing `_threat_scenario` exactly as ticket 13's caging path already calls
  it. No second risk engine, no second appetite store.
- **"Old" is the version the last signed composed artefact's own header recorded** for that
  `(party, kind)` — one more field of the same `_previous_header` tickets 14/15 already read. No
  prior header, or no prior edge of that kind, means nothing to compare a bump against yet: old and
  new both price at this run's own version, an honest "no move". This runs *every* run, not only
  when a version actually moved — whether the two prices differ is the separate `changed` field.
- **Every proposed tier travels as `proposed_as: "label"`** — ADR-0022 retired the `deny` rung.
  `select_tier` now bottoms out at `isolated`, a running, unreachable cage (quarantine's dials plus
  no ingress, no egress and first eviction), so every value it can return is a real label value and
  nothing is ever denied. This is the mark, not the act — composition itself opens nothing;
  ticket 17 wires the proposer that reads it.
- **Every `prices[]` entry carries `perspective`, `currency`, `source`, `kind`, `amount` and a
  `per_customer` restatement** (ticket 25; ADR-0020, ADR-0021). No sum crosses a perspective or a
  currency: the one summing helper is `fair.sum_prices`, and it raises on a mixed list. A regime
  entry also carries `holes[]` — the regulator's own published control weights, each with its own
  amount — and a `total` those amounts sum to, which IS the entry amount, because a hole partitions
  the regime exposure rather than adding to it. An adopter whose own repo publishes a
  `twin/forward-intel/v<major>/feed.json` gets one further entry, `source: twin`, annualised
  through `fair.py` and carrying the adopter's selection-policy version, the curve hash and
  `fair.summarize()`'s own `tail`; no such feed simply means no such entry. A missing instrument —
  no appetite band, no converter for a declared feed, no FX rate for the date — refuses and names
  what is missing (ADR-0020).
- **Pricing touches no rendered file.** Pricing and threat edges carry no rule and are never looped
  into the members/render step, so a price move changes `prices[]` and the header's `parents[]`
  entry for that one edge, and nothing else composition renders — proved byte-for-byte.
- **No wall clock anywhere in this module.** Since ticket 84 the feeds module's `eol` subcommand
  is called with `--as-of`, and the date it gets is the composition's own as-of (below) or the
  CLI's `--as-of` -- a date the caller hands in, never one this module reads.
- The document gains `prices[]`.

## What eco-system ticket 84 changes: being behind costs something

- **`cve` and `eol` price.** `FEED_CONVERTERS` gained the two rows; both go through platform's
  `feeds/to_fair_scenario.py`, which prices the feed's HEADLINE entry (largest expected annual
  loss, mode lef x mode lm; `eol` as ramped at the composition's as-of) and names on the line which
  entry that is and which it did not price. One entry, not a sum: PERT triples do not add. The
  currency is read off the payload's `currency`, or -- for the versions the adopters' checkouts
  already carry -- off the publisher's own magnitude key (`severity_lm_gbp`, `base_lm_gbp`): a
  declaration in the publisher's signed schema, not a default.
- **The composition's as-of is the newest SIGNED date among its inputs**: every pinned envelope's
  `published_at` (ticket 38) and every edge's own `since`. A fresh subscription is therefore a
  zero-month window and never ticket 45's backwards-window refusal, which was this contradiction
  surfacing on the ordinary case. `compose --as-of YYYY-MM-DD` overrides it; the scheduled proposer
  passes the day it runs on and commits nothing (ADR-0024); the composition an adopter signs passes
  none.
- **A pin behind a newer major the publisher has SIGNED gets a `supersede` line** (ticket 13 D5,
  ADR-0010's banner): `amount = base x (eol_ramp(since, as_of) - 1)`, `base` the feed line's own
  amount, `since` the day the newer major's tag was cut, `as_of` the composition's. Zero on that day
  and before it, printed with both dates; +1x per year behind, capped at +4x; under the adopter's own
  perspective and currency; `proposed_tier: null` so it never moves the party fold; NOT an exposure
  kind, because the line it surcharges is already summed there. "Published" is a signed tag read off
  the publisher's checkout, exactly as `pin_signature` is: an untagged directory publishes nothing,
  and no `supersedes:` field was added because the tag namespace already declares it and a second
  declaration could drift from the first. The feed entry carries a `superseded` observation either
  way (`behind`, `current`, or `unobserved` for a checkout that cannot show the tags). The live
  case: tuppence and ludlow pin `threat-register@v1` while `threat-register/v2.0.0` was cut on
  2026-09-01.
- **Publisher observations travel with the artefact (ticket 110).** A fresh `compose`
  records the complete observed tag state in each feed's `PROVENANCE.json`: the pin's signature
  state, the supersede observation (including current or unobserved), the newest readable signed
  target and the oldest signed major's tag date. The snapshot names the feed, version and parent
  SHA. `verify` always replays that signed observation, even when a publisher clone is present
  and has gained tags since composition. An offline `compose` reuses the vendored snapshot;
  a fresh `compose` with the publisher present observes its tags again. No wall clock is read.
  An explicit `--as-of` is recorded in the header and replayed by verification too.

  Portability wins: the surcharge describes the publisher state recorded when this artefact was
  composed, **not the publisher's current newest major**. The handbook prints this limitation,
  along with the surcharge's start and pricing dates. Zero rows remain visible: they name the day
  the clock starts. The scheduled proposer's existing `compose --as-of` is a fresh composition,
  so it observes newly fetched tags and grows the ramp; verification never refreshes history.

  **Migration:** legacy `PROVENANCE.json` without `publisher_observation` is not guessed from a
  live clone during verification and is not treated as “current” offline. Replay refuses with a
  named missing instrument. Verify an old signed artefact with the composer its tag pins; to
  adopt this composer, re-compose with the publishers present and sign the new artefact through
  the normal release workflow. Invalid snapshots or snapshots belonging to another feed or SHA
  also refuse. This does not retroactively make an old artefact portable under a newer renderer.

- **Every feed line carries `pin_signature` and `hole`** (ticket 69's rule reaching past the
  premium): an untagged feed pin is a hole of the whole line, naming the tag that does not exist.
- The proposer reads the `supersede` line: `wargamer.wargame_retirement()` and `tier_pr.py`'s
  retirement landing move the one `inherits[]` edge forward in `party.yaml`, forward-only.

## What eco-system ticket 38 changes: a hole is priced, not counted

- **The new-hole, baseline-widening and new-ungoverned-namespace refusals are gone.** Each prints
  as a `deltas[]` entry under the adopter's own perspective and currency — what changed since the
  last signed composed artefact and what a pinned instrument prices it at. A delta no pinned
  instrument names carries `amount: null` and `priced_by: null`: a named absence, never a zero.
  The only hole-shaped refusal left is a bespoke control with no signed scenario (a missing
  instrument, ADR-0020). `removed-control` stands: a removal is an exemption by another name.
- **Every hole is `(source, id)`** across every `controls` parent, an adopter's own catalogue
  included. A claim's source is its component-definition's `source` href (`../nist/...` → `nist`);
  a bare `overlay.controls` id is the baseline's catalogue's, `party:id` names another controls
  parent's. The header writes the bare id where the source is the baseline's own and `source:id`
  otherwise, so the three real adopters' headers keep their shape byte for byte. `holes[]` entries
  carry `source`, `control_id`, `status`, `perspective`, `currency`, `amount` and `priced_by`; the
  regime entry's `holes[]` partition (ticket 25) is untouched and each line gains the adopter's
  `status` for that control (`new`/`recorded`/`closed`/`covered`/`unselected`).
- **An ungoverned namespace is priced**, on its `ungoverned[]` entry: its workload share
  (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs in the repo walk, over the same across
  every namespace carrying the `institution` label) of the adopter's whole uncaged residual (the
  `exposure` total), LEF-ramped from `since` by the feeds module's own `eol_ramp` and bounded at the
  whole residual. `since` is read off the first *signed* tag whose header names the namespace — no
  new header field, and it survives a close and a reopen — and `as_of` is the newest `published_at`
  among the pinned feeds, so the module still reads no clock. What cannot be read is named in
  `price.limits[]`, never invented. The live case is tuppence's `tuppence-reset`.
- **A bespoke control** is a small OSCAL catalogue the adopter publishes and pins as a `controls`
  parent of *itself*; the self-pin resolves to the adopter's own tree (the catalogue is signed by
  the same tag as the composed artefact — ADR-0017's "no separate pin"). Its hole is priced by the
  scenario the control's `props[name=scenario]` names, repo-relative, through the same cage engine
  the restate path uses. It is reported on the hole and its delta; it does not yet enter
  `prices[]` (a `PRICE_KINDS` major the £ seam grades), so it is priced but not yet tiered — a
  named limit. The amount is labelled in the adopter's reporting currency and this path takes no
  FX rate, so a band declared in another currency refuses as a missing instrument naming both
  (one currency on both sides; a relabelled amount is a minted one). The self-pin may sit
  anywhere in `inherits[]`: the header's bare ids key to the first `controls` parent that is
  not the adopter, on writing and on reading alike.
- The document gains `deltas[]`. `verify/priced-holes/` in the hub grades all of this on the
  composed evidence; the superseding ADR for ADR-0013/0017/0018 point 3 is ticket 39's.

## Run

```sh
python3 composition.py compose ../../driftwood [--estate-clone ../../.. /.estate-clone] [--out DIR]
python3 composition.py verify ../../driftwood
python3 composition.py --selfcheck      # runnable asserts; SKIPs (exit 0) if the estate clone is absent
./verify-composition.sh                  # the beat
```

`compose` writes the rendered files under `<out or adopter-dir>/composed/`, prints the evidence
document as JSON, and exits non-zero on a refusal. `verify` re-renders from a fresh resolution of
the same parent trees and diffs byte-for-byte against whatever is already committed.

## The handbook (ticket 34; ADR-0007's last-mile section)

`handbook.py` renders one page of Markdown, `composed/HANDBOOK.md`, from an adopter's composed
artefact and from nothing else. `compose()` calls it after it has built the evidence document and
puts the result in the same `rendered` mapping as `HEADER.yaml`, so — **from the platform tag that
carries this file on** — the page lands in the same pull request as the artefact, is byte-compared
by the same `verify`, is failed by the same drift check in each adopter's `cut-release.yml`, and is
carried under the same gitsign tag.

Until an adopter's pin moves onto such a tag, none of that holds for it: the `composition.py` at
its pin neither writes nor verifies the page (`verify()` compares only what it rendered plus
`composed/**/*.yaml`), so a hand-edited `HANDBOOK.md` passes `composition.py verify` at that pin
and `cut-release.yml` there would sign it. What catches that is the byte comparison in
`verify-fresh.sh` and the hub's `verify/handbook/`, which prints how many adopters pin a tag
carrying this renderer. Measured 2026-09-08: all three pin `v2.0.1`, which does not.

The property that makes the page worth reading is that it is a **pure function of the artefact**:
it reads no clock, no environment, no network and no file outside the mapping it is handed. So it
is re-derivable by anyone who holds the artefact, and a page that said something the artefact does
not could not survive a byte comparison against a re-render.

Where a sentence would need a field the artefact does not carry — no `exposure`, no
`selection-policy`, a price with no `lef_basis` — the render **names the absent field** and states
nothing in its place. It never defaults to prose and never defaults to zero (ADR-0020). Every such
absence is listed and counted in the page's last section and again in its footer, so a disclosed
limit is a number that moves rather than a sentence that goes stale. A price with no `perspective`
or no `currency` is refused outright: it is not a price this render will state.

What it is **not**: a plain-language summary of anybody's reasoning. The original generator's
`claude -p` summaries are not derivable from the artefact and would break the property above, so
they are a human-run Claude Code skill (`.claude/skills/handbook-summaries/` in the hub) whose
output lands by its own pull request, outside `composed/`.

```sh
python3 handbook.py render ../../driftwood                 # from the working tree
python3 handbook.py render ../../driftwood --ref v1.1.0    # from the tree at a ref
python3 handbook.py --selfcheck                            # the render seam's own tests
./verify-fresh.sh ../../driftwood v1.1.0                   # render-at-ref equals the page at that ref
./verify-fresh.sh                                          # no adopter named: the tool's own proofs
```

`verify-fresh.sh` with no arguments reads **no adopter** — NORTH-STAR §2 forbids the publisher
reading an institution's repository, and this script ships in the publisher's tree. It proves the
tool over planted git repositories instead. The estate-wide read of the real adopters is the hub's
`verify/handbook/verify-handbook-is-a-compose-time-render.sh`.

**Retired with it**: the original `handbook-generator`'s `verify.sh` — an end-to-end script that
generated a handbook against a real signed tag and then graded its own output. Nothing replaces it
because nothing needs to: the chain that used to justify it is now three checks the estate already
runs on every change — `cut-release.yml` runs `composition.py verify` before a tag is cut (which
grades the page only once the adopter's pin carries this renderer, see above), and
`verify-fresh.sh` and the hub's `verify/handbook/` re-render from a served ref regardless of the
pin. `verify.sh` was never lifted into this estate, so there is no file here to delete; this
paragraph is the retirement.

### Floor-change evidence (ecosystem ticket 27)

Delegated architectural decision under hub ADR-0025: compare the recorded previous
`overlay.floor` with the current floor **holding this composition's other inputs
fixed**. This isolates the floor's effect when a publisher version, scenario,
appetite or selection package changes in the same pull request. It is a
counterfactual at current inputs, not a reconstruction of a historical price.
The ordinary publisher `old_price`/`new_price` and `old_tier`/`proposed_tier`
comparison keeps its existing meaning: old and new publisher versions under the
current adopter inputs. Its amounts remain uncaged exposure.

`HEADER.yaml` now records `floor-comparison` schema 1 with `before` and `after`
floor states. `{known: true, value: null}` means a known absent floor;
`{known: false}` means the earlier artefact did not record it. A selected tier
cannot establish a previous floor, so legacy history is never guessed from
`prices[]`. A missing historical input yields a named could-not-look, not a zero
delta. Invalid recorded floor history refuses composition.

A fresh floor edit starts a comparison from the previously recorded after-floor.
While that after-floor remains unchanged, repeated composition preserves the
same before-floor. Thus a saved artefact retains its change evidence through
verification; a second floor edit starts the next comparison. Current pricing
inputs are re-derived from the artefact's pinned/vendored sources on every run.
The floor states are historical inputs attested by the artefact that records
them, not an independent proof of the predecessor's signature or Git history.

`composed/floor-change.json` and `evidence.json`'s `floor_change` record each
exposure line's identity, perspective, currency, current uncaged amount, selected
tiers, retained residuals and residual delta. `deltas[]` gets a `floor-change`
entry when the known floor differs, even when its selection effect is zero.
The handbook prints the same figures, and `verify` compares the rendered JSON
and handbook byte for byte. Feed selection uses the ordinary composer and twin
selection uses the adopter's existing package; retained residuals use the
composer's pinned `platform-cage-tiers` instrument, just as the aggregate does.
No monetary threshold or calibration is introduced.

Limits: these are per-line selection counterfactuals, not enacted Namespace
tiers, automatic permission to loosen, summed independent losses, historical
operating costs, or measurements of cage effectiveness. The platform reduction
table is self-declared calibration. Contract premiums and surcharge/switching
rows do not select a cage and are excluded. A missing selectable exposure is
named. This completes only ticket 27's floor-change evidence subtask; access
retirement, per-organisation break-glass bands and other ticket 27 scope remain
separate. Previously signed artefacts retain their previously pinned verifier;
an upgrade produces the new history record without fabricating a predecessor.

Run the public compose/replay regression seam with:

```sh
python3 -m unittest discover -s compose -p test_floor_change.py
```

### Durable transition comparisons

Fresh composition records `HEADER.yaml` → `comparison-inputs` (schema 1). The
before-state contains only the historical fields used by control, namespace,
publisher-version, pin-hole, twin-tier and restatement-cage comparisons. It does
not contain rendered deltas or money to copy into the new answer. Current pinned
instruments still compute all amounts, selections and transition evidence.

The after-state is a SHA-256 identity over the adopter's non-hidden source files
(excluding `composed/` and Python caches), resolved parent records, publisher
observations, effective composition date and parsed namespace/workload facts.
Including parsed namespace facts covers manifests in hidden source directories
that the namespace scanner also reads. Paths are relative: relocating a checkout
or substituting a verified vendored publisher does not start a new transition.
Changing source bytes (even an unrelated non-hidden document), a parent pin,
observation or pricing date does. This conservative source boundary does not
promise to distinguish meaningful edits from formatting. Parent contents must
still match their pins; this identity is not a replacement for pin-content and
provenance verification. Existing adopter Git-tag history used by namespace
pricing must still be available to replay its clock.

Identical inputs retain the same before-state through compose, saving **all**
outputs including `evidence.json`, repeated composition and verification. A new
input state advances the before-state to the existing recorded after-state.
Thus a new or closed hole remains a transition until inputs next change; saving
its outputs alone no longer erases it. The handbook explicitly distinguishes a
retained closed pin-hole transition from an open priced hole. Floor comparison
history remains its separate floor-specific contract: an unchanged floor retains
its own before-floor even when other inputs change.

This is the delegated architecture decision for the held subscription replay
failure, under ADR-0025; it changes no owner date, purpose, appetite or price
calibration. The signed artefact is the authority for the historical input
snapshot. Shape validation detects incomplete/malformed history and replay
refuses a snapshot bound to different current inputs; it does not authenticate
unsigned local files or reconstruct history that an older compiler overwrote.

Legacy compatibility is explicit. Verification with no `comparison-inputs`
retains the old compiler comparison behavior and does not add the field to its
re-render. Already-replayable artefacts in the v3.1 output format remain replayable; a
legacy transition whose delta already disappeared still fails naturally. This
fallback does not remove v3.1's existing floor-format migration: real v3.0
Tuppence/Ludlow artefacts still need fresh composition for the new floor header,
`floor-change.json` and handbook section. Fresh compose
always upgrades, using the existing header/evidence as its before-state (absent
legacy evidence supplies empty price/cage history, not invented lost events).
Present invalid history or corrupt present header/evidence refuses, never silently
falls back. To preserve a previously failed subscription's original transition,
re-compose its intended source edit against the actual prior composed artefact;
refreshing an already-overwritten legacy output cannot recover its lost event.

Downstream migration therefore needs the fixed software compiler and fresh
composition for these held subscriptions, followed by review and replay checks.
It does not change economic policy pins or require a new policy tag. Legacy
verification retains the v3.1 baseline contract, so this fix is a software patch
candidate relative to v3.1.0, not a claim of byte-compatible v3.0 output. The
existing v3.0-to-v3.1 floor refresh requirement still applies. Release approval and signed publication
remain separate from this implementation.
