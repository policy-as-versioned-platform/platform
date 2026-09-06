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
- **No wall clock anywhere in this module.** Neither converter this section calls takes an `--as-of`
  at all (`ico`'s `build`, the feeds module's `threat` subcommand); an `eol` parent kind does not
  exist in the party artefact schema, so composition never has occasion to pass one.
- The document gains `prices[]`.

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
puts the result in the same `rendered` mapping as `HEADER.yaml`, so the page lands in the same pull
request as the artefact, is byte-compared by the same `verify`, is failed by the same drift check
in each adopter's `compose-check` job, and is carried under the same gitsign tag.

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
runs on every change — each adopter's `compose-check` fails on drift in the page, `cut-release.yml`
runs `composition.py verify` before a tag is cut, and `verify-fresh.sh` re-renders from a served
ref. `verify.sh` was never lifted into this estate, so there is no file here to delete; this
paragraph is the retirement.
