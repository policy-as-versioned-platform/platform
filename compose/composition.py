#!/usr/bin/env python3
"""composition.py -- the seam (policy-composition tickets 12-15). ADR-0012, ADR-0013,
ADR-0014, ADR-0016, ADR-0017, ADR-0018.

One entry point, `compose()`. It takes an adopter repo state plus its pinned
parent trees and gives back two things: the evidence document, as a
dictionary, and the rendered composed artefact, as a mapping of path to file
content. Every later ticket in this effort (16-18: pricing/threat
re-pricing, the proposer, wiring into CI) adds a field or a refusal
*through this seam and nothing else* -- see spec.md, "Testing Decisions",
"One seam".

TICKET 13 adds three structural refusals and a caging path, all inside this
same compose():

  * SPLIT DIAMOND -- two edges in the adopter's own `inherits` reaching the
    same (party, kind) at two different versions. "Every path from the
    adopter to one parent must resolve to one version" (spec.md,
    Resolution). This estate has no second data source recording a further
    parent's own pin today (`platform` ships no `party.yaml`), so the only
    real route to a diamond is two direct edges -- which is exactly what
    "every path ... must resolve to one version" also covers, and is what
    is checked here. A fixture is what proves it; the real estate has none.
  * CROSS-PARTY RULE CONFLICT -- two `implementations` parents supplying the
    same (family, name, version) with different content. Never merged,
    never last-wins: refused, naming both sources and both contents. Proved
    only inside one publisher today (the estate pins exactly one
    `implementations` party) -- a fixture with two exercises it, and the
    document's `limits[]` says so on every run via the two-publisher count.
  * RESTATEMENT OF A NON-VALIDATING MEMBER -- `overlay.restate` names an
    inherited member with no strictness ladder (a `MutatingPolicy` or a
    `GeneratingPolicy`). Refused; there is nothing to compare on (ADR-0016).
  * RESTATEMENT ON A `ValidatingPolicy` -- a stricter action (higher on
    `Audit < Deny`) is accepted, and the rendered member carries the
    restated action. A weaker action is never an override and never an
    exemption: it is a DECLARED INABILITY, priced by the estate's own
    `graded/cage.py` against that party's own appetite band
    (its own signed `party.yaml`), reusing the estate's engine exactly as it
    stands. The rendered member keeps the INHERITED action -- the composed
    artefact carries no tier and no tier floor; only the proposer (ADR-0015)
    ever turns a tier, later, in its own PR.

What ticket 12's compose() does, precisely:

  1. Loads the adopter's party artefact (ticket 11) and runs its existing
     `check()` -- schema, pinned-tag agreement, baseline mirror. A party
     artefact that does not check out is a refusal before anything else runs;
     there is nothing safe to compose from it (mirrors party_artefact.py's
     own "a structurally invalid document can't be checked any further").
  2. Resolves every declared parent to a commit SHA. `controls` and
     `implementations` are pinned by a Flux GitRepository in this estate --
     the SHA is the one Renovate already wrote to `spec.ref.commit`, read
     straight off disk, never re-derived (ADR-0012: "the resolved git commit
     SHA Renovate already pins", not a freshly invented digest). `pricing`
     and `threat` have no Flux pin anywhere in this estate (ticket 11's
     README says so plainly): resolved instead by reading the party
     directly -- `git log` on the version-scoped subdirectory of the
     party's own clone (ico's `schema/v1/`, platform's
     `feeds/threat-register/v1/`), falling back to a content digest for a
     party tree that is not a git repo at all (a test fixture).
  3. Loads every member of every kind (`ValidatingPolicy`, `MutatingPolicy`,
     `GeneratingPolicy`) from each `implementations` parent, for every
     policy version the parent's own version array currently declares live.
     Keyed on the identity family plus the name with its version suffix
     stripped -- NOT on (family, version), which is the prototype's bug
     ADR-0016 names: `graded-enforcement` alone covers `cage-tier` and
     `cage-netpol`, so keying on the family drops one silently. The
     `platform-machinery` orphan guard loads through the parent's own
     offline twin (`render-orphan-guard.py`), under the platform tag as a
     second numbering axis, never forced onto the policy-version axis.
  4. Renders every loaded member back down: the whole inherited body, plus
     one `composed-for` label and two provenance annotations
     (`inherited-from`, `source-path`) -- exactly what the prototype's
     `render()`/`render_is_faithful()` already proved, except `spec.
     validationActions` is now written ONLY onto a `ValidatingPolicy`
     (the prototype's other named defect: it wrote that field onto every
     kind, inventing a field the Kyverno schema does not have on a mutate
     or a generate).
  5. Writes one advisory header, once, separate from the per-rule
     annotations: the composed marker, each parent's resolved SHA (once
     each, not once per version), the selected baseline name, and the
     governed namespace names read off the adopter's own `Namespace`
     manifests. Hole and ungoverned-namespace lists join the header in
     tickets 14/15.

What this ticket's compose() deliberately does NOT do, because the tickets
that own it come later: no baseline/hole resolution, no governed-namespace
refusal, no pricing/threat re-pricing beyond what ticket 13's own caging
path needs. Nothing in the real estate exercises the diamond or the
cross-party conflict paths yet either (spec.md, "Further Notes": "no
restatement fires... no second publisher is pinned") -- the rule is written
before the first case, and fixtures are what prove it fires.

TICKET 14 adds baseline coverage, control claims and holes, still inside
this same compose():

  * The selected baseline resolves BY NAME against the `controls` parent's
    real published profiles (`catalog/BASELINE_VERSIONS.json`, ticket 09),
    walking nested controls so an enhancement like `ac-6.10` is found. An
    id absent from the catalogue -- a claimed control-id, or an adopter's
    `overlay.controls` addition -- is a HARD FAILURE (`unknown-control-id`),
    never a hole; exact-string, no case-fold, no prefix-strip (ADR-0013).
  * CONTROL CLAIMS merge over every party that ships a member: every
    `implementations` parent's own `oscal/component-definition.json`, and
    -- new this ticket -- the adopter's own, next to the party artefact it
    signs (ADR-0017). This is also the first ticket to load `overlay.add`
    at all: it was declared in ticket 11's schema but never wired into
    compose(), and "an adopter claim... fills it" has no route without it.
  * A control counts as COVERED the instant any claim exists for it, valid
    or not -- "no claim", not "no valid claim" (spec.md) -- so a DANGLING
    claim (the policy it names is shipped by nobody composed) or a claim
    AGAINST ANOTHER PARTY'S POLICY (ADR-0017) both still close a hole while
    separately refusing on their own account. The real `platform`
    component-definition carries two dangling claims today
    (`ac-6`->`may-run-root-if-attested`, `cm-6`->`require-policy-version`,
    ticket 10's own named, still-open defect) -- composition now catches
    them, so the real estate's own composition REFUSES, for real, today.
  * HOLES compare against the last signed composed artefact's own header
    (`_previous_header()`): a NEW hole refuses and names it, a RECORDED one
    does not, a hole that closes since prints so. `None` (no committed
    header at all) is the bootstrap case -- the first composition ever
    records every hole and refuses on none (spec.md). The real estate's
    first composition records exactly 285.
  * A control that LEAVES the selected set refuses, no exceptions
    (`check_selected_set`); a named-baseline WIDENING (MODERATE->HIGH
    shape) refuses too, with no override (`check_baseline_widening`) --
    narrowing is left entirely to the removed-control check so the two
    never double-fire on one change.
  * The header gains `holes` (the still-open recorded set) and
    `selected-controls` (the full resolved set) -- what the NEXT run
    compares against.

TICKET 15 adds the governed-namespace lint, the exact new/recorded/closed
shape ticket 14's holes already use, applied to a different signal:

  * A `Namespace` manifest in the adopter's own repo that carries the
    `institution` label and not `governed: "true"` is UNGOVERNED
    (`ungoverned_namespaces`) -- ADR-0014's silence hole moved up one level
    (ADR-0018). A Namespace with no `institution` label at all is
    infrastructure and is ignored entirely.
  * `compute_ungoverned` compares the current ungoverned set against the
    last signed composed artefact's own recorded set
    (`_previous_header`'s `ungoverned-namespaces`): a NEW one refuses and
    names it, a RECORDED one does not, and one that gains the label since
    prints CLOSED. `None` (no committed header at all) is the same
    bootstrap case ticket 14 uses -- the first composition ever records
    every ungoverned namespace and refuses on none.
  * The header gains `ungoverned-namespaces` (the still-open recorded set),
    next to `holes`. The composed artefact still carries no namespace list
    as a declaration -- the governed set stays advisory only, exactly as
    ticket 12 left it. Nothing in the rendered per-member files ever reads
    either namespace set.

TICKET 16 adds pricing and threat re-pricing, still inside this same
compose() -- ADR-0006, ADR-0010, ADR-0015:

  * Every declared `pricing` and `threat` edge is priced twice, through the
    estate's OWN machinery and no other: the `ico` penalty schema through
    `ico`'s own converter (`schema/to_fair_scenario.py build`, the fixed
    `uk-gdpr`/`lower-tier` entry -- spec.md's own acceptance wording), the
    threat feed through `platform/feeds/to_fair_scenario.py`, reusing
    `_threat_scenario` exactly as ticket 13's caging path already calls it.
    No second risk engine, no second appetite store (`_appetite`,
    `_cage_engine`, both already ticket 13's).
  * "Old" is the version the LAST SIGNED composed artefact's own header
    recorded for that (party, kind) -- the same `_previous_header` ticket
    14/15 already read, one more field of it. No prior header, or no prior
    edge of that kind at all, means nothing to compare a bump against yet:
    old and new both price at THIS run's version, which is a real, honest
    "no move" -- not a skipped computation. This runs every time, not only
    when a version actually moved: "for each party it prints the old
    price, the new price, the old tier and the proposed tier" (spec.md) is
    unconditional; whether the two prices differ is a separate fact the
    `changed` field carries.
  * `select_tier` can return `"deny"`, and the `cage-tier` MutatingPolicy
    coerces any label value it does not recognise to `baseline` -- ADR-0015
    names the consequence: a merged `tier: deny` label would invert the
    proposal in silence. A proposed `deny` is therefore marked
    `proposed_as: "issue"` here; every other tier is `"label"`. This is the
    mark, not the act -- composition itself opens nothing, ticket 17 wires
    the proposer that reads this mark and opens the right kind of thing.
  * Pricing touches NO rendered file. `render_member`/the members loop
    never sees a pricing or threat edge at all -- they carry no rule, by
    construction (spec.md: "the last two supply no rule and are never
    asked for one") -- so a price move changes `prices[]` and the header's
    `parents[]` entry for that one edge, and nothing else composition
    renders.
  * No wall clock anywhere in this module. Both converters this section
    calls take no `--as-of` at all (`ico`'s `build` and the feeds module's
    `threat` subcommand); an `eol` parent kind does not exist in the party
    artefact schema, so composition never has occasion to pass one. ADR-
    0006/ADR-0010's line stays exactly where the earlier tickets already
    drew it: a feed may re-price, and it may never apply -- nothing here
    ever reads `datetime.now()` or a scheduler of any kind.

ECO-SYSTEM TICKET 21 (ADR-0019) opens the parent kind to `feed` with a
free `name`: `{party: feeds, kind: feed, name: threat-register, version: v1}`
resolves to `<estate>/feeds/threat-register/v1/feed.json`, the envelope is
checked against `platform/feeds/schema.json` (stdlib only) and its `payload`
is what the publisher's converter prices. `{party: ico, kind: feed, name:
penalty-schema}` resolves the same way, falling back to ico's pre-envelope
`schema/<version>/penalty-schema.json` until ico v3 lands. The legacy kinds
`pricing` and `threat` stay as read-only aliases of those two names, so a
header recorded before the rename still yields an "old" version. A file
that is not a valid envelope is an `invalid-feed` refusal, never a crash.

ECO-SYSTEM TICKET 38 (ticket 15's resolution; ADR-0020; the ADR superseding
ADR-0013/0017/0018 point 3 is ticket 39's): A HOLE IS PRICED, NOT COUNTED.

  * The new-hole, baseline-widening and new-ungoverned-namespace refusals are
    GONE. Each prints as a `deltas[]` entry under the adopter's own
    perspective and currency: what changed since the last signed composed
    artefact, and what a pinned instrument prices it at. A delta no pinned
    instrument names carries `amount: null` and `priced_by: null` -- a named
    absence, never a zero and never a refusal.
  * Every hole is keyed on (source, id) -- the catalogue that defines the
    control and its bare id in it -- across EVERY `controls` parent, an
    adopter's own catalogue included. A claim's source is its component-
    definition's `source` href; a bare `overlay.controls` id is the
    baseline's catalogue's, and `party:id` names another controls parent's.
    The header writes the bare id where the source is the baseline's own and
    `source:id` otherwise, so the real estate's header shape is byte-stable.
  * An UNGOVERNED NAMESPACE is priced: its workload share (Deployments,
    StatefulSets, DaemonSets, Jobs and CronJobs in the repo walk, over the
    same across every institution namespace) of the adopter's whole uncaged
    residual, LEF-ramped from `since` by the EOL feed's own `eol_ramp`, and
    bounded at the whole residual. `since` is READ off the first SIGNED tag
    whose header names the namespace (no new header field, and it survives a
    close and a reopen because tag history does); `as_of` is the newest
    `published_at` among the pinned feeds, so this module still reads no
    clock. A since no signed tag carries, or a residual no feed prices, is a
    named limit on the entry, never an invented date and never a zero.
  * A BESPOKE CONTROL is one the adopter defines in a small OSCAL catalogue
    it publishes as a `controls` parent of ITSELF (the self-pin resolves to
    the adopter's own tree: the catalogue is signed by the same tag as the
    composed artefact, ADR-0017's "no separate pin"). Its hole is priced by
    the scenario the catalogue's control names (`props[name=scenario]`,
    repo-relative) through the same cage engine the restate path uses. A
    bespoke hole with NO scenario is the one hole-shaped refusal left: a
    missing instrument (ADR-0020), because only the party that invented the
    control can say what missing it costs.

ECO-SYSTEM TICKET 69 (ticket 58 Q5(b); ADR-0020): AN UNTAGGED PIN IS A
PRICED HOLE. The premium edge reads the pin's signature state off the
parent tree's OWN tags (`pin_signature` on the entry: `signed` when a tag
of the pinned form is an annotated tag object carrying a signature block,
`untagged` when the checkout shows the publisher's tags and none of them
signs the pin, `unobserved` when this checkout is in no position to say --
no git metadata, no tag at all, or a matched tag that is not an annotated
object because a second fetch flattened it). Untagged, the pin
is a `hole` on the premium entry -- the premium itself, booked as paid
against a quote no tag signs, under the adopter's own perspective and
currency -- printed as a `new-untagged-pin` delta, recorded on the next
composition, and closed (a `closed-untagged-pin` delta) by the first
signed tag that carries it, with no edit. Unobserved opens nothing and
closes nothing. Nothing here refuses, and nothing here claims a signature
VERIFIES: the identity-pinned verification against the publisher's real
remote is the hub's verify/feed-contract/verify-untagged-pin-is-priced.sh.

ECO-SYSTEM TICKET 45 (ADR-0019, ADR-0020, ADR-0025): SWITCHING COST,
COMPUTED IN COMPOSITION -- AND THE TREE THAT MAKES IT PAYABLE.

  * A `switching` entry lands in prices[] for every SUBSTITUTABLE parent
    edge -- a `feed`, because a feed is discovered through the publisher's
    own `publishes[]` record and any party may publish one (ADR-0019
    point 5). `implementations` and `controls` resolve through a Flux pin
    and a catalogue; dropping one is not a switch and nothing here prices
    it. That limit is printed, not implied.
  * The amount is MEASURED: the whole edge set is re-priced with that
    publisher's feed edges dropped and the two priceable exposures are
    differenced through the estate's one summing helper. Re-composing, not
    subtracting -- driftwood's own twin borrows its loss-event frequency
    from the threat register it subscribes to, so dropping that publisher
    does not merely remove a line, it stops the twin pricing at all, and a
    subtraction would have printed a confident number and been wrong.
  * It is an annual rate, because every figure in prices[] is one.
    `over_pin_life` carries that rate over the window the pin has actually
    stood, from the edge's own signed `since` to this composition's own
    as-of -- two signed facts, so no clock is read (D1). An edge with no
    `since` is a window with one end and REFUSES as a missing instrument.
  * A counterfactual that cannot be priced at all is a named
    could-not-look: no amount, no per-customer restatement, and the
    publisher's own refusal carried verbatim on `could_not_look`. Never a
    pass and never a guess.
  * A `premium` is a cost, not exposure, so dropping an insurer moves the
    priceable exposure by nothing. The premium that goes with it is named
    on `unpriceable[]` beside the figure and never folded into it.
  * VENDORING. `composed/feeds/<party>/<version>/` carries the adopter's
    own copy of every payload it was priced from, the publisher's party
    artefact where it has one, and the converter that priced it -- each at
    the publisher's OWN relative path, so feed_file(), _converter() and
    pin_content read a vendored tree with no special case. Every file is
    digested into `PROVENANCE.json` and the digests ride on the header, so
    the adopter's own tag signs them. With a publisher's clone absent the
    adopter re-derives its own signed prices from that copy and names the
    substitution on an open `publisher-clone-absent` limit; a copy that
    does not match its signed digest REFUSES rather than pricing from
    bytes nobody signed.

Usage:
    composition.py compose <adopter-dir> [--estate-clone DIR] [--out DIR]
    composition.py verify <adopter-dir> [--estate-clone DIR]
    composition.py --selfcheck
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PLATFORM_DIR = HERE.parent
ESTATE_CLONE = PLATFORM_DIR.parent
# A nested worktree of the platform clone (`.estate-clone/platform/.work/<ticket>`,
# the build brief's layout) resolves to a parent that is not the estate; the
# override names the estate to compose against without moving the file.
DEFAULT_ESTATE_CLONE = Path(os.environ["PAVC_ESTATE_CLONE"]) if os.environ.get("PAVC_ESTATE_CLONE") \
    else ESTATE_CLONE

sys.path.insert(0, str(PLATFORM_DIR / "party"))
import party_artefact  # noqa: E402
# Ticket 77 item 1: the one "a pinned tree must carry the section the pin is used for" rule,
# stated once in party/pin_content.py and applied here, in the insurer's pricer, and (restated
# in git plumbing, because the hub is not a party and pins no platform) in the hub's
# verify/feed-contract.
import pin_content  # noqa: E402

ADMISSION_KINDS = ("ValidatingPolicy", "MutatingPolicy", "GeneratingPolicy")
VERSION_SUFFIX = re.compile(r"-\d+-\d+-\d+$")

# The whole strictness ladder (ADR-0016: a ValidatingPolicy concept and
# nothing else). A restatement is accepted only when it does not decrease.
STRICTNESS = {"Audit": 0, "Deny": 1}

LABEL_FAMILY = "policy-as-versioned.dev/policy"
LABEL_VERSION = "policy-as-versioned.dev/policy-version"
COMPOSED_FOR = "policy-as-versioned.dev/composed-for"
PROVENANCE_INHERITED = "policy-as-versioned.dev/inherited-from"
PROVENANCE_SOURCE = "policy-as-versioned.dev/source-path"
GOVERNED_LABEL = "policy-as-versioned.dev/governed"
INSTITUTION_LABEL = "policy-as-versioned.dev/institution"
# What counts as a workload when an ungoverned namespace is priced as a share
# (ticket 38): the pod-owning kinds a repo walk can see. A namespace created by
# hand on the cluster stays invisible (ADR-0018 point 3) -- it is Flux drift,
# owned by the estate's drift tooling, not something merge time can price.
WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")
# A control key is (source, id): the party whose catalogue defines the control
# and the bare id exactly as that catalogue writes it (ADR-0013's exact-string
# rule, per catalogue). `source:id` is how a party names a control off the
# baseline's own catalogue in `overlay.controls` and how the header records
# one; a bare id is the baseline's catalogue's. Catalogue ids carry no colon.
CONTROL_KEY_SEP = ":"
# The OSCAL prop on a bespoke control that names the adopter-signed scenario
# pricing its hole, repo-relative to the adopter's own tree.
BESPOKE_SCENARIO_PROP = "scenario"
# The deltas[] kinds: what replaced the three refusals, plus their closings.
DELTA_KINDS = ("new-hole", "closed-hole", "baseline-widening",
               "new-ungoverned-namespace", "closed-ungoverned-namespace",
               "new-untagged-pin", "closed-untagged-pin")
# Ticket 69: what a premium entry's `pin_signature.state` may read, and the
# kind of the hole an untagged pin opens on that entry.
PIN_SIGNATURE_STATES = ("signed", "untagged", "unobserved")
UNTAGGED_PIN_HOLE_KIND = "untagged-pin"

# Where an unpinned parent kind's version lives inside the PARTY'S OWN clone
# -- ticket 11's forward note: "the seam/resolver (ticket 12) must resolve
# them by reading the party directly (ico's schema/v1/, platform's
# feeds/threat-register/v1/), not via a GitRepository."
UNPINNED_VERSION_SUBDIR: dict[str, tuple[str, ...]] = {
    "pricing": ("schema", "{version}"),
    "threat": ("feeds", "threat-register", "{version}"),
}

# Eco-system ticket 21 (ADR-0019): the parent kind is closed to controls,
# implementations, feed; a feed carries a free `name`. The two legacy kinds
# stay as read-only aliases this phase so the three adopters still compose
# without rewriting their pins.
FEED_ALIASES: dict[str, str] = {"pricing": "penalty-schema", "threat": "threat-register"}
FEED_KINDS = ("feed",) + tuple(FEED_ALIASES)
FEED_SCHEMA_PATH = PLATFORM_DIR / "feeds" / "schema.json"
# The converter each feed name is priced through, and the version key its
# legacy raw shape carries (injected into the payload when the envelope
# carries it instead, so the unmodified converters keep working).
FEED_CONVERTERS: dict[str, tuple[str, ...]] = {
    "threat-register": ("feeds", "to_fair_scenario.py"),
    "penalty-schema": ("schema", "to_fair_scenario.py"),
}
FEED_VERSION_KEY = {"threat-register": "feed_version", "penalty-schema": "schema_version"}

# Eco-system ticket 25 (ADR-0020, ADR-0021): the one prices[] schema.
# Every entry carries perspective, currency, source, kind, amount and a
# per-customer restatement. NO SUM CROSSES A PERSPECTIVE OR A CURRENCY.
#   feed        a subscribed publisher's price (source: the publishing party)
#   twin        the adopter's own forward-intel scenario (source: twin)
#   premium     an insurance contract cost (source: insurer), read off the
#               insurer's own signed quote feed by price_quote() below --
#               ticket 36, the producer ticket 25 reserved this kind for. What
#               cover COSTS under the adopter's perspective, never what the
#               insurer's own layer arithmetic makes of it (ticket 14 answer 3).
#   switching   a portability/lock-in cost (source: twin) -- RESERVED, schema
#               support only. Producer: ticket 32.
#   reliability a failed cross-org reach demand, priced under the CALLER's
#               perspective, never gated (ticket 15 amendment C18) -- RESERVED,
#               schema support only. Producer: ticket 32.
# Two of the four items in the spec's one schema pass are therefore reserved,
# not observed: nothing in this estate constructs an entry of those kinds yet.
PRICE_KINDS = ("feed", "twin", "premium", "switching", "reliability")

# ---- eco-system ticket 45: the switching cost, and the tree that pays it ----
#
# A SUBSTITUTABLE parent is a `feed`. A feed is discovered through the
# publisher's own `publishes[]` record and any party may publish one
# (ADR-0019 point 5), so leaving one publisher for another is a move this
# estate can describe. `implementations` and `controls` resolve through a Flux
# pin and a catalogue; dropping one is not a switch, it is leaving the estate,
# and nothing here prices that. The limit is printed, not implied.
#
# The amount is MEASURED, never modelled: the same composition is re-priced
# with that publisher's feed edges dropped and the two priceable exposures are
# differenced. That is why it must re-compose rather than subtract the entry it
# was about to lose -- driftwood's twin entry annualises on the threat
# register's own LEF, so dropping the threat publisher moves a price that is
# not the threat publisher's.
#
# `premium` is not exposure (EXPOSURE_KINDS below says why), so dropping an
# insurer moves the priceable exposure by nothing. The premium that goes with
# it is NAMED on `unpriceable[]` rather than folded into a figure it does not
# belong in: no sum crosses a perspective, a currency, or the line between what
# a party is on the hook for and what it pays to lay that off.
SWITCHING_KIND = "switching"
SWITCHING_BASIS = "re-composed with this publisher's feed edges dropped"
# Annualised over the pin's life: the amount is a rate (£/yr, like every other
# figure in prices[]), and `over_pin_life` carries that rate over the window the
# pin has actually stood -- from the edge's own signed `since` to this
# composition's own as-of. Both ends are signed facts, so no clock is read (D1).
MONTHS_PER_YEAR = 12
# Where the adopter keeps its own copy of every payload it was priced from and
# the converter that priced it, under the adopter's OWN signature. Without it
# the adopter cannot restate its own signed history at all once a publisher's
# repository is unreachable: the payload lives in the publisher's tree and the
# converter is a script in somebody else's repo. `<party>/<version>/` is the
# ticket's own layout; inside, the publisher's OWN relative paths are
# reproduced, so feed_file(), _converter() and pin_content read a vendored tree
# with no special case at all.
VENDORED_DIR = ("composed", "feeds")
VENDORED_PROVENANCE = "PROVENANCE.json"
VENDORED_LIMIT = "publisher-clone-absent"
# Named ceiling: a vendored tree carries the feed and its converter, not the FX
# publisher's `converters/fx.py`. Every party in this estate reports in GBP and
# every feed prices in GBP, so no re-derivation has ever needed a rate; one that
# did would refuse for want of an instrument (_fx_rate), which is the right
# answer and not a silent one.
# A feed whose name starts with this is an insurance quote: one feed per insured
# adopter (`quote-driftwood`, ticket 14 answer 4), priced by its publisher under
# the INSURER's perspective and read here as one contract cost line under the
# adopter's own. Matched on the name, not on the publishing party, so a second
# carrier quoting the same adopter needs no change here.
QUOTE_PREFIX = "quote-"
# A party that states no reporting currency reports in USD (spec.md, "The £
# seam"); the UK parties all declare GBP on their own artefacts.
DEFAULT_REPORTING_CURRENCY = "USD"
# The adopter's own twin publishes forward intelligence into the adopter's own
# repo as an ADR-0019 envelope (ADR-0021). No feed = no twin entry, never a
# refusal.
FORWARD_INTEL = "forward-intel"
FORWARD_INTEL_DIR = ("twin", FORWARD_INTEL)
# The adopter's own versioned selection-policy package (ADR-0021). The curve
# never picks; this package does, and the proposal PR names its version.
SELECTION_POLICY_DIR = "selection-policy"
# The signed FX feed. An amount in a currency other than the perspective's
# reporting currency needs a rate for the price's own as-of date; no rate is a
# MISSING INSTRUMENT and refuses (ADR-0020). Never sum unconverted.
FX_FEED = "fx"

YAML_KWARGS = dict(sort_keys=False, allow_unicode=True, width=4096)

HEADER_COMMENT = (
    "# advisory header -- policy-as-versioned.dev/composed (ticket 12; ADR-0012).\n"
    "# Never read by Kyverno. Strip this file and every other file in this\n"
    "# tree is what the engine reads (per-rule composed-for/inherited-from/\n"
    "# source-path annotations are the same story, one level down).\n"
)


class Refused(Exception):
    """A reason composition cannot even start. Turned into outcome:refused,
    never a crash and never a silent pass."""


# --------------------------------------------------------------------------
# 1. resolving parents to a commit SHA
# --------------------------------------------------------------------------


def resolve_sha(party: str, kind: str, version: str, adopter_dir: Path, tree_path: Path,
                name: str | None = None) -> str:
    """The commit SHA a parent edge resolves to. `controls`/`implementations`
    read the SHA Renovate already wrote into the adopter's own Flux pin
    (ADR-0012: reused, never re-derived). `pricing`/`threat` have no such
    pin in this estate, so they resolve by reading the party's own tree."""
    pin_rel = party_artefact.PIN_FILES.get((party, kind))
    if pin_rel is not None:
        docs = [d for d in yaml.safe_load_all((adopter_dir / pin_rel).read_text()) if isinstance(d, dict)]
        gitrepo = next((d for d in docs if d.get("kind") == "GitRepository"), None)
        if gitrepo is None:
            raise Refused(f"{pin_rel}: no GitRepository document found")
        commit = gitrepo.get("spec", {}).get("ref", {}).get("commit")
        if not commit:
            raise Refused(f"{pin_rel}: spec.ref.commit is not set")
        return commit
    return _resolve_unpinned_sha(tree_path, kind, version, name)


def _pin_containment_limit(parents: list[dict], parent_trees: dict[str, Path] | None,
                           merged: dict) -> dict:
    """Does the commit the adopter PINS actually contain the policy version
    trees this composed set renders?

    `resolve_sha` takes the implementations SHA from the adopter's own Flux pin
    (ADR-0012: reused, never re-derived) while the BYTES are read out of the
    parent worktree. Those two can disagree, and on 2026-08-29 they did: the
    header asserted platform 1.1.1 at 58ef9c57 while the set rendered v4.0.0,
    which that commit does not contain. Nothing graded the pair, so a composed
    set could name a parent release that holds none of its own policy trees.

    Named here rather than refused, because the honest reason it is open today
    is that the phase is unpushed: the commit that DOES carry v4.0.0 is on a
    local branch, and hard rule 3 says a signed tag cannot be cut locally. The
    limit closes the day the owner merges and the adopter's pin moves.
    ponytail: implementations only -- the one kind with both a Flux pin and a
    per-version directory. Add controls when nist ships versioned trees.
    """
    versions = sorted({key[0] for key in merged})
    absent: list[str] = []
    checked = 0
    for parent in parents:
        if parent["kind"] != "implementations":
            continue
        tree = (parent_trees or {}).get(parent["party"])
        if tree is None or not (Path(tree) / ".git").exists():
            continue
        for version in versions:
            checked += 1
            probe = subprocess.run(
                ["git", "-C", str(tree), "cat-file", "-e",
                 f"{parent['sha']}:distribution/policies/v{version}"],
                capture_output=True, text=True)
            if probe.returncode != 0:
                absent.append(f"{parent['party']}@{parent['version']} ({parent['sha'][:8]}) "
                              f"does not contain distribution/policies/v{version}")
    return {
        "name": "pinned-parent-lacks-rendered-versions",
        "detail": "the composed set renders policy versions the pinned parent commit does "
                  "not contain; the header names a parent release that holds none of these "
                  "trees. " + ("; ".join(absent) if absent else "every rendered version is "
                  "present at the pinned commit"),
        "count": len(absent),
        "checked": checked,
        "status": "open" if absent else "closed",
    }


def _resolve_unpinned_sha(tree_path: Path, kind: str, version: str, name: str | None = None) -> str:
    # A VENDORED tree (ticket 45) is not a git repository and its content digest
    # is not the publisher's commit. The SHA the publisher's own clone resolved
    # to is recorded in the provenance the adopter signed, so a re-derivation
    # with the clone absent names the same parent commit the signed artefact
    # names -- rather than a digest of the copy, which would make every
    # re-derivation disagree with the thing it is re-deriving.
    provenance = Path(tree_path) / VENDORED_PROVENANCE
    if provenance.exists():
        try:
            recorded = json.loads(provenance.read_text()).get("sha")
        except json.JSONDecodeError:
            recorded = None
        if recorded:
            return str(recorded)
    if kind == "feed" and name:
        version_dir = feed_file("", name, version, tree_path).parent
    else:
        parts = UNPINNED_VERSION_SUBDIR.get(kind)
        version_dir = tree_path.joinpath(*(p.format(version=version) for p in parts)) if parts else None
    if (tree_path / ".git").exists():
        cmd = ["git", "-C", str(tree_path), "log", "-1", "--format=%H"]
        if version_dir is not None and version_dir.is_dir():
            cmd += ["--", str(version_dir.relative_to(tree_path))]
        result = subprocess.run(cmd, capture_output=True, text=True)
        sha = result.stdout.strip()
        if result.returncode == 0 and sha:
            return sha
    # ponytail: not a git repo (a test fixture), or git found no history for
    # the path -- a deterministic content digest stands in. Advisory
    # metadata only; never compared against a real git object. Upgrade path:
    # none needed unless a real non-git party tree turns up.
    digest_root = version_dir if version_dir is not None and version_dir.is_dir() else tree_path
    h = hashlib.sha256()
    # __pycache__ is excluded: load_implementations() dynamically imports
    # this same tree's render-orphan-guard.py, which writes a .pyc cache
    # file to disk as a side effect the FIRST time it runs in a process.
    # Without this exclusion the digest of an unpinned tree is not stable
    # across repeated calls in one process (found by ticket 14's verify()
    # round-trip, which is the first caller to compose() the same
    # non-git fixture tree twice) -- it is a bytecode-cache byproduct, not
    # tree content.
    for f in sorted(p for p in digest_root.rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts):
        h.update(f.read_bytes())
    return h.hexdigest()


def _parent_key(edge: dict) -> str:
    """One identity per parent: the feed name for a feed (aliased or not),
    the kind otherwise -- so `ico/pricing@v1` and `ico/feed:penalty-schema@v2`
    are the same parent at two versions."""
    return _feed_name(edge) or edge["kind"]


def _feed_name(edge: dict) -> str | None:
    """The feed name an edge subscribes to: `name` on a `feed` edge, the
    aliased name on a legacy `pricing`/`threat` edge, None otherwise."""
    if edge.get("kind") == "feed":
        return edge.get("name")
    return FEED_ALIASES.get(edge.get("kind"))


def _major_dir(version: str) -> str:
    """'v1' -> 'v1'; '1.4.0' -> 'v1'. A feed file lives at <name>/v<MAJOR>/."""
    v = version.lstrip("v")
    return "v" + v.split(".")[0]


def _published_path(tree_path: Path, name: str) -> str | None:
    """The directory the PUBLISHER itself declares for a feed name, on its own
    party.yaml `publishes[]` (ADR-0019: the composer resolves `name` to `path`).
    None where the tree carries no party artefact or does not publish that name.

    Every feed in this estate but the insurer's publishes at a directory equal
    to its name, so this changes nothing for them; the insurer publishes one
    feed per adopter (`quote-driftwood` at `quote/driftwood`, ticket 14 answer
    4) and is the first publisher whose name and path differ."""
    party_yaml = Path(tree_path) / "party.yaml"
    if not party_yaml.exists():
        return None
    doc = yaml.safe_load(party_yaml.read_text()) or {}
    return next((e.get("path") for e in doc.get("publishes") or []
                 if e.get("name") == name), None)


def feed_file(party: str, name: str, version: str, tree_path: Path) -> Path:
    """Where a feed parent's file lives inside the party's own tree. The
    envelope path `<path>/v<MAJOR>/feed.json` wins when it exists -- `<path>`
    being what the publisher's own party.yaml declares for that name, or the
    name itself; otherwise the pre-envelope location of the two migrating
    feeds."""
    envelope = (Path(tree_path) / (_published_path(tree_path, name) or name)
                / _major_dir(version) / "feed.json")
    if envelope.exists():
        return envelope
    # ponytail: bridge until ico v3 lands (penalty-schema) and the platform
    # copies of threat-register are deleted; drop these two lines then.
    if name == "penalty-schema":
        return Path(tree_path) / "schema" / version / "penalty-schema.json"
    if name == "threat-register":
        return Path(tree_path) / "feeds" / "threat-register" / version / "register.json"
    return envelope


def _validate_envelope(doc: dict, where: str) -> None:
    """A stdlib-only check of feeds/schema.json: required keys, types, the
    kind enum, the version/date patterns, no extra keys. ponytail: no
    jsonschema in the estate's python3; switch to it if the schema grows
    beyond what this reads."""
    schema = json.loads(FEED_SCHEMA_PATH.read_text())
    props = schema["properties"]
    errors = []
    for k in schema["required"]:
        if k not in doc:
            errors.append(f"missing {k}")
    for k in doc.keys() - props.keys():
        errors.append(f"unknown key {k}")
    types = {"string": str, "object": dict}
    for k, spec in props.items():
        if k not in doc:
            continue
        if "enum" in spec and doc[k] not in spec["enum"]:
            errors.append(f"{k}: {doc[k]!r} not in {spec['enum']}")
        if "type" in spec and not isinstance(doc[k], types[spec["type"]]):
            errors.append(f"{k}: expected {spec['type']}")
        if "pattern" in spec and isinstance(doc[k], str) and not re.match(spec["pattern"], doc[k]):
            errors.append(f"{k}: {doc[k]!r} does not match {spec['pattern']}")
        if spec.get("minLength") and isinstance(doc[k], str) and len(doc[k]) < spec["minLength"]:
            errors.append(f"{k}: empty")
    if errors:
        raise Refused(f"{where}: not a valid feed envelope: " + "; ".join(errors))


def load_feed_payload(path: Path, name: str, version: str) -> dict:
    """The priced body of a feed parent. An envelope is validated against
    feeds/schema.json and its `payload` returned; a pre-envelope raw file
    (the bridge above) is returned as it is."""
    doc = json.loads(Path(path).read_text())
    if "payload" not in doc and "kind" not in doc:
        return doc  # legacy raw shape
    _validate_envelope(doc, str(path))
    if doc["name"] != name:
        raise Refused(f"{path}: envelope names feed {doc['name']!r}, pin says {name!r}")
    payload = dict(doc["payload"])
    # ponytail: the unmodified converters read their own version key from
    # the body; fill it from the envelope when the payload does not carry it.
    payload.setdefault(FEED_VERSION_KEY.get(name, "feed_version"), version)
    return payload


def _converter(name: str, tree_path: Path) -> Path:
    """The publisher-shipped converter for a feed name: beside the feed in
    its own tree if it ships one, else the estate's existing copy."""
    for candidate in (Path(tree_path) / name / "to_fair_scenario.py",
                      Path(tree_path).joinpath(*FEED_CONVERTERS[name]),
                      PLATFORM_DIR.joinpath(*FEED_CONVERTERS[name])):
        if candidate.exists():
            return candidate
    raise Refused(f"no converter for feed {name!r} under {tree_path}")


# --------------------------------------------------------------------------
# 1b. the vendored feed tree (eco-system ticket 45)
# --------------------------------------------------------------------------


def vendored_rel(party: str, version: str) -> str:
    """`composed/feeds/<party>/<version>` -- the ticket's own layout."""
    return "/".join((*VENDORED_DIR, party, str(version)))


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def vendor_feed(edge: dict, tree: Path, sha: str) -> tuple[str, dict[str, str], dict]:
    """The adopter's own copy of ONE priced feed: the publisher's party
    artefact, the payload at the version this adopter pins, and the converter
    that prices it -- each at the publisher's own relative path, so a vendored
    tree is read by feed_file(), _converter() and pin_content with no special
    case anywhere.

    Returns (base path relative to the adopter, files by relative path, the
    provenance record). Every file is digested INTO the record and the record
    is rendered, so the adopter's own tag signs the digests and a later
    re-derivation is held to them.

    Refuses -- never partially vendors -- when a file it must copy is not
    there: a half-vendored tree re-derives half a price, which is worse than
    saying it cannot look (ADR-0020)."""
    name, version = _feed_name(edge), str(edge["version"])
    tree = Path(tree)
    feed_path = feed_file(edge["party"], name, version, tree)
    if not feed_path.exists():
        raise Refused(f"missing instrument: no file at {feed_path} for feed {name!r}@{version}")
    feed_rel = str(feed_path.relative_to(tree))
    files = {feed_rel: feed_path.read_text()}
    # The publisher's own party artefact travels too, where it has one: it is
    # what says WHERE that publisher keeps the feed (ADR-0019 point 5), and
    # without it a vendored tree can only be read through the two pre-envelope
    # locations feed_file still bridges. A publisher that ships none is
    # recorded as shipping none rather than given one it never signed.
    party_yaml = tree / "party.yaml"
    if party_yaml.exists():
        files["party.yaml"] = party_yaml.read_text()

    converter_rel: str | None = None
    converter_from: str | None = None
    if name in FEED_CONVERTERS:
        converter = _converter(name, tree)
        # `<name>/to_fair_scenario.py` is the FIRST place _converter looks, so a
        # vendored tree ships its converter there whichever party's copy priced
        # it -- and the record says whose copy that was. The threat register's
        # publisher ships none of its own today and platform's is used; that is
        # a fact about the estate, and it is written down rather than smoothed
        # over by copying the file to a path that implies the publisher's.
        converter_rel = f"{name}/{converter.name}"
        converter_from = next((p for p, t in (("platform", PLATFORM_DIR),)
                               if str(converter).startswith(str(t))
                               and not str(converter).startswith(str(tree))), edge["party"])
        files[converter_rel] = converter.read_text()

    record = {
        "party": edge["party"], "kind": edge["kind"], "name": name, "version": version,
        "sha": sha,
        "feed_path": feed_rel,
        "party_artefact": "party.yaml" if party_yaml.exists() else None,
        "converter": converter_rel,
        "converter_from": converter_from,
        "published_at": _feed_as_of(feed_path),
        "files": {rel: _digest(text) for rel, text in sorted(files.items())},
    }
    files[VENDORED_PROVENANCE] = json.dumps(record, indent=2, sort_keys=True) + "\n"
    return vendored_rel(edge["party"], version), files, record


def vendored_tree(adopter_dir: Path, party: str, version: str) -> Path | None:
    """The adopter's own vendored copy of a publisher's tree, if it carries one
    for this exact pin AND every file in it still digests to what the adopter's
    own signature recorded. A tampered copy is a MISSING instrument, not a
    cheaper one: it refuses (ADR-0020) rather than pricing from bytes nobody
    signed."""
    base = Path(adopter_dir) / vendored_rel(party, version)
    provenance = base / VENDORED_PROVENANCE
    if not provenance.exists():
        return None
    try:
        record = json.loads(provenance.read_text())
    except json.JSONDecodeError as e:
        raise Refused(f"missing instrument: {provenance} is not readable JSON ({e}), so the "
                       f"vendored copy of {party}@{version} cannot be trusted to re-derive "
                       f"anything") from None
    for rel, digest in (record.get("files") or {}).items():
        path = base / rel
        if not path.exists():
            raise Refused(f"missing instrument: {provenance} records {rel}, and the vendored "
                           f"copy of {party}@{version} does not carry it")
        if _digest(path.read_text()) != digest:
            raise Refused(f"missing instrument: the vendored {rel} for {party}@{version} does "
                           f"not match the digest {provenance} signed, so the bytes this "
                           f"composition would price from are not the bytes anybody signed")
    return base


def _feed_publishers(adopter_dir: Path, parent_trees: dict[str, Path]) -> dict[str, list[str]]:
    """feed name -> every party this composition can see that DECLARES it
    publishes that name on its own signed party.yaml. `publishes[]` is the only
    discovery record there is (ADR-0019 point 5), so this is what the estate can
    honestly say about whether a publisher has an alternate: it is a survey of
    the pinned parent set and the adopter itself, and it never asserts that no
    alternate exists anywhere -- only that none is visible from here."""
    found: dict[str, list[str]] = {}
    for tree in [Path(adopter_dir), *(Path(t) for t in parent_trees.values())]:
        party_yaml = tree / "party.yaml"
        if not party_yaml.exists():
            continue
        try:
            doc = yaml.safe_load(party_yaml.read_text()) or {}
        except yaml.YAMLError:
            continue
        who = doc.get("party")
        for record in doc.get("publishes") or []:
            if record.get("kind") != "feed" or not record.get("name") or not who:
                continue
            names = found.setdefault(record["name"], [])
            if who not in names:
                names.append(who)
    return {name: sorted(parties) for name, parties in found.items()}


# --------------------------------------------------------------------------
# 2. loading every member of every kind from an implementations parent
# --------------------------------------------------------------------------


def _version_array(root: Path) -> list[dict]:
    doc = yaml.safe_load((root / "distribution" / "versions.yaml").read_text())
    return doc["spec"]["inputs"][0]["versions"]


def load_implementations(root: Path) -> tuple[dict[str, dict[tuple[str, str], dict]], list[dict]]:
    """Every admission member of every live policy version, keyed within
    each version on (identity family, name with its version stripped) --
    ADR-0016's fix for the prototype's (family, version) key, which drops a
    second member of one family in silence. Plus every `platform-machinery`
    guard (orphan guard, governed-namespace guard), each rendered through
    the parent's own offline twin under a second numbering axis."""
    live = [v["version"] for v in _version_array(root)]
    members_by_version: dict[str, dict[tuple[str, str], dict]] = {}

    for version in live:
        tree_dir = root / "distribution" / "policies" / f"v{version}"
        members: dict[tuple[str, str], dict] = {}
        for path in sorted(tree_dir.glob("*.yaml")):
            if path.name in ("kustomization.yaml",):
                continue
            for doc in yaml.safe_load_all(path.read_text()):
                if not isinstance(doc, dict) or doc.get("kind") not in ADMISSION_KINDS:
                    continue  # PriorityClasses are dials, not admission.
                labels = (doc.get("metadata") or {}).get("labels") or {}
                family = labels.get(LABEL_FAMILY, "(none)")
                base = VERSION_SUFFIX.sub("", doc["metadata"]["name"])
                action = None
                if doc["kind"] == "ValidatingPolicy":
                    action = (doc.get("spec", {}).get("validationActions") or ["Audit"])[0]
                members[(family, base)] = {
                    "kind": doc["kind"], "doc": doc, "action": action,
                    "path": str(path.relative_to(root)),
                }
        members_by_version[version] = members

    return members_by_version, _load_guards(root)


def load_overlay_add(party_doc: dict) -> dict[tuple[str, str, str], dict]:
    """Every `overlay.add` entry -- a member the adopter ships itself,
    keyed like a parent's own members: (version, identity family, name
    with its version suffix stripped). Each entry is `{"version": ...,
    "manifest": <a full admission-kind document>}`. Versioned with the
    composed artefact itself: no separate semver axis, no separate pin
    (ADR-0017 consequences: "Shipping a member adds no obligation ADR-0012
    did not already impose")."""
    out: dict[tuple[str, str, str], dict] = {}
    for i, item in enumerate(party_doc.get("overlay", {}).get("add", []) or []):
        doc = item["manifest"]
        if doc.get("kind") not in ADMISSION_KINDS:
            continue
        labels = (doc.get("metadata") or {}).get("labels") or {}
        family = labels.get(LABEL_FAMILY, "(none)")
        base = VERSION_SUFFIX.sub("", doc["metadata"]["name"])
        action = None
        if doc["kind"] == "ValidatingPolicy":
            action = (doc.get("spec", {}).get("validationActions") or ["Audit"])[0]
        out[(item["version"], family, base)] = {
            "kind": doc["kind"], "doc": doc, "action": action,
            "path": f"party.yaml overlay.add[{i}]",
        }
    return out


def _load_module(root: Path, filename: str, module_name: str):
    path = root / "distribution" / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_guards(root: Path) -> list[dict]:
    """Every `platform-machinery` member: the orphan guard and its CAGE (both ranged from
    the version array), the governed-namespace cage and its paired report (static,
    ADR-0014's fifth named gap), and the bottom-rung reach cage. All load through the
    parent's own offline twins, the same reason `_load_guard` always has: `verify-*.sh` and
    the shift-left check run without flux-operator in the loop.

    The last three arrived with eco-system ticket 89 and are read defensively, so an adopter
    pinned to a parent tag from before that ticket composes exactly what it composed then."""
    versions_yaml = root / "distribution" / "versions.yaml"
    orphan_twin = _load_module(root, "render-orphan-guard.py", "render_orphan_guard")
    # CUT versions only (eco-system ticket 89 R3): an uncut declared version has no tag and
    # no served cage, so it must fall into the orphan population rather than be allowed.
    # Read defensively -- a parent tag from before that fix has no served_versions().
    allowed = (orphan_twin.served_versions(versions_yaml)
               if hasattr(orphan_twin, "served_versions")
               else orphan_twin.versions(versions_yaml))
    orphan_doc = orphan_twin.orphan_guard(allowed)
    governed_twin = _load_module(root, "render-governed-namespace-guard.py", "render_governed_namespace_guard")
    governed_doc = governed_twin.governed_namespace_guard()
    members = [
        {"kind": orphan_doc["kind"], "doc": orphan_doc,
         "path": "distribution/versions.yaml (rendered from the array)",
         "out_path": "composed/orphan-guard.yaml", "member_name": "policy-version-orphan-guard"},
        {"kind": governed_doc["kind"], "doc": governed_doc,
         "path": "distribution/versions.yaml (static, ADR-0014)",
         "out_path": "composed/governed-namespace-guard.yaml", "member_name": "governed-namespace-requires-claim"},
    ]
    # Eco-system ticket 89. The two guards above stopped refusing anything, so an adopter that
    # inherited only them would inherit an ESTATE WITH A HOLE: the orphan guard reports and does
    # not cage, and every served cage-tier is scoped to its own version, so an orphan claim
    # would reach no cage at all. Whatever ships the guards must ship the cages beside them, or
    # the demotion is a regression for every consumer. Older parents that do not carry the new
    # renderers compose exactly as they did; this is read through `hasattr`, not assumed, so a
    # pinned tag from before this ticket still composes.
    if hasattr(orphan_twin, "orphan_cage"):
        cage_doc = orphan_twin.orphan_cage(allowed)
        members.append(
            {"kind": cage_doc["kind"], "doc": cage_doc,
             "path": "distribution/versions.yaml (rendered from the array, ticket 89)",
             "out_path": "composed/orphan-cage.yaml", "member_name": "policy-version-orphan-cage"})
    if hasattr(orphan_twin, "orphan_cage_hold"):
        # The UPDATE half. Without it an adopter inherits a cage a pod can relabel its way out
        # of; with the full body on UPDATE instead, it inherits one that refuses the currency
        # controller's re-cage patch. Both halves travel together or neither is correct.
        hold_doc = orphan_twin.orphan_cage_hold(allowed)
        members.append(
            {"kind": hold_doc["kind"], "doc": hold_doc,
             "path": "distribution/versions.yaml (rendered from the array, ticket 89)",
             "out_path": "composed/orphan-cage-holds.yaml",
             "member_name": hold_doc["metadata"]["name"]})
    if hasattr(governed_twin, "governed_namespace_hold"):
        ghold_doc = governed_twin.governed_namespace_hold()
        members.append(
            {"kind": ghold_doc["kind"], "doc": ghold_doc,
             "path": "distribution/versions.yaml (static, ticket 89)",
             "out_path": "composed/governed-namespace-holds.yaml",
             "member_name": ghold_doc["metadata"]["name"]})
    if hasattr(governed_twin, "governed_namespace_report"):
        report_doc = governed_twin.governed_namespace_report()
        members.append(
            {"kind": report_doc["kind"], "doc": report_doc,
             "path": "distribution/versions.yaml (static, ticket 89)",
             "out_path": "composed/governed-namespace-report.yaml",
             "member_name": "governed-namespace-unclaimed-report"})
    try:
        netpol_twin = _load_module(root, "render-bottom-rung-netpol.py", "render_bottom_rung_netpol")
    except FileNotFoundError:
        netpol_twin = None
    if netpol_twin is not None:
        netpol_doc = netpol_twin.bottom_rung_netpol(allowed)
        members.append(
            {"kind": netpol_doc["kind"], "doc": netpol_doc,
             "path": "distribution/versions.yaml (rendered from the array, ticket 89)",
             "out_path": "composed/bottom-rung-netpol.yaml",
             "member_name": "cage-netpol-bottom-rung"})
        # ...and the eviction class the two cages NAME. Every served PriorityClass is
        # version-suffixed (`cage-isolated-4-0-0`), so an adopter that inherited the cages
        # without this object would have every pod they cage refused by the Priority admission
        # plugin -- the cage becoming a refusal by another name. It is the one non-policy
        # member here, and it carries the same composed-for label and provenance annotations
        # every other member carries.
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("cage_body", root / "distribution" / "cage_body.py")
        _cb = _ilu.module_from_spec(_spec)
        sys.modules["cage_body"] = _cb
        _spec.loader.exec_module(_cb)
        pc_doc = _cb.bottom_rung_priorityclass()
        members.append(
            {"kind": pc_doc["kind"], "doc": pc_doc,
             "path": "distribution/versions.yaml (static, ticket 89)",
             "out_path": "composed/bottom-rung-priorityclass.yaml",
             "member_name": pc_doc["metadata"]["name"]})
    return members


# --------------------------------------------------------------------------
# 3. render: the hard constraint -- source-level only, flat, advisory-only additions
# --------------------------------------------------------------------------


def render_member(source_doc: dict, action: str | None, adopter_party: str,
                   source_ref: str, source_path: str) -> dict:
    """The whole inherited body, carried unchanged, plus one composed-for
    label and two provenance annotations. `action` is written to
    `spec.validationActions` ONLY on a ValidatingPolicy -- a MutatingPolicy
    and a GeneratingPolicy have no such field, and inventing one produces a
    manifest the Kyverno CRD schema refuses (the prototype's other named
    defect, ADR-0016)."""
    doc = copy.deepcopy(source_doc)
    if doc.get("kind") == "ValidatingPolicy" and action is not None:
        doc.setdefault("spec", {})["validationActions"] = [action]
    md = doc.setdefault("metadata", {})
    md.setdefault("labels", {})[COMPOSED_FOR] = adopter_party
    md.setdefault("annotations", {}).update({
        PROVENANCE_INHERITED: source_ref,
        PROVENANCE_SOURCE: source_path,
    })
    return doc


def strip_provenance(doc: dict) -> dict:
    """The inverse of render_member's advisory additions. Strip these and
    what remains must equal the committed source file, byte for byte after
    parsing -- the hard constraint `render_is_faithful` asserts."""
    doc = copy.deepcopy(doc)
    md = doc.get("metadata", {})
    labels = md.get("labels") or {}
    labels.pop(COMPOSED_FOR, None)
    if labels:
        md["labels"] = labels
    else:
        md.pop("labels", None)
    annotations = md.get("annotations") or {}
    for key in (PROVENANCE_INHERITED, PROVENANCE_SOURCE):
        annotations.pop(key, None)
    if annotations:
        md["annotations"] = annotations
    else:
        md.pop("annotations", None)
    return doc


def render_is_faithful(rendered_doc: dict, source_doc: dict) -> bool:
    return strip_provenance(rendered_doc) == source_doc


# --------------------------------------------------------------------------
# 4. governed namespaces (advisory metadata) and the governed-namespace lint
#    (ticket 15; ADR-0014, ADR-0018)
# --------------------------------------------------------------------------


def _namespace_facts(adopter_dir: Path) -> tuple[dict[str, bool], dict[str, int]]:
    """ONE walk over the adopter's own manifests (skipping .git, composed/ and
    other tickets' .work/): every Namespace carrying the `institution` label,
    mapped to whether it also carries `governed: "true"`, and the number of
    workloads (WORKLOAD_KINDS) declared in each namespace. A Namespace with no
    `institution` label at all is infrastructure and is not a candidate; the
    workloads in it are counted but never enter the institution denominator."""
    institution: dict[str, bool] = {}
    workloads: dict[str, int] = {}
    for path in sorted(Path(adopter_dir).rglob("*.yaml")):
        if ".git" in path.parts or "composed" in path.parts or ".work" in path.parts:
            continue
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text()) if isinstance(d, dict)]
        except yaml.YAMLError:
            continue
        for doc in docs:
            md = doc.get("metadata") or {}
            if doc.get("kind") == "Namespace":
                labels = md.get("labels") or {}
                if INSTITUTION_LABEL in labels:
                    institution[md["name"]] = labels.get(GOVERNED_LABEL) == "true"
            elif doc.get("kind") in WORKLOAD_KINDS:
                ns = str(md.get("namespace") or "default")
                workloads[ns] = workloads.get(ns, 0) + 1
    return institution, workloads


def governed_namespaces(adopter_dir: Path) -> list[str]:
    institution, _ = _namespace_facts(adopter_dir)
    return sorted(n for n, governed in institution.items() if governed)


def ungoverned_namespaces(adopter_dir: Path) -> list[str]:
    """Every Namespace manifest in the adopter's own repo that carries the
    `institution` label and not `governed: "true"` -- ADR-0014's silence
    hole moved up one level (ADR-0018): such a namespace can exempt every
    workload inside it by omission, the same way an unclaimed hole does. A
    Namespace with no `institution` label at all is infrastructure, not a
    candidate, and is ignored entirely -- the same walk `governed_namespaces`
    does, over the same files, just the other label."""
    institution, _ = _namespace_facts(adopter_dir)
    return sorted(n for n, governed in institution.items() if not governed)


def compute_ungoverned(current: set[str], prev_ids: set[str] | None) -> list[dict]:
    """ungoverned[] entries (new/recorded/closed) -- "the rule is the hole
    rule" (ticket 15): the exact new/recorded/closed shape compute_holes uses.
    prev_ids is None on the FIRST composition ever. Nothing here refuses any
    more (ticket 38): a new one is PRICED by price_ungoverned below and
    printed as a delta, exactly as a new hole is."""
    entries: list[dict] = []
    for name in sorted(current):
        status = "recorded" if prev_ids is None or name in prev_ids else "new"
        entries.append({"namespace": name, "status": status})
    if prev_ids is not None:
        for name in sorted(prev_ids - current):
            entries.append({"namespace": name, "status": "closed"})
    return entries


def _signed_tags(repo: Path) -> list[tuple[str, str]]:
    """(tag, date) for every annotated tag in the adopter's own repo that
    carries a signature block, oldest first. Presence of the block is what is
    read here; whether the signature VERIFIES is verify/provenance's job, and
    this module never claims it. [] where the tree is not a git repo (a
    fixture) or carries no such tag."""
    repo = Path(repo)
    if not (repo / ".git").exists():
        return []
    listed = subprocess.run(
        ["git", "-C", str(repo), "for-each-ref", "--sort=creatordate",
         "--format=%(refname:short) %(creatordate:short) %(objecttype)", "refs/tags"],
        capture_output=True, text=True)
    out: list[tuple[str, str]] = []
    for line in listed.stdout.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[2] != "tag":
            continue
        body = subprocess.run(["git", "-C", str(repo), "cat-file", "-p", parts[0]],
                              capture_output=True, text=True).stdout
        if "-----BEGIN" in body:
            out.append((parts[0], parts[1]))
    return out


def _first_signed_since(adopter_dir: Path, namespace: str) -> tuple[str | None, str | None]:
    """The date of the FIRST signed tag whose composed header records
    `namespace` as ungoverned -- the `since` an ungoverned namespace ramps
    from (ticket 38, ticket 15 Q3(a)). Read off tag history, so no new header
    field carries it and a namespace that closes and reopens keeps its
    original since. (date, None) when found; (None, why) when no signed
    composed artefact names it -- a fact to carry, never a date to invent."""
    for tag, date in _signed_tags(adopter_dir):
        shown = subprocess.run(["git", "-C", str(adopter_dir), "show", f"{tag}:composed/HEADER.yaml"],
                               capture_output=True, text=True)
        if shown.returncode != 0:
            continue
        text = shown.stdout
        if text.startswith(HEADER_COMMENT):
            text = text[len(HEADER_COMMENT):]
        try:
            header = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if isinstance(header, dict) and namespace in (header.get("ungoverned-namespaces") or []):
            return date, None
    return None, f"no signed composed artefact names {namespace}"


def _feeds_module():
    """platform's own feeds converter, imported for its `eol_ramp` -- the
    estate's one time-varying ramp (ticket 15 Q3: "the ramp already exists,
    so no invented formula and no knob"). The dates it takes are both signed
    facts; this module still reads no clock."""
    spec = importlib.util.spec_from_file_location("_pavc_feeds", PLATFORM_DIR / "feeds" / "to_fair_scenario.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ramp(since: str | None, as_of: str | None) -> float:
    """The LEF multiplier for how far `as_of` sits past `since`: the EOL feed's
    own eol_ramp, +1x per year past, capped at +4x. 1.0 where either date is
    unknown -- an unramped share, with the missing date named beside it."""
    if not since or not as_of:
        return 1.0
    return float(_feeds_module().eol_ramp(since, as_of))


def ungoverned_price(base: float, workloads: int, total_workloads: int, ramp: float) -> tuple[float, bool]:
    """The amount an ungoverned namespace prices at, and whether the bound
    bit: workloads inside over workloads in every institution namespace, times
    the whole uncaged residual, times the ramp, never above the whole residual
    (the bound keeps it a price of a SHARE). Pure, so the verifier and the
    hub tests re-derive it."""
    share = workloads / total_workloads if total_workloads else 0.0
    raw = base * share * ramp
    return min(base, raw), raw > base


def price_ungoverned(entries: list[dict], adopter_dir: Path, adopter_party: str, currency: str,
                     base: float | None, as_of: str | None) -> None:
    """Attach a `price` to every OPEN ungoverned entry (new or recorded).
    Everything on it is a fact the composition read or a limit it names:
    the workload counts, the share, `since` off the first signed tag naming
    the namespace, `as_of` off the newest pinned feed, the ramp between them,
    the base (the adopter's whole uncaged residual) and the bounded amount.
    Mutates `entries` in place."""
    institution, workloads = _namespace_facts(adopter_dir)
    total = sum(n for ns, n in workloads.items() if ns in institution)
    for entry in entries:
        if entry["status"] == "closed":
            continue
        name = entry["namespace"]
        inside = workloads.get(name, 0)
        since, since_limit = _first_signed_since(adopter_dir, name)
        limits: list[str] = []
        if since_limit:
            limits.append(f"{since_limit}: ramp held at 1.0 until a signed tag records it")
        if as_of is None and since is not None:
            limits.append("no pinned feed carries a published_at, so there is no as_of to ramp to")
        ramp = _ramp(since, as_of)
        share = inside / total if total else 0.0
        amount: float | None = None
        bounded = False
        if base is None:
            limits.append(f"no priced exposure: {adopter_party} pins no feed that prices its "
                          f"residual, so there is nothing to take a share of")
        else:
            amount, bounded = ungoverned_price(base, inside, total, ramp)
        entry["price"] = {
            "perspective": adopter_party, "currency": currency, "amount": amount,
            "share": share, "workloads": inside, "workloads_total": total,
            "base": base, "ramp": ramp, "since": since, "as_of": as_of,
            "bounded": bounded, "limits": limits,
        }


# --------------------------------------------------------------------------
# 5. structural refusals: the split diamond, and the cross-party conflict
#    (ticket 13, spec.md "Resolution")
# --------------------------------------------------------------------------


def check_diamonds(edges: list[dict]) -> list[dict]:
    """"Every path from the adopter to one parent must resolve to one
    version" (spec.md, Resolution). Two edges in the adopter's own
    `inherits` reaching the same (party, kind) at two different versions is
    refused, naming both edges -- never picked silently. This estate has no
    further data source recording a *second-hop* parent's own pin (`platform`
    ships no `party.yaml` of its own), so the diamond this estate can
    actually manifest today is two direct edges; that is also the literal
    reading of "a path ... resolve to one version", so no transitive walk is
    invented for a case nothing here can produce yet."""
    by_parent: dict[tuple[str, str], dict[str, list[dict]]] = {}
    for edge in edges:
        by_parent.setdefault((edge["party"], _parent_key(edge)), {}) \
            .setdefault(edge["version"], []).append(edge)
    refusals = []
    for (party, kind), by_version in sorted(by_parent.items()):
        if len(by_version) > 1:
            routes = "; ".join(f"{v}: {edges!r}" for v, edges in sorted(by_version.items()))
            refusals.append({
                "kind": "split-diamond",
                "subject": f"{party}/{kind}",
                "detail": f"{party} ({kind}) is inherited at {len(by_version)} versions "
                          f"through {sum(len(e) for e in by_version.values())} edges -> {routes}",
                "needs_composition": True,
            })
    return refusals


# --------------------------------------------------------------------------
# 6. restatement and caging (ticket 13, spec.md "Restatement and caging")
# --------------------------------------------------------------------------


def _enforce():
    """The ONE appetite helper (`risk/enforce.py`), reached through the cage
    engine that already imports it -- no second appetite store and no second
    path to a party's band."""
    return _cage_engine().enforce


def _appetite(party: str, adopter_dir: Path | None = None,
               parent_trees: dict[str, Path] | None = None) -> dict:
    """`appetite.tolerance` = {amount, currency} off the PARTY'S OWN signed
    party.yaml (ticket 25, ADR-0021). `risk/appetite.json` is retired: no
    fixture prices a party any more. A party that declares no appetite is a
    MISSING INSTRUMENT and refuses (ADR-0020), naming what is missing."""
    enforce = _enforce()
    path = str(_party_yaml(party, adopter_dir, parent_trees)) if adopter_dir is not None else None
    try:
        return enforce.appetite_money(party, path)
    except enforce.MissingInstrument as e:
        raise Refused(f"missing instrument: {e}") from None


def _party_yaml(party: str, adopter_dir: Path, parent_trees: dict[str, Path] | None) -> Path:
    """Where a named party's own signed artefact is, from where this
    composition is standing: the adopter under composition, one of its pinned
    parent trees, or the party's sibling checkout."""
    adopter_dir = Path(adopter_dir)
    candidate = adopter_dir / "party.yaml"
    if candidate.exists():
        doc = yaml.safe_load(candidate.read_text()) or {}
        if doc.get("party") == party:
            return candidate
    tree = (parent_trees or {}).get(party)
    if tree is not None and (Path(tree) / "party.yaml").exists():
        return Path(tree) / "party.yaml"
    return Path(_enforce().party_yaml_path(party))


def _party_doc(party: str, adopter_dir: Path,
                parent_trees: dict[str, Path] | None = None) -> dict:
    """The named party's own signed artefact, or {} when this composition
    cannot see one. Never invents a fact about another party."""
    path = _party_yaml(party, adopter_dir, parent_trees)
    if not path.exists():
        return {}
    doc = yaml.safe_load(path.read_text())
    return doc if isinstance(doc, dict) else {}


def _reporting_currency(doc: dict) -> str:
    return doc.get("reporting_currency") or DEFAULT_REPORTING_CURRENCY


def _fx_rate(frm: str, to: str, as_of: str | None,
              trees: dict[str, Path] | None) -> tuple[float, dict]:
    """The signed FX feed's rate for THIS date, and where it was read. ADR-0020:
    no rate is a missing instrument and refuses -- an unconverted sum was the
    live bug (GAPS 3.18) and never happens again.

    The rate is read through the FX publisher's OWN converter
    (`feeds/converters/fx.py`), never re-implemented here: the same rule as every
    other feed in this module (spec, the £ seam -- "each publisher ships its
    converter beside its feed; composition calls it"). Which month a rate is in
    force for, how a cross-rate is taken through the base currency, and what
    counts as an unpublished date are all the publisher's business, and a second
    copy of that logic here is exactly how the two halves of an FX seam drift
    apart without either side going red.

    Only the PINNED parent trees are searched. A converter found in whatever
    happens to be checked out beside the estate is not a pinned instrument, and
    a price it produced could not be re-derived from the signed parent set."""
    if frm == to:
        return 1.0, {}
    if not as_of:
        raise Refused(f"missing instrument: no FX rate {frm}->{to}: the price carries no as_of "
                      f"date, and a rate is in force for a date or for nothing")
    where = "no PINNED parent tree ships converters/fx.py"
    for party, tree in sorted((trees or {}).items()):
        converter = Path(tree) / "converters" / f"{FX_FEED}.py"
        if not converter.exists():
            continue
        spec = importlib.util.spec_from_file_location(f"_fx_{Path(tree).name}", converter)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        try:
            rate = float(mod.convert(1.0, frm, to, as_of, root=str(tree)))
        except getattr(mod, "MissingInstrument", Exception) as exc:
            # The publisher's OWN refusal: it has no rate for this date. Keep
            # looking; another pinned parent may publish one.
            where = f"{converter}: {exc}"
            continue
        except Exception as exc:                       # noqa: BLE001
            # A converter that will not run is BROKEN, not silent about a date.
            # Reporting it as "no rate published" would hide a defect behind a
            # missing instrument, which is the one refusal this estate allows.
            raise Refused(f"{converter} does not run, so no FX rate {frm}->{to} for {as_of} "
                          f"could be read at all: {exc}") from None
        return rate, {"fx_publisher": party, "fx_feed_version": _fx_feed_version(tree)}
    raise Refused(f"missing instrument: no FX rate {frm}->{to} for {as_of} ({where})")


def _fx_feed_version(tree: Path) -> str | None:
    """The version of the signed fx feed the rate was read out of, so a converted
    price can be re-derived from the pinned parent set and not just believed.
    ponytail: highest published major in the tree that shipped the converter. The
    upgrade is an explicit `inherits[]` edge of `{kind: feed, name: fx}` that
    pins ONE version -- that needs price_parent to price an fx edge, which is a
    publisher change, not this seam's."""
    found = sorted(Path(tree).glob(f"{FX_FEED}/v*/feed.json"))
    if not found:
        return None
    try:
        return json.loads(found[-1].read_text()).get("version")
    except (OSError, json.JSONDecodeError):
        return None


def _price_entry(source: str, kind: str, perspective: str, currency: str, amount: float,
                  perspective_doc: dict, **extra) -> dict:
    """ONE prices[] entry, the one shape every price in this estate has.

    `perspective` is the party whose balance sheet this is; `currency` is the
    currency the amount is actually in; `per_customer` restates the amount
    against THAT party's own signed `size.customers`, or is null where the
    party declares no size (ticket 25 -- a restatement is never invented)."""
    if kind not in PRICE_KINDS:
        raise Refused(f"unknown price kind {kind!r} (known: {', '.join(PRICE_KINDS)})")
    customers = (perspective_doc.get("size") or {}).get("customers")
    # `amount` is None only on a ticket-45 switching entry whose counterfactual
    # could not be priced at all. A restatement of a figure nobody has is not a
    # zero and not an error; it is absent, exactly as it is for a party that
    # signs no customer count.
    per_customer = ({"amount": amount / customers, "currency": currency}
                     if isinstance(customers, int) and customers > 0
                     and isinstance(amount, (int, float)) and not isinstance(amount, bool)
                     else None)
    return {"source": source, "kind": kind, "perspective": perspective,
            "currency": currency, "amount": amount, "per_customer": per_customer, **extra}


def _sum_prices(entries: list[dict], perspective: str, currency: str) -> float:
    """The ONE summing helper -- `fair.sum_prices`, the estate's own £ engine.
    It refuses a mixed list by raising: no sum crosses a perspective or a
    currency, ever (spec.md, "The £ seam")."""
    # The entry's OWN labels win; the arguments only fill in a breakdown line
    # (a hole) that carries none. An entry that disagrees is what must refuse.
    # The entry's OWN labels win; the arguments only fill in a breakdown line
    # (a hole) that carries none. An entry that disagrees is what must refuse.
    labelled = [{"perspective": perspective, "currency": currency, **e} for e in entries]
    try:
        return _cage_engine().fair.sum_prices(labelled)
    except ValueError as e:
        raise Refused(str(e)) from None


def _appetite_tolerance(party: str, adopter_dir: Path | None = None,
                         parent_trees: dict[str, Path] | None = None) -> float | None:
    """Back-compatible bare band for the caging path below. Kept as a name
    because ticket 13's restatement caging already calls it; the store moved
    to the party's own artefact and nowhere else.

    Reads the artefact of the tree UNDER COMPOSITION, not whatever sibling
    checkout happens to sit beside the estate: composing a copied tree (the
    e2e harness does exactly that) must price that copy's own signed band."""
    try:
        return _appetite(party, adopter_dir, parent_trees)["amount"]
    except Refused:
        return None


def _load_scenario(rel_path: str, root: Path = PLATFORM_DIR) -> dict:
    """A restate entry's own `scenario`, resolved against this repo
    (platform) -- the same convention the prototype used for its named
    scenario (`policy/scenarios/driftwood-root-residual.json`). A bespoke
    control's scenario (ticket 38) resolves against the ADOPTER's own tree
    instead: the party that invented the control signs its price."""
    return json.loads((Path(root) / rel_path).read_text())


# One converter run per (converter bytes, payload bytes, arguments). Ticket 45
# re-prices the whole edge set once per substitutable publisher to MEASURE the
# switching cost, which multiplies the converter subprocesses this module runs
# by the number of feed edges. The key is CONTENT, not a path or a version, so a
# fixture that rewrites a payload in place under the same version is a different
# key and is really re-run -- a cache keyed on the pin would have quietly
# answered a stale price to the very tests that plant a change.
_CONVERTER_CACHE: dict[tuple, dict] = {}


def _run_converter(name: str, version: str, tree_path: Path, args: list[str]) -> dict:
    """Resolve the feed file, unwrap its envelope, hand the payload to the
    publisher's converter as a file (the converters take a path, unchanged)."""
    path = feed_file("", name, version, tree_path)
    if not path.exists():
        raise Refused(f"feed {name}@{version}: no file at {path}")
    payload = load_feed_payload(path, name, version)
    converter = _converter(name, tree_path)
    body = json.dumps(payload, sort_keys=True)
    key = (name, body, _digest(converter.read_text()), tuple(args))
    if key in _CONVERTER_CACHE:
        return copy.deepcopy(_CONVERTER_CACHE[key])
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(payload, fh)
    try:
        result = subprocess.run(
            [sys.executable, str(converter), *args[:1], fh.name, *args[1:]],
            capture_output=True, text=True, check=True)
    finally:
        Path(fh.name).unlink(missing_ok=True)
    scenario = json.loads(result.stdout)
    _CONVERTER_CACHE[key] = copy.deepcopy(scenario)
    return scenario


def _threat_scenario(feed_version: str, party: str, tree_path: Path = PLATFORM_DIR) -> dict:
    """REAL. Falls back to the pinned threat feed, through the estate's own
    converter, when a restate entry names no scenario of its own."""
    return _run_converter("threat-register", feed_version, tree_path, ["threat", party])


def _cage_engine():
    """Import the estate's REAL £ engine rather than modelling it again --
    graded/cage.py lives in this same repo (platform)."""
    sys.path.insert(0, str(PLATFORM_DIR / "graded"))
    import cage  # noqa: E402
    return cage


def _previous_header(adopter_dir: Path) -> dict | None:
    """The last signed composed artefact's own advisory header, if one is
    already committed -- the comparison point ticket 14's holes, selected
    control set and baseline name read (spec.md, "The composed artefact":
    the header carries "the recorded hole ids"). None means this is the
    FIRST composition ever, and spec.md's bootstrap rule applies: "the
    first composition records every hole and refuses on none", because
    there is nothing yet to compare a hole or a removed control against."""
    path = adopter_dir / "composed" / "HEADER.yaml"
    if not path.exists():
        return None
    text = path.read_text()
    if text.startswith(HEADER_COMMENT):
        text = text[len(HEADER_COMMENT):]
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def _previous_cages(adopter_dir: Path) -> list[dict]:
    """The last signed composed artefact's own cages[], if one is already
    committed -- the comparison point `changed` reads (same "new/recorded"
    shape holes and ungoverned namespaces use in tickets 14/15, one field
    simplified to a boolean since a cage carries no status ladder)."""
    prev = adopter_dir / "composed" / "evidence.json"
    if not prev.exists():
        return []
    try:
        return json.loads(prev.read_text()).get("cages", [])
    except (OSError, json.JSONDecodeError):
        return []


def _previous_prices(adopter_dir: Path) -> list[dict]:
    """The last signed composed artefact's own prices[], if one is committed --
    the comparison point the twin entry's `changed` reads (same shape
    `_previous_cages` uses for cages)."""
    prev = Path(adopter_dir) / "composed" / "evidence.json"
    if not prev.exists():
        return []
    try:
        return json.loads(prev.read_text()).get("prices", [])
    except (OSError, json.JSONDecodeError):
        return []


def apply_restatements(party_doc: dict, merged: dict, parents: list[dict],
                        adopter_dir: Path, parent_trees: dict[str, Path] | None = None
                        ) -> tuple[list[dict], list[dict], list[dict]]:
    """Every `overlay.restate` entry against the merged member set. Returns
    (restatements, refusals, cages). Mutates `merged` in place: an accepted
    (stricter) restatement overwrites the rendered action; a weaker one does
    NOT -- the rendered file keeps the inherited action, and the residual is
    priced instead (spec.md: "The rendered action stays the inherited
    one... The composed artefact carries no tier and no tier floor")."""
    restatements: list[dict] = []
    refusals: list[dict] = []
    cages: list[dict] = []
    adopter_party = party_doc["party"]
    threat_edge = next((p for p in parents if _feed_name(p) == "threat-register"), None)
    threat_pin = threat_edge["version"] if threat_edge else None
    threat_tree = Path((parent_trees or {}).get(threat_edge["party"], PLATFORM_DIR)) \
        if threat_edge else PLATFORM_DIR
    previous_cages = _previous_cages(adopter_dir)

    for r in party_doc.get("overlay", {}).get("restate", []) or []:
        name, version, action = r["name"], r["version"], r["action"]
        match = next(((k, m) for k, m in merged.items() if k[2] == name and k[0] == version), None)
        if match is None:
            continue  # names nothing this composition resolved; ticket 14 owns dangling claims
        key, meta = match
        family = key[1]
        rule = f"{family}/{name}@{version}"

        if meta["kind"] != "ValidatingPolicy":
            refusals.append({
                "kind": "restatement-of-non-validating",
                "subject": rule,
                "detail": f"{rule} is a {meta['kind']}; a restatement applies to a "
                          f"ValidatingPolicy and to nothing else, because only a "
                          f"ValidatingPolicy carries the Audit<Deny strictness ladder "
                          f"a restatement compares on (ADR-0016)",
                "needs_composition": True,
            })
            continue

        inherited_action = meta["action"]
        accepted = STRICTNESS[action] >= STRICTNESS[inherited_action]
        restatements.append({
            "rule": rule, "inherited_action": inherited_action,
            "restated_action": action, "outcome": "accepted" if accepted else "caged",
        })
        if accepted:
            merged[key] = dict(meta, action=action)
            continue

        # Weaker. Never an override, never an exemption (CONTEXT.md
        # "Exemption"): a declared inability, priced against THIS party's
        # own appetite band by the estate's own cage engine. merged[key] is
        # left untouched, so the render below still carries inherited_action.
        band = _appetite_tolerance(adopter_party, adopter_dir, parent_trees)
        if band is None:
            refusals.append({
                # ADR-0020's one allowed refusal, under the kind the rest of
                # this module uses. The fixture it used to name is retired:
                # whose money is at risk is the party's own signed fact.
                "kind": "missing-instrument", "subject": adopter_party,
                "detail": f"missing instrument: {adopter_party}/party.yaml declares no "
                          f"appetite.tolerance, so its residual on {rule} cannot be priced",
                "needs_composition": True,
            })
            continue

        scenario_rel = r.get("scenario")
        if scenario_rel:
            scenario, priced_from = _load_scenario(scenario_rel), scenario_rel
        elif threat_pin is not None:
            scenario, priced_from = _threat_scenario(threat_pin, adopter_party, threat_tree), \
                f"threat-register {threat_pin}"
        else:
            refusals.append({
                "kind": "unpriceable-inability", "subject": rule,
                "detail": f"{adopter_party} declared an inability on {rule} with no "
                          f"scenario of its own, and inherits no threat parent to price "
                          f"it from",
                "needs_composition": True,
            })
            continue

        decision = _cage_engine().select(scenario, adopter_party, band, mode="warn")
        tier = decision["tier"]
        prior = next((c for c in previous_cages
                      if c.get("party") == adopter_party and c.get("rule") == rule), None)
        cages.append({
            "party": adopter_party, "rule": rule, "band": band,
            "residual": decision.get("tcor", {}).get("residual", decision.get("uncaged_residual")),
            "tier": tier, "action": decision["action"], "priced_from": priced_from,
            "changed": prior is None or prior.get("tier") != tier,
        })
    return restatements, refusals, cages


# --------------------------------------------------------------------------
# 7. baseline coverage, control claims and holes (ticket 14; ADR-0013, ADR-0017)
# --------------------------------------------------------------------------

# A party's own OSCAL component-definition -- the platform layout ADR-0013
# already fixed (ticket 10). The ADOPTER's own claims live NEXT TO the
# party artefact it signs (ADR-0017: "in its own repo, next to the party
# artefact it signs"), i.e. directly in adopter_dir, no subdirectory.
PARENT_CLAIMS_PATH = ("oscal", "component-definition.json")
ADOPTER_CLAIMS_FILE = "component-definition.json"


ControlKey = tuple[str, str]   # (source party, bare catalogue id)


def _catalog_dir(root: Path) -> Path:
    """Where a controls party's catalogue lives in its own tree: the path its
    party.yaml `publishes[]` declares for `kind: controls` (ADR-0019, the
    discovery record), else `catalog/` -- nist's layout, and the default an
    adopter's own small bespoke catalogue uses."""
    root = Path(root)
    party_yaml = root / "party.yaml"
    if party_yaml.exists():
        doc = yaml.safe_load(party_yaml.read_text()) or {}
        declared = next((e.get("path") for e in doc.get("publishes") or []
                         if e.get("kind") == "controls" and e.get("path")), None)
        if declared:
            return root / declared
    return root / "catalog"


def _catalog_controls(root: Path) -> dict[str, dict[str, str]]:
    """Every control id a controls party's catalogue carries, mapped to its
    props by name, walking nested (enhancement) controls so `ac-6.10` is
    found by a group-level scan -- the same walk as nist/scripts/
    verify_baselines.py and platform/oscal/lint_claims.py's
    catalog_control_ids(). Duplicated on purpose: each reader stays self-
    contained (lint_claims.py's own docstring names this convention). The
    props are what a bespoke control names its scenario in (ticket 38)."""
    catalog_dir = _catalog_dir(root)
    meta = json.loads((catalog_dir / "CATALOG_VERSION.json").read_text())
    catalog_doc = json.loads((catalog_dir / meta["file"]).read_bytes())
    controls: dict[str, dict[str, str]] = {}

    def walk(items):
        for c in items:
            controls[c["id"]] = {p["name"]: p["value"] for p in c.get("props", [])
                                 if "name" in p and "value" in p}
            walk(c.get("controls", []))

    for group in catalog_doc["catalog"].get("groups", []):
        walk(group.get("controls", []))
    walk(catalog_doc["catalog"].get("controls", []))
    return controls


def _catalog_ids(nist_root: Path) -> set[str]:
    return set(_catalog_controls(nist_root))


def _baseline_ids(nist_root: Path, name: str) -> set[str] | None:
    """The bare control ids a named OSCAL baseline profile selects, exact-
    string off `with-ids` (ADR-0013). None means the controls parent
    publishes no baseline of this name -- "a missing baseline file" is a
    lint finding (spec.md), not something only composition could see."""
    meta_path = _catalog_dir(nist_root) / "BASELINE_VERSIONS.json"
    if not meta_path.exists():
        return None
    meta = json.loads(meta_path.read_text())
    entry = meta.get("baselines", {}).get(name)
    if entry is None:
        return None
    profile_doc = json.loads((_catalog_dir(nist_root) / entry["file"]).read_bytes())
    return set(profile_doc["profile"]["imports"][0]["include-controls"][0]["with-ids"])


def _load_claims(comp_def_path: Path) -> list[tuple[str | None, str, str]]:
    """(source href, control-id, claimed policy name) for every Check_Id
    prop in one OSCAL component-definition -- the same read as
    oscal/lint_claims.py's claimed_policy_names(), duplicated so this reader
    stays self-contained too, plus the enclosing block's `source`: the one
    place OSCAL names the catalogue a bare id belongs to (ADR-0013). [] when
    the party ships no such file (an adopter need not)."""
    if not comp_def_path.exists():
        return []
    comp_def = json.loads(comp_def_path.read_text())
    out: list[tuple[str | None, str, str]] = []
    for comp in comp_def["component-definition"]["components"]:
        for ci in comp.get("control-implementations", []):
            source = ci.get("source")
            for ir in ci.get("implemented-requirements", []):
                control = ir["control-id"]
                for p in ir.get("props", []):
                    if p.get("name") == "Check_Id":
                        out.append((source, control, p["value"]))
    return out


def _claim_source(href: str | None, claiming_party: str, sources: set[str],
                  baseline_source: str | None) -> str | None:
    """Which controls parent a claim's `source` href names: the first path
    segment that is a pinned controls party (`../nist/catalog/...` -> nist).
    An href that names none is the claiming party's own catalogue where it
    pins itself as a controls parent (a bespoke catalogue, `catalog/...`),
    else the baseline's catalogue -- ADR-0013's one authority."""
    for seg in re.split(r"[\\/]+", str(href or "")):
        if seg and seg not in (".", "..") and seg in sources:
            return seg
    if claiming_party in sources:
        return claiming_party
    return baseline_source


def _control_spec(spec: str, baseline_source: str | None) -> ControlKey:
    """An `overlay.controls` entry as written: `party:id` names that controls
    parent's catalogue; a bare id is the baseline's catalogue's."""
    if CONTROL_KEY_SEP in spec:
        source, cid = spec.split(CONTROL_KEY_SEP, 1)
        return source, cid
    return str(baseline_source), spec


def _encode_control(key: ControlKey, baseline_source: str | None) -> str:
    """How the header records a control key: the bare id where the source is
    the baseline's own catalogue (the real estate's shape, byte-stable), and
    `source:id` for any other controls parent."""
    source, cid = key
    return cid if source == baseline_source else f"{source}{CONTROL_KEY_SEP}{cid}"


def _decode_control(text: str, baseline_source: str | None) -> ControlKey:
    return _control_spec(str(text), baseline_source)


def _header_controls_source(header: dict | None, adopter_party: str | None = None) -> str | None:
    """The baseline's catalogue in a recorded header: its first `controls`
    parent that is not the adopter itself -- what its bare hole ids were
    keyed to. The same rule compose() keys baseline_source by, so an adopter
    that lists its self-pin before the regulator in inherits[] decodes its
    own header the way it was written (2026-09-04 review: reading the FIRST
    controls parent decoded every bare id as the adopter's own and refused
    the whole baseline as removed on an unchanged tree)."""
    if not header:
        return None
    return next((p.get("party") for p in header.get("parents", [])
                 if p.get("kind") == "controls" and p.get("party") != adopter_party), None)


def _unknown_control_refusals(specs: list[tuple[str, ControlKey]], catalogs: dict[str, set[str]],
                              subject_prefix: str) -> list[dict]:
    """A (source, id) absent from that source's catalogue, exact-string -- no
    case-fold, no prefix-strip (ADR-0013): a hard failure, never a hole. A
    plain lint of the id against the catalogue would also catch this, so
    needs_composition is False (spec.md: "a prefixed id... are lint
    findings"). `specs` pairs each key with the spelling the party wrote."""
    out: list[dict] = []
    seen: set[str] = set()
    for spelled, (source, cid) in specs:
        if spelled in seen:
            continue
        seen.add(spelled)
        if cid in catalogs.get(source, set()):
            continue
        where = (f"{source}'s catalogue" if source in catalogs
                 else f"any pinned controls parent ({', '.join(sorted(catalogs)) or 'none'})")
        out.append({
            "kind": "unknown-control-id",
            "subject": f"{subject_prefix}: {spelled}",
            "detail": f"{spelled!r} is absent from {where} -- exact-string resolution finds no "
                      f"case-folded or prefix-stripped match, and an unknown id is a hard failure, "
                      f"not a hole (ADR-0013)",
            "needs_composition": False,
        })
    return out


def resolve_claims(all_claims: list[tuple[str | None, str, str, str]], policy_owner: dict[str, str],
                    catalogs: dict[str, set[str]], baseline_source: str | None
                    ) -> tuple[set[ControlKey], list[dict]]:
    """Every (source href, control_id, policy_name, claiming_party) claim,
    resolved three ways:

      * its control key is (source, id): the href names the catalogue
        (ADR-0013's enclosing block), the id must be in THAT catalogue, else
        an unknown-control-id -- a lint finding, needs_composition False;
      * the claimed policy must be shipped by SOME composed party, else a
        DANGLING claim -- a lint finding a per-party check would also catch
        (oscal/lint_claims.py already does, for platform's);
      * it must be shipped by the SAME party that claims it, else the claim
        is against ANOTHER party's policy (ADR-0017) -- telling whose policy
        it is needs the whole composed set, so needs_composition is True.

    A control counts as COVERED -- not a hole -- the moment ANY claim exists
    for it, valid or not: "a baseline control with no claim is a hole"
    (spec.md) says no claim, not no VALID claim. A dangling or cross-party
    claim is its own refusal, orthogonal to hole counting."""
    covered: set[ControlKey] = set()
    refusals: list[dict] = []
    for href, control_id, policy_name, claiming_party in all_claims:
        source = _claim_source(href, claiming_party, set(catalogs), baseline_source)
        key = (str(source), control_id)
        covered.add(key)
        unknown = _unknown_control_refusals([(control_id, key)], catalogs,
                                            f"{claiming_party} component-definition")
        if unknown:
            refusals += unknown
            continue
        owner = policy_owner.get(policy_name)
        if owner is None:
            refusals.append({
                "kind": "dangling-claim",
                "subject": f"{claiming_party}: {control_id} -> {policy_name}",
                "detail": f"{claiming_party}'s component-definition claims {control_id} is "
                          f"evidenced by {policy_name!r}, but no composed member of any kind "
                          f"carries that name",
                "needs_composition": False,
            })
        elif owner != claiming_party:
            refusals.append({
                "kind": "claim-against-another-partys-policy",
                "subject": f"{claiming_party}: {control_id} -> {policy_name}",
                "detail": f"{claiming_party} claims {control_id} is evidenced by "
                          f"{policy_name!r}, which {owner} ships, not {claiming_party} -- a "
                          f"control claim belongs to whoever ships the implementation "
                          f"(ADR-0017)",
                "needs_composition": True,
            })
    return covered, refusals


def compute_holes(selected_set: set[ControlKey], covered: set[ControlKey],
                   prev_holes: set[ControlKey] | None) -> list[dict]:
    """holes[] entries (new/recorded/closed), each keyed on (source, id).
    prev_holes is None on the FIRST composition ever -- nothing yet to
    compare a hole as new against. Nothing here refuses (ticket 38): a new
    hole is priced by compute_deltas and printed as a delta, because a
    control unimplemented is a missing behaviour, never a missing
    instrument (ADR-0020)."""
    holes = sorted(selected_set - covered)
    entries: list[dict] = []
    for source, cid in holes:
        status = "recorded" if prev_holes is None or (source, cid) in prev_holes else "new"
        entries.append({"source": source, "control_id": cid, "status": status})
    if prev_holes is not None:
        for source, cid in sorted((prev_holes & selected_set) - set(holes)):
            entries.append({"source": source, "control_id": cid, "status": "closed"})
    return entries


def check_selected_set(selected_set: set[ControlKey], prev_selected: set[ControlKey] | None,
                       baseline_source: str | None) -> list[dict]:
    """A control leaving the selected set is refused, no exceptions:
    "a removal is refused... the composition compares the selected set
    against the last signed composed artefact's selected set and refuses
    on any control that left" (spec.md; ADR-0013's removal rule, which
    ticket 38 leaves standing -- a removal is an exemption by another name).
    None means the first composition -- nothing to compare against yet."""
    if prev_selected is None:
        return []
    return [{
        "kind": "removed-control", "subject": _encode_control(key, baseline_source),
        "detail": f"{_encode_control(key, baseline_source)} was in the last signed composed "
                  f"artefact's selected control set and is absent now -- a control may be "
                  f"added, never removed (ADR-0013)",
        "needs_composition": True,
    } for key in sorted(prev_selected - selected_set)]


def baseline_widening_delta(baseline_ids: set[str], prev_baseline_ids: set[str] | None,
                            prev_name: str | None, name: str, baseline_source: str | None,
                            hole_prices: dict[ControlKey, tuple[float, str]],
                            perspective: str, currency: str) -> dict | None:
    """A named-baseline change that only ADDS controls prints as ONE priced
    delta (ticket 38; reversals 9-10: widening is priced, never refused):
    how many controls it adds, how many of those a pinned regulator weight
    prices, and the sum of those prices -- or no amount at all where no
    pinned weight names any of them, a named absence rather than a zero.
    The controls themselves print as new-hole deltas beside it. A change
    that drops a control is check_selected_set's, so a narrowing is never
    double-counted here."""
    if prev_baseline_ids is None or prev_name == name or not (baseline_ids > prev_baseline_ids):
        return None
    added = sorted(baseline_ids - prev_baseline_ids)
    priced = [hole_prices[(str(baseline_source), cid)][0] for cid in added
              if (str(baseline_source), cid) in hole_prices]
    return {
        "kind": "baseline-widening", "subject": f"{prev_name} -> {name}",
        "perspective": perspective, "currency": currency,
        "added": len(added), "priced": len(priced),
        "amount": sum(priced) if priced else None,
        "detail": f"{prev_name} -> {name} adds {len(added)} control(s); {len(priced)} of them "
                  f"carry a pinned regulator weight and price at "
                  f"{sum(priced):.2f} {currency}; the rest are holes no pinned weight names"
                  if priced else
                  f"{prev_name} -> {name} adds {len(added)} control(s), none of which a pinned "
                  f"regulator weight names, so the widening carries no amount yet -- a named "
                  f"absence, not a zero",
    }


def _regime_hole_prices(prices: list[dict]) -> dict[ControlKey, tuple[float, str]]:
    """(source, id) -> (amount, priced_by) for every hole a pinned regime
    entry's published weights price -- what a hole delta is priced with.
    The regulator's weights partition its regime's exposure (ticket 25), so
    a hole's price is its share of that entry and never an addition to it."""
    out: dict[ControlKey, tuple[float, str]] = {}
    for e in prices:
        if e.get("kind") != "feed":
            continue
        for h in e.get("holes") or []:
            key = (str(h["source"]), str(h["id"]))
            out.setdefault(key, (float(h["amount"]),
                                 f"{e['source']} {e.get('name') or e['kind']}@{e.get('new_version')} "
                                 f"{ICO_REGIME}/{ICO_VIOLATION_TYPE} weight {h['weight']}"))
    return out


def _price_holes(hole_entries: list[dict], hole_prices: dict[ControlKey, tuple[float, str]],
                 perspective: str, currency: str) -> None:
    """Attach perspective, currency and -- where a pinned weight names the
    hole -- its amount and what priced it, to every holes[] entry. A hole no
    pinned instrument names carries `amount: null`, never a zero."""
    for h in hole_entries:
        priced = hole_prices.get((h["source"], h["control_id"]))
        h["perspective"] = perspective
        h["currency"] = currency
        h["amount"] = priced[0] if priced else None
        h["priced_by"] = priced[1] if priced else None


def _price_bespoke_holes(hole_entries: list[dict], adopter_party: str, adopter_dir: Path,
                         catalog_props: dict[str, dict[str, str]], band: dict | None,
                         reporting: str, floor: str | None) -> list[dict]:
    """A bespoke control (its source is the adopter's own catalogue) prices
    its hole through the scenario the catalogue's control names -- the
    restate path's own `_load_scenario` mechanism against the adopter's own
    tree, and the estate's own cage engine against the adopter's own band.
    One with NO scenario is the one hole-shaped refusal left: an instrument
    fault (ADR-0020), because only the party that invented the control can
    say what missing it costs, and a regulator's weight never names it.
    The residual is labelled in `reporting`, the adopter's reporting
    currency, and this path takes no FX rate: a band declared in another
    currency is the same instrument fault (hard rule 7, one currency on both
    sides), because a relabelled amount is a minted one."""
    refusals: list[dict] = []
    band_currency = (band.get("currency") or reporting) if band else reporting
    for h in hole_entries:
        if h["source"] != adopter_party or h["status"] == "closed":
            continue
        scenario_rel = (catalog_props.get(h["control_id"]) or {}).get(BESPOKE_SCENARIO_PROP)
        if not scenario_rel or not (Path(adopter_dir) / scenario_rel).exists():
            refusals.append({
                "kind": "missing-instrument",
                "subject": f"{adopter_party}{CONTROL_KEY_SEP}{h['control_id']}",
                "detail": f"missing instrument: bespoke control {h['control_id']} in "
                          f"{adopter_party}'s own catalogue is a hole and names no signed "
                          f"scenario ({BESPOKE_SCENARIO_PROP} prop"
                          + (f" points at {scenario_rel!r}, which does not exist" if scenario_rel
                             else " absent")
                          + f"); only {adopter_party} can price a control it invented (ADR-0020)",
                "needs_composition": True,
            })
            continue
        if band is None:
            continue    # the missing appetite is already refused as an instrument
        if band_currency != reporting:
            refusals.append({
                "kind": "missing-instrument",
                "subject": f"{adopter_party}{CONTROL_KEY_SEP}{h['control_id']}",
                "detail": f"missing instrument: bespoke control {h['control_id']} would be priced "
                          f"against {adopter_party}'s appetite band in {band_currency} and labelled "
                          f"in its reporting currency {reporting}; this path takes no rate, and a "
                          f"relabelled amount is a minted one, not a converted one (ADR-0020)",
                "needs_composition": True,
            })
            continue
        decision = _cage_engine().select(_load_scenario(scenario_rel, adopter_dir), adopter_party,
                                         band["amount"], mode="warn", floor=floor)
        h["amount"] = decision["uncaged_residual"]
        h["priced_by"] = f"{adopter_party} scenario {scenario_rel}"
    return refusals


def _decorate_regime_holes(prices: list[dict], hole_entries: list[dict], selected: set[ControlKey],
                           covered: set[ControlKey]) -> None:
    """Every holes[] line on a regime entry gains the adopter's own status
    for that control: new / recorded / closed (this run's hole entries),
    covered (a claim exists), or unselected (the weight names a control
    outside this party's selected set). The partition itself is untouched:
    the weights still sum to one and the amounts to the entry (ticket 25)."""
    status_by_key = {(h["source"], h["control_id"]): h["status"] for h in hole_entries}
    for e in prices:
        for h in e.get("holes") or []:
            key = (str(h["source"]), str(h["id"]))
            if key in status_by_key:
                h["status"] = status_by_key[key]
            elif key in selected and key in covered:
                h["status"] = "covered"
            else:
                h["status"] = "unselected"


def compute_deltas(hole_entries: list[dict], ungoverned_entries: list[dict],
                   widening: dict | None, perspective: str, currency: str) -> list[dict]:
    """deltas[]: what changed since the last signed composed artefact, each
    under the adopter's own perspective and currency with the amount its
    hole or namespace entry carries. This is what the three refusals
    became (ticket 38): a report of a priced move, never a wall."""
    deltas: list[dict] = []
    for h in hole_entries:
        if h["status"] in ("new", "closed"):
            deltas.append({
                "kind": f"{h['status']}-hole", "source": h["source"], "control_id": h["control_id"],
                "perspective": perspective, "currency": currency,
                "amount": h.get("amount"), "priced_by": h.get("priced_by"),
                "detail": (f"{h['source']}{CONTROL_KEY_SEP}{h['control_id']} is selected and no "
                           f"claim covers it, and it was not in the last signed composed "
                           f"artefact's recorded holes" if h["status"] == "new" else
                           f"{h['source']}{CONTROL_KEY_SEP}{h['control_id']} was a recorded hole "
                           f"and a claim now covers it")
                          + (f"; priced at {h['amount']:.2f} {currency} by {h['priced_by']}"
                             if h.get("amount") is not None else
                             "; no pinned instrument names a price for it"),
            })
    if widening is not None:
        deltas.append(widening)
    for e in ungoverned_entries:
        if e["status"] in ("new", "closed"):
            price = e.get("price") or {}
            deltas.append({
                "kind": f"{e['status']}-ungoverned-namespace", "namespace": e["namespace"],
                "perspective": perspective, "currency": currency,
                "amount": price.get("amount"),
                "detail": (f"{e['namespace']} carries the institution label and not governed: "
                           f"\"true\", and was not in the last signed composed artefact's "
                           f"recorded ungoverned set" if e["status"] == "new" else
                           f"{e['namespace']} was a recorded ungoverned namespace and now carries "
                           f"governed: \"true\"")
                          + (f"; priced at {price['amount']:.2f} {currency} as {price['workloads']} "
                             f"of {price['workloads_total']} institution workloads x ramp "
                             f"{price['ramp']:.4f}" if price.get("amount") is not None else
                             ("; " + "; ".join(price["limits"]) if price.get("limits") else "")),
            })
    return deltas


# --------------------------------------------------------------------------
# 8. pricing and threat re-pricing (ticket 16; ADR-0006, ADR-0010, ADR-0015)
# --------------------------------------------------------------------------

# The one regime/violation-type this composition re-prices through ico's own
# converter -- "the uncaged exposure on the uk-gdpr lower-tier entry"
# (spec.md's own acceptance wording, and the prototype's own section 9).
# WHICH regimes actually apply to which workload is a separate, still-open
# gap this composition does not decide -- see ico's own to_fair_scenario.py
# docstring. This re-prices the one entry named, nothing more.
ICO_REGIME = "uk-gdpr"
ICO_VIOLATION_TYPE = "lower-tier"

# ADR-0022 retired the `deny` rung: graded/cage.py's ladder is
# baseline < restricted < quarantine < isolated (plus platform-only `infra`),
# and the bottom rung is a RUNNING, unreachable cage. Every selected tier is
# now a real label value, so every proposal travels as a label and none as an
# issue. `proposed_as` stays on the entry because wargamer/tier_pr.py reads it.
PROPOSED_AS_LABEL = "label"


def _ico_scenario(ico_root: Path, version: str, turnover: float | None = None) -> dict:
    """REAL. ico's own converter, `build`, against its own
    <version>/penalty-schema.json -- the same subprocess convention
    `_threat_scenario` above already uses for the threat parent.

    `turnover` is the ADOPTER's own signed turnover, in the regime's currency.
    The percent-of-turnover formula scales against it, so the price is this
    party's and no fixture's; without it the publisher prices at its statutory
    cap (spec, the £ seam)."""
    args = ["build", ICO_REGIME, ICO_VIOLATION_TYPE]
    if turnover is not None:
        args += ["--turnover", f"{turnover:.2f}"]
    return _run_converter("penalty-schema", version, ico_root, args)


def _previous_parent_version(prev_header: dict | None, edge: dict) -> str | None:
    """The version a pricing/threat parent was pinned to in the LAST SIGNED
    composed artefact's own header -- the "old" half of a price move. None
    on the first composition ever, or when the prior header never recorded
    an edge of this (party, kind) at all -- both mean there is nothing yet
    to compare a bump against."""
    if prev_header is None:
        return None
    return next((p["version"] for p in prev_header.get("parents", [])
                 if p["party"] == edge["party"] and _parent_key(p) == _parent_key(edge)), None)


def _feed_as_of(path: Path) -> str | None:
    """The date the publisher stamped on the envelope -- the as-of an FX rate
    is looked up for. A pre-envelope raw file carries none."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None
    published = doc.get("published_at")
    return published[:10] if isinstance(published, str) else None


def _composition_as_of(edges: list[dict], parent_trees: dict[str, Path]) -> str | None:
    """The date THIS composition prices as of: the newest `published_at`
    among the pinned feed envelopes (ticket 38). A signed fact, so the
    ungoverned ramp reads it rather than a clock (D1), and a re-composition
    from the same parents lands on the same date. None where no pinned feed
    carries one -- a named limit on the entry, never today's date."""
    dates: list[str] = []
    for edge in edges:
        if edge["kind"] not in FEED_KINDS:
            continue
        tree = parent_trees.get(edge["party"])
        name = _feed_name(edge)
        if tree is None or not name:
            continue
        as_of = _feed_as_of(feed_file(edge["party"], name, edge["version"], Path(tree)))
        if as_of:
            dates.append(as_of)
    return max(dates) if dates else None


def _feed_currency(name: str, payload: dict) -> str | None:
    """The currency the PUBLISHER declares for what it prices. ico declares one
    per regime; every other feed declares one on its payload.

    None where the publisher declares none -- and price_parent REFUSES that as a
    missing instrument. Defaulting to the reader's reporting currency would
    relabel the publisher's magnitudes into a currency nobody converted them
    into: a minted currency, not a converted one, which is exactly the live bug
    ADR-0020 was written against (GAPS 3.18)."""
    if name == "penalty-schema":
        return (payload.get("regimes", {}).get(ICO_REGIME, {}) or {}).get("currency")
    return payload.get("currency")


def _converted(amount: float, frm: str, to: str, as_of: str | None,
                trees: dict[str, Path] | None) -> tuple[float, dict]:
    """The amount in the perspective's reporting currency, plus the provenance
    of the conversion. No rate for the date is a missing instrument (ADR-0020);
    an unconverted amount is never summed."""
    if frm == to:
        return amount, {}
    rate, provenance = _fx_rate(frm, to, as_of, trees)
    return amount * rate, {"native_currency": frm, "native_amount": amount,
                            "fx_rate": rate, "fx_as_of": as_of, **provenance}


def _regime_holes(payload: dict, amount: float, perspective: str, currency: str) -> list[dict]:
    """The per-hole breakdown under a regime entry (ticket 15 item 1, landed in
    this one schema pass). The regulator publishes control_weights keyed
    (source, id); a hole PARTITIONS the regime's exposure, it never adds to it,
    so the weights sum to one and the hole amounts sum to the entry amount.
    A pinned feed version that publishes no weights has no breakdown -- an
    empty list, never an invented one.

    Every published weight becomes a hole, whether or not this adopter has that
    control open: the list is the PARTITION of the exposure, not the adopter's
    open holes. ponytail ceiling: pricing a hole by its status (so implementing
    pl-2 actually shrinks the regime entry) needs the adopter's open hole ids,
    which compose() computes elsewhere -- that is ticket 15's build, not this
    schema pass."""
    weights = (payload.get("control_weights", {}).get(ICO_REGIME, {}) or {}
                ).get(ICO_VIOLATION_TYPE, [])
    if not weights:
        return []
    published = sum(float(w["weight"]) for w in weights)
    if not math.isclose(published, 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise Refused(
            f"missing instrument: control_weights for {ICO_REGIME}/{ICO_VIOLATION_TYPE} sum to "
            f"{published}, not 1.0 -- a partition that does not cover the exposure is not a "
            f"partition, and the share it leaves out has no published price")
    return [{"source": w["source"], "id": w["id"], "weight": w["weight"],
             "amount": amount * float(w["weight"])} for w in weights]


# A signed size fact older than this many MONTHS, measured against the date the
# feed being priced was published, is STALE: the loss triple widens back to the
# publisher's statutory cap rather than scaling to a number nobody has restated
# in a year (spec, the £ seam; ADR-0020 -- a missing behaviour is priced, never
# refused). Months, not days, because this module may not read a clock or import
# a date library at all (D1, and its own selfcheck enforces it): two YYYY-MM
# prefixes are all the arithmetic this needs.
SIZE_STALE_MONTHS = 12


def _sized_turnover(perspective_doc: dict, currency: str, as_of: str | None,
                     trees: dict[str, Path] | None) -> float | None:
    """The perspective party's OWN signed turnover, stated in the currency the
    regime prices in -- what a percent-of-turnover formula scales against
    (spec, the £ seam: "each publisher ships its converter beside its feed;
    composition calls it with the adopter's size").

    None -- so the publisher prices at its own statutory cap, the widest read --
    where the party signs no turnover at all, or where the size it signed is
    stale. Neither refuses: a missing SIZE is a missing behaviour."""
    size = perspective_doc.get("size") or {}
    turnover = size.get("turnover")
    if not isinstance(turnover, dict) or "amount" not in turnover:
        return None
    signed = size.get("as_of")
    if signed and as_of and _months_apart(str(signed), as_of) > SIZE_STALE_MONTHS:
        return None
    amount, _ = _converted(float(turnover["amount"]),
                            str(turnover.get("currency") or currency), currency, as_of, trees)
    return amount


def _months_apart(a: str, b: str) -> int:
    """Whole months between two YYYY-MM-DD strings, from the strings alone --
    no clock, no calendar library (D1: this module never reads either)."""
    try:
        ay, am = int(a[:4]), int(a[5:7])
        by, bm = int(b[:4]), int(b[5:7])
    except ValueError:
        return 0        # an unreadable date is not evidence of staleness
    return abs((by * 12 + bm) - (ay * 12 + am))


def price_parent(edge: dict, adopter_party: str, tolerance: float, tree: Path | None,
                  prev_version: str | None, *, perspective_doc: dict,
                  reporting_currency: str, band_currency: str | None,
                  floor: str | None, parent_trees: dict[str, Path] | None = None) -> dict:
    """One prices[] entry for one feed edge, in the one schema every price in
    this estate shares: perspective, currency, source, kind, amount and a
    per-customer restatement (ticket 25). Priced at the OLD version (the last
    signed artefact's recorded pin, or -- with nothing to compare -- this run's
    own version, an honest "no move") and at the NEW version, both through the
    estate's own £ engine and the adopter's own signed appetite band, never a
    second one. A regime entry also carries its per-hole breakdown and the
    total those holes sum to; the entry's amount IS that total, so the entry
    and its own per-customer restatement never disagree. The band converts into
    the publisher's currency before anything is compared -- it never refuses
    for want of a conversion nobody asked the fx feed for."""
    party, kind, new_version = edge["party"], edge["kind"], edge["version"]
    old_version = prev_version if prev_version is not None else new_version
    name = _feed_name(edge)
    tree = Path(tree) if tree is not None else PLATFORM_DIR

    if name not in FEED_CONVERTERS:
        # ADR-0020: a declared feed parent with no converter is a MISSING
        # INSTRUMENT -- the gate cannot read it, so it must not emit a number.
        raise Refused(f"missing instrument: feed {name!r} declared by {adopter_party} has no "
                       f"converter this composition can price through")
    path = feed_file("", name, new_version, tree)
    payload, as_of = load_feed_payload(path, name, new_version), _feed_as_of(path)

    # The currency the PUBLISHER prices in. No declaration is a missing
    # instrument: an amount cannot be relabelled into the reader's reporting
    # currency without a rate, and a relabelled amount is a minted one.
    native = _feed_currency(name, payload)
    if not native:
        raise Refused(f"missing instrument: feed {name}@{new_version} published by {party} "
                       f"declares no currency, so the magnitudes it prices cannot be stated "
                       f"in {adopter_party}'s {reporting_currency}")

    if name == "penalty-schema":
        # This party's OWN signed size reaches the publisher's converter, so the
        # percent-of-turnover formula prices this balance sheet and no fixture's.
        turnover = _sized_turnover(perspective_doc, native, as_of, parent_trees)
        old_sc = _ico_scenario(tree, old_version, turnover)
        new_sc = _ico_scenario(tree, new_version, turnover)
    else:
        old_sc = _threat_scenario(old_version, adopter_party, tree)
        new_sc = _threat_scenario(new_version, adopter_party, tree)

    # The band and the residual must be one currency before either is compared:
    # the selection happens in the publisher's currency, so the band converts
    # into it (or refuses for want of a rate -- never refuses for want of a
    # conversion nobody asked the fx feed for).
    band_native, _ = _converted(tolerance, band_currency or reporting_currency, native,
                                 as_of, parent_trees)
    cage = _cage_engine()
    old = cage.select(old_sc, adopter_party, band_native, mode="warn", floor=floor)
    new = cage.select(new_sc, adopter_party, band_native, mode="warn", floor=floor)
    old_price, _ = _converted(old["uncaged_residual"], native, reporting_currency, as_of, parent_trees)
    new_price, fx = _converted(new["uncaged_residual"], native, reporting_currency, as_of, parent_trees)

    # The holes are computed BEFORE the entry, because the entry's amount IS
    # their total and its per-customer restatement divides that same amount.
    # Building the entry first and overwriting `amount` afterwards left the two
    # disagreeing.
    holes = _regime_holes(payload, new_price, adopter_party, reporting_currency)
    total = _sum_prices(holes, adopter_party, reporting_currency) if holes else None
    amount = total if holes else new_price

    # Every figure on this entry is an ANNUALISED loss, and the frequency that annualised it is
    # editorial: ico's converter carries `DEFAULT_WARN_LEF = (1, 2, 4)` because the penalty schema
    # publishes no frequency at all, and the threat register's driftwood entry carries [2, 4, 9]
    # from a DBIR base rate. The converter says so in its own `note`, and this entry used to drop
    # it -- so the amount arrived with no way to see how often the event was assumed to happen,
    # and two lines annualised at 2.167 and 4.5 events a year were summed into one total. Carried,
    # not computed: the note is the publisher's own words.
    entry = _price_entry(
        party, kind if kind in PRICE_KINDS else "feed", adopter_party, reporting_currency,
        amount, perspective_doc,
        **({"name": name} if name else {}),
        old_version=old_version, new_version=new_version,
        old_price=old_price, new_price=amount,
        old_tier=old["tier"], proposed_tier=new["tier"],
        changed=old["tier"] != new["tier"],
        lef=(new_sc.get("warn") or {}).get("lef"),
        lef_basis=str(new_sc.get("note") or "") or None,
        proposed_as=PROPOSED_AS_LABEL,
        **fx,
    )
    entry["holes"] = holes
    entry["total"] = total
    return entry


# --------------------------------------------------------------------------
# 8b. the twin edge (ticket 25; ADR-0021)
# --------------------------------------------------------------------------


def _forward_intel(adopter_dir: Path) -> tuple[dict, Path] | None:
    """The adopter's OWN twin publishes forward intelligence into the adopter's
    own repo, as an ADR-0019 envelope (ADR-0021). The highest published major
    wins. No feed at all is simply no twin entry -- never a refusal."""
    root = Path(adopter_dir).joinpath(*FORWARD_INTEL_DIR)
    majors = sorted((d for d in root.glob("v*") if (d / "feed.json").exists()),
                     key=lambda d: int(re.sub(r"\D", "", d.name) or 0)) if root.is_dir() else []
    if not majors:
        return None
    path = majors[-1] / "feed.json"
    doc = json.loads(path.read_text())
    _validate_envelope(doc, str(path))
    if doc["name"] != FORWARD_INTEL:
        raise Refused(f"{path}: envelope names feed {doc['name']!r}, expected {FORWARD_INTEL!r}")
    return doc, path


def _selection_policy(adopter_dir: Path, adopter_party: str):
    """The adopter's OWN selection-policy package, imported and CALLED.

    ADR-0021: "a versioned, signed selection policy package, published by the
    adopter and pinned by Renovate, turns the curve into one tier." Stamping a
    version read out of a file onto a tier some other engine picked is a
    provenance claim the £ cannot back, so the package that is named is the
    package that runs. `graded/cage.py` stays the cross-check: verify/pound-seam
    runs both over the same residuals and refuses a disagreement.

    No package at all is a MISSING INSTRUMENT: the estate cannot say which
    versioned rule chose this party's cage (ADR-0020)."""
    pkg = Path(adopter_dir) / SELECTION_POLICY_DIR / "selection_policy.py"
    if not pkg.exists():
        raise Refused(f"missing instrument: {adopter_party} publishes forward intelligence but "
                       f"ships no {SELECTION_POLICY_DIR}/selection_policy.py, so no versioned "
                       f"rule can be named as the one that picked its tier (ADR-0021)")
    spec = importlib.util.spec_from_file_location(f"_selpol_{Path(adopter_dir).name}", pkg)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pinned = _selection_policy_version(adopter_dir)
    if pinned is not None and pinned != getattr(mod, "VERSION", None):
        raise Refused(f"missing instrument: {adopter_party}'s {SELECTION_POLICY_DIR}/PIN.yaml "
                       f"pins {pinned!r} but the package on disk is "
                       f"{getattr(mod, 'VERSION', None)!r}; which rule picked is unreadable")
    return mod


def _selection_policy_version(adopter_dir: Path) -> str | None:
    """The version of the adopter's OWN selection-policy package (ADR-0021:
    the curve never picks, a pinned package does, and the proposal PR names
    its version). Read from the package's own `PIN.yaml` -- the party schema
    forbids unknown keys, so the pin lives beside the rule, not on party.yaml.
    None where the adopter ships no such package yet."""
    pin = Path(adopter_dir) / SELECTION_POLICY_DIR / "PIN.yaml"
    if not pin.exists():
        return None
    doc = yaml.safe_load(pin.read_text()) or {}
    return doc.get("policy_version")


def _curve_hash(curve: object) -> str:
    """A stable digest of the trade-off curve the twin published -- WHICH curve
    this scenario shipped with, named on the proposal PR beside the policy
    version (ADR-0021), and what resets the rejection ledger when it moves. It
    is an identifier, NOT the input to the selection: the rule picks over the
    priced residuals, which the entry records as `residuals`. Byte-identical to
    the adopter's own vendorable `selection-policy/selection_policy.py:curve_hash`
    (named that, not `select.py`, because a `select.py` on sys.path shadows the
    stdlib `select` module and breaks subprocess), so the estate and the adopter
    never disagree about which curve was priced. `verify/pound-seam` runs the
    adopter's own function over its published curve and compares the two."""
    canonical = json.dumps(curve, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def price_twin(adopter_dir: Path, adopter_party: str, tolerance: float, floor: str | None,
                parent_trees: dict[str, Path], prev_prices: list[dict],
                lef_by_feed: dict[str, dict], band_currency: str | None = None) -> dict | None:
    """The `source: twin` pricing parent edge. The twin emits a scenario under a
    perspective and has no frequency; fair.py annualises it and the ADOPTER'S OWN
    versioned selection-policy package picks the tier (ADR-0021). One entry,
    carrying that package's version, the curve hash, the residuals it picked
    over and fair.py's own tail name."""
    found = _forward_intel(adopter_dir)
    if found is None:
        return None
    doc, path = found
    payload = doc["payload"]
    perspective = payload.get("perspective") or adopter_party
    if perspective != adopter_party:
        # Hard rule 7 and ADR-0020: this composition holds ONE party's signed
        # appetite band and reporting currency. Tiering another balance sheet
        # against them, and filing the result in this party's prices[], is the
        # cross-perspective comparison the whole £ seam exists to prevent.
        raise Refused(f"missing instrument: {path} prices {perspective}'s balance sheet, and "
                       f"this composition holds only {adopter_party}'s signed appetite; another "
                       f"party's money is never tiered against this party's band")
    perspective_doc = _party_doc(perspective, adopter_dir, parent_trees)
    native = payload.get("currency") or _reporting_currency(perspective_doc)
    reporting = _reporting_currency(perspective_doc)
    # A null lef means a SUBSCRIBED pricing feed supplies the frequency (ticket 08 Answer 2), and
    # the payload has to NAME which one. It used to fall through to "whatever single feed happens
    # to publish a triple", so the borrow was unconditional and invisible: the twin's shock was
    # annualised at 4.5 events a year off the threat register while the ico line beside it used
    # 2.167, and nothing on either entry said so.
    #
    # What names it is `derived_from`, which the published payload schema already carries: the
    # emitter now puts in it exactly what the render read, and the one subscribed feed whose
    # frequency it borrows. `claim_scope.frequency_from` is read first where a payload carries it
    # (additionalProperties:false today, so it is a payload major, not this seam's).
    lef, lef_from, lef_basis = payload.get("lef"), None, None
    if lef is None:
        wanted = ((payload.get("claim_scope") or {}).get("frequency_from") or {}).get("name")
        if wanted is None:
            named = sorted({str(d.get("name")) for d in (payload.get("derived_from") or [])
                            if d.get("kind") == "feed" and d.get("party") != perspective
                            and str(d.get("name")) in lef_by_feed})
            if len(named) != 1:
                raise Refused(
                    f"missing instrument: {path} supplies no lef and its derived_from names "
                    f"{len(named)} subscribed feeds that price one ({named or 'none'}); a "
                    f"borrowed frequency has to be named, not guessed at")
            wanted = named[0]
        borrowed = lef_by_feed.get(wanted) if wanted else None
        if borrowed is None:
            raise Refused(
                f"missing instrument: {path} supplies no lef and names no subscribed feed "
                f"that does (wanted {wanted!r}, priced {sorted(lef_by_feed)})")
        lef, lef_basis = borrowed["lef"], borrowed["basis"]
        lef_from = wanted
    fair = _cage_engine().fair
    try:
        summary = fair.summarize(fair.simulate(lef, payload["lm"]))
    except (KeyError, TypeError, ValueError) as e:
        raise Refused(f"missing instrument: {path} carries no severity this estate can "
                       f"annualise ({e})") from None
    as_of = _feed_as_of(path)
    amount, fx = _converted(summary["ale"], native, reporting, as_of, parent_trees)
    cage = _cage_engine()
    # One currency on both sides before either is compared (hard rule 7).
    band, _ = _converted(tolerance, band_currency or reporting, reporting, as_of, parent_trees)
    # The residuals the versioned rule actually picked over, recorded on the
    # entry so the tier can be re-derived from it rather than believed.
    residuals = {t: cage.caged_residual(amount, t) for t in cage.ORDER}
    policy = _selection_policy(adopter_dir, adopter_party)
    try:
        picked = policy.select({t: {"amount": r, "currency": reporting}
                                 for t, r in residuals.items()},
                                {"amount": band, "currency": reporting}, floor)
    except Exception as e:                       # noqa: BLE001 -- the package's own refusal
        raise Refused(f"missing instrument: {adopter_party}'s {SELECTION_POLICY_DIR} package "
                       f"could not pick from the priced residuals ({e})") from None
    tier = picked["tier"]
    prior = next((e for e in prev_prices if e.get("source") == "twin"), None)
    return _price_entry(
        "twin", "twin", perspective, reporting, amount, perspective_doc,
        name=FORWARD_INTEL,
        feed_version=doc["version"],
        tail=summary["tail"],
        policy_version=picked["policy_version"],
        policy_basis=picked["basis"],
        # WHICH reduction set produced those residuals. `policy_basis` is the selection package's
        # own sentence about the rung it picked ("the loosest tier whose caged residual is within
        # the tolerance"), and a reader attributed the residuals in it to the adopter's own
        # published curve. They are not: they are `ale * (1 - platform's table reduce)`, and the
        # curve_hash beside them is an identifier of the input, not the input. Named, so the
        # attribution is readable rather than inferred.
        residual_basis=f"platform-cage-tiers@{getattr(cage, 'TABLE_VERSION', 'unversioned')}",
        residuals=residuals,
        curve_hash=_curve_hash(payload.get("curve", [])),
        shock=payload.get("shock"),
        horizon=payload.get("horizon"),
        lef=lef,
        lef_basis=lef_basis,
        **({"lef_from": lef_from} if lef_from else {}),
        old_tier=(prior or {}).get("proposed_tier", tier),
        proposed_tier=tier,
        changed=prior is not None and prior.get("proposed_tier") != tier,
        proposed_as=PROPOSED_AS_LABEL,
        **fx,
    )


# --------------------------------------------------------------------------
# 8c. the insurance premium edge (ticket 36; ticket 14 answer 3)
# --------------------------------------------------------------------------


def _pin_tag_pattern(name: str, version: str) -> re.Pattern:
    """The tag forms that sign a feed pin: `<name>/vX.Y.Z` or bare `vX.Y.Z`
    (a single tag line for every feed, ticket 14 answer 4). A bare-major pin
    (`v1`) is signed by any `v1.x.y`; a full version must match exactly. The
    same rule the hub's feed_contract.py resolves a pin by."""
    v = version.lstrip("v")
    ver = re.escape(v) if "." in v else rf"{re.escape(v)}\.\d+\.\d+"
    return re.compile(rf"^(?:{re.escape(name)}/)?v{ver}$")


def _tag_version_key(tag: str) -> list[int]:
    """Sort key over the tags of ONE pin form, tolerant of a pre-release
    suffix (`v1.0.0-rc1`): each dotted field orders on its leading digits, and
    a field carrying anything else sorts the tag below the plain release of
    the same numbers. A pre-release pin is a legal pin, so reading its state
    may not raise on the way to the highest tag."""
    key: list[int] = []
    release = 1
    for field in tag.rsplit("v", 1)[-1].split("."):
        digits = re.match(r"\d+", field)
        key.append(int(digits.group()) if digits else 0)
        if digits is None or digits.end() != len(field):
            release = 0
    return key + [release]


def pin_signature_state(tree: Path | None, party: str, name: str, version: str) -> dict:
    """Ticket 69. What the parent tree's OWN tags say about the pin:
    `signed` when the highest tag of the pinned form is an annotated tag
    carrying a signature block, `untagged` when the checkout demonstrably
    carries the publisher's tags and none of them signs the pin, `unobserved`
    when this checkout is in no position to say. Presence of the block is what
    is read here, the same reading `_signed_tags` makes for the adopter's own
    tags; whether it VERIFIES under the pinned identity is the hub check's,
    and this module never claims it. Never a refusal.

    Only a checkout that can actually show the publisher's tag namespace may
    say `untagged`, because `untagged` books a hole of the whole premium and
    an absent tag and an unfetched one look identical from inside a checkout:

      - no git metadata at all: nothing to read (a fixture, a copied tree);
      - a git checkout carrying NO tag whatever: `actions/checkout` fetches
        none unless `fetch-tags: true` is set, so an empty tag namespace is
        the shape of a shallow fetch, not of a publisher who never tagged;
      - a matching tag that is not an annotated tag OBJECT (`objecttype` is
        `commit`): a lightweight tag, or an annotated tag flattened by
        checkout's second fetch (release.yml re-fetches the real ref before
        verifying for exactly this reason) -- the object that would carry the
        signature is not in this checkout to read.

    All three are could-not-look: they keep a recorded hole open and open
    none (ticket 69 decision 6). A tag of the pinned form that IS an
    annotated object and carries no signature block is a real observation and
    stays `untagged`: an unsigned tag signs nothing (decision 5)."""
    if tree is None or not (Path(tree) / ".git").exists():
        return {"state": "unobserved", "tag": None,
                "detail": f"the {party} parent tree carries no git metadata, so no tag could be "
                          f"read for {name}@{version}; the signature state is unobserved, not absent"}
    listed = subprocess.run(
        ["git", "-C", str(tree), "for-each-ref", "--format=%(refname:short) %(objecttype)",
         "refs/tags"], capture_output=True, text=True)
    refs = [r for r in (line.split() for line in listed.stdout.splitlines()) if len(r) == 2]
    if listed.returncode != 0 or not refs:
        return {"state": "unobserved", "tag": None,
                "detail": f"the {party} parent's checkout carries no tag at all, so it cannot "
                          f"tell an untagged {name}@{version} from a checkout fetched without "
                          f"tags; the signature state is unobserved, not absent"}
    pattern = _pin_tag_pattern(name, version)
    hits = sorted((tag, kind) for tag, kind in refs if pattern.match(tag))
    if not hits:
        return {"state": "untagged", "tag": None,
                "detail": f"no tag of the form {name}/v* or v* signs @{version} on the {party} "
                          f"parent's checkout, which carries {len(refs)} tag(s) of its own"}
    tag, kind = max(hits, key=lambda h: _tag_version_key(h[0]))
    if kind != "tag":
        return {"state": "unobserved", "tag": tag,
                "detail": f"tag {tag} on the {party} checkout is a {kind}, not an annotated tag "
                          f"object -- a lightweight tag, or one flattened by a second fetch -- so "
                          f"the object that would carry a signature is not here to read"}
    body = subprocess.run(["git", "-C", str(tree), "cat-file", "-p", tag],
                          capture_output=True, text=True).stdout
    if "-----BEGIN" in body:
        return {"state": "signed", "tag": tag,
                "detail": f"tag {tag} on the {party} checkout carries a signature block"}
    return {"state": "untagged", "tag": tag,
            "detail": f"annotated tag {tag} exists on the {party} checkout but carries no "
                      f"signature block, so it signs nothing"}


def _previous_pin_hole(prev_prices: list[dict], party: str, name: str) -> dict | None:
    """The open (new or recorded) untagged-pin hole the last signed composed
    artefact carried on this premium edge, or None."""
    for e in prev_prices or []:
        if e.get("kind") == "premium" and e.get("source") == party and e.get("name") == name:
            hole = e.get("hole")
            if isinstance(hole, dict) and hole.get("status") in ("new", "recorded"):
                return hole
            return None
    return None


def untagged_pin_hole(signature: dict, prev_hole: dict | None, *, party: str, name: str,
                      version: str, perspective: str, currency: str, amount: float) -> dict | None:
    """The hole an untagged premium pin opens on its own entry (ticket 69):
    the premium, booked as paid against a quote no tag signs, under the
    adopter's own perspective and currency. `new` on first sight, `recorded`
    once the last signed artefact carried it, `closed` when a signed tag now
    carries the pin, None when there is nothing to report. An unobserved
    state keeps a recorded hole open and opens none: a could-not-look is
    never a signature and never a closure."""
    state = signature["state"]
    priced_by = (f"{party} {name}@{version}: the premium the pin books, paid against a quote "
                 f"no signed tag carries")
    base = {"kind": UNTAGGED_PIN_HOLE_KIND, "source": party, "name": name, "version": version,
            "perspective": perspective, "currency": currency}
    if state == "untagged":
        return {**base, "status": "recorded" if prev_hole else "new", "amount": amount,
                "priced_by": priced_by, "detail": signature["detail"]}
    if prev_hole is None:
        return None
    if state == "unobserved":
        return {**base, "status": "recorded", "amount": amount, "priced_by": priced_by,
                "detail": f"{signature['detail']}; the recorded hole stays open"}
    return {**base, "status": "closed", "amount": amount, "priced_by": priced_by,
            "detail": f"{signature['detail']}; the hole the last signed artefact recorded is closed"}


def untagged_pin_deltas(prices: list[dict], perspective: str, currency: str) -> list[dict]:
    """deltas[] for the premium entries whose untagged-pin hole opened or
    closed since the last signed composed artefact (ticket 69), in the same
    shape compute_deltas prints a control hole's move."""
    deltas: list[dict] = []
    for e in prices:
        hole = e.get("hole") if e.get("kind") == "premium" else None
        if not isinstance(hole, dict) or hole.get("status") not in ("new", "closed"):
            continue
        deltas.append({
            "kind": f"{hole['status']}-untagged-pin", "source": hole["source"],
            "name": hole["name"], "version": hole["version"],
            "perspective": perspective, "currency": currency,
            "amount": hole["amount"], "priced_by": hole["priced_by"],
            "detail": (f"{perspective} pins {hole['source']}/{hole['name']}@{hole['version']} and "
                       f"{hole['detail']}; {hole['amount']:.2f} {currency} of premium is booked "
                       f"as paid against an unsigned quote" if hole["status"] == "new" else
                       f"{perspective} pins {hole['source']}/{hole['name']}@{hole['version']}; "
                       f"{hole['detail']}; {hole['amount']:.2f} {currency} of premium is again "
                       f"paid against a signed quote"),
        })
    return deltas


def price_quote(edge: dict, adopter_party: str, tree: Path | None, *,
                 perspective_doc: dict, reporting_currency: str,
                 prev_version: str | None,
                 parent_trees: dict[str, Path] | None = None,
                 prev_prices: list[dict] | None = None) -> dict:
    """One `kind: premium` prices[] entry, read off the insurer's own signed
    quote feed. There is no arithmetic here on purpose: the premium is a
    CONTRACT COST -- what this adopter pays, booked under its own perspective
    beside costs.fix -- and the insurer's layer arithmetic that produced it
    stays under `perspective: insurer` and is never summed with anything of the
    adopter's (ticket 14 answer 3, ADR-0021).

    Refuses (missing instrument, ADR-0020) only where the quote cannot be read
    as this party's own cover: another adopter's quote, or a premium booked on
    somebody else's balance sheet. A stale `priced_against` and a lapsed
    `valid_until` are FACTS carried onto the entry, not refusals -- a pin past
    the expiry is lapsed cover the composition prices as fully retained, and
    this module may not read a clock to decide that (D1). ponytail ceiling:
    the lapse is recorded, not yet priced; the upgrade path is the composition's
    own as-of date reaching this function, which ticket 37 (insurance round 2)
    is the place to decide."""
    name = _feed_name(edge)
    tree = Path(tree) if tree is not None else PLATFORM_DIR
    path = feed_file(edge["party"], name, edge["version"], tree)
    if not path.exists():
        raise Refused(f"missing instrument: {adopter_party} pins {edge['party']}'s {name} "
                       f"@{edge['version']} but {path} does not exist, so the cover it names "
                       f"cannot be read")
    payload = load_feed_payload(path, name, edge["version"])
    quote_version = json.loads(path.read_text()).get("version")

    insured = payload.get("adopter")
    if insured != adopter_party:
        raise Refused(f"missing instrument: {name}@{edge['version']} insures {insured!r}, not "
                       f"{adopter_party!r} -- one composition holds one party's cover")
    premium = payload.get("premium") or {}
    booked = premium.get("perspective")
    if booked != adopter_party:
        raise Refused(f"missing instrument: {name}@{edge['version']} books its premium under "
                       f"perspective {booked!r}; a premium on {adopter_party}'s balance sheet "
                       f"is booked under {adopter_party!r} and no other party (ADR-0021)")
    native = premium.get("currency")
    if native is None or premium.get("amount") is None:
        raise Refused(f"missing instrument: {name}@{edge['version']} states no premium amount "
                       f"and currency, so there is no cost line to book")
    amount, fx = _converted(float(premium["amount"]), native, reporting_currency,
                             _feed_as_of(path), parent_trees)
    # Ticket 69: the pin's signature state, read off the parent tree's own
    # tags (`tree` as passed, never the platform fallback: the platform's
    # tags sign nothing of the insurer's), and the hole an untagged pin is.
    signature = pin_signature_state(tree if tree != PLATFORM_DIR else None, edge["party"], name,
                                    str(edge["version"]))
    hole = untagged_pin_hole(
        signature, _previous_pin_hole(prev_prices or [], edge["party"], name),
        party=edge["party"], name=name, version=str(edge["version"]),
        perspective=adopter_party, currency=reporting_currency, amount=amount)
    return _price_entry(
        edge["party"], "premium", adopter_party, reporting_currency, amount, perspective_doc,
        name=name,
        old_version=prev_version if prev_version is not None else edge["version"],
        new_version=edge["version"],
        quote_version=quote_version,
        attachment=payload.get("attachment"),
        limit=payload.get("limit"),
        exclusions=payload.get("exclusions") or [],
        conditions=payload.get("conditions") or [],
        valid_from=payload.get("valid_from"),
        valid_until=payload.get("valid_until"),
        priced_against=payload.get("priced_against") or [],
        pin_signature=signature,
        hole=hole,
        **fx,
    )


# --------------------------------------------------------------------------
# 8d. the signed exposure section (ticket 36; ticket 14 answer 2)
# --------------------------------------------------------------------------

# The name an exposure line is EXCLUDED BY. A quote's exclusions[] are keyed on
# obligation regime names and (source, id) control keys (ticket 14 answer 1), so
# a line is named by the regime its publisher prices where the publisher names
# one, and by the feed's own name where it does not.
EXPOSURE_REGIMES = {"penalty-schema": ICO_REGIME}
# Which prices[] kinds ARE exposure. `premium` is what cover COSTS, not what is
# at risk: folding it in would make the premium an input to the formula that
# computes it. `switching` and `reliability` are costs too, and neither is
# emitted yet.
EXPOSURE_KINDS = ("feed", "twin")


def exposure_section(prices: list[dict], adopter_party: str, band: dict | None,
                      reporting_currency: str) -> dict | None:
    """The adopter's own signed exposure: what it is on the hook for, under its
    own perspective and currency, its appetite as the attachment, and the
    breakdown by regime name and control id -- enough for an insurer to price a
    layer from signed facts alone and never from the insurer's own model of
    somebody else's business (ticket 14 answer 2).

    The total is the estate's ONE summing helper over the exposure entries, so
    it refuses rather than sums if a price of another party's ever lands in this
    party's prices[] (ADR-0021). None where nothing priced -- a named absence,
    never a zero this party did not declare.

    ponytail ceiling: the total is the sum of the priced parent edges, not an
    aggregate loss DISTRIBUTION (ale/var95/tvar over per-risk annual loss lists
    summed year by year, ticket 14 answer 2's fuller shape). A layer attaching
    at the appetite can be read off this total; a layer priced off the tail
    between attachment and limit needs the distribution. Upgrade path: fair.py
    gains a portfolio aggregate and this section gains its summary beside the
    total -- the section's shape does not change."""
    lines = []
    for e in prices:
        if e.get("kind") not in EXPOSURE_KINDS:
            continue
        feed = e.get("name") or e["kind"]
        lines.append({
            "name": EXPOSURE_REGIMES.get(feed, feed),
            "source": e["source"],
            "feed": feed,
            "version": e.get("new_version") or e.get("feed_version"),
            "amount": e["amount"],
            "controls": [{"source": h["source"], "id": h["id"], "amount": h["amount"]}
                          for h in e.get("holes") or []],
        })
    if not lines:
        return None
    return {
        "perspective": adopter_party,
        "currency": reporting_currency,
        # The attachment IS the appetite, seen from the other side: the retention
        # this party already signed, never a second number an insurer proposed
        # (ticket 14 answer 1). Its own currency label rides with it, because an
        # appetite declared in another currency is not silently relabelled.
        "attachment": ({"amount": band["amount"],
                         "currency": band.get("currency") or reporting_currency}
                        if band else None),
        "total": _sum_prices([e for e in prices if e.get("kind") in EXPOSURE_KINDS],
                              adopter_party, reporting_currency),
        "regimes": lines,
    }


# --------------------------------------------------------------------------
# 8e. the switching cost (eco-system ticket 45; ADR-0020)
# --------------------------------------------------------------------------


def compute_switching(edges: list[dict], adopter_party: str, tolerance: float,
                       parent_trees: dict[str, Path], prev_header: dict | None,
                       *, adopter_dir: Path, perspective_doc: dict,
                       band_currency: str | None, floor: str | None,
                       prev_prices: list[dict] | None, full_prices: list[dict]) -> list[dict]:
    """One `switching` entry per substitutable parent edge, under the adopter's
    own perspective and in the adopter's own reporting currency.

    The amount is what this adopter's PRICEABLE EXPOSURE loses if this publisher
    goes: the whole edge set is re-priced with that publisher's feed edges
    dropped and the two exposures are differenced through the estate's one
    summing helper, so nothing crosses a perspective or a currency on the way.
    It is an annual rate because every figure in prices[] is one;
    `over_pin_life` carries it over the window the pin has actually stood.

    Refuses -- never defaults -- where the window has only one end: an edge with
    no signed `since`, or a composition whose pinned feeds carry no published_at
    to be as-of. A pin's life is a window between two signed dates (ADR-0020)."""
    reporting = _reporting_currency(perspective_doc)
    as_of = _composition_as_of(edges, parent_trees)
    exposure_of = (lambda entries: _sum_prices(
        [e for e in entries if e.get("kind") in EXPOSURE_KINDS], adopter_party, reporting))
    full_exposure = exposure_of(full_prices)
    publishers = _feed_publishers(adopter_dir, parent_trees)
    # The percent-of-turnover half of every regime price scales against the
    # perspective party's OWN signed size; without one the publisher prices at
    # its statutory cap, which is a ceiling every firm shares and therefore says
    # nothing about THIS one. Priced (a cap is a published number, not a guess),
    # flagged, and graded as a could-not-look by the check rather than a pass.
    sized = isinstance((perspective_doc.get("size") or {}).get("turnover"), dict)
    entries: list[dict] = []
    for edge in edges:
        if edge["kind"] not in FEED_KINDS:
            continue
        name = _feed_name(edge)
        since = edge.get("since")
        if not since:
            raise Refused(
                f"missing instrument: the {edge['party']} feed edge {name!r}@{edge['version']} "
                f"declares no `since`, so the life of the pin its switching cost is annualised "
                f"over is a window with one end")
        if not as_of:
            raise Refused(
                f"missing instrument: no feed {adopter_party} pins carries a published_at, so "
                f"this composition has no as-of date and the life of the {name!r} pin cannot be "
                f"measured against one")
        # THE COUNTERFACTUAL. It can refuse, and when it does that refusal is
        # the answer rather than an error: driftwood's own forward-intel
        # borrows its loss-event frequency from the threat register it
        # subscribes to, so with that publisher dropped the twin has no
        # frequency to annualise on and composition will not guess one. The
        # switching cost is then not a number at all -- it is "this adopter
        # stops being able to price its own book" -- and the entry says so, in
        # the publisher's own words, with NO amount. Never a pass, never a
        # guess. Subtracting the entry we were about to lose would have printed
        # a confident figure here and been wrong.
        could_not_look: str | None = None
        without: list[dict] = []
        try:
            without = compute_prices(
                [e for e in edges if e is not edge], adopter_party, tolerance, parent_trees,
                prev_header, adopter_dir=adopter_dir, perspective_doc=perspective_doc,
                band_currency=band_currency, floor=floor, prev_prices=prev_prices,
                include_switching=False)
        except Refused as e:
            could_not_look = str(e)
        amount = None if could_not_look else full_exposure - exposure_of(without)
        # A counterfactual that refused prices NOTHING, so nothing is kept: the
        # whole book goes unpriceable, not just the dropped publisher's line.
        kept = {(e["kind"], e.get("name")) for e in without} if could_not_look is None else set()
        months = _months_apart(str(since), as_of)
        entries.append(_price_entry(
            edge["party"], SWITCHING_KIND, adopter_party, reporting, amount, perspective_doc,
            name=name, version=edge["version"],
            since=str(since), as_of=as_of, pin_life_months=months,
            over_pin_life=None if amount is None else amount * months / MONTHS_PER_YEAR,
            could_not_look=could_not_look,
            # Every party visible from here that declares it publishes this same
            # feed name, minus the one this edge pins. Empty is a surveyed
            # absence printed by name, never an assumption that none exists.
            alternates=[p for p in publishers.get(name, []) if p != edge["party"]],
            # What stops being priced AT ALL if this edge goes -- carried beside
            # the amount, never summed into it, because a premium is a cost and
            # an exposure is not, and one array must not add them together.
            unpriceable=[{"kind": e["kind"], "source": e["source"], "name": e.get("name"),
                           "perspective": e["perspective"], "currency": e["currency"],
                           "amount": e["amount"]}
                          for e in full_prices if (e["kind"], e.get("name")) not in kept],
            sized=sized,
            basis=SWITCHING_BASIS,
            dropped_edges=[f"{edge['party']}/{edge['kind']}"
                            + (f":{name}" if name else "") + f"@{edge['version']}"]))
    return entries


def compute_prices(edges: list[dict], adopter_party: str, tolerance: float | None,
                    parent_trees: dict[str, Path], prev_header: dict | None,
                    *, adopter_dir: Path, perspective_doc: dict,
                    band_currency: str | None = None, floor: str | None = None,
                    prev_prices: list[dict] | None = None,
                    include_switching: bool = True) -> list[dict]:
    """prices[] -- one entry per declared feed edge, plus the twin edge when the
    adopter's own repo carries forward intelligence. Computed EVERY run, not
    only when a version actually moved: "for each party it prints the old price,
    the new price, the old tier and the proposed tier" (spec.md) is
    unconditional, and "a price move that changes no tier prints as no change"
    is what the `changed` field says. `tolerance` is None only when the party
    declares no appetite, which compose() has already refused as a missing
    instrument (ADR-0020)."""
    if tolerance is None:
        return []
    reporting = _reporting_currency(perspective_doc)
    prices: list[dict] = []
    lef_by_feed: dict[str, dict] = {}
    for edge in edges:
        if edge["kind"] not in FEED_KINDS:
            continue
        prev_version = _previous_parent_version(prev_header, edge)
        if (_feed_name(edge) or "").startswith(QUOTE_PREFIX):
            # An insurance quote is not priced through a converter: the premium
            # is a contract cost the insurer already priced and signed.
            prices.append(price_quote(
                edge, adopter_party, parent_trees.get(edge["party"]),
                perspective_doc=perspective_doc, reporting_currency=reporting,
                prev_version=prev_version, parent_trees=parent_trees,
                prev_prices=prev_prices))
            continue
        prices.append(price_parent(
            edge, adopter_party, tolerance, parent_trees.get(edge["party"]), prev_version,
            perspective_doc=perspective_doc, reporting_currency=reporting,
            band_currency=band_currency, floor=floor, parent_trees=parent_trees))
        if _feed_name(edge) == "threat-register":
            tree = Path(parent_trees.get(edge["party"], PLATFORM_DIR))
            scenario = _threat_scenario(edge["version"], adopter_party, tree)
            lef_by_feed["threat-register"] = {
                "lef": scenario["warn"]["lef"],
                # The converter's own words about where the triple came from, carried so a reader
                # of the twin entry can see the editorial frequency instead of inferring it.
                "basis": str(scenario.get("note") or "") or None,
            }
    twin = price_twin(adopter_dir, adopter_party, tolerance, floor, parent_trees,
                       prev_prices or [], lef_by_feed, band_currency)
    if twin is not None:
        prices.append(twin)
    if include_switching:
        # Last, and over the finished list: a switching cost is a statement
        # ABOUT the prices above it, and re-pricing an edge set that already
        # contains one would price the statement.
        prices += compute_switching(
            edges, adopter_party, tolerance, parent_trees, prev_header,
            adopter_dir=adopter_dir, perspective_doc=perspective_doc,
            band_currency=band_currency, floor=floor, prev_prices=prev_prices,
            full_prices=prices)
    return prices


# --------------------------------------------------------------------------
# the seam
# --------------------------------------------------------------------------


def _refused(errors: list[str]) -> dict:
    return {
        "outcome": "refused",
        "party_artefact_errors": list(errors),
        "parents": [],
        "members": [],
        "refusals": [],
        "restatements": [],
        "cages": [],
        "holes": [],
        "ungoverned": [],
        "prices": [],
        "deltas": [],
        "limits": [],
        "vendored": [],
    }


def compose(adopter_dir: Path, parent_trees: dict[str, Path]) -> tuple[dict, dict[str, str]]:
    """The one entry point. Takes the adopter repo state (a directory) and
    the pinned parent trees (party name -> that party's directory). Returns
    the evidence document as a dict and the rendered composed artefact as a
    mapping of path (relative to `adopter_dir`) to file content. Writes
    nothing to disk -- that is the CLI's job."""
    adopter_dir = Path(adopter_dir)
    party_yaml = adopter_dir / "party.yaml"
    if not party_yaml.exists():
        return _refused([f"{party_yaml} does not exist"]), {}

    check_result = party_artefact.check(party_yaml, adopter_dir)
    if check_result["errors"]:
        # A party artefact that does not check out cannot be composed from --
        # there is nothing safe to read a resolved parent from (mirrors
        # party_artefact.check()'s own "can't be checked any further").
        return _refused(check_result["errors"]), {}

    party_doc = yaml.safe_load(party_yaml.read_text())
    adopter_party = party_doc["party"]
    edges = party_doc.get("inherits", []) or []

    parents: list[dict] = []
    missing: list[str] = []
    parent_trees = dict(parent_trees)
    if any(e.get("party") == adopter_party for e in edges):
        # A SELF-PIN (ticket 38): the adopter pins its own bespoke controls
        # catalogue as a parent. The tree is the tree under composition --
        # always, so composing a copy prices that copy's own catalogue -- and
        # the catalogue is signed by the same tag as the composed artefact
        # (ADR-0017's "no separate pin"), so no tag of its own is needed.
        parent_trees[adopter_party] = adopter_dir
    # Eco-system ticket 45. A feed parent whose CLONE is not here is priced from
    # the adopter's own vendored copy of it, if the adopter carries one that
    # still digests to what its own signature recorded. This is the whole point
    # of vendoring: an adopter that cannot reach a publisher can still restate
    # its own signed history. The substitution is never silent -- every party
    # read this way is named on an open limits[] entry below.
    from_vendor: list[str] = []
    for edge in edges:
        if edge["kind"] not in FEED_KINDS or edge["party"] == adopter_party:
            continue
        tree = parent_trees.get(edge["party"])
        if tree is not None and Path(tree).is_dir():
            continue
        try:
            vendored = vendored_tree(adopter_dir, edge["party"], str(edge["version"]))
        except Refused as e:
            missing.append(f"{edge['party']}/{edge['kind']}@{edge['version']}: {e}")
            continue
        if vendored is not None:
            parent_trees[edge["party"]] = vendored
            if edge["party"] not in from_vendor:
                from_vendor.append(edge["party"])
    for edge in edges:
        party, kind, version = edge["party"], edge["kind"], edge["version"]
        tree = parent_trees.get(party)
        if tree is None or not Path(tree).is_dir():
            missing.append(f"{party}/{kind}@{version}: no parent tree provided")
            continue
        try:
            sha = resolve_sha(party, kind, version, adopter_dir, Path(tree), edge.get("name"))
        except Refused as e:
            missing.append(f"{party}/{kind}@{version}: {e}")
            continue
        # Ticket 77 item 1. The pin resolves; does the tree it names CARRY what this pin is
        # used for? Until now nothing asked, so a pin could resolve to a tag whose tree could
        # not have produced the number priced from it -- which is exactly how the insurer came
        # to attribute three quotes to `exposure v1.1.0`, a tag with no exposure section in it.
        # A self-pin is exempt: its tree IS the tree under composition (above), so there is no
        # other tree for the content to be missing from.
        if party != adopter_party:
            lacks = pin_content.refusal_for_pin(str(tree), party, kind, edge.get("name"), version)
            if lacks:
                missing.append(f"{party}/{kind}@{version}: {lacks}")
                continue
        parent = {"party": party, "kind": kind, "version": version, "sha": sha}
        if kind == "feed":
            parent = {"party": party, "kind": kind, "name": edge["name"], "version": version, "sha": sha}
        parents.append(parent)
    if missing:
        return _refused(missing), {}

    refusals: list[dict] = check_diamonds(edges)

    # Merge every implementations parent's members into one set, keyed on
    # (version, family, name). Two sources supplying the same key with
    # different content is refused -- never merged, never last-wins
    # (spec.md, Resolution) -- and dropped from the composed set entirely,
    # because there is no principled way to pick one.
    merged: dict[tuple[str, str, str], dict] = {}
    conflicting_keys: set[tuple[str, str, str]] = set()
    implementations_parties: set[str] = set()
    guards: list[dict] = []
    # (source href, control_id, claimed policy name, claiming party) -- every
    # OSCAL control claim composition can see: each implementations parent's
    # own (ADR-0017: a claim belongs to whoever ships the implementation),
    # plus the adopter's own, gathered below the loop. The href is what keys
    # the claim to a catalogue (ticket 38: every claim is a (source, id)).
    claims: list[tuple[str | None, str, str, str]] = []

    for edge in edges:
        if edge["kind"] != "implementations":
            continue
        impl_party, impl_version = edge["party"], edge["version"]
        implementations_parties.add(impl_party)
        impl_sha = next(p["sha"] for p in parents
                         if p["party"] == impl_party and p["kind"] == "implementations")
        impl_root = Path(parent_trees[impl_party])
        members_by_version, this_guards = load_implementations(impl_root)
        source_ref = f"{impl_party}@{impl_version}"

        for href, control_id, policy_name in _load_claims(impl_root.joinpath(*PARENT_CLAIMS_PATH)):
            claims.append((href, control_id, policy_name, impl_party))

        for version, members in sorted(members_by_version.items()):
            for (family, base), meta in sorted(members.items()):
                key = (version, family, base)
                prior = merged.get(key)
                if prior is not None and prior["doc"] != meta["doc"]:
                    refusals.append({
                        "kind": "rule-conflict",
                        "subject": f"{family}/{base}@{version}",
                        "detail": (
                            f"{prior['source_ref']} and {source_ref} both supply "
                            f"{family}/{base}@{version} with different content -- "
                            f"{prior['source_ref']}: {json.dumps(prior['doc'], sort_keys=True)} "
                            f"vs {source_ref}: {json.dumps(meta['doc'], sort_keys=True)}"
                        ),
                        "needs_composition": True,
                    })
                    conflicting_keys.add(key)
                    merged.pop(key, None)
                    continue
                if key in conflicting_keys:
                    continue
                merged[key] = dict(meta, source_party=impl_party, source_sha=impl_sha,
                                    source_ref=source_ref)

        if not guards:
            guards = [dict(g, source_party=impl_party, source_sha=impl_sha,
                           source_ref=source_ref) for g in this_guards]

    # The adopter's own overlay members -- shipped by the adopter, not any
    # parent (ADR-0017). A key already supplied by a parent is left alone;
    # a genuinely new (version, family, name) is a new member, not a
    # restatement (ADR-0016's own consequence: "It is a new member, not a
    # restatement").
    for key, meta in load_overlay_add(party_doc).items():
        merged.setdefault(key, dict(meta, source_party=adopter_party, source_sha=None,
                                     source_ref=f"{adopter_party} (overlay)"))

    # The adopter's own control claims -- next to the party artefact it
    # signs (ADR-0017), never mixed with a parent's.
    for href, control_id, policy_name in _load_claims(adopter_dir / ADOPTER_CLAIMS_FILE):
        claims.append((href, control_id, policy_name, adopter_party))

    limits = [{
        "name": "two-publisher-conflict",
        "detail": "the cross-party rule-conflict path above is only exercised in the real "
                   "estate once a second implementations publisher is pinned",
        "count": len(implementations_parties),
        "status": "closed" if len(implementations_parties) >= 2 else "open",
    }]
    limits.append(_pin_containment_limit(parents, parent_trees, merged))
    feed_edges = [e for e in edges if e["kind"] in FEED_KINDS and e["party"] != adopter_party]
    limits.append({
        "name": VENDORED_LIMIT,
        "detail": ("priced from the adopter's own vendored copy because the publisher's clone "
                    "was not there to read: " + ", ".join(from_vendor)) if from_vendor else
                   "every priced feed was read from its publisher's own pinned tree",
        "count": len(from_vendor),
        "checked": len(feed_edges),
        "status": "open" if from_vendor else "closed",
    })

    restatements, restate_refusals, cages = apply_restatements(party_doc, merged, parents, adopter_dir,
                                                                parent_trees)
    refusals += restate_refusals

    # -----------------------------------------------------------------
    # ticket 14: baseline coverage, control claims and holes
    # -----------------------------------------------------------------

    policy_owner: dict[str, str] = {}
    for (_version, _family, base), meta in merged.items():
        policy_owner.setdefault(base, meta["source_party"])
    for g in guards:
        policy_owner.setdefault(g["member_name"], g["source_party"])

    # Every controls parent's catalogue, keyed on the party that publishes
    # it (ticket 38: a control key is (source, id), and an adopter's own
    # bespoke catalogue is a controls parent like any other). The BASELINE's
    # catalogue is the first controls parent that is not the adopter itself
    # -- the regulator's, ADR-0013's one authority for a bare id.
    controls_edges = [e for e in edges if e["kind"] == "controls"]
    controls_edge = next((e for e in controls_edges if e["party"] != adopter_party), None)
    catalogs: dict[str, set[str]] = {}
    catalog_props: dict[str, dict[str, dict[str, str]]] = {}
    for e in controls_edges:
        controls = _catalog_controls(Path(parent_trees[e["party"]]))
        catalog_props[e["party"]] = controls
        catalogs[e["party"]] = set(controls)
    nist_root: Path | None = None
    baseline_source: str | None = controls_edge["party"] if controls_edge else None
    baseline_ids: set[str] = set()
    baseline_name = party_doc["baseline"]
    if controls_edge is None:
        refusals.append({
            "kind": "no-controls-parent", "subject": adopter_party,
            "detail": f"{adopter_party} declares no controls parent, so its selected "
                      f"baseline {baseline_name!r} cannot be resolved against a catalogue",
            "needs_composition": True,
        })
    else:
        nist_root = Path(parent_trees[controls_edge["party"]])
        resolved = _baseline_ids(nist_root, baseline_name)
        if resolved is None:
            refusals.append({
                "kind": "missing-baseline-file", "subject": baseline_name,
                "detail": f"{controls_edge['party']} publishes no baseline named "
                          f"{baseline_name!r}",
                "needs_composition": False,
            })
        else:
            baseline_ids = resolved

    added_specs = [(str(spec), _control_spec(str(spec), baseline_source))
                   for spec in party_doc.get("overlay", {}).get("controls", []) or []]
    refusals += _unknown_control_refusals(added_specs, catalogs, f"{adopter_party} overlay.controls")
    selected_set: set[ControlKey] = {(str(baseline_source), cid) for cid in baseline_ids}
    selected_set |= {key for _spelled, key in added_specs if key[1] in catalogs.get(key[0], set())}

    covered, claim_refusals = resolve_claims(claims, policy_owner, catalogs, baseline_source)
    refusals += claim_refusals

    prev_header = _previous_header(adopter_dir)
    prev_source = _header_controls_source(prev_header, adopter_party) or baseline_source
    prev_holes = ({_decode_control(h, prev_source) for h in prev_header.get("holes", [])}
                  if prev_header is not None else None)
    prev_selected = ({_decode_control(c, prev_source) for c in prev_header.get("selected-controls", [])}
                     if prev_header is not None else None)
    prev_baseline_name = prev_header.get("baseline") if prev_header is not None else None
    prev_baseline_ids = (
        _baseline_ids(nist_root, prev_baseline_name)
        if prev_header is not None and nist_root is not None and prev_baseline_name
        else None
    )
    prev_ungoverned_ids = (
        set(prev_header.get("ungoverned-namespaces", [])) if prev_header is not None else None
    )

    hole_entries = compute_holes(selected_set, covered, prev_holes)
    refusals += check_selected_set(selected_set, prev_selected, baseline_source)

    # -----------------------------------------------------------------
    # ticket 15: the governed namespace lint (priced, not refused: ticket 38)
    # -----------------------------------------------------------------
    ungoverned_entries = compute_ungoverned(set(ungoverned_namespaces(adopter_dir)), prev_ungoverned_ids)

    # -----------------------------------------------------------------
    # ticket 16: pricing and threat parents re-price, and never apply
    # -----------------------------------------------------------------
    # The adopter's own signed facts: its appetite band, its reporting currency
    # and its tighten-only cage floor. No fixture prices a party (ticket 25).
    band = None
    try:
        band = _appetite(adopter_party, adopter_dir, parent_trees)
        prices = compute_prices(
            edges, adopter_party, band["amount"], parent_trees, prev_header,
            adopter_dir=adopter_dir, perspective_doc=party_doc,
            band_currency=band.get("currency"),
            floor=(party_doc.get("overlay", {}) or {}).get("floor"),
            prev_prices=_previous_prices(adopter_dir))
    except Refused as e:
        # ADR-0020: a missing instrument (no appetite band, no price for a
        # declared regime, no FX rate for the date) refuses and NAMES what is
        # missing -- never a crash, never a silently skipped price, and never
        # a number the gate could not actually read.
        prices = []
        refusals.append({"kind": "missing-instrument", "subject": adopter_party,
                         "detail": str(e), "needs_composition": True})

    # -----------------------------------------------------------------
    # ticket 38: a hole is priced, not counted
    # -----------------------------------------------------------------
    reporting = _reporting_currency(party_doc)
    # What this party is on the hook for, signed under its own tag beside the
    # cage it bought (ticket 36; ticket 14 answer 2). Computed here because
    # its total is also the base an ungoverned namespace takes its share of.
    exposure = exposure_section(prices, adopter_party, band, reporting)
    price_ungoverned(ungoverned_entries, adopter_dir, adopter_party, reporting,
                     exposure["total"] if exposure else None,
                     _composition_as_of(edges, parent_trees))
    hole_prices = _regime_hole_prices(prices)
    _price_holes(hole_entries, hole_prices, adopter_party, reporting)
    refusals += _price_bespoke_holes(hole_entries, adopter_party, adopter_dir,
                                     catalog_props.get(adopter_party, {}), band, reporting,
                                     (party_doc.get("overlay", {}) or {}).get("floor"))
    _decorate_regime_holes(prices, hole_entries, selected_set, covered)
    deltas = compute_deltas(
        hole_entries, ungoverned_entries,
        baseline_widening_delta(baseline_ids, prev_baseline_ids, prev_baseline_name, baseline_name,
                                baseline_source, hole_prices, adopter_party, reporting),
        adopter_party, reporting)
    # Ticket 69: a premium pin that opened or closed as an untagged-pin hole.
    deltas += untagged_pin_deltas(prices, adopter_party, reporting)

    members_evidence: list[dict] = []
    rendered: dict[str, str] = {}

    # Eco-system ticket 45: the adopter's own copy of every payload it was
    # priced from and the converter that priced it, rendered into the composed
    # tree so the adopter's OWN tag signs it. Nothing in composed/ reads it and
    # no Flux Kustomization points at composed/feeds/ (the adopter's
    # ResourceSet ranges composed/policies/v<version> only); it is there so a
    # reader with this repository and nothing else can re-derive these prices.
    vendored_records: list[dict] = []
    for edge in feed_edges:
        base = vendored_rel(edge["party"], str(edge["version"]))
        if any(r["path"] == base for r in vendored_records):
            # Two feeds from one party at one version would land on one another
            # in `composed/feeds/<party>/<version>/`. Refuse rather than
            # overwrite: a silently clobbered payload re-derives the wrong price
            # and looks fine doing it.
            refusals.append({"kind": "missing-instrument", "subject": edge["party"],
                              "detail": f"missing instrument: two feed edges of {edge['party']} "
                                        f"at {edge['version']} both vendor to {base}, and one "
                                        f"would overwrite the other",
                              "needs_composition": True})
            continue
        try:
            _, files, record = vendor_feed(
                edge, parent_trees[edge["party"]],
                next(p["sha"] for p in parents if p["party"] == edge["party"]
                      and p.get("name") == edge.get("name")))
        except Refused as e:
            refusals.append({"kind": "missing-instrument", "subject": edge["party"],
                              "detail": str(e), "needs_composition": True})
            continue
        for rel, content in files.items():
            rendered[f"{base}/{rel}"] = content
        vendored_records.append({**record, "path": base})

    for (version, family, base), meta in sorted(merged.items()):
        doc = render_member(meta["doc"], meta["action"], adopter_party, meta["source_ref"], meta["path"])
        # The member's own identity, not its source path's basename -- an
        # overlay.add member has no real on-disk file to name (ticket 14).
        # Equivalent for every parent-sourced member today: each is shipped
        # at exactly "<base>.yaml".
        filename = f"{base}.yaml"
        out_path = f"composed/policies/v{version}/{filename}"
        rendered[out_path] = yaml.safe_dump(doc, **YAML_KWARGS)
        members_evidence.append({
            "family": family, "name": base, "kind": meta["kind"], "version": version,
            "source_party": meta["source_party"], "source_sha": meta["source_sha"],
            "action": meta["action"],
        })

    for g in guards:
        guard_doc = render_member(g["doc"], None, adopter_party, g["source_ref"], g["path"])
        rendered[g["out_path"]] = yaml.safe_dump(guard_doc, **YAML_KWARGS)
        members_evidence.append({
            "family": "platform-machinery", "name": g["member_name"],
            "kind": g["kind"], "version": None,
            "source_party": g["source_party"], "source_sha": g["source_sha"], "action": None,
        })

    # The recorded hole ids -- open (new + recorded), never closed ones --
    # are what the NEXT run's compute_holes() compares against. A closed
    # hole drops out of the recorded set: if it becomes a hole again later
    # it is "new" again, not "recorded" (spec.md names no reopened case).
    recorded_hole_ids = sorted(_encode_control((e["source"], e["control_id"]), baseline_source)
                               for e in hole_entries if e["status"] != "closed")
    # Same shape: the recorded (open) set the NEXT run compares against.
    # A closed namespace drops out -- if it goes ungoverned again later it
    # is "new" again, not "recorded" (compute_ungoverned names no reopened
    # case, matching compute_holes).
    recorded_ungoverned = sorted(e["namespace"] for e in ungoverned_entries if e["status"] != "closed")

    header = {
        "policy-as-versioned.dev/composed": True,
        "parents": parents,
        "baseline": baseline_name,
        "governed-namespaces": governed_namespaces(adopter_dir),
        "holes": recorded_hole_ids,
        "selected-controls": sorted(_encode_control(k, baseline_source) for k in selected_set),
        "ungoverned-namespaces": recorded_ungoverned,
    }
    # Which versioned rule picked the tier (ADR-0021). Recorded only where the
    # adopter actually ships a selection-policy package -- a null key on an
    # adopter that ships none would be noise in a rendered, Flux-applied file.
    # Which feed payloads and converters this artefact carries its own copy of,
    # and what they digest to (ticket 45). On the header, so the adopter's own
    # tag signs the digests: a vendored copy nobody signed is not an instrument,
    # it is a file.
    if vendored_records:
        header["vendored-feeds"] = [
            {"party": r["party"], "name": r["name"], "version": r["version"],
             "path": r["path"], "sha": r["sha"], "files": r["files"]}
            for r in vendored_records]
    selection_policy = _selection_policy_version(adopter_dir)
    if selection_policy is not None:
        header["selection-policy"] = selection_policy
    # The exposure lands on the RENDERED header, not only in the evidence
    # document, so `composition.py verify` re-derives it byte for byte from
    # the same parents: an exposure an insurer prices a layer against is a
    # fact a verifier can re-compute, not a summary written once. Absent --
    # never zero -- where nothing priced.
    if exposure is not None:
        header["exposure"] = exposure
    rendered["composed/HEADER.yaml"] = HEADER_COMMENT + yaml.safe_dump(header, **YAML_KWARGS)

    document = {
        "outcome": "refused" if refusals else "composed",
        "party_artefact_errors": [],
        "parents": parents,
        "members": members_evidence,
        "refusals": refusals,
        "restatements": restatements,
        "cages": cages,
        "holes": hole_entries,
        "ungoverned": ungoverned_entries,
        "prices": prices,
        "deltas": deltas,
        "limits": limits,
        "vendored": vendored_records,
    }
    return document, rendered


def verify(adopter_dir: Path, parent_trees: dict[str, Path]) -> tuple[bool, list[str]]:
    """Re-renders from a fresh resolution of the same parent trees and
    compares byte-for-byte against whatever is already committed under
    `adopter_dir`. A verifier runs this with parent_trees checked out at the
    exact SHAs the committed HEADER.yaml records (that checkout is the
    verifier's job, not this function's)."""
    adopter_dir = Path(adopter_dir)
    document, rendered = compose(adopter_dir, parent_trees)
    if document["outcome"] != "composed":
        return False, [f"re-composition refused: {document['party_artefact_errors']} "
                        f"{document.get('refusals', [])}"]
    mismatches: list[str] = []
    for rel_path, content in rendered.items():
        committed = adopter_dir / rel_path
        if not committed.exists():
            mismatches.append(f"{rel_path}: not committed on disk")
        elif committed.read_text() != content:
            mismatches.append(f"{rel_path}: committed content differs from the re-render")
    composed_dir = adopter_dir / "composed"
    if composed_dir.is_dir():
        for path in composed_dir.rglob("*.yaml"):
            rel = str(path.relative_to(adopter_dir))
            if rel not in rendered:
                mismatches.append(f"{rel}: committed but no longer produced by a re-render")
    return (not mismatches), mismatches


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _default_parent_trees(party_doc: dict, estate_clone: Path) -> dict[str, Path]:
    names = {edge["party"] for edge in (party_doc.get("inherits", []) or [])}
    return {name: estate_clone / name for name in names}


def cmd_compose(adopter_dir: Path, estate_clone: Path, out_dir: Path | None) -> int:
    party_yaml = adopter_dir / "party.yaml"
    party_doc = yaml.safe_load(party_yaml.read_text()) if party_yaml.exists() else {}
    parent_trees = _default_parent_trees(party_doc, estate_clone)
    document, rendered = compose(adopter_dir, parent_trees)
    print(json.dumps(document, indent=2))
    if document["outcome"] == "composed":
        out_dir = out_dir or adopter_dir
        for rel_path, content in rendered.items():
            target = out_dir / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        (out_dir / "composed" / "evidence.json").write_text(json.dumps(document, indent=2))
        return 0
    return 1


def cmd_verify(adopter_dir: Path, estate_clone: Path) -> int:
    party_yaml = adopter_dir / "party.yaml"
    if not party_yaml.exists():
        print(f"REFUSED: {party_yaml} does not exist", file=sys.stderr)
        return 1
    party_doc = yaml.safe_load(party_yaml.read_text())
    parent_trees = _default_parent_trees(party_doc, estate_clone)
    ok, mismatches = verify(adopter_dir, parent_trees)
    if ok:
        print("OK: composed artefact re-renders byte-for-byte from the recorded parent SHAs")
        return 0
    for m in mismatches:
        print(f"MISMATCH: {m}", file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        # composition.py ships inside platform's own repo, so `platform` is
        # always present here -- what can genuinely be missing is the rest
        # of the estate this module composes AGAINST (driftwood, nist, ico, feeds),
        # which only exists once clone-estate.sh has run.
        missing = [name for name in ("driftwood", "nist", "ico", "feeds")
                   if not (DEFAULT_ESTATE_CLONE / name).is_dir()]
        if missing:
            print(f"SKIP: .estate-clone/{{{','.join(missing)}}} absent. Run ./clone-estate.sh first.")
            return 0
        selfcheck()
        return 0

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("compose", "verify"):
        c = sub.add_parser(name)
        c.add_argument("adopter_dir", type=Path)
        c.add_argument("--estate-clone", type=Path, default=DEFAULT_ESTATE_CLONE)
        if name == "compose":
            c.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv[1:])

    if args.cmd == "compose":
        return cmd_compose(args.adopter_dir, args.estate_clone, args.out)
    if args.cmd == "verify":
        return cmd_verify(args.adopter_dir, args.estate_clone)
    return 2


# --------------------------------------------------------------------------
# selfcheck -- every acceptance criterion, against real files on disk
# --------------------------------------------------------------------------


def _real_parent_trees() -> dict[str, Path]:
    # `insurer` joined the list with ticket 36: driftwood pins its signed quote
    # feed, and a parent with no tree is a party_artefact error, not a price.
    return {name: DEFAULT_ESTATE_CLONE / name
            for name in ("platform", "nist", "ico", "feeds", "insurer")}


def _adopter_copy(name: str, dest: Path) -> Path:
    """Copy a real adopter's committed tree (party.yaml + gitops/) into a
    scratch directory, so a fixture can edit party.yaml's overlay without
    touching the real repo, and without re-deriving party_artefact.check()'s
    own checks against real pin files and the real baseline mirror."""
    src = DEFAULT_ESTATE_CLONE / name
    work = dest / name
    work.mkdir(parents=True)
    (work / "party.yaml").write_text((src / "party.yaml").read_text())
    shutil.copytree(src / "gitops", work / "gitops")
    # The release workflow travels too: party_artefact.check() reads it to
    # decide whether a party that declares publishes[] can actually publish
    # (ADR-0019 point 5 -- the tag signs). driftwood declares one since its
    # twin started emitting forward-intel. `twin/` deliberately does NOT
    # travel: a fixture adopter with no forward-intel feed is exactly how this
    # selfcheck proves a missing twin feed is silence, not a refusal.
    if (src / ".github").is_dir():
        shutil.copytree(src / ".github", work / ".github")
    return work


def _insurer_copy(dest: Path, *, git: bool) -> Path:
    """Ticket 69's could-not-look fixtures: the real insurer's party.yaml and
    quote/ tree in a scratch directory with NO tag -- `git init` and nothing
    else when `git`, which is the shape a CI checkout without `fetch-tags`
    has; no git metadata at all otherwise. Both read `unobserved`: a checkout
    that cannot show the publisher's tags cannot call a pin untagged. No
    fixture here ever claims a signature."""
    src = DEFAULT_ESTATE_CLONE / "insurer"
    dest.mkdir(parents=True)
    (dest / "party.yaml").write_text((src / "party.yaml").read_text())
    shutil.copytree(src / "quote", dest / "quote")
    if git:
        subprocess.run(["git", "init", "-q", str(dest)], check=True)
    return dest


def _insurer_clone(dest: Path) -> Path:
    """Ticket 69's untagged fixture, half one: a real `git clone` of the
    insurer, so the publisher's OWN tags travel -- its real annotated v1.0.0
    and nothing invented. A checkout like this one is the only kind that can
    honestly say a pin is untagged."""
    subprocess.run(["git", "clone", "-q", str(DEFAULT_ESTATE_CLONE / "insurer"), str(dest)],
                   check=True, capture_output=True)
    return dest


def _quote_at_untagged_major(tree: Path, adopter: str, major: str) -> None:
    """Ticket 69's untagged fixture, half two: the quote the insurer already
    publishes, copied to a MAJOR it has never tagged, so the pin below points
    at a real quote file no tag of the publisher's signs. No tag is created,
    deleted, renamed or edited here: the tag namespace stays exactly the
    publisher's own."""
    src = tree / "quote" / adopter / "v1"
    dest = tree / "quote" / adopter / major
    shutil.copytree(src, dest)
    doc = json.loads((dest / "feed.json").read_text())
    doc["version"] = f"{major.lstrip('v')}.0.0"
    (dest / "feed.json").write_text(json.dumps(doc, indent=2) + "\n")


def _bump_feed_pin(work: Path, party: str, name: str, version: str) -> None:
    """Move ONE adopter feed pin, the edit a Renovate PR would make."""
    doc = yaml.safe_load((work / "party.yaml").read_text())
    for edge in doc["inherits"]:
        if edge.get("kind") == "feed" and edge.get("party") == party and edge.get("name") == name:
            edge["version"] = version
    (work / "party.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _flatten_tag(tree: Path, tag: str) -> None:
    """Overwrite `refs/tags/<tag>` onto the commit it resolves to -- exactly
    what `actions/checkout`'s second fetch does to an annotated tag object,
    and why release.yml re-fetches the real ref before verifying it. The tag
    name and the commit stay the publisher's own; only the object the local
    ref points at changes, which is the whole point of the fixture."""
    commit = subprocess.run(["git", "-C", str(tree), "rev-parse", f"{tag}^{{commit}}"],
                            check=True, capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "-C", str(tree), "update-ref", f"refs/tags/{tag}", commit],
                   check=True, capture_output=True)


def _tag_shape_repo(dest: Path, *, tag: str | None, annotated: bool, flatten: bool = False) -> Path:
    """A throwaway repo of this fixture's own -- no publisher's name on it --
    carrying one commit and at most one tag, to read the SHAPES a checkout can
    present back: no tag, a lightweight tag, an annotated tag, and an
    annotated tag flattened onto its commit the way `actions/checkout`'s
    second fetch flattens one (release.yml re-fetches the ref for exactly this
    reason). Nothing here is signed and nothing claims to be."""
    dest.mkdir(parents=True)
    git = ["git", "-C", str(dest), "-c", "user.name=fixture", "-c", "user.email=fixture@invalid",
           "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
    subprocess.run(["git", "init", "-q", str(dest)], check=True)
    subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "fixture"], check=True,
                   capture_output=True)
    if tag:
        subprocess.run(git + (["tag", "-a", tag, "-m", tag] if annotated else ["tag", tag]),
                       check=True, capture_output=True)
        if flatten:
            _flatten_tag(dest, tag)
    return dest


def _with_restate(work: Path, restate: list[dict]) -> None:
    doc = yaml.safe_load((work / "party.yaml").read_text())
    doc["overlay"]["restate"] = restate
    (work / "party.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _bump_parent_version(work: Path, party: str, kind: str, version: str) -> None:
    """Ticket 16's own fixture primitive: edit ONE declared edge's pinned
    version in place, leaving every other edge untouched -- the "a pricing
    or threat parent bumps" scenario, the same edit a real Renovate PR
    would make to `party.yaml`."""
    doc = yaml.safe_load((work / "party.yaml").read_text())
    for edge in doc["inherits"]:
        if _parent_key(edge) == _parent_key({"kind": kind}):
            edge["version"] = version
    (work / "party.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _write_baseline_configmap(work: Path, baseline: str) -> None:
    (work / "gitops" / "apps").mkdir(parents=True, exist_ok=True)
    doc = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": "x-nist-pin", "namespace": "x"},
           "data": {"baselineName": baseline}}
    (work / "gitops" / "apps" / "nist-pin-configmap.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


# ---- ticket 14 fixtures: a small, CLEAN synthetic estate (no dangling
# claims of its own), used wherever a test needs an outcome that can
# actually reach "composed" -- the real estate cannot today, because
# platform's own two dangling claims (ticket 10's named, still-open defect)
# refuse every real composition regardless of holes. ----

KNOWN_DANGLING_PLATFORM_CLAIMS = 0  # ac-6/cm-6 fixed: ac-6's stale duplicate dropped,
# cm-6 now claims governed-namespace-requires-claim (ADR-0014's fifth gap, built for real).


def _assert_only_known_dangling(refusals: list[dict], context: str) -> None:
    """Every real driftwood/tuppence/ludlow composition carries zero
    refusals -- platform's two formerly-dangling claims (ticket 10 named
    them) are now fixed, and this proves composition adds no OTHER refusal
    for a party artefact that otherwise checks out."""
    others = [r for r in refusals if r["kind"] != "dangling-claim"]
    assert not others, (context, others)
    assert len(refusals) == KNOWN_DANGLING_PLATFORM_CLAIMS, (context, refusals)


def _write_fixture_catalog(nist_root: Path) -> None:
    """aa-1 (with a nested enhancement aa-1.1), aa-2, aa-3, bb-1. Three
    named baselines: SMALL={aa-1,aa-1.1,aa-2}, BIG=SMALL plus aa-3 (a
    strict superset, for the widening refusal), TINY={aa-1} (a strict
    subset, for the removed-control refusal)."""
    catalog_dir = nist_root / "catalog"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    catalog_doc = {"catalog": {"uuid": "f" * 8, "groups": [{"id": "fam", "controls": [
        {"id": "aa-1", "controls": [{"id": "aa-1.1"}]},
        {"id": "aa-2"}, {"id": "aa-3"}, {"id": "bb-1"},
    ]}]}}
    (catalog_dir / "catalog.json").write_text(json.dumps(catalog_doc))
    (catalog_dir / "CATALOG_VERSION.json").write_text(json.dumps({"file": "catalog.json"}))

    def profile(ids):
        return {"profile": {"imports": [{"href": "catalog.json",
                 "include-controls": [{"with-ids": ids}]}]}}

    (catalog_dir / "small.json").write_text(json.dumps(profile(["aa-1", "aa-1.1", "aa-2"])))
    (catalog_dir / "big.json").write_text(json.dumps(profile(["aa-1", "aa-1.1", "aa-2", "aa-3"])))
    (catalog_dir / "tiny.json").write_text(json.dumps(profile(["aa-1"])))
    (catalog_dir / "BASELINE_VERSIONS.json").write_text(json.dumps({"baselines": {
        "SMALL": {"file": "small.json"}, "BIG": {"file": "big.json"}, "TINY": {"file": "tiny.json"},
    }}))


def _write_fixture_platform(root: Path, real_platform: Path, claims: list[tuple[str, str]]) -> None:
    """One clean ValidatingPolicy member, "member-a", plus whatever
    (control_id, policy_name) claims the caller wants in its own
    component-definition.json -- deliberately separate from the real
    platform's own two dangling claims, so a hole/claim test here isn't
    muddied by an unrelated, already-covered defect."""
    _write_versions_yaml(root, [{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "e" * 40}])
    shutil.copy(real_platform / "distribution" / "render-orphan-guard.py",
                root / "distribution" / "render-orphan-guard.py")
    shutil.copy(real_platform / "distribution" / "render-governed-namespace-guard.py",
                root / "distribution" / "render-governed-namespace-guard.py")
    _write_admission_doc(root / "distribution" / "policies" / "v1.0.0" / "member-a.yaml",
                          "ValidatingPolicy", "member-a-1-0-0", "fam-a", "1.0.0",
                          validation_actions=["Audit"])
    _write_component_definition(root / "oscal" / "component-definition.json", claims)


def _write_component_definition(path: Path, claims: list[tuple[str, str]],
                                source: str = "../fixture-nist/catalog/catalog.json") -> None:
    """`source` is the enclosing block's href naming the catalogue the bare
    ids belong to (ADR-0013) -- the fixture regulator's by default."""
    path.parent.mkdir(parents=True, exist_ok=True)
    comp_def = {"component-definition": {"components": [{"control-implementations": [{
        "source": source,
        "implemented-requirements": [
            {"control-id": control_id, "props": [{"name": "Check_Id", "value": policy_name}]}
            for control_id, policy_name in claims
        ],
    }]}]}}
    path.write_text(json.dumps(comp_def))


def _write_small_catalog(root: Path, controls: dict[str, dict[str, str]]) -> None:
    """A minimal OSCAL catalogue under `<root>/catalog/`: flat controls, each
    with the props given (a bespoke control names its `scenario` there). The
    shape a second controls parent -- or an adopter pinning itself -- ships."""
    catalog_dir = Path(root) / "catalog"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    doc = {"catalog": {"uuid": "b" * 8, "groups": [{"id": "bespoke", "controls": [
        {"id": cid, "props": [{"name": k, "value": v} for k, v in props.items()]}
        for cid, props in controls.items()
    ]}]}}
    (catalog_dir / "catalog.json").write_text(json.dumps(doc))
    (catalog_dir / "CATALOG_VERSION.json").write_text(json.dumps({"file": "catalog.json"}))


def _write_workload(work: Path, namespace: str, name: str) -> None:
    """One Deployment manifest in `namespace` -- what the ungoverned share
    counts (ticket 38)."""
    doc = {"apiVersion": "apps/v1", "kind": "Deployment",
           "metadata": {"name": name, "namespace": namespace}, "spec": {}}
    (work / "gitops" / "apps").mkdir(parents=True, exist_ok=True)
    (work / "gitops" / "apps" / f"workload-{namespace}-{name}.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _hole(document: dict, control_id: str) -> dict:
    return next(h for h in document["holes"] if h["control_id"] == control_id)


def _write_fixture_ico(root: Path, real_ico: Path) -> None:
    """A fixture `ico` parent tree: the real converter script (`schema/
    to_fair_scenario.py`, copied unchanged -- same fixture convention
    `_write_fixture_platform` already uses for `render-orphan-guard.py`)
    against two fixture `schema/v{1,2}/penalty-schema.json` bands. Ticket
    16's crossing case needs an appetite band the bump actually crosses,
    and no real band anywhere in the estate straddles one on either real
    bump (spec.md's own Testing Decisions: the pricing call itself is not
    a sanctioned seam to assert on directly) -- so the LM band moves here,
    in a fixture parent tree, and the crossing is proved through
    `compose()` against a real adopter's real GBP tolerance, the only
    sanctioned seam."""
    def band(version: str, lo: float, hi: float) -> None:
        doc = {
            "schema_version": version, "published_by": "fixture-ico",
            "regimes": {ICO_REGIME: {
                "authority": "fixture", "statute": "fixture", "currency": "GBP",
                "violation_types": {ICO_VIOLATION_TYPE: {
                    "formula": {"type": "per_violation_tier", "min_gbp": lo, "max_gbp": hi},
                }},
            }},
        }
        d = root / "schema" / version
        d.mkdir(parents=True, exist_ok=True)
        (d / "penalty-schema.json").write_text(json.dumps(doc))

    (root / "schema").mkdir(parents=True, exist_ok=True)
    shutil.copy(real_ico / "schema" / "to_fair_scenario.py", root / "schema" / "to_fair_scenario.py")
    band("v1", 100_000, 400_000)  # ALE ~GBP541k -> quarantine residual ~GBP43.3k: over driftwood's GBP40k -> deny
    band("v2", 50_000, 250_000)   # ALE ~GBP324k -> quarantine residual ~GBP26.0k: under driftwood's GBP40k -> quarantine


def _write_fixture_adopter(work: Path, baseline: str, controls_add: list[str] | None = None,
                            add: list[dict] | None = None, own_claims: list[tuple[str, str]] | None = None,
                            nist_party: str = "fixture-nist", impl_party: str = "fixture-platform",
                            extra_inherits: list[dict] | None = None) -> None:
    party_doc = {
        "party": "fixture-adopter14", "roles": ["adopter"], "baseline": baseline,
        # A synthetic party is still a party: it signs its own appetite band
        # and its own reporting currency, because a party that declares
        # neither is a missing instrument and refuses (ADR-0020, ticket 25).
        "reporting_currency": "GBP",
        "appetite": {"tolerance": {"amount": 40000, "currency": "GBP"}},
        "inherits": [
            {"party": nist_party, "kind": "controls", "version": "1.0.0"},
            {"party": impl_party, "kind": "implementations", "version": "1.0.0"},
            *(extra_inherits or []),
        ],
        "overlay": {"add": add or [], "restate": [], "controls": controls_add or []},
    }
    work.mkdir(parents=True, exist_ok=True)
    (work / "party.yaml").write_text(yaml.safe_dump(party_doc, sort_keys=False))
    _write_baseline_configmap(work, baseline)
    if own_claims:
        _write_component_definition(work / ADOPTER_CLAIMS_FILE, own_claims)


def _write_namespace(work: Path, name: str, *, institution: bool = True, governed: bool = False) -> None:
    """A `Namespace` manifest with only the labels the caller asks for --
    ticket 15's own fixture primitive, mirroring the real
    `<adopter>/gitops/apps/namespace.yaml` shape but named per-namespace so
    a test can add several under one adopter tree."""
    labels: dict[str, str] = {}
    if institution:
        labels[INSTITUTION_LABEL] = name
    if governed:
        labels[GOVERNED_LABEL] = "true"
    doc = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}}
    (work / "gitops" / "apps").mkdir(parents=True, exist_ok=True)
    (work / "gitops" / "apps" / f"namespace-{name}.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _commit_header(work: Path, rendered: dict[str, str]) -> None:
    """What `cmd_compose` does for HEADER.yaml alone -- write the just-
    composed header so the NEXT compose() call in the same test reads it
    back as `_previous_header`."""
    (work / "composed").mkdir(exist_ok=True)
    (work / "composed" / "HEADER.yaml").write_text(rendered["composed/HEADER.yaml"])


def selfcheck() -> None:
    driftwood = DEFAULT_ESTATE_CLONE / "driftwood"
    parent_trees = _real_parent_trees()
    # The restatement cases below need a version that is actually DECLARED, and
    # they used to name "2.0.0" as a literal. On 2026-08-29 2.0.0, 2.0.1 and
    # 3.0.0 were retired from distribution/versions.yaml (they could not admit a
    # pod), the literal named a version composition no longer loads, and every
    # restatement silently matched nothing -- the refusal cases stopped
    # refusing. Read the oldest LIVE version from the same array composition
    # itself reads, so a retirement can never make these cases vacuous again.
    live_v = _version_array(PLATFORM_DIR)[0]["version"]

    document, rendered = compose(driftwood, parent_trees)
    assert document["party_artefact_errors"] == []
    # ticket 14 found the real platform component-definition carrying two
    # claims against a policy that existed nowhere (ticket 10 named them).
    # Both are now fixed (ac-6's stale duplicate dropped; cm-6 claims the
    # real governed-namespace-requires-claim, ADR-0014's fifth gap, built)
    # -- so the real estate now COMPOSES cleanly on its first run.
    assert document["outcome"] == "composed", document
    _assert_only_known_dangling(document["refusals"], "real driftwood")
    print("OK compose(): the real driftwood composes against its real pinned parents; "
          "platform's two formerly-dangling claims are fixed, zero refusals")

    assert {"outcome", "parents", "members", "refusals", "restatements", "cages",
            "holes", "ungoverned", "prices", "deltas", "limits"} <= document.keys(), document.keys()
    print("OK document: carries outcome, parents[], members[], refusals[], restatements[], "
          "cages[], holes[], ungoverned[], prices[], deltas[], limits[]")

    # --- prices[] is populated on the real driftwood's first-ever composition
    # too, with nothing to compare a bump against yet (an honest "no move") ---
    feed_prices = [p for p in document["prices"] if p["kind"] == "feed"]
    assert len(feed_prices) == 2, feed_prices  # both declared feed parents
    assert {_parent_key(p) for p in feed_prices} == {"penalty-schema", "threat-register"}
    for p in feed_prices:
        assert p["old_version"] == p["new_version"], p  # nothing committed yet to bump against
        assert p["changed"] is False, p
    print("OK prices[]: computed on the real driftwood's very first composition too, with no "
          "prior signed artefact to compare a bump against -- old and new both price at this "
          "run's own pin, an honest 'no move'")

    # ======================================================================
    # ticket 25: THE ONE prices[] SCHEMA (ADR-0020, ADR-0021)
    # ======================================================================

    # --- every entry, whatever its source, carries the same six fields, and
    # the per-customer restatement is the entry's own amount over the
    # PERSPECTIVE party's own signed size.customers (null where it signs none) ---
    driftwood_doc = yaml.safe_load((driftwood / "party.yaml").read_text())
    customers = (driftwood_doc.get("size") or {}).get("customers")
    for entry in document["prices"]:
        assert set(entry) >= {"source", "kind", "perspective", "currency", "amount",
                              "per_customer"}, entry
        assert entry["perspective"] == "driftwood", entry
        assert entry["currency"] == _reporting_currency(driftwood_doc) == "GBP", entry
        assert entry["kind"] in PRICE_KINDS, entry
        if customers and entry["amount"] is not None:
            assert entry["per_customer"] == {"amount": entry["amount"] / customers,
                                              "currency": entry["currency"]}, entry
        else:
            # No signed customer count, or (ticket 45) a switching entry whose
            # counterfactual could not be priced: a restatement of a figure
            # nobody has is absent, never a zero.
            assert entry["per_customer"] is None, entry
    print("OK prices[]: every entry names its perspective, currency, source and kind, and "
          "restates its own amount per customer against driftwood's OWN signed size "
          "(%s customers)" % (customers if customers else "unsigned -> null"))

    # ======================================================================
    # ticket 36: the exposure section and the premium it buys
    # ======================================================================

    # --- the insurer's signed quote lands as ONE contract cost line, under the
    # ADOPTER's perspective, and its amount is the quote's own signed premium ---
    quote_path = feed_file("insurer", "quote-driftwood", "v1", DEFAULT_ESTATE_CLONE / "insurer")
    if quote_path.exists():
        quoted = json.loads(quote_path.read_text())["payload"]
        premiums = [e for e in document["prices"] if e["kind"] == "premium"]
        assert len(premiums) == 1, premiums
        premium = premiums[0]
        assert premium["source"] == "insurer" and premium["name"] == "quote-driftwood", premium
        assert premium["perspective"] == "driftwood", premium
        assert premium["amount"] == quoted["premium"]["amount"], (premium, quoted["premium"])
        assert quoted["premium"]["perspective"] == "driftwood", quoted["premium"]
        # The insurer's own layer arithmetic never crosses into this document.
        assert quoted["perspective"] == "insurer", quoted
        assert quoted["formula"]["layer"] not in [e["amount"] for e in document["prices"]]
        print("OK prices[]: the insurer's signed quote books as one `premium` cost line under "
              "driftwood's own perspective (%.2f %s), and the insurer's layer arithmetic stays "
              "under its own" % (premium["amount"], premium["currency"]))

        # A quote that insures somebody else, or books its premium on somebody
        # else's sheet, is a MISSING INSTRUMENT and prices nothing.
        with tempfile.TemporaryDirectory() as tmp:
            for key, value, why in (("adopter", "ludlow", "another party's cover"),
                                     ("premium", {"amount": 1.0, "currency": "GBP",
                                                  "perspective": "insurer"},
                                      "a premium on another party's sheet")):
                planted = Path(tmp) / key
                (planted / "quote" / "driftwood" / "v1").mkdir(parents=True)
                (planted / "party.yaml").write_text(
                    (DEFAULT_ESTATE_CLONE / "insurer" / "party.yaml").read_text())
                doc = json.loads(quote_path.read_text())
                doc["payload"][key] = value
                (planted / "quote" / "driftwood" / "v1" / "feed.json").write_text(json.dumps(doc))
                try:
                    price_quote({"party": "insurer", "kind": "feed", "name": "quote-driftwood",
                                 "version": "v1"}, "driftwood", planted,
                                perspective_doc=driftwood_doc, reporting_currency="GBP",
                                prev_version=None)
                    raise AssertionError(f"priced {why} instead of refusing")
                except Refused:
                    pass
        print("OK prices[]: a quote insuring another party, or booking its premium on another "
              "party's sheet, refuses as a missing instrument and prices nothing")

    # --- the signed exposure section: the insurer's whole input, and the
    # premium is NOT in it (a cost is not an exposure) ---
    exposure = yaml.safe_load(rendered["composed/HEADER.yaml"])["exposure"]
    assert exposure["perspective"] == "driftwood" and exposure["currency"] == "GBP", exposure
    band = _appetite("driftwood", driftwood, parent_trees)
    assert exposure["attachment"] == {"amount": band["amount"],
                                      "currency": band["currency"]}, exposure["attachment"]
    priced = [e for e in document["prices"] if e["kind"] in EXPOSURE_KINDS]
    assert math.isclose(exposure["total"], sum(e["amount"] for e in priced)), exposure["total"]
    assert len(exposure["regimes"]) == len(priced), exposure["regimes"]
    assert not any(e["kind"] == "premium" for e in document["prices"]
                    if e["amount"] in [r["amount"] for r in exposure["regimes"]])
    regime = next(r for r in exposure["regimes"] if r["name"] == ICO_REGIME)
    assert math.isclose(sum(c["amount"] for c in regime["controls"]), regime["amount"])
    assert {c["source"] for c in regime["controls"]} == {"nist"}, regime
    print("OK exposure: driftwood's composed artefact signs its total priced exposure "
          "(%.2f %s), its appetite as the attachment and the %s breakdown by regime name and "
          "control id; the premium it buys is a cost and is not counted in it"
          % (exposure["total"], exposure["currency"], len(exposure["regimes"])))

    # ======================================================================
    # eco-system ticket 69: an untagged pin is a priced hole
    # ======================================================================
    # The real insurer clone carries its signed v1.x.y tag, so the real
    # driftwood's premium entry reads `signed` and carries no hole. The
    # untagged case is a real CLONE of the insurer -- the publisher's own tags
    # travel -- carrying the quote it already publishes at a major it has
    # never tagged, with driftwood's pin moved onto it: the quote still
    # prices, the pin is a hole of its own premium under driftwood's own
    # perspective and currency, printed as a delta and never a refusal; a
    # second composition records it; a checkout that cannot show the
    # publisher's tags (no git metadata, no tag at all, a flattened tag) is a
    # could-not-look that opens nothing and closes nothing; and a pin back
    # onto the version the insurer's real signed tag carries closes it. No
    # fixture here claims a signature: the only signed tag read is the
    # insurer's real one.
    if quote_path.exists():
        real_premium = next(e for e in document["prices"] if e["kind"] == "premium")
        sig = real_premium["pin_signature"]
        assert sig["state"] == "signed" and re.match(r"^v1\.\d+\.\d+$", sig["tag"] or ""), sig
        assert real_premium["hole"] is None, real_premium["hole"]
        assert not [d for d in document["deltas"] if d["kind"].endswith("untagged-pin")], document["deltas"]
        print("OK pin signature: the real driftwood's quote pin resolves to the insurer's signed "
              "tag %s on the checkout, and carries no hole" % sig["tag"])

        # The three shapes a checkout can present, read at the pure seam on
        # this fixture's own throwaway repos: only the annotated tag object is
        # an observation. Red before the fix: a tagless checkout and a
        # flattened tag both read `untagged` and booked a hole of the whole
        # premium into a signed artefact.
        with tempfile.TemporaryDirectory() as td:
            shapes = Path(td)
            for label, kwargs, want in (
                    ("a checkout with no tag at all", dict(tag=None, annotated=False), "unobserved"),
                    ("a lightweight tag", dict(tag="v1.0.0", annotated=False), "unobserved"),
                    ("an annotated tag flattened onto its commit",
                     dict(tag="v1.0.0", annotated=True, flatten=True), "unobserved"),
                    ("an annotated tag carrying no signature block",
                     dict(tag="v1.0.0", annotated=True), "untagged")):
                repo = _tag_shape_repo(shapes / label.replace(" ", "-"), **kwargs)  # type: ignore[arg-type]
                got = pin_signature_state(repo, "fixture-publisher", "fixture-feed", "v1")
                assert got["state"] == want, (label, got)
            # and a pre-release pin reads rather than raising on its own tag
            pre = _tag_shape_repo(shapes / "pre-release", tag="v1.0.0-rc1", annotated=True)
            assert pin_signature_state(pre, "fixture-publisher", "fixture-feed",
                                        "v1.0.0-rc1")["state"] == "untagged"
        print("OK pin signature: only a checkout that can show the publisher's tag namespace may "
              "say `untagged` -- no tag at all, a lightweight tag and a flattened annotated tag "
              "all read `unobserved`; an annotated tag with no signature block is untagged")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            untagged = _insurer_clone(root / "insurer-untagged")
            _quote_at_untagged_major(untagged, "driftwood", "v2")
            tagless = _insurer_copy(root / "insurer-tagless", git=True)
            _quote_at_untagged_major(tagless, "driftwood", "v2")
            bare = _insurer_copy(root / "insurer-bare", git=False)
            _quote_at_untagged_major(bare, "driftwood", "v2")
            flattened = _insurer_clone(root / "insurer-flattened")
            _flatten_tag(flattened, "v1.0.0")
            trees = {**parent_trees, "insurer": untagged}
            work = _adopter_copy("driftwood", root)
            _bump_feed_pin(work, "insurer", "quote-driftwood", "v2")

            def _premium(doc: dict) -> dict:
                return next(e for e in doc["prices"] if e["kind"] == "premium")

            def _pin_deltas(doc: dict) -> list[dict]:
                return [d for d in doc["deltas"] if d["kind"].endswith("untagged-pin")]

            def _commit(doc: dict, rendered: dict[str, str]) -> None:
                _commit_header(work, rendered)
                (work / "composed" / "evidence.json").write_text(json.dumps(doc))

            # 1. untagged: priced as a hole of the premium, never refused
            doc1, rendered1 = compose(work, trees)
            assert doc1["outcome"] == "composed", doc1["refusals"]
            p1 = _premium(doc1)
            assert p1["pin_signature"]["state"] == "untagged", p1["pin_signature"]
            assert p1["pin_signature"]["tag"] is None, p1["pin_signature"]
            hole = p1["hole"]
            assert hole is not None and hole["kind"] == UNTAGGED_PIN_HOLE_KIND, hole
            assert hole["status"] == "new", hole
            assert hole["source"] == "insurer" and hole["name"] == "quote-driftwood", hole
            assert hole["version"] == "v2", hole
            assert hole["perspective"] == "driftwood" and hole["currency"] == "GBP", hole
            assert hole["amount"] == p1["amount"] and hole["amount"] > 0, (hole, p1["amount"])
            assert hole["priced_by"], hole
            d1 = _pin_deltas(doc1)
            assert len(d1) == 1 and d1[0]["kind"] == "new-untagged-pin", doc1["deltas"]
            assert d1[0]["source"] == "insurer" and d1[0]["name"] == "quote-driftwood", d1
            assert d1[0]["version"] == "v2", d1
            assert d1[0]["perspective"] == "driftwood" and d1[0]["currency"] == "GBP", d1
            assert d1[0]["amount"] == p1["amount"] and d1[0]["priced_by"] == hole["priced_by"], d1
            assert "amount" in d1[0] and "detail" in d1[0], d1
            print("OK untagged pin: a quote pinned at a version no tag on the insurer's checkout "
                  "signs composes (no refusal) with a hole of its own premium (%.2f %s) under "
                  "driftwood's perspective, printed as a new-untagged-pin delta"
                  % (hole["amount"], hole["currency"]))

            # 2. recorded: the last signed artefact already carried the hole
            _commit(doc1, rendered1)
            doc2, rendered2 = compose(work, trees)
            assert doc2["outcome"] == "composed", doc2["refusals"]
            assert _premium(doc2)["hole"]["status"] == "recorded", _premium(doc2)["hole"]
            assert _premium(doc2)["hole"]["amount"] == p1["amount"], _premium(doc2)["hole"]
            assert _pin_deltas(doc2) == [], doc2["deltas"]
            print("OK untagged pin: a second composition records the hole and prints no delta")

            # 3. unobserved: a checkout that cannot show the publisher's tags
            # -- no git metadata, and no tag at all (the shape `actions/checkout`
            # leaves without `fetch-tags: true`) -- is a could-not-look that
            # neither opens a hole nor closes the recorded one
            _commit(doc2, rendered2)
            rendered3: dict[str, str] = {}
            for tree, expected in ((bare, "no git"), (tagless, "no tag at all")):
                doc3, rendered3 = compose(work, {**parent_trees, "insurer": tree})
                assert doc3["outcome"] == "composed", doc3["refusals"]
                p3 = _premium(doc3)
                assert p3["pin_signature"]["state"] == "unobserved", p3["pin_signature"]
                assert expected in p3["pin_signature"]["detail"], p3["pin_signature"]
                assert p3["hole"]["status"] == "recorded", p3["hole"]
                assert _pin_deltas(doc3) == [], doc3["deltas"]
                fresh = _adopter_copy("driftwood", root / f"fresh-{expected.replace(' ', '-')}")
                _bump_feed_pin(fresh, "insurer", "quote-driftwood", "v2")
                doc3b, _ = compose(fresh, {**parent_trees, "insurer": tree})
                assert _premium(doc3b)["pin_signature"]["state"] == "unobserved", _premium(doc3b)
                assert _premium(doc3b)["hole"] is None, _premium(doc3b)["hole"]
                assert _pin_deltas(doc3b) == [], doc3b["deltas"]
            print("OK unobserved pin: a parent tree with no git metadata, and a checkout carrying "
                  "no tag at all, both read `unobserved` -- they keep a recorded hole and open "
                  "none, a could-not-look and never a signature")

            # 3b. the defect this fix closes: driftwood's real, SIGNED pin
            # against an insurer checkout whose annotated tag a second fetch
            # flattened. A checkout like that is what the adopters' workflows
            # produce, and reading it as `untagged` books a six-figure hole
            # into a signed artefact over a signature that is really there.
            flat_work = _adopter_copy("driftwood", root / "flattened")
            doc_flat, _ = compose(flat_work, {**parent_trees, "insurer": flattened})
            p_flat = _premium(doc_flat)
            assert p_flat["pin_signature"]["state"] == "unobserved", p_flat["pin_signature"]
            assert p_flat["hole"] is None, p_flat["hole"]
            assert _pin_deltas(doc_flat) == [], doc_flat["deltas"]
            print("OK unobserved pin: a real signed tag flattened onto its commit by a second "
                  "fetch reads `unobserved` and books NO hole -- a fabricated hole is worse than "
                  "a missed one, and the fetch is the workflow's to fix (ticket 69)")

            # 4. closed: the pin moves back onto the version the insurer's real
            # signed tag carries, and the recorded hole closes itself
            _bump_feed_pin(work, "insurer", "quote-driftwood", "v1")
            doc4, rendered4 = compose(work, parent_trees)
            assert doc4["outcome"] == "composed", doc4["refusals"]
            p4 = _premium(doc4)
            assert p4["pin_signature"]["state"] == "signed", p4["pin_signature"]
            assert p4["hole"]["status"] == "closed", p4["hole"]
            d4 = _pin_deltas(doc4)
            assert len(d4) == 1 and d4[0]["kind"] == "closed-untagged-pin", doc4["deltas"]
            assert d4[0]["amount"] == p1["amount"], d4
            assert sig["tag"] in d4[0]["detail"], d4
            _commit(doc4, rendered4)
            doc5, _ = compose(work, parent_trees)
            assert _premium(doc5)["hole"] is None and _pin_deltas(doc5) == [], doc5["deltas"]
            print("OK closed pin: composing against the insurer's real signed tag closes the "
                  "hole, prints one closed-untagged-pin delta, and the next composition "
                  "carries no hole -- the hole heals itself when the tag lands")

            # 5. the rendered policies never change on a signature state move.
            # Compared across untagged, recorded and unobserved, which are the
            # same pin against the same quote read three ways -- the closed
            # case moves the pin itself, so its render is not the same input.
            # (The header records the parent SHAs, which differ between the
            # fixture insurer trees, so it is compared without.)
            moved = [k for k in rendered1
                     if k != "composed/HEADER.yaml"
                     and not (rendered1[k] == rendered2.get(k) == rendered3.get(k))]
            assert not moved, moved
            print("OK untagged pin: the rendered artefact is byte-identical across untagged, "
                  "recorded and unobserved -- signature state lives in the evidence, never the "
                  "render")

    # --- no sum crosses a perspective or a currency: the one summing helper
    # REFUSES a mixed list rather than returning a number (spec.md, "The £ seam") ---
    assert _sum_prices([{"amount": 1.0}, {"amount": 2.0}], "driftwood", "GBP") == 3.0
    for mixed in ([{"amount": 1.0, "perspective": "ludlow"}],
                   [{"amount": 1.0, "currency": "USD"}]):
        try:
            _sum_prices(mixed + [{"amount": 2.0}], "driftwood", "GBP")
            raise AssertionError(f"a mixed sum must refuse: {mixed}")
        except Refused:
            pass
    print("OK prices[]: the one summing helper refuses a list that crosses a perspective or a "
          "currency -- no number in this estate is a lie by addition")

    # --- the twin edge (ADR-0021): the adopter's own forward-intel feed
    # annualises through fair.py into ONE source:twin entry naming its
    # selection-policy version, its curve hash and fair.py's own tail ---
    twin_entries = [e for e in document["prices"] if e["source"] == "twin"]
    if twin_entries:
        twin = twin_entries[0]
        assert len(twin_entries) == 1, twin_entries
        assert twin["kind"] == "twin" and twin["name"] == FORWARD_INTEL, twin
        assert set(twin) >= {"policy_version", "curve_hash", "tail"}, twin
        assert twin["tail"], twin
        assert twin["curve_hash"].startswith("sha256:") and len(twin["curve_hash"]) == 71, twin
        assert twin["proposed_tier"] in _cage_engine().ORDER, twin
        print("OK prices[]: driftwood's own forward-intel feed prices as one source:twin entry "
              "-- perspective %s, %s, tail %s, curve %s, policy version %s"
              % (twin["perspective"], twin["currency"], twin["tail"],
                 twin["curve_hash"][:12], twin["policy_version"]))
    else:
        print("OK prices[]: driftwood publishes no forward-intel feed yet, so there is no "
              "source:twin entry -- a missing twin feed is silence, never a refusal")

    # --- a missing forward-intel feed is silence, not a refusal: the fixture
    # adopter copy carries no twin/ directory at all ---
    with tempfile.TemporaryDirectory() as td:
        bare = _adopter_copy("driftwood", Path(td))
        doc_bare, _ = compose(bare, parent_trees)
        assert doc_bare["outcome"] == "composed", doc_bare["refusals"]
        assert not [e for e in doc_bare["prices"] if e["source"] == "twin"], doc_bare["prices"]
    print("OK prices[]: an adopter with no forward-intel feed simply has no twin entry -- a "
          "missing twin feed is never a refusal (ticket 25)")

    # --- the regime entry's per-hole breakdown: the regulator's own published
    # control weights partition the regime exposure, and the entry amount IS
    # the sum of its holes (ticket 15 item 1, landed in this schema pass) ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        _bump_parent_version(work, "ico", "pricing", "v3")
        doc_v3, _ = compose(work, parent_trees)
        _assert_only_known_dangling(doc_v3["refusals"], "ico v3 weights")
        regime = next(e for e in doc_v3["prices"] if _parent_key(e) == "penalty-schema")
        assert regime["holes"], "ico v3 publishes control_weights; the breakdown must appear"
        assert all({"source", "id", "weight", "amount", "status"} == set(h) for h in regime["holes"]), regime
        assert abs(sum(h["weight"] for h in regime["holes"]) - 1.0) < 1e-9, regime["holes"]
        assert abs(regime["total"] - sum(h["amount"] for h in regime["holes"])) < 1e-6, regime
        assert regime["amount"] == regime["total"], regime
        print("OK prices[]: an ico pin at v3 carries the published control weights as a per-hole "
              "breakdown -- %d holes, weights sum to 1.0, and the entry amount IS the sum of "
              "the hole amounts (a hole partitions the regime, it never adds to it)"
              % len(regime["holes"]))

    # --- ADR-0020: a party that declares no appetite is a MISSING INSTRUMENT.
    # It refuses, naming what is missing, and emits no price at all ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        doc_yaml = yaml.safe_load((work / "party.yaml").read_text())
        doc_yaml.pop("appetite", None)
        (work / "party.yaml").write_text(yaml.safe_dump(doc_yaml, sort_keys=False))
        doc_no_band, _ = compose(work, parent_trees)
        assert doc_no_band["prices"] == [], doc_no_band["prices"]
        missing = [r for r in doc_no_band["refusals"] if r["kind"] == "missing-instrument"]
        assert missing, doc_no_band["refusals"]
        assert "appetite" in missing[0]["detail"], missing
    print("OK prices[]: an adopter with no signed appetite refuses as a missing instrument "
          "(ADR-0020), naming the artefact that declares none -- and prices nothing")

    # --- the adopter's own tighten-only floor clamps the selection UP
    # (ADR-0022): the threat-register price picks baseline on driftwood's real
    # band, and a declared quarantine floor holds it at quarantine ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        doc_yaml = yaml.safe_load((work / "party.yaml").read_text())
        doc_yaml["overlay"]["floor"] = "quarantine"
        (work / "party.yaml").write_text(yaml.safe_dump(doc_yaml, sort_keys=False))
        doc_floor, _ = compose(work, parent_trees)
        _assert_only_known_dangling(doc_floor["refusals"], "declared floor")
        threat = next(e for e in doc_floor["prices"] if _parent_key(e) == "threat-register")
        assert threat["proposed_tier"] == "quarantine", threat
        assert threat["proposed_as"] == "label", threat
    print("OK prices[]: driftwood's own overlay.floor clamps the selection UP -- the "
          "threat-register price that picks baseline unclamped is held at the declared "
          "quarantine floor, tighten-only (ADR-0022)")

    # --- ticket 13: the two-publisher limit prints OPEN at one publisher ---
    limit = next(l for l in document["limits"] if l["name"] == "two-publisher-conflict")
    assert limit["count"] == 1 and limit["status"] == "open", limit
    assert document["restatements"] == [] and document["cages"] == []
    print("OK limits[]: the two-publisher-conflict limit prints open at driftwood's one "
          "pinned implementations publisher")

    declared_kinds = {_parent_key(e) for e in yaml.safe_load(
        (driftwood / "party.yaml").read_text())["inherits"]}
    assert declared_kinds == {"controls", "implementations", "penalty-schema", "threat-register",
                              "quote-driftwood"}
    assert len(document["parents"]) == 5
    for parent in document["parents"]:
        assert parent["sha"], parent
    print("OK parents[]: all five declared parent kinds resolve to a non-empty SHA")

    # --- two members of one family at one version both survive resolution ---
    members_by_version, guards = load_implementations(parent_trees["platform"])
    live_version = sorted(members_by_version)[-1]
    at_version = members_by_version[live_version]
    assert ("graded-enforcement", "cage-tier") in at_version, at_version.keys()
    assert ("graded-enforcement", "cage-netpol") in at_version, at_version.keys()
    print("OK load_implementations: cage-tier and cage-netpol, one family, one version, both survive "
          "(ADR-0016's fix for the prototype's (family, version) key)")

    # a dedicated synthetic fixture, not just the estate's own luck
    with tempfile.TemporaryDirectory() as td:
        fixture_root = Path(td) / "fixture-platform"
        _write_versions_yaml(fixture_root, [{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "f" * 40}])
        shutil.copy(parent_trees["platform"] / "distribution" / "render-orphan-guard.py",
                    fixture_root / "distribution" / "render-orphan-guard.py")
        shutil.copy(parent_trees["platform"] / "distribution" / "render-governed-namespace-guard.py",
                    fixture_root / "distribution" / "render-governed-namespace-guard.py")
        tree = fixture_root / "distribution" / "policies" / "v1.0.0"
        _write_admission_doc(tree / "member-a.yaml", "ValidatingPolicy", "member-a-1-0-0",
                              "one-family", "1.0.0", validation_actions=["Audit"])
        _write_admission_doc(tree / "member-b.yaml", "MutatingPolicy", "member-b-1-0-0",
                              "one-family", "1.0.0")
        fixture_members, _ = load_implementations(fixture_root)
        assert ("one-family", "member-a") in fixture_members["1.0.0"]
        assert ("one-family", "member-b") in fixture_members["1.0.0"]
    print("OK load_implementations: a dedicated fixture, two members of one family at one version, "
          "both keys present")

    # --- render faithfulness across the whole live implementations set ---
    faithful_count = 0
    for version, members in members_by_version.items():
        for (family, base), meta in members.items():
            out_path = f"composed/policies/v{version}/{Path(meta['path']).name}"
            rendered_doc = yaml.safe_load(rendered[out_path])
            assert render_is_faithful(rendered_doc, meta["doc"]), (family, base, version)
            faithful_count += 1
    assert faithful_count == sum(len(m) for m in members_by_version.values())
    print(f"OK render_is_faithful: every member of every live version ({faithful_count} total) "
          "renders back byte-identical after the header is stripped")

    # --- no validationActions written onto a mutate or a generate ---
    mutating_or_generating = 0
    for path, text in rendered.items():
        if path.startswith("composed/policies/") and ("cage-tier.yaml" in path or "cage-netpol.yaml" in path):
            assert "validationActions" not in text, path
            mutating_or_generating += 1
    assert mutating_or_generating > 0
    print("OK render_member: no validationActions field written onto cage-tier (Mutating) "
          "or cage-netpol (Generating)")

    # --- both platform-machinery guards compose under the platform tag, matching their offline twins ---
    for g in guards:
        g_rendered = yaml.safe_load(rendered[g["out_path"]])
        assert render_is_faithful(g_rendered, g["doc"]), g["member_name"]
        g_member = next(m for m in document["members"] if m["name"] == g["member_name"])
        assert g_member["family"] == "platform-machinery"
        assert g_member["version"] is None
    print("OK guards: orphan guard and governed-namespace-requires-claim both compose under "
          "the platform tag (no policy-version), rendering back to their offline twins' output")

    # --- the header ---
    header = yaml.safe_load(rendered["composed/HEADER.yaml"])
    assert header["policy-as-versioned.dev/composed"] is True
    assert len(header["parents"]) == 5
    assert all(p["sha"] for p in header["parents"])
    assert header["baseline"] == "MODERATE"
    assert header["governed-namespaces"] == ["driftwood"]
    # ticket 14: the estate starts at 285 recorded holes and refuses on
    # none of them (spec.md's bootstrap rule -- nothing is committed for
    # the real estate yet, so this IS the first composition every time).
    assert len(document["holes"]) == 285, len(document["holes"])
    assert all(h["status"] == "recorded" for h in document["holes"])
    assert {h["control_id"] for h in document["holes"]} == set(header["holes"])
    assert "ac-6.10" in {h["control_id"] for h in document["holes"]}
    assert "ac-6" not in {h["control_id"] for h in document["holes"]}  # claimed (even if dangling)
    assert "cm-6" not in {h["control_id"] for h in document["holes"]}  # claimed (even if dangling)
    assert len(header["selected-controls"]) == 287  # MODERATE
    print("OK HEADER.yaml/holes[]: the real estate's first composition records 285 holes, all "
          "recorded (none new, none refused), ac-6.10 found by walking nested controls, and "
          "ac-6/cm-6 are covered (a claim exists, even the dangling one)")

    # ticket 15: real driftwood's own Namespace manifest already carries
    # BOTH labels (ticket 11 landed it labelled from the start) -- so the
    # real estate has zero ungoverned namespaces to record or refuse on.
    assert document["ungoverned"] == [], document["ungoverned"]
    assert header["ungoverned-namespaces"] == [], header["ungoverned-namespaces"]
    print("OK ungoverned[]: real driftwood's own namespace already carries governed: \"true\", "
          "so composition records zero ungoverned namespaces")

    # --- verify mode + CLI wrapper: a dedicated clean fixture, isolated from
    # the real estate clone on disk so this test never writes into it (the
    # real estate composes cleanly too now -- see the cmd_compose block
    # against real driftwood, below -- this fixture just keeps the write
    # side effects out of a real checkout). ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write_fixture_catalog(root / "fixture-nist")
        _write_fixture_platform(root / "fixture-platform", parent_trees["platform"],
                                 claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": root / "fixture-nist", "fixture-platform": root / "fixture-platform"}

        work = root / "fixture-adopter14"
        _write_fixture_adopter(work, "SMALL")
        clean_doc, work_rendered = compose(work, fixture_trees)
        assert clean_doc["outcome"] == "composed", clean_doc
        for rel, content in work_rendered.items():
            target = work / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        ok, mismatches = verify(work, fixture_trees)
        assert ok, mismatches
        print("OK verify(): a freshly composed and committed tree re-renders clean")

        (work / "composed" / "orphan-guard.yaml").write_text("kind: Tampered\n")
        ok, mismatches = verify(work, fixture_trees)
        assert not ok and mismatches, mismatches
        print("OK verify(): a tampered committed file is caught as a byte-for-byte mismatch")

    # --- CLI wrapper: writes files, prints the document, exits non-zero on refusal ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _write_fixture_catalog(root / "fixture-nist")
        _write_fixture_platform(root / "fixture-platform", parent_trees["platform"],
                                 claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": root / "fixture-nist", "fixture-platform": root / "fixture-platform"}
        # cmd_compose resolves parent trees from --estate-clone by NAME, so
        # the fixture parties live directly under root, matching that layout.
        out = root / "fixture-adopter14"
        _write_fixture_adopter(out, "SMALL")
        rc = cmd_compose(out, root, out)
        assert rc == 0, (rc, (out / "party.yaml").read_text())
        assert (out / "composed" / "HEADER.yaml").exists()
        assert (out / "composed" / "evidence.json").exists()
    print("OK cmd_compose: writes the rendered files and the evidence document, exits 0 on success")

    # --- and against the real estate, cmd_compose now exits 0: platform's
    # two formerly-dangling claims are fixed, so the real driftwood's first
    # pull request composes and writes for real ---
    with tempfile.TemporaryDirectory() as td:
        out = _adopter_copy("driftwood", Path(td))
        rc = cmd_compose(out, DEFAULT_ESTATE_CLONE, out)
        assert rc == 0
        assert (out / "composed" / "HEADER.yaml").exists()
        assert (out / "composed" / "evidence.json").exists()
    print("OK cmd_compose: against the real estate, exits 0 -- platform's two formerly-"
          "dangling claims are fixed, and the real driftwood's first pull request composes "
          "and writes for real")

    # --- refusal: a structurally invalid party artefact never composes, CLI exits non-zero ---
    with tempfile.TemporaryDirectory() as td:
        broken = Path(td) / "broken-adopter"
        broken.mkdir()
        bad_doc = {"party": "broken", "roles": ["adopter"], "baseline": "MODERATE",
                   "inherits": [], "overlay": {"add": [], "restate": []}}
        del bad_doc["roles"]  # missing required field
        (broken / "party.yaml").write_text(yaml.safe_dump(bad_doc))
        doc, files = compose(broken, {})
        assert doc["outcome"] == "refused"
        assert doc["party_artefact_errors"]
        assert files == {}
        rc = cmd_compose(broken, DEFAULT_ESTATE_CLONE, broken)
        assert rc == 1
        assert not (broken / "composed").exists()
    print("OK compose()/cmd_compose: a party artefact that doesn't check out refuses, "
          "renders nothing, and the CLI exits non-zero")

    # ======================================================================
    # ticket 13: structural refusals, restatement, and caging
    # ======================================================================

    # --- a split diamond refuses and names both edges ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        doc = yaml.safe_load((work / "party.yaml").read_text())
        # ico/pricing carries no Flux pin (party_artefact.check_tags only
        # NOTES it), so a second declared version here can't also trip the
        # unrelated tag-mismatch refusal -- this is the diamond, isolated.
        ico_edge = next(e for e in doc["inherits"] if _parent_key(e) == "penalty-schema")
        # A SECOND version, whichever one this party is not already pinned to,
        # so the plant survives a pin bump instead of hard-coding today's.
        other = "v1" if ico_edge["version"] != "v1" else "v2"
        doc["inherits"].append(dict(ico_edge, version=other))
        (work / "party.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
        document, files = compose(work, parent_trees)
        assert document["outcome"] == "refused", document
        diamond = [r for r in document["refusals"] if r["kind"] == "split-diamond"]
        assert len(diamond) == 1, document["refusals"]
        assert diamond[0]["subject"] == "ico/penalty-schema", diamond[0]
        assert ico_edge["version"] in diamond[0]["detail"], diamond[0]
        assert other in diamond[0]["detail"], diamond[0]
        assert diamond[0]["needs_composition"] is True
    print("OK check_diamonds: two edges to ico/penalty-schema at two versions refuse, naming both")

    # --- two sources for one rule with different content refuse, naming both;
    #     the two-publisher limit closes ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for name, action in (("impl-a", "Audit"), ("impl-b", "Deny")):
            fx = root / name
            _write_versions_yaml(fx, [{"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "c" * 40}])
            shutil.copy(parent_trees["platform"] / "distribution" / "render-orphan-guard.py",
                        fx / "distribution" / "render-orphan-guard.py")
            shutil.copy(parent_trees["platform"] / "distribution" / "render-governed-namespace-guard.py",
                        fx / "distribution" / "render-governed-namespace-guard.py")
            _write_admission_doc(fx / "distribution" / "policies" / "v1.0.0" / "dup-member.yaml",
                                  "ValidatingPolicy", "dup-member-1-0-0", "dup-family", "1.0.0",
                                  validation_actions=[action])
        work = root / "fixture-adopter"
        work.mkdir()
        fixture_doc = {
            "party": "fixture-adopter", "roles": ["adopter"], "baseline": "MODERATE",
            "inherits": [
                {"party": "impl-a", "kind": "implementations", "version": "1.0.0"},
                {"party": "impl-b", "kind": "implementations", "version": "1.0.0"},
            ],
            "overlay": {"add": [], "restate": []},
        }
        (work / "party.yaml").write_text(yaml.safe_dump(fixture_doc, sort_keys=False))
        _write_baseline_configmap(work, "MODERATE")
        document, files = compose(work, {"impl-a": root / "impl-a", "impl-b": root / "impl-b"})
        assert document["outcome"] == "refused", document
        conflicts = [r for r in document["refusals"] if r["kind"] == "rule-conflict"]
        assert len(conflicts) == 1, document["refusals"]
        assert conflicts[0]["subject"] == "dup-family/dup-member@1.0.0", conflicts[0]
        assert "impl-a@1.0.0" in conflicts[0]["detail"] and "impl-b@1.0.0" in conflicts[0]["detail"]
        assert "Audit" in conflicts[0]["detail"] and "Deny" in conflicts[0]["detail"]
        assert conflicts[0]["needs_composition"] is True
        assert not any("dup-member.yaml" in p for p in files), files.keys()
        two_pub = next(l for l in document["limits"] if l["name"] == "two-publisher-conflict")
        assert two_pub["count"] == 2 and two_pub["status"] == "closed", two_pub
    print("OK rule-conflict: two implementations publishers on one key with different "
          "content refuse, naming both sources and both contents, never merged; the "
          "two-publisher limit prints closed at two")

    # --- a restatement of a mutate refuses (ADR-0016) ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        _with_restate(work, [{"name": "cage-tier", "version": live_v, "action": "Deny"}])
        document, files = compose(work, parent_trees)
        assert document["outcome"] == "refused", document
        mutate_refusals = [r for r in document["refusals"] if r["kind"] == "restatement-of-non-validating"]
        assert len(mutate_refusals) == 1, document["refusals"]
        assert mutate_refusals[0]["subject"] == f"graded-enforcement/cage-tier@{live_v}"
        assert mutate_refusals[0]["needs_composition"] is True
        assert document["restatements"] == [], document["restatements"]
    print("OK restatement-of-non-validating: restating cage-tier (a MutatingPolicy) refuses")

    # --- a stricter restatement is accepted and the rendered file carries it ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        _with_restate(work, [{"name": "require-nonroot", "version": live_v, "action": "Deny"}])
        document, files = compose(work, parent_trees)
        assert document["outcome"] == "composed", document
        _assert_only_known_dangling(document["refusals"], "stricter restatement")
        r = next(r for r in document["restatements"]
                 if r["rule"] == f"require-nonroot/require-nonroot@{live_v}")
        assert r["inherited_action"] == "Audit" and r["restated_action"] == "Deny"
        assert r["outcome"] == "accepted", r
        rendered_doc = yaml.safe_load(files[f"composed/policies/v{live_v}/require-nonroot.yaml"])
        assert rendered_doc["spec"]["validationActions"] == ["Deny"], rendered_doc
    print("OK restatement accepted: Audit -> Deny is stricter, and the rendered file carries "
          "the restated Deny")

    # --- a weaker restatement is caged; the rendered file keeps the inherited action;
    #     the same weaker restatement prices three parties to the prototype's table ---
    scenario_rel = "policy/scenarios/driftwood-root-residual.json"
    assert (PLATFORM_DIR / scenario_rel).exists(), scenario_rel
    tiers: dict[str, str] = {}
    last_files: dict[str, str] = {}
    for org, expected_tier in (("driftwood", "baseline"), ("tuppence", "baseline"),
                                ("ludlow", "quarantine")):
        with tempfile.TemporaryDirectory() as td:
            work = _adopter_copy(org, Path(td))
            _with_restate(work, [{
                "name": "posture-trust-boundary", "version": live_v, "action": "Audit",
                "scenario": scenario_rel, "why": "needs CAP_NET_RAW; cannot meet condition C",
            }])
            document, files = compose(work, parent_trees)
            # a caged inability adds no refusal of its own
            assert document["outcome"] == "composed", document
            _assert_only_known_dangling(document["refusals"], f"weaker restatement ({org})")
            r = next(r for r in document["restatements"]
                     if r["rule"] == f"posture/posture-trust-boundary@{live_v}")
            assert r["inherited_action"] == "Deny" and r["restated_action"] == "Audit"
            assert r["outcome"] == "caged", r
            cage_entry = next(c for c in document["cages"]
                               if c["rule"] == f"posture/posture-trust-boundary@{live_v}")
            assert cage_entry["party"] == org
            tiers[org] = cage_entry["tier"]
            assert cage_entry["tier"] == expected_tier, (org, cage_entry)
            rendered_doc = yaml.safe_load(files[f"composed/policies/v{live_v}/posture-trust-boundary.yaml"])
            assert rendered_doc["spec"]["validationActions"] == ["Deny"], rendered_doc  # stays inherited
            last_files = files
    print(f"OK cages[]: a weaker restatement is caged against each party's own appetite band, "
          f"the rendered file keeps the inherited Deny, and the same declared inability prices "
          f"three parties to the prototype's table: {tiers}")

    # --- no tier and no tier floor appears anywhere composition itself writes ---
    # (cage-tier.yaml's OWN inherited body legitimately reads posture.acme.io/tier
    # off the workload at admission time -- that is the runtime dial-selection
    # mechanism this composition carries unchanged, not a declared verdict. What
    # must never appear is composition's OWN advisory additions -- the header and
    # the policy-as-versioned.dev/* labels/annotations render_member writes --
    # naming a tier or a tier floor.)
    header = yaml.safe_load(last_files["composed/HEADER.yaml"])
    assert "tier" not in header and "cages" not in header, header
    for path, text in last_files.items():
        if not path.endswith(".yaml"):
            continue
        for doc in yaml.safe_load_all(text):
            if not isinstance(doc, dict):
                continue
            md = doc.get("metadata") or {}
            # Exact-key: composition's own three added keys (COMPOSED_FOR,
            # PROVENANCE_INHERITED, PROVENANCE_SOURCE) are never a tier field.
            # A substring check would false-positive on cage-tier's own
            # legitimate source-path value ("...cage-tier.yaml" contains
            # "tier" as a member NAME, not a declared verdict).
            for section in (md.get("annotations") or {}, md.get("labels") or {}):
                assert "posture.acme.io/tier" not in (section or {}), (path, section)
    print("OK no tier and no tier floor appears anywhere in what composition itself writes -- "
          "only the proposer (ADR-0015) ever turns one, later, in its own PR")

    # --- refusals[] carries needs_composition on every entry, across every kind seen above ---
    for r in diamond + conflicts + mutate_refusals:
        assert "needs_composition" in r and isinstance(r["needs_composition"], bool), r
    print("OK refusals[]: needs_composition is present on every entry "
          "(split-diamond, rule-conflict, restatement-of-non-validating)")

    # ======================================================================
    # ticket 14: baseline coverage, control claims and holes
    # ======================================================================

    # --- the baseline resolver: exact-string, walks nested controls; a
    # prefixed or upper-case id is a hard failure, not a hole ---
    with tempfile.TemporaryDirectory() as td:
        nist_root = Path(td) / "fixture-nist"
        _write_fixture_catalog(nist_root)
        assert _catalog_ids(nist_root) == {"aa-1", "aa-1.1", "aa-2", "aa-3", "bb-1"}
        assert _baseline_ids(nist_root, "SMALL") == {"aa-1", "aa-1.1", "aa-2"}
        assert _baseline_ids(nist_root, "NONEXISTENT") is None
        print("OK _catalog_ids/_baseline_ids: SMALL resolves by name, exact-string, and the "
              "nested enhancement aa-1.1 is found by walking; an unpublished name resolves None")

        platform_root = Path(td) / "fixture-platform"
        _write_fixture_platform(platform_root, parent_trees["platform"], claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": nist_root, "fixture-platform": platform_root}

        # A prefixed/upper-case addition: a hard failure, not a hole. Never
        # enters the selected set (no ghost hole for a string that names no
        # real control), and needs_composition is False -- a plain lint of
        # the id against the catalogue would also catch it.
        work = Path(td) / "bad-ids"
        _write_fixture_adopter(work, "SMALL", controls_add=["AA-1", "fam:aa-2"])
        doc, _ = compose(work, fixture_trees)
        assert doc["outcome"] == "refused", doc
        bad_ids = [r for r in doc["refusals"] if r["kind"] == "unknown-control-id"]
        assert {r["needs_composition"] for r in bad_ids} == {False}, bad_ids
        assert any("AA-1" in r["subject"] for r in bad_ids), bad_ids
        assert any("fam:aa-2" in r["subject"] for r in bad_ids), bad_ids
        assert "AA-1" not in {h["control_id"] for h in doc["holes"]}  # never even considered a hole
        print("OK unknown-control-id: an upper-case id and a prefixed id both refuse as hard "
              "failures (needs_composition False), and are never counted as a hole")

        # --- first composition: holes recorded, refuses on none; claims
        # merge across the parent AND the adopter's own component-definition ---
        base = Path(td) / "run1"
        _write_fixture_adopter(base, "SMALL")
        doc1, rendered1 = compose(base, fixture_trees)
        assert doc1["outcome"] == "composed", doc1
        assert {h["control_id"]: h["status"] for h in doc1["holes"]} == {
            "aa-1.1": "recorded", "aa-2": "recorded"}
        _commit_header(base, rendered1)
        print("OK compute_holes: a first composition (nothing committed yet) records every "
              "hole and refuses on none")

        # --- a second composition with one NEW hole COMPOSES and prints the
        # hole as a priced delta (ticket 38; ADR-0020: a missing behaviour is
        # priced, never refused). This fixture pins no regime feed, so the
        # delta carries no amount and says why -- a named absence, never a
        # zero and never a refusal ---
        added = Path(td) / "run2-new-hole"
        shutil.copytree(base, added)
        doc_added = yaml.safe_load((added / "party.yaml").read_text())
        doc_added["overlay"]["controls"] = ["aa-3"]
        (added / "party.yaml").write_text(yaml.safe_dump(doc_added, sort_keys=False))
        doc2, _ = compose(added, fixture_trees)
        assert doc2["outcome"] == "composed", doc2
        assert not [r for r in doc2["refusals"] if r["kind"] == "new-hole"], doc2["refusals"]
        new_hole = _hole(doc2, "aa-3")
        assert new_hole["status"] == "new" and new_hole["source"] == "fixture-nist", new_hole
        assert new_hole["perspective"] == "fixture-adopter14" and new_hole["currency"] == "GBP"
        assert _hole(doc2, "aa-1.1")["status"] == "recorded", doc2["holes"]
        new_deltas = [d for d in doc2["deltas"] if d["kind"] == "new-hole"]
        assert len(new_deltas) == 1 and new_deltas[0]["control_id"] == "aa-3", doc2["deltas"]
        assert new_deltas[0]["source"] == "fixture-nist", new_deltas
        assert new_deltas[0]["amount"] is None and new_deltas[0]["priced_by"] is None, new_deltas
        assert new_deltas[0]["perspective"] == "fixture-adopter14", new_deltas
        assert new_deltas[0]["currency"] == "GBP", new_deltas
        print("OK compute_holes: a second composition with one new hole composes and prints it "
              "as a priced delta (aa-3, added via overlay.controls, no claim yet) -- no "
              "refusal; with no regime feed pinned the amount is a named absence, not a zero")

        # --- the SAME added control, but filled in the same run by the
        # adopter's own claim against its own overlay.add member: never
        # becomes a hole at all, and claims merge across every party ---
        filled = Path(td) / "run2-adopter-fills"
        shutil.copytree(base, filled)
        own_member = {
            "apiVersion": "policies.kyverno.io/v1alpha1", "kind": "ValidatingPolicy",
            "metadata": {"name": "own-policy-1-0-0", "labels": {LABEL_FAMILY: "own-fam"}},
            "spec": {"validationActions": ["Audit"]},
        }
        doc_filled = yaml.safe_load((filled / "party.yaml").read_text())
        doc_filled["overlay"]["controls"] = ["aa-3"]
        doc_filled["overlay"]["add"] = [{"version": "1.0.0", "manifest": own_member}]
        (filled / "party.yaml").write_text(yaml.safe_dump(doc_filled, sort_keys=False))
        _write_component_definition(filled / ADOPTER_CLAIMS_FILE, [("aa-3", "own-policy")])
        doc3, files3 = compose(filled, fixture_trees)
        assert doc3["outcome"] == "composed", doc3
        assert "aa-3" not in {h["control_id"] for h in doc3["holes"]}, doc3["holes"]
        assert "composed/policies/v1.0.0/own-policy.yaml" in files3, files3.keys()
        print("OK resolve_claims: an adopter-added control is a priced new hole when unfilled "
              "(above), and an adopter claim in its own component-definition -- against its own "
              "overlay.add member -- fills it in the same run, so it is never even a hole")

        # --- a hole filled ACROSS runs marks it closed ---
        closes = Path(td) / "run2-closes"
        shutil.copytree(base, closes)
        doc_closes = yaml.safe_load((closes / "party.yaml").read_text())
        doc_closes["overlay"]["add"] = [{"version": "1.0.0", "manifest": own_member}]
        (closes / "party.yaml").write_text(yaml.safe_dump(doc_closes, sort_keys=False))
        _write_component_definition(closes / ADOPTER_CLAIMS_FILE, [("aa-1.1", "own-policy")])
        doc4, _ = compose(closes, fixture_trees)
        assert doc4["outcome"] == "composed", doc4
        assert _hole(doc4, "aa-1.1")["status"] == "closed", doc4["holes"]
        assert _hole(doc4, "aa-2")["status"] == "recorded", doc4["holes"]
        assert [d["kind"] for d in doc4["deltas"]] == ["closed-hole"], doc4["deltas"]
        print("OK compute_holes: a second composition with a hole filled (aa-1.1, by an "
              "adopter claim added since the last signed artefact) marks it closed")

        # --- a removed control refuses ---
        shrunk = Path(td) / "run2-removed"
        shutil.copytree(base, shrunk)
        doc_shrunk = yaml.safe_load((shrunk / "party.yaml").read_text())
        doc_shrunk["baseline"] = "TINY"  # {aa-1} -- drops aa-1.1 and aa-2
        (shrunk / "party.yaml").write_text(yaml.safe_dump(doc_shrunk, sort_keys=False))
        _write_baseline_configmap(shrunk, "TINY")
        doc5, _ = compose(shrunk, fixture_trees)
        assert doc5["outcome"] == "refused", doc5
        removed = [r for r in doc5["refusals"] if r["kind"] == "removed-control"]
        assert {r["subject"] for r in removed} == {"aa-1.1", "aa-2"}, doc5["refusals"]
        assert all(r["needs_composition"] is True for r in removed)
        print("OK check_selected_set: TINY drops aa-1.1 and aa-2 from SMALL's selected set, and "
              "a removed control refuses, naming both")

        # --- a widened baseline composes and prints as a priced delta, beside
        # the new hole it opens (ticket 38; reversals 9-10: widening is priced,
        # never refused, and there is no override flag because there is
        # nothing to override) ---
        widened = Path(td) / "run2-widened"
        shutil.copytree(base, widened)
        doc_widened = yaml.safe_load((widened / "party.yaml").read_text())
        doc_widened["baseline"] = "BIG"  # SMALL plus aa-3 -- a strict superset
        (widened / "party.yaml").write_text(yaml.safe_dump(doc_widened, sort_keys=False))
        _write_baseline_configmap(widened, "BIG")
        doc6, _ = compose(widened, fixture_trees)
        assert doc6["outcome"] == "composed", doc6
        assert not [r for r in doc6["refusals"] if r["kind"] == "baseline-widening"], doc6["refusals"]
        widening = [d for d in doc6["deltas"] if d["kind"] == "baseline-widening"]
        assert len(widening) == 1 and widening[0]["subject"] == "SMALL -> BIG", doc6["deltas"]
        assert widening[0]["added"] == 1 and widening[0]["priced"] == 0, widening
        assert widening[0]["amount"] is None, widening
        assert [d["control_id"] for d in doc6["deltas"] if d["kind"] == "new-hole"] == ["aa-3"]
        assert _hole(doc6, "aa-3")["status"] == "new", doc6["holes"]
        removed_on_widen = [r for r in doc6["refusals"] if r["kind"] == "removed-control"]
        assert removed_on_widen == [], doc6["refusals"]  # nothing left the selected set
        print("OK baseline_widening_delta: SMALL -> BIG composes and prints one widening delta "
              "(1 control added, 0 of them named by a pinned weight, so no amount) beside the "
              "new hole it opens; nothing refuses, and a removal does not also fire")

        # --- an adopter claim against a PARENT's policy refuses ---
        cross = Path(td) / "run2-cross-party-claim"
        shutil.copytree(base, cross)
        _write_component_definition(cross / ADOPTER_CLAIMS_FILE, [("aa-2", "member-a")])
        doc7, _ = compose(cross, fixture_trees)
        assert doc7["outcome"] == "refused", doc7
        cross_refusals = [r for r in doc7["refusals"] if r["kind"] == "claim-against-another-partys-policy"]
        assert len(cross_refusals) == 1, doc7["refusals"]
        assert "aa-2" in cross_refusals[0]["subject"] and "member-a" in cross_refusals[0]["subject"]
        assert cross_refusals[0]["needs_composition"] is True
        # aa-2 still counts as COVERED -- a claim exists, invalid or not
        # (spec.md: "no claim", not "no valid claim") -- so it closes as a
        # hole even though the claim that closed it is itself refused.
        assert _hole(doc7, "aa-2")["status"] == "closed", doc7["holes"]
        print("OK resolve_claims: an adopter claim against fixture-platform's own member-a "
              "refuses (ADR-0017) -- 'fixture-adopter14 claims aa-2 is evidenced by "
              "\"member-a\", which fixture-platform ships, not fixture-adopter14' -- and still "
              "counts as coverage (a claim exists), orthogonal to the claim's own validity")

    # --- and against the real estate: platform's former two dangling claims
    # are fixed, so a claim whose policy exists nowhere no longer fires
    # here -- proof the fix took, not just that the refusal path works
    # (that path is still proved above via resolve_claims's own fixtures) ---
    real_doc, _ = compose(driftwood, parent_trees)
    dangling = [r for r in real_doc["refusals"] if r["kind"] == "dangling-claim"]
    assert dangling == [], real_doc["refusals"]
    print("OK resolve_claims: the real platform component-definition's two formerly-dangling "
          "claims (ac-6, cm-6) are fixed -- zero dangling-claim refusals against the real estate")

    # --- the header carries the recorded hole ids (asserted against the
    # real estate's first composition, above: "OK HEADER.yaml/holes[]").
    # Stripping it is a no-op on every other rendered file: HEADER.yaml is
    # its own separate file, and "holes"/"selected-controls" appear
    # nowhere else in what composition renders. ---
    for path, text in rendered.items():
        if path == "composed/HEADER.yaml":
            continue
        assert '"holes"' not in text and "holes:" not in text, path
        assert "selected-controls" not in text, path
    print("OK HEADER.yaml: 'holes' and 'selected-controls' live only in the advisory header -- "
          "stripping it leaves every other rendered file unchanged")

    # ======================================================================
    # ticket 15: the governed namespace lint
    # ======================================================================
    with tempfile.TemporaryDirectory() as td:
        nist_root = Path(td) / "fixture-nist"
        _write_fixture_catalog(nist_root)
        platform_root = Path(td) / "fixture-platform"
        _write_fixture_platform(platform_root, parent_trees["platform"], claims=[("aa-1", "member-a")])
        fixture_trees = {"fixture-nist": nist_root, "fixture-platform": platform_root}

        # --- a namespace with no institution label is ignored entirely ---
        ignored = Path(td) / "ignored"
        _write_fixture_adopter(ignored, "SMALL")
        _write_namespace(ignored, "infra", institution=False, governed=False)
        assert ungoverned_namespaces(ignored) == []
        doc0, _ = compose(ignored, fixture_trees)
        assert doc0["outcome"] == "composed", doc0
        assert doc0["ungoverned"] == [], doc0["ungoverned"]
        print("OK ungoverned_namespaces: a Namespace with no institution label is ignored "
              "entirely, never entering the ungoverned set")

        # --- bootstrap: the FIRST composition (nothing committed yet)
        # records a pre-existing ungoverned namespace and refuses on none --
        # same bootstrap rule compute_holes already uses (spec.md, Further
        # Notes: "the first composition records ... three ungoverned "
        # namespaces and refuses on none") ---
        base = Path(td) / "run1"
        _write_fixture_adopter(base, "SMALL")
        _write_namespace(base, "acme", institution=True, governed=False)
        doc1, rendered1 = compose(base, fixture_trees)
        assert doc1["outcome"] == "composed", doc1
        assert [(e["namespace"], e["status"]) for e in doc1["ungoverned"]] == [("acme", "recorded")], doc1["ungoverned"]
        assert "price" in doc1["ungoverned"][0], doc1["ungoverned"]
        assert doc1["deltas"] == [], doc1["deltas"]   # recorded on a first composition: no move
        _commit_header(base, rendered1)
        print("OK compute_ungoverned: a first composition (nothing committed yet) records a "
              "pre-existing ungoverned namespace, priced, and refuses on none")

        # --- an unchanged second run: still recorded, still no refusal ---
        again = Path(td) / "run1-again"
        shutil.copytree(base, again)
        doc2, _ = compose(again, fixture_trees)
        assert doc2["outcome"] == "composed", doc2
        assert [(e["namespace"], e["status"]) for e in doc2["ungoverned"]] == [("acme", "recorded")], doc2["ungoverned"]
        assert doc2["deltas"] == [], doc2["deltas"]
        print("OK compute_ungoverned: a recorded ungoverned namespace records and does not refuse")

        # --- it gains the label since the last signed artefact: closed ---
        labelled = Path(td) / "run1-labelled"
        shutil.copytree(base, labelled)
        _write_namespace(labelled, "acme", institution=True, governed=True)
        doc3, _ = compose(labelled, fixture_trees)
        assert doc3["outcome"] == "composed", doc3
        assert doc3["ungoverned"] == [{"namespace": "acme", "status": "closed"}], doc3["ungoverned"]
        assert [d["kind"] for d in doc3["deltas"]] == ["closed-ungoverned-namespace"], doc3["deltas"]
        print("OK compute_ungoverned: a namespace that gains the label prints as closed, and as "
              "a closed-ungoverned-namespace delta")

        # --- a genuinely NEW ungoverned namespace (absent from the last
        # signed artefact, which recorded none) refuses and names it ---
        clean_base = Path(td) / "run2"
        _write_fixture_adopter(clean_base, "SMALL")
        doc4, rendered4 = compose(clean_base, fixture_trees)
        assert doc4["outcome"] == "composed", doc4
        assert doc4["ungoverned"] == [], doc4["ungoverned"]
        _commit_header(clean_base, rendered4)

        new_ns = Path(td) / "run2-new"
        shutil.copytree(clean_base, new_ns)
        _write_namespace(new_ns, "acme", institution=True, governed=False)
        _write_namespace(new_ns, "home", institution=True, governed=True)
        _write_workload(new_ns, "acme", "reset-a")
        for i in range(3):
            _write_workload(new_ns, "home", f"app-{i}")
        _write_workload(new_ns, "flux-system", "infra")  # no institution label: not counted
        doc5, _ = compose(new_ns, fixture_trees)
        assert doc5["outcome"] == "composed", doc5
        assert not [r for r in doc5["refusals"] if r["kind"] == "new-ungoverned-namespace"], doc5["refusals"]
        acme = next(e for e in doc5["ungoverned"] if e["namespace"] == "acme")
        assert acme["status"] == "new", acme
        price = acme["price"]
        assert price["perspective"] == "fixture-adopter14" and price["currency"] == "GBP", price
        assert price["workloads"] == 1 and price["workloads_total"] == 4, price
        assert price["share"] == 0.25, price
        # No signed composed artefact names acme (a fixture is not a signed
        # repo), and this fixture pins no feed that prices its residual: both
        # are named limits, the ramp stays at 1.0 and the amount is absent.
        assert price["since"] is None and price["ramp"] == 1.0, price
        assert price["as_of"] is None and price["base"] is None and price["amount"] is None, price
        assert len(price["limits"]) == 2, price["limits"]
        new_deltas = [d for d in doc5["deltas"] if d["kind"] == "new-ungoverned-namespace"]
        assert len(new_deltas) == 1 and new_deltas[0]["namespace"] == "acme", doc5["deltas"]
        assert new_deltas[0]["amount"] is None, new_deltas
        print("OK compute_ungoverned: a new ungoverned namespace (absent from the last signed "
              "artefact) composes and is priced as its workload share (1 of 4 institution "
              "workloads = 0.25) with the two things it cannot yet read named as limits")

        # --- the header carries the recorded ungoverned set, and stripping
        # it leaves every other rendered file unchanged; nothing in the
        # per-member files ever reads either namespace set ---
        header1 = yaml.safe_load(rendered1["composed/HEADER.yaml"])
        assert header1["ungoverned-namespaces"] == ["acme"], header1["ungoverned-namespaces"]
        for path, text in rendered1.items():
            if path == "composed/HEADER.yaml":
                continue
            assert "ungoverned" not in text, path
            assert "acme" not in text, path
            # composed/governed-namespace-guard.yaml legitimately carries
            # GOVERNED_LABEL in its own namespaceSelector (ADR-0014) -- a
            # structurally different, correct use of the same string, not
            # a leak of composition's own ungoverned-namespace bookkeeping.
            if path != "composed/governed-namespace-guard.yaml":
                assert GOVERNED_LABEL not in text, path
        print("OK HEADER.yaml: carries the recorded ungoverned namespaces, and stripping it "
              "leaves every other rendered file unchanged -- nothing composition renders reads "
              "either namespace set")

    # ======================================================================
    # eco-system ticket 38: a hole is priced, not counted
    # ======================================================================

    # --- the ramp and the bound, as pure arithmetic: a share of the residual,
    # ramped by the EOL feed's own eol_ramp from `since`, never above the
    # whole residual ---
    assert ungoverned_price(1000.0, 1, 4, 1.0) == (250.0, False)
    assert ungoverned_price(1000.0, 1, 4, 5.0) == (1000.0, True)   # 1250 bounded at the residual
    assert ungoverned_price(1000.0, 4, 4, 1.0) == (1000.0, False)
    assert ungoverned_price(1000.0, 0, 0, 3.0) == (0.0, False)     # nothing inside prices nothing
    r3d = _ramp("2026-08-25", "2026-08-28")
    assert 1.0 < r3d < 1.01 and math.isclose(r3d, 1.0 + 3 / 365.0), r3d
    assert _ramp("2026-08-25", "2026-08-20") == 1.0            # as_of before since: no ramp
    assert _ramp(None, "2026-08-28") == 1.0 and _ramp("2026-08-25", None) == 1.0
    assert _ramp("2020-01-01", "2030-01-01") == 5.0            # capped at +4x, the feed's own cap
    print("OK ungoverned_price/_ramp: workload share x the EOL feed's own ramp from since, "
          "bounded at the whole uncaged residual; no since or no as_of ramps nothing (1.0)")

    # --- the one live ramp case: tuppence-reset, recorded ungoverned since
    # tuppence's first signed composed artefact. `since` is READ off the first
    # signed tag whose header names it, never typed; the date below is that
    # tag's own date, so this assert is a fact about the clone, not a fixture ---
    tuppence = DEFAULT_ESTATE_CLONE / "tuppence"
    since, since_limit = _first_signed_since(tuppence, "tuppence-reset")
    signed = _signed_tags(tuppence)
    if signed:
        assert since is not None and re.match(r"^\d{4}-\d{2}-\d{2}$", since), (since, since_limit)
        assert since in {d for _t, d in signed}, (since, signed)
        assert _first_signed_since(tuppence, "no-such-namespace") == (
            None, "no signed composed artefact names no-such-namespace"), "an unnamed namespace has no since"
        doc_t, rendered_t = compose(tuppence, parent_trees)
        _assert_only_known_dangling(doc_t["refusals"], "real tuppence")
        reset = next(e for e in doc_t["ungoverned"] if e["namespace"] == "tuppence-reset")
        assert reset["status"] == "recorded", reset
        p = reset["price"]
        _ns, counts = _namespace_facts(tuppence)
        assert p["workloads"] == counts.get("tuppence-reset", 0) > 0, (p, counts)
        assert p["workloads_total"] == sum(n for ns, n in counts.items() if ns in _ns), (p, counts)
        assert p["share"] == p["workloads"] / p["workloads_total"], p
        assert p["since"] == since and p["as_of"] and p["ramp"] == _ramp(since, p["as_of"]), p
        header_t = yaml.safe_load(rendered_t["composed/HEADER.yaml"])
        assert p["base"] == header_t["exposure"]["total"], (p["base"], header_t["exposure"]["total"])
        assert p["amount"] == min(p["base"], p["base"] * p["share"] * p["ramp"]), p
        assert p["perspective"] == "tuppence" and p["currency"] == "GBP", p
        assert p["limits"] == [], p["limits"]
        assert not [r for r in doc_t["refusals"] if r["kind"] == "new-ungoverned-namespace"]
        print("OK ungoverned[]: the real tuppence-reset prices at %.2f %s -- %d of %d institution "
              "workloads (share %.2f) x ramp %.4f from since %s (the first signed tag naming it) "
              "as of %s, of a %.2f residual%s"
              % (p["amount"], p["currency"], p["workloads"], p["workloads_total"], p["share"],
                 p["ramp"], p["since"], p["as_of"], p["base"],
                 ", bounded at the whole residual" if p["bounded"] else ""))
    else:
        print("OK ungoverned[]: the tuppence clone carries no signed tag, so tuppence-reset's "
              "since could not be read here (named: %s)" % since_limit)

    # --- (source, id): claims and holes resolve across EVERY controls parent,
    # an adopter's own catalogue included; the header encodes the source only
    # where it is not the baseline's own, so the real estate's header shape
    # is byte-stable ---
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        nist_root = root / "fixture-nist"
        _write_fixture_catalog(nist_root)
        platform_root = root / "fixture-platform"
        _write_fixture_platform(platform_root, parent_trees["platform"], claims=[("aa-1", "member-a")])
        _write_small_catalog(root / "fixture-nist2", {"cc-1": {}, "aa-2": {}})   # aa-2 collides on purpose
        fixture_trees = {"fixture-nist": nist_root, "fixture-platform": platform_root,
                         "fixture-nist2": root / "fixture-nist2"}
        second = {"party": "fixture-nist2", "kind": "controls", "version": "1.0.0"}

        two = root / "two-sources"
        _write_fixture_adopter(two, "SMALL", controls_add=["fixture-nist2:cc-1"], extra_inherits=[second])
        docA, renderedA = compose(two, fixture_trees)
        assert docA["outcome"] == "composed", docA
        keys = {(h["source"], h["control_id"]): h["status"] for h in docA["holes"]}
        assert keys == {("fixture-nist", "aa-1.1"): "recorded", ("fixture-nist", "aa-2"): "recorded",
                        ("fixture-nist2", "cc-1"): "recorded"}, keys
        headerA = yaml.safe_load(renderedA["composed/HEADER.yaml"])
        assert headerA["holes"] == ["aa-1.1", "aa-2", "fixture-nist2:cc-1"], headerA["holes"]
        assert "fixture-nist2:cc-1" in headerA["selected-controls"] and "aa-1" in headerA["selected-controls"]
        _commit_header(two, renderedA)
        docB, _ = compose(two, fixture_trees)          # the encoding round-trips
        assert {(h["source"], h["control_id"]): h["status"] for h in docB["holes"]} == keys, docB["holes"]
        assert docB["deltas"] == [], docB["deltas"]
        print("OK (source, id): a control added from a second controls parent is a hole keyed on "
              "its own source; the header encodes `source:id` only off the baseline's catalogue "
              "and round-trips as recorded")

        # A bare id resolves against the baseline's catalogue and nowhere else:
        # `aa-2` bare is fixture-nist's, `fixture-nist2:aa-2` is the other one.
        amb = root / "bare-vs-namespaced"
        _write_fixture_adopter(amb, "SMALL", controls_add=["fixture-nist2:aa-2", "cc-1"], extra_inherits=[second])
        docC, _ = compose(amb, fixture_trees)
        assert docC["outcome"] == "refused", docC
        unknown = [r for r in docC["refusals"] if r["kind"] == "unknown-control-id"]
        assert len(unknown) == 1 and "cc-1" in unknown[0]["subject"], docC["refusals"]
        assert ("fixture-nist2", "aa-2") in {(h["source"], h["control_id"]) for h in docC["holes"]}
        print("OK (source, id): a bare id resolves against the baseline's catalogue only (bare cc-1 "
              "is unknown there), and fixture-nist2:aa-2 is a different control from aa-2")

        # A claim is keyed on (source, id) by its source href: the same bare id
        # claimed under fixture-nist2's href covers fixture-nist2:cc-1 and not
        # fixture-nist's aa-2.
        claimed = root / "claim-source"
        _write_fixture_adopter(claimed, "SMALL", controls_add=["fixture-nist2:cc-1"],
                                add=[{"version": "1.0.0", "manifest": own_member}], extra_inherits=[second])
        _write_component_definition(claimed / ADOPTER_CLAIMS_FILE, [("cc-1", "own-policy")],
                                     source="../fixture-nist2/catalog/catalog.json")
        docD, _ = compose(claimed, fixture_trees)
        assert docD["outcome"] == "composed", docD
        assert ("fixture-nist2", "cc-1") not in {(h["source"], h["control_id"]) for h in docD["holes"]}
        _write_component_definition(claimed / ADOPTER_CLAIMS_FILE, [("cc-1", "own-policy")],
                                     source="../fixture-nist/catalog/catalog.json")
        docE, _ = compose(claimed, fixture_trees)
        assert [r["kind"] for r in docE["refusals"]] == ["unknown-control-id"], docE["refusals"]
        assert ("fixture-nist2", "cc-1") in {(h["source"], h["control_id"]) for h in docE["holes"]}
        print("OK resolve_claims: a claim resolves on (source, id) through its source href -- "
              "cc-1 under fixture-nist2's href fills fixture-nist2:cc-1; the same id under "
              "fixture-nist's href is unknown there and fills nothing")

        # --- a bespoke control: the adopter pins ITSELF as a controls parent,
        # ships a small OSCAL catalogue, and prices the hole with a scenario it
        # signs. No scenario is the one remaining refusal (an instrument fault,
        # ADR-0020) ---
        self_edge = {"party": "fixture-adopter14", "kind": "controls", "version": "0.0.0"}
        bespoke = root / "bespoke"
        _write_fixture_adopter(bespoke, "SMALL", controls_add=["fixture-adopter14:zz-1"],
                                extra_inherits=[self_edge])
        _write_small_catalog(bespoke, {"zz-1": {"scenario": "scenarios/zz-1.json"}})
        (bespoke / "scenarios").mkdir()
        shutil.copy(PLATFORM_DIR / scenario_rel, bespoke / "scenarios" / "zz-1.json")
        docF, renderedF = compose(bespoke, fixture_trees)     # no tree for the self-pin: adopter_dir is it
        assert docF["outcome"] == "composed", docF
        zz = _hole(docF, "zz-1")
        assert zz["source"] == "fixture-adopter14" and zz["status"] == "recorded", zz
        assert zz["amount"] and zz["amount"] > 0 and "scenarios/zz-1.json" in zz["priced_by"], zz
        assert zz["perspective"] == "fixture-adopter14" and zz["currency"] == "GBP", zz
        assert "fixture-adopter14:zz-1" in yaml.safe_load(renderedF["composed/HEADER.yaml"])["holes"]
        self_parent = next(p for p in docF["parents"] if p["party"] == "fixture-adopter14")
        assert self_parent["kind"] == "controls" and self_parent["sha"], self_parent
        print("OK bespoke: an adopter pinning itself as a controls parent adds fixture-adopter14:zz-1 "
              "as a hole priced by its own signed scenario (%.2f %s), the self-pin resolving to "
              "the adopter's own tree" % (zz["amount"], zz["currency"]))

        _write_small_catalog(bespoke, {"zz-1": {}})           # the scenario prop goes
        docG, _ = compose(bespoke, fixture_trees)
        assert docG["outcome"] == "refused", docG
        faults = [r for r in docG["refusals"] if r["kind"] == "missing-instrument"]
        assert len(faults) == 1 and "zz-1" in faults[0]["subject"], docG["refusals"]
        assert "scenario" in faults[0]["detail"], faults
        assert [r["kind"] for r in docG["refusals"]] == ["missing-instrument"], docG["refusals"]
        print("OK bespoke: the same control with no signed scenario refuses as a missing "
              "instrument naming zz-1 -- the one hole-shaped refusal that remains (ADR-0020)")

        _write_component_definition(bespoke / ADOPTER_CLAIMS_FILE, [("zz-1", "own-policy")],
                                     source="catalog/catalog.json")
        docH_yaml = yaml.safe_load((bespoke / "party.yaml").read_text())
        docH_yaml["overlay"]["add"] = [{"version": "1.0.0", "manifest": own_member}]
        (bespoke / "party.yaml").write_text(yaml.safe_dump(docH_yaml, sort_keys=False))
        docH, _ = compose(bespoke, fixture_trees)
        assert docH["outcome"] == "composed", docH
        assert "zz-1" not in {h["control_id"] for h in docH["holes"]}, docH["holes"]
        print("OK bespoke: a bespoke control the adopter's own claim covers is no hole, so it "
              "needs no scenario and nothing refuses")

        # --- the self-pin listed FIRST in inherits[] (an order an adopter is
        # free to write). The recorded header keys its bare ids to the first
        # controls parent that is NOT the adopter, exactly as compose() keys
        # baseline_source, so an unchanged tree re-composes clean: no
        # removed-control refusal, no new-hole delta (the 2026-09-04 review's
        # blocking defect: reading the FIRST controls parent decoded every
        # bare id as the adopter's own and refused the whole baseline) ---
        first = root / "bespoke-self-first"
        _write_fixture_adopter(first, "SMALL", controls_add=["fixture-adopter14:zz-1"],
                                extra_inherits=[self_edge])
        first_yaml = yaml.safe_load((first / "party.yaml").read_text())
        first_yaml["inherits"] = [self_edge, *[e for e in first_yaml["inherits"]
                                               if e["party"] != "fixture-adopter14"]]
        (first / "party.yaml").write_text(yaml.safe_dump(first_yaml, sort_keys=False))
        _write_small_catalog(first, {"zz-1": {"scenario": "scenarios/zz-1.json"}})
        (first / "scenarios").mkdir()
        shutil.copy(PLATFORM_DIR / scenario_rel, first / "scenarios" / "zz-1.json")
        docI, renderedI = compose(first, fixture_trees)
        assert docI["outcome"] == "composed" and docI["refusals"] == [] and docI["deltas"] == [], docI
        assert docI["parents"][0]["party"] == "fixture-adopter14", docI["parents"]
        headerI = yaml.safe_load(renderedI["composed/HEADER.yaml"])
        assert "aa-2" in headerI["holes"] and "fixture-adopter14:zz-1" in headerI["holes"], headerI["holes"]
        _commit_header(first, renderedI)
        docJ, _ = compose(first, fixture_trees)
        assert docJ["outcome"] == "composed", docJ["refusals"]
        assert docJ["refusals"] == [] and docJ["deltas"] == [], (docJ["refusals"], docJ["deltas"])
        assert {h["status"] for h in docJ["holes"]} == {"recorded"}, docJ["holes"]
        print("OK _header_controls_source: with the self-pin listed first in inherits[], an "
              "unchanged tree re-composes clean -- bare header ids decode to the first controls "
              "parent that is not the adopter, as compose() keys them, so nothing refuses as "
              "removed and nothing prints as a new hole")

        # --- a band in one currency cannot price a bespoke hole labelled in
        # another: this path takes no rate, so it refuses as a missing
        # instrument naming both, never a relabelled (minted) amount ---
        first_yaml["appetite"]["tolerance"]["currency"] = "USD"
        (first / "party.yaml").write_text(yaml.safe_dump(first_yaml, sort_keys=False))
        docK, _ = compose(first, fixture_trees)
        faults = [r for r in docK["refusals"] if r["kind"] == "missing-instrument"]
        assert len(faults) == 1 and "zz-1" in faults[0]["subject"], docK["refusals"]
        assert "USD" in faults[0]["detail"] and "GBP" in faults[0]["detail"], faults
        assert _hole(docK, "zz-1")["amount"] is None, _hole(docK, "zz-1")
        print("OK bespoke: an appetite band in USD cannot price a bespoke hole reported in GBP -- "
              "no rate is taken on this path, so it refuses as a missing instrument naming both "
              "currencies rather than relabelling the residual")

    # --- the regime entry's holes[] carry each hole's status next to its
    # weighted amount, and a widening against the real catalogue prints the
    # number of added controls a pinned weight actually prices ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        doc0, rendered0 = compose(work, parent_trees)
        _assert_only_known_dangling(doc0["refusals"], "real widening, before")
        regime0 = next(e for e in doc0["prices"] if _parent_key(e) == "penalty-schema")
        statuses = {(h["source"], h["id"]): h["status"] for h in regime0["holes"]}
        assert statuses and set(statuses.values()) <= {"new", "recorded", "closed", "covered", "unselected"}, statuses
        open_keys = {(h["source"], h["control_id"]) for h in doc0["holes"] if h["status"] != "closed"}
        for key, status in statuses.items():
            assert (status in ("new", "recorded")) == (key in open_keys), (key, status)
        priced_holes = [h for h in doc0["holes"] if h["amount"] is not None]
        assert priced_holes and all(h["priced_by"] for h in priced_holes), doc0["holes"][:3]
        assert all(math.isclose(h["amount"], next(r["amount"] for r in regime0["holes"]
                                                  if (r["source"], r["id"]) == (h["source"], h["control_id"])))
                   for h in priced_holes)
        _commit_header(work, rendered0)
        doc_yaml = yaml.safe_load((work / "party.yaml").read_text())
        doc_yaml["baseline"] = "HIGH"
        (work / "party.yaml").write_text(yaml.safe_dump(doc_yaml, sort_keys=False))
        _write_baseline_configmap(work, "HIGH")
        doc1, _ = compose(work, parent_trees)
        _assert_only_known_dangling(doc1["refusals"], "real widening, after")
        widening = next(d for d in doc1["deltas"] if d["kind"] == "baseline-widening")
        new_holes = [d for d in doc1["deltas"] if d["kind"] == "new-hole"]
        assert widening["subject"] == "MODERATE -> HIGH" and widening["added"] == len(new_holes) > 0, widening
        assert widening["priced"] == len([d for d in new_holes if d["amount"] is not None]), widening
        assert widening["perspective"] == "driftwood" and widening["currency"] == "GBP", widening
        print("OK deltas[]: driftwood MODERATE -> HIGH composes and prints one widening delta -- "
              "%d controls added, %d of them named by ico's pinned weights (amount %s), each "
              "added control a new-hole delta beside it; the regime entry's holes[] carry status"
              % (widening["added"], widening["priced"],
                 "none" if widening["amount"] is None else "%.2f" % widening["amount"]))

    # ======================================================================
    # ticket 16: pricing and threat parents re-price, and never apply
    # ======================================================================

    # --- an ico penalty-schema bump (v1 -> v2) moves the uncaged exposure
    # on uk-gdpr/lower-tier through ico's own converter; on driftwood's
    # real band both versions land on the same tier, so the document
    # prints no change; no rendered file changes on the price move ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        # Start the copy at v1 whatever the real party is pinned to today: this
        # case is about a v1 -> v2 MOVE, not about which version driftwood
        # happens to carry (it pins v3, the first with control_weights).
        _bump_parent_version(work, "ico", "pricing", "v1")
        doc0, rendered0 = compose(work, parent_trees)
        _assert_only_known_dangling(doc0["refusals"], "ico bump, before")
        _commit_header(work, rendered0)
        _bump_parent_version(work, "ico", "pricing", "v2")
        doc1, files1 = compose(work, parent_trees)
        _assert_only_known_dangling(doc1["refusals"], "ico bump, after")
        price = next(p for p in doc1["prices"] if _parent_key(p) == "penalty-schema")
        assert price["source"] == "ico", price
        assert price["old_version"] == "v1" and price["new_version"] == "v2", price
        assert price["old_price"] != price["new_price"], price
        assert price["old_tier"] == price["proposed_tier"] == "isolated", price
        assert price["changed"] is False, price
        # ADR-0022: isolated is a REAL label value -- a running, unreachable
        # cage -- so this travels as a label, never as an issue.
        assert price["proposed_as"] == "label", price
        _assert_only_the_moved_feed_changed(rendered0, files1)
    print("OK prices[]: an ico penalty-schema bump (v1 -> v2) moves the uncaged uk-gdpr/lower-"
          "tier exposure through ico's own converter; on driftwood's real band both versions "
          "land on isolated, the bottom rung, so the document prints no tier change and it "
          "travels as a label; no rendered POLICY file changes -- a byte comparison proves it, "
          "and the only file that does move is the adopter's own vendored copy of the payload "
          "that moved")

    # --- a threat-register bump (v1 -> v2) moves tuppence's exposure
    # through the feeds module; same real-band 'no change' shape ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("tuppence", Path(td))
        doc0, rendered0 = compose(work, parent_trees)
        _assert_only_known_dangling(doc0["refusals"], "threat bump, before")
        _commit_header(work, rendered0)
        _bump_parent_version(work, "platform", "threat", "v2")
        doc1, files1 = compose(work, parent_trees)
        _assert_only_known_dangling(doc1["refusals"], "threat bump, after")
        price = next(p for p in doc1["prices"] if _parent_key(p) == "threat-register")
        assert price["source"] in ("platform", "feeds"), price
        assert price["old_version"] == "v1" and price["new_version"] == "v2", price
        assert price["old_price"] != price["new_price"], price  # v2 raises tuppence's LEF
        assert price["old_tier"] == price["proposed_tier"] == "isolated", price
        assert price["changed"] is False, price
        _assert_only_the_moved_feed_changed(rendered0, files1)
    print("OK prices[]: a threat-register bump (v1 -> v2) moves tuppence's exposure through the "
          "feeds module; on the real band both versions land on isolated, no tier change; no "
          "rendered POLICY file changes")

    # --- a fixture band that a bump crosses prints a proposed tier, and
    # the mark flips from 'label' (a real tier) as soon as it stops being
    # deny -- proved through compose(), the only sanctioned seam (spec.md's
    # own Testing Decisions names the pricing call off-limits to assert on
    # directly), since no real appetite band anywhere in the estate
    # actually straddles a boundary on either real price move above (the
    # prototype's own honest finding, reproduced: the wiring moves, the
    # real-band outcome does not). Only ico's own tree is fixtured -- the
    # bump crosses driftwood's real GBP40,000 tolerance, not a fixture one ---
    with tempfile.TemporaryDirectory() as td:
        work = _adopter_copy("driftwood", Path(td))
        fixture_ico = Path(td) / "fixture-ico"
        _write_fixture_ico(fixture_ico, parent_trees["ico"])
        crossing_parents = dict(parent_trees, ico=fixture_ico)
        _bump_parent_version(work, "ico", "pricing", "v1")   # the fixture publishes v1 and v2

        doc0, rendered0 = compose(work, crossing_parents)
        _assert_only_known_dangling(doc0["refusals"], "crossing fixture, before")
        _commit_header(work, rendered0)
        _bump_parent_version(work, "ico", "pricing", "v2")
        doc1, files1 = compose(work, crossing_parents)
        _assert_only_known_dangling(doc1["refusals"], "crossing fixture, after")
        price = next(p for p in doc1["prices"] if _parent_key(p) == "penalty-schema")
        assert price["old_version"] == "v1" and price["new_version"] == "v2", price
        assert price["old_tier"] == "isolated", price
        assert price["proposed_tier"] == "quarantine", price
        assert price["changed"] is True, price
        assert price["proposed_as"] == "label", price  # quarantine is a real label value
        _assert_only_the_moved_feed_changed(rendered0, files1)
    print("OK prices[]: a fixture ico band (v1->v2) that crosses driftwood's real GBP40,000 "
          "tolerance prints a proposed tier through compose() (isolated -> quarantine, "
          "changed=True), marked as a label; no rendered POLICY file changes")

    # ------------------------------------------------------------------
    # ECO-SYSTEM TICKET 45: switching cost, and the vendored feed tree
    # ------------------------------------------------------------------
    # One switching entry per SUBSTITUTABLE parent edge -- a feed, because a
    # feed is discovered through publishes[] and any party may publish one
    # (ADR-0019 point 5). Its amount is measured, not modelled: the same
    # composition is re-priced with that publisher's feed edges dropped and
    # the two priceable exposures are differenced.
    # `document` and `rendered` above are rebound by the fixtures in between, so
    # this section composes the real driftwood again rather than grading a
    # leftover -- the mistake this very assertion caught on its first run.
    doc45, rendered45 = compose(driftwood, _real_parent_trees())
    assert doc45["outcome"] == "composed", doc45["refusals"]
    drift_doc = yaml.safe_load((driftwood / "party.yaml").read_text())
    feed_edges = [e for e in drift_doc["inherits"] if e.get("kind") in FEED_KINDS]
    switching = [e for e in doc45["prices"] if e["kind"] == "switching"]
    assert len(switching) == len(feed_edges), (len(switching), len(feed_edges))
    by_name = {e["name"]: e for e in switching}
    assert set(by_name) == {_feed_name(e) for e in feed_edges}, sorted(by_name)
    for entry in switching:
        assert entry["perspective"] == "driftwood", entry
        assert entry["currency"] == "GBP", entry
        assert entry["source"] != "driftwood", entry
        # Every price carries a perspective and a currency, and restates itself
        # per customer against the perspective party's own signed size.
        assert entry["sized"] is True, entry
        if entry["amount"] is None:
            # A counterfactual that could not be priced is a NAMED could-not-
            # look: no amount, no restatement, and the publisher's own refusal
            # carried verbatim.
            assert entry["could_not_look"] and entry["over_pin_life"] is None, entry
            assert entry["per_customer"] is None, entry
        else:
            assert entry["could_not_look"] is None, entry
            assert entry["per_customer"]["currency"] == "GBP", entry
            assert math.isclose(entry["per_customer"]["amount"] * drift_doc["size"]["customers"],
                                entry["amount"]), entry
            assert math.isclose(entry["over_pin_life"],
                                entry["amount"] * entry["pin_life_months"] / MONTHS_PER_YEAR), entry
        # Annualised over the pin's life: a rate, and the window it has been
        # running over, from the edge's own signed `since` and the composition's
        # own as-of. No clock is read (D1).
        assert entry["since"] == "2026-08-28", entry
        assert entry["as_of"] and entry["pin_life_months"] >= 0, entry
        # Nobody in this estate publishes a second feed of any of these names,
        # so the alternate set is EMPTY and said so by name -- never assumed.
        assert entry["alternates"] == [], entry
        assert entry["basis"] == SWITCHING_BASIS, entry

    # The regime feed is the biggest single line driftwood prices, and dropping
    # ico takes exactly that line out of the priceable exposure.
    ico_regime_price = next(e for e in doc45["prices"]
                            if e["kind"] == "feed" and e["name"] == "penalty-schema")
    assert math.isclose(by_name["penalty-schema"]["amount"], ico_regime_price["amount"]), \
        (by_name["penalty-schema"]["amount"], ico_regime_price["amount"])
    # Dropping the THREAT publisher is not a number at all, and re-composing is
    # the only way to find that out: driftwood's own forward-intel borrows its
    # loss-event frequency from the threat register it subscribes to, so with
    # that publisher gone the twin has no frequency to annualise on and the
    # whole composition refuses. Subtracting the line we were about to lose
    # would have printed a confident GBP19,558 and been wrong by the rest of
    # the book. The entry carries no amount, the publisher's own refusal
    # verbatim, and every price that stops being computable.
    threat = by_name["threat-register"]
    assert threat["amount"] is None and "no lef" in threat["could_not_look"], threat
    assert {(u["kind"], u.get("name")) for u in threat["unpriceable"]} == \
        {(e["kind"], e.get("name")) for e in doc45["prices"] if e["kind"] != "switching"}, threat
    # The insurer's quote is a COST, not exposure. Dropping it moves the
    # priceable exposure by nothing, and the premium that goes with it is
    # NAMED rather than folded into a figure it does not belong in.
    quote = by_name["quote-driftwood"]
    assert math.isclose(quote["amount"], 0.0, abs_tol=1e-9), quote
    assert [(u["kind"], u["source"]) for u in quote["unpriceable"]] == [("premium", "insurer")], quote
    print("OK prices[]: one `switching` entry per feed edge, each measured by re-composing with "
          "that publisher's edges dropped -- ico's costs its whole regime line, the threat "
          "publisher's is not a number at all because driftwood's own twin borrows that feed's "
          "LEF and stops pricing without it, and the insurer's moves the exposure by nothing "
          "and names the premium it would lose instead of folding it in")

    # --- the vendored feed tree: the adopter's own copy of every priced
    # payload and the converter that priced it, under its own signature ---
    vendored = {p: c for p, c in rendered45.items() if p.startswith("composed/feeds/")}
    for edge in feed_edges:
        base = f"composed/feeds/{edge['party']}/{edge['version']}"
        assert f"{base}/party.yaml" in vendored, sorted(vendored)
        assert f"{base}/PROVENANCE.json" in vendored, sorted(vendored)
        record = json.loads(vendored[f"{base}/PROVENANCE.json"])
        assert record["party"] == edge["party"] and record["name"] == edge["name"], record
        assert record["sha"] == next(p["sha"] for p in doc45["parents"]
                                     if p["party"] == edge["party"]
                                     and p.get("name") == edge["name"]), record
        # Every vendored file is digested INTO the record, and the record is
        # rendered, so the adopter's own tag signs the digests.
        for rel, digest in record["files"].items():
            assert f"{base}/{rel}" in vendored, (rel, sorted(vendored))
            assert hashlib.sha256(vendored[f"{base}/{rel}"].encode()).hexdigest() == digest, rel
        assert vendored[f"{base}/{record['feed_path']}"] == \
            feed_file("", edge["name"], edge["version"],
                      _real_parent_trees()[edge["party"]]).read_text(), record
    # The threat register's publisher ships no converter of its own: composition
    # falls back to platform's copy, and the record says whose copy priced it.
    assert json.loads(vendored["composed/feeds/feeds/v2/PROVENANCE.json"])["converter_from"] \
        == "platform", vendored["composed/feeds/feeds/v2/PROVENANCE.json"]
    # A quote feed is priced without a converter at all, so none is vendored --
    # a named absence, never an empty file that pretends to be one.
    assert json.loads(vendored["composed/feeds/insurer/v1/PROVENANCE.json"])["converter"] is None
    header_doc = yaml.safe_load(rendered45["composed/HEADER.yaml"])
    assert sorted(v["path"] for v in header_doc["vendored-feeds"]) == \
        sorted(f"composed/feeds/{e['party']}/{e['version']}" for e in feed_edges), header_doc
    print("OK composed/feeds/: every priced payload, the publisher's own party artefact and the "
          "converter that priced it are vendored under the adopter's own signature, digested "
          "into a PROVENANCE.json the header names, with the converter's real source party "
          "recorded and a quote feed's absent converter named rather than faked")

    # --- and the point of vendoring: the prices re-derive with the publisher
    # clone ABSENT (ticket 45's verify-portability, proved here at the seam) ---
    with tempfile.TemporaryDirectory() as tmp:
        work = _adopter_copy("driftwood", Path(tmp) / "driftwood")
        for extra in ("twin", "selection-policy"):
            shutil.copytree(driftwood / extra, work / extra)
        _, first = compose(work, _real_parent_trees())
        for rel, content in first.items():
            target = work / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        # The reference is this same tree composed with every clone PRESENT, so
        # the comparison is publisher-absent against publisher-present and not
        # against a differently-shaped copy.
        doc_present, _ = compose(work, _real_parent_trees())
        without_ico = {p: t for p, t in _real_parent_trees().items() if p != "ico"}
        doc_absent, _ = compose(work, without_ico)
        assert doc_absent["outcome"] == "composed", doc_absent["refusals"]
        priced = {(e["kind"], e.get("name")): e["amount"] for e in doc_absent["prices"]}
        assert priced, doc_absent["prices"]
        for entry in doc_present["prices"]:
            got = priced[(entry["kind"], entry.get("name"))]
            if entry["amount"] is None:
                assert got is None, (entry, got)
            else:
                assert math.isclose(got, entry["amount"]), (entry, got)
        limit = next(l for l in doc_absent["limits"] if l["name"] == VENDORED_LIMIT)
        assert limit["status"] == "open" and "ico" in limit["detail"], limit
        # ...and a TAMPERED vendored payload is refused, not priced: the digest
        # the adopter's own tag signs is what the re-derivation is held to.
        payload = work / "composed" / "feeds" / "ico" / "v3" / "penalty-schema" / "v3" / "feed.json"
        payload.write_text(payload.read_text().replace("uk-gdpr", "uk-gdpr ", 1))
        doc_tampered, _ = compose(work, without_ico)
        assert doc_tampered["outcome"] == "refused", doc_tampered["prices"]
        assert any("missing instrument" in e and "digest" in e
                   for e in doc_tampered["party_artefact_errors"]), doc_tampered
    print("OK portability: with ico's clone ABSENT, driftwood re-derives every price it signed, "
          "from its own vendored payload and converter, and prints the substitution as an open "
          "limit; a tampered vendored payload refuses against the digest its own tag signed")

    # --- a feed edge with no `since` cannot be annualised over a pin's life,
    # and that is a missing instrument, not a defaulted window (ADR-0020) ---
    with tempfile.TemporaryDirectory() as tmp:
        work = _adopter_copy("driftwood", Path(tmp) / "driftwood")
        doc_party = yaml.safe_load((work / "party.yaml").read_text())
        for e in doc_party["inherits"]:
            if e.get("name") == "penalty-schema":
                e.pop("since", None)
        (work / "party.yaml").write_text(yaml.safe_dump(doc_party, **YAML_KWARGS))
        doc_nosince, _ = compose(work, _real_parent_trees())
        assert doc_nosince["prices"] == [], doc_nosince["prices"]
        assert any(r["kind"] == "missing-instrument" and "since" in r["detail"]
                   and "penalty-schema" in r["detail"] for r in doc_nosince["refusals"]), \
            doc_nosince["refusals"]
    print("OK switching: a feed edge carrying no `since` refuses as a missing instrument naming "
          "the edge -- a pin's life is a window between two signed dates, never a default")

    # --- no scheduler, no wall-clock read anywhere in composition.py
    # itself, except through an explicit --as-of passed to the feeds
    # module (spec.md's own acceptance wording) -- neither converter this
    # section calls even takes one: ico's build and the feeds module's
    # threat subcommand are both timeless, and an "eol" parent kind does
    # not exist in the party artefact schema at all ---
    # Import statements in the real, load-bearing code above selfcheck(),
    # not prose or this very check's own forbidden-token list (both would
    # otherwise match themselves) -- composition.py never gained the
    # CAPABILITY to read a clock or a scheduler at all.
    own_source = Path(__file__).read_text().split("\ndef selfcheck()", 1)[0]
    forbidden_imports = ("import datetime", "from datetime", "import time",
                          "import sched", "import croniter")
    hits = [tok for tok in forbidden_imports if tok in own_source]
    assert not hits, hits
    print("OK composition.py itself calls no scheduler and reads no wall clock of its own")

    print(
        "\nselfcheck ok: one seam composes the real driftwood against its real pinned parents; "
        "every member of every live version renders back byte-identical after the header is "
        "stripped; two members of one family at one version both survive (real estate and a "
        "dedicated fixture); no validationActions leaks onto a mutate or a generate; the orphan "
        "guard composes under the platform tag and matches its own offline twin; the header "
        "carries the composed marker, every parent SHA once, the baseline and the governed "
        "namespace names; verify() catches a byte-for-byte drift; the CLI writes files and "
        "exits non-zero on a refusal; a split diamond and a cross-party rule conflict refuse, "
        "naming both edges/sources/contents; a restatement of a mutate refuses; a stricter "
        "restatement is accepted and rendered; a weaker restatement is caged against the "
        "estate's real cage engine and appetite bands, rendering the inherited action and "
        "pricing driftwood/tuppence/ludlow to the prototype's own baseline/baseline/quarantine "
        "table; no tier ever appears in the rendered artefact; the two-publisher limit prints "
        "open at one and closed at two; every refusal carries needs_composition. TICKET 14: the "
        "baseline resolves by name exact-string, walking nested controls (ac-6.10 found); a "
        "prefixed or upper-case id is a hard failure, not a hole; the real estate's first "
        "composition records 285 holes and refuses on none -- platform's own two formerly-"
        "dangling claims (ac-6, cm-6) are now fixed, so a real first composition composes "
        "clean; a new hole composes and prints as a priced delta; a closed hole is marked so; "
        "an adopter-added control is a priced hole unfilled and is filled by the adopter's own "
        "claim against its own overlay.add member; a removed control refuses and a widened "
        "baseline prints as a priced delta; a claim against a parent's policy refuses; and the "
        "header carries the recorded hole ids and the selected control set, in a file that "
        "strips away clean. TICKET 15: a Namespace with no institution label is ignored "
        "entirely; the first composition records a pre-existing ungoverned namespace; a "
        "recorded one records and does not refuse; one that gains the governed label prints as "
        "closed; a genuinely new one composes, priced as its workload share; and the header "
        "carries the recorded ungoverned set, in a file that strips away clean, with neither "
        "namespace set ever read by anything composition renders. ECO-SYSTEM TICKET 38: the "
        "new-hole, baseline-widening and new-ungoverned-namespace refusals are gone and each "
        "prints as a deltas[] entry under the adopter's perspective and currency; an ungoverned "
        "namespace prices as its workload share of the uncaged residual, ramped by the EOL "
        "feed's own eol_ramp from the first signed tag naming it and bounded at the whole "
        "residual (tuppence-reset is the live case); claims and holes resolve on (source, id) "
        "across every controls parent, an adopter's own catalogue included; a bespoke control "
        "prices by the scenario its adopter signs, and one with no scenario is the one "
        "hole-shaped refusal left, a missing instrument. TICKET 16: an ico penalty-schema bump and a threat-"
        "register bump each move the priced exposure through the estate's own converters, "
        "printing old/new price and old/proposed tier every run; on the real bands neither "
        "changes a tier; a fixture band that a bump crosses prints a proposed tier; every "
        "selected tier is a real label value now that ADR-0022 retired the deny rung and made "
        "the bottom rung a running, unreachable `isolated` cage; no rendered POLICY file ever "
        "changes on a price move (narrowed by ticket 45: the adopter's own vendored copy of "
        "the payload that moved does, and nothing under composed/feeds/ is an applied object); "
        "and composition itself reads no wall clock and calls no scheduler. TICKET 25 (the £ seam, ADR-0020/ADR-0021): every prices[] entry names its "
        "perspective, currency, source and kind and restates its own amount per customer "
        "against the perspective party's OWN signed size; the one summing helper "
        "(fair.sum_prices) refuses any list crossing a perspective or a currency; a regime "
        "entry pinned at an ico version that publishes control weights carries a per-hole "
        "breakdown whose amounts sum to the entry amount; the adopter's own forward-intel "
        "feed prices as ONE source:twin entry naming its selection-policy version, curve hash "
        "and fair.py's tail, and a missing forward-intel feed is silence, not a refusal; an "
        "adopter with no signed appetite refuses as a missing instrument and prices nothing; "
        "and the adopter's own overlay.floor clamps the selection UP and never down. "
        "TICKET 36 (the insurer quote slice): the composed artefact signs an `exposure` section "
        "-- the adopter's total priced exposure under its own perspective and currency, its "
        "appetite as the attachment, and the breakdown by regime name and control id -- and the "
        "insurer's signed quote books as ONE `premium` contract cost line under the adopter's "
        "perspective, is left out of the exposure it was priced from, and refuses as a missing "
        "instrument if it insures another party or books its premium on another party's sheet. "
        "ECO-SYSTEM TICKET 69: the premium entry reads the pin's signature state off the "
        "insurer tree's own tags; an untagged pin composes with a hole of its own premium under "
        "the adopter's perspective and currency, printed as a new-untagged-pin delta, recorded "
        "on the next composition, kept open under an unobserved tree, and closed by the first "
        "signed tag that carries it -- never a refusal and never a claimed signature; and only "
        "a checkout that can show the publisher's tag namespace says `untagged` at all, so a "
        "tagless checkout, a lightweight tag and a flattened annotated tag read `unobserved` "
        "rather than booking a hole over a signature that is really there. "
        "ECO-SYSTEM TICKET 45 (the switching cost, computed in composition): every "
        "substitutable parent -- a feed, because publishes[] is what discovers one -- carries a "
        "`switching` entry under the adopter's own perspective and currency, measured by "
        "RE-COMPOSING with that publisher's edges dropped rather than by subtracting the line "
        "about to be lost, annualised and carried over the life the pin has actually stood "
        "from the edge's own signed `since` to this composition's own as-of; a counterfactual "
        "that cannot be priced at all is a named could-not-look carrying the publisher's own "
        "refusal and no amount; a premium that stops being computable is named beside the "
        "figure and never folded into it; an edge with no `since` refuses as a missing "
        "instrument; every priced payload, its publisher's party artefact and the converter "
        "that priced it are vendored under composed/feeds/<party>/<version>/ and digested into "
        "the header the adopter's own tag signs; and with a publisher's clone ABSENT the "
        "adopter re-derives every price it signed from that vendored copy, printing the "
        "substitution as an open limit, while a tampered copy refuses against its own signed "
        "digest."
    )



def _assert_only_the_moved_feed_changed(before: dict[str, str], after: dict[str, str]) -> None:
    """A price move rewrites no rendered POLICY file -- the estate's oldest
    promise about pricing, and the byte comparison that proves it.

    Narrowed 2026-09-06 (eco-system ticket 45). The adopter now vendors the
    payload it was priced from under `composed/feeds/<party>/<version>/`, so a
    bump DOES add its new version's copy and drop the old one's. That is the
    whole point of vendoring and not a leak of a price into an applied file:
    nothing under composed/feeds/ is a Kubernetes object, no Kustomization path
    reaches it, and the promise it would break -- a tier appearing in something
    Kyverno reads -- is untouched. The narrowing is stated here rather than by
    quietly widening the comparison."""
    vendored = "/".join(VENDORED_DIR) + "/"
    for path, content in before.items():
        if path == "composed/HEADER.yaml" or path.startswith(vendored):
            continue
        assert after[path] == content, path
    assert {p for p in after if not p.startswith(vendored)} == \
        {p for p in before if not p.startswith(vendored)}, (sorted(after), sorted(before))


def _write_versions_yaml(root: Path, versions: list[dict]) -> None:
    (root / "distribution").mkdir(parents=True, exist_ok=True)
    doc = {
        "apiVersion": "fluxcd.controlplane.io/v1", "kind": "ResourceSet",
        "metadata": {"name": "policy-versions", "namespace": "flux-system"},
        "spec": {"inputs": [{"versions": versions}], "resourcesTemplate": ""},
    }
    (root / "distribution" / "versions.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))


def _write_admission_doc(path: Path, kind: str, name: str, family: str, version: str,
                          validation_actions: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "apiVersion": "policies.kyverno.io/v1alpha1", "kind": kind,
        "metadata": {"name": name, "labels": {
            LABEL_FAMILY: family, LABEL_VERSION: version,
        }},
        "spec": {},
    }
    if validation_actions is not None:
        doc["spec"]["validationActions"] = validation_actions
    path.write_text(yaml.safe_dump(doc, sort_keys=False))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
