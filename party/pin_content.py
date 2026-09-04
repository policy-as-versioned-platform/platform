#!/usr/bin/env python3
"""pin_content.py -- ONE rule, in one place: a pinned tree must contain the section the pin
is used for (eco-system ticket 77 item 1).

The estate pins its parents by tag and, since ticket 62, by {tag, commit} pair. Everything
that checked a pin checked that the tag RESOLVED. Nothing checked that the tree the tag names
carries what the consumer then prices or enforces out of it. That is not a theoretical hole:
the insurer's three quotes assert `<adopter> exposure v1.1.0`, and no adopter's v1.1.0 tree
has an exposure section at all -- the number was priced from a working tree and attributed to
a tag whose content could not have produced it (found 2026-08-29, and a second time by the
2026-09-02 review).

The rule, stated once:

    a pin names (party, kind, [name], version). The publisher's own party.yaml `publishes[]`
    record for that (kind, name) says WHERE the thing lives in the publisher's tree
    (ADR-0019 point 5: publishes[] is the only discovery record there is). The pin has
    content only if the pinned tree really carries it:

      kind controls / implementations   <path> exists in the tree
      kind feed, payload_schema set     <path>/v<MAJOR>/feed.json exists (an ADR-0019 envelope)
      kind feed, payload_schema null    <path>/HEADER.yaml exists AND carries a section keyed
                                        by the feed's `name` -- the adopter's `exposure`,
                                        which is a SECTION of that party's own signed
                                        artefact and never an envelope of its own

A pin whose tree lacks its section is a MISSING INSTRUMENT (ADR-0020): the consumer cannot
read the signed fact it must price or enforce from, so it refuses rather than guessing. It is
never a count, a denial or a filing.

WHO USES IT. This module is the single source of the rule, and it lives in platform/party/
beside party_artefact.py because that is what every consumer already pins and imports through:

  * platform/compose/composition.py -- refuses a parent pin whose tree lacks the declared path
  * insurer/pricing/quote.py        -- never emits `priced_against` naming a tag whose tree
                                       lacks `exposure`; imports this file out of its own
                                       pinned platform checkout
  * the hub's verify/feed-contract/feed_contract.py -- states the SAME rule again in git
    plumbing, deliberately. The hub is not a party and pins no platform, so it cannot import
    this file; what it can do is read the publisher's real tag out of the clone with
    `git show <tag>:<path>` and apply the same three cases. Two implementations of one rule is
    a cost; the alternative is the hub importing a party's code to grade that party, which is
    worse. The wording of the three cases is kept identical on purpose so a reader can see
    they are the same rule.

No dependency beyond pyyaml (estate scripts are python3 stdlib plus pyyaml).

Usage:
    pin_content.py --selfcheck
"""
from __future__ import annotations

import os
import sys

import yaml

# The exact phrase every consumer's refusal starts with (ADR-0020's one allowed refusal).
MISSING = "missing instrument"


def load_yaml(path):
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def record_for(publisher_doc: dict, kind: str, name: str | None) -> dict | None:
    """The publisher's `publishes[]` record a pin of this (kind, name) resolves to, or None
    when the publisher declares no such thing. `name` is only meaningful for feeds."""
    for entry in publisher_doc.get("publishes") or []:
        if entry.get("kind") != kind:
            continue
        if kind != "feed" or entry.get("name") == name:
            return entry
    return None


def major_of(version) -> str:
    """The major of a pin, whether it is written `v3`, `3.0.0` or `v1.1.0`."""
    return str(version).lstrip("v").split(".")[0]


def missing_section(tree: str, record: dict, version=None) -> str | None:
    """None when the tree carries what the record declares; otherwise the reason it does not,
    in the words the consumer will refuse with. `version` narrows a feed to one major; leave
    it None to ask only whether the feed is published in this tree at all."""
    path = record.get("path")
    if not path:
        return f"the publishes[] record for {record.get('name') or record.get('kind')} names no path"
    full = os.path.join(tree, path)
    if record.get("kind") != "feed":
        return None if os.path.exists(full) else \
            f"the pinned tree has no {path} for the {record.get('kind')} this pin names"

    if record.get("payload_schema") is None:
        # a SECTION of the publisher's own signed artefact, not an envelope of its own
        header = os.path.join(full, "HEADER.yaml")
        if not os.path.isfile(header):
            return f"the pinned tree has no {path}/HEADER.yaml, so the {record['name']} section " \
                   f"this pin names cannot be in it"
        section = (load_yaml(header) or {}).get(record["name"])
        if not isinstance(section, (dict, list)):
            return f"the pinned tree's {path}/HEADER.yaml carries no {record['name']} section -- " \
                   f"the tag resolves, but not to the content this pin is used for"
        return None

    if version is None:
        published = [d for d in sorted(os.listdir(full)) if d.startswith("v")] \
            if os.path.isdir(full) else []
        if any(os.path.isfile(os.path.join(full, d, "feed.json")) for d in published):
            return None
        return f"the pinned tree publishes no {path}/v*/feed.json for the feed this pin names"
    feed = os.path.join(full, f"v{major_of(version)}", "feed.json")
    return None if os.path.isfile(feed) else \
        f"the pinned tree has no {path}/v{major_of(version)}/feed.json, so the " \
        f"{record['name']} this pin names at {version} is not in it"


def refusal_for_pin(tree: str, party: str, kind: str, name: str | None, version,
                    require_declaration: bool = False) -> str | None:
    """The whole rule for one pin: read the publisher's own party.yaml out of the PINNED tree
    (never out of a working copy -- the point is to grade the tree that was pinned), find the
    publishes[] record, and check the tree carries it. Returns the refusal message, or None.

    A pinned tree with NO party.yaml is not a refusal by default. This rule grades a DECLARED
    section against the tree that was pinned; with no declaration there is nothing to grade,
    and turning an unknowable into a refusal would fail every synthetic parent tree a caller
    composes against while saying nothing about the estate. That every real unit carries a
    party.yaml is a different question, graded by verify/party and by the hub's feed-contract,
    which read the artefacts directly. Callers that have already established the tree is a
    real party's release pass `require_declaration=True` and get the refusal."""
    party_yaml = os.path.join(tree, "party.yaml")
    if not os.path.isfile(party_yaml):
        if not require_declaration:
            return None
        return f"{MISSING}: the pinned {party} tree carries no party.yaml, so what " \
               f"{kind}{'/' + name if name else ''}@{version} names cannot be resolved"
    record = record_for(load_yaml(party_yaml), kind, name)
    if record is None:
        return f"{MISSING}: the pinned {party} tree's party.yaml declares no publishes[] " \
               f"record for {kind}{'/' + name if name else ''}, so this pin names nothing"
    reason = missing_section(tree, record, version)
    return None if reason is None else \
        f"{MISSING}: {party}/{kind}{'/' + name if name else ''}@{version}: {reason}"


# --------------------------------------------------------------------------
def selfcheck() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        def w(rel, obj):
            p = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                yaml.safe_dump(obj, fh)

        ico = os.path.join(tmp, "ico")
        w("ico/party.yaml", {"party": "ico", "roles": ["publisher"], "publishes": [
            {"kind": "feed", "name": "penalty-schema", "path": "penalty-schema",
             "payload_schema": "penalty-schema/payload.schema.json"}]})
        w("ico/penalty-schema/v3/feed.json", {"kind": "feed"})
        assert refusal_for_pin(ico, "ico", "feed", "penalty-schema", "v3") is None
        # a major the pinned tree does not publish
        r = refusal_for_pin(ico, "ico", "feed", "penalty-schema", "v9")
        assert r and "no penalty-schema/v9/feed.json" in r, r
        # a feed the publisher declares nothing about
        r = refusal_for_pin(ico, "ico", "feed", "nope", "v1")
        assert r and "declares no publishes[] record" in r, r

        # the exposure case: a SECTION of the party's own signed artefact
        drift = os.path.join(tmp, "driftwood")
        w("driftwood/party.yaml", {"party": "driftwood", "roles": ["publisher"], "publishes": [
            {"kind": "feed", "name": "exposure", "path": "composed", "payload_schema": None}]})
        w("driftwood/composed/HEADER.yaml", {"perspective": "driftwood"})
        r = refusal_for_pin(drift, "driftwood", "feed", "exposure", "v1.1.0")
        assert r and "carries no exposure section" in r, r
        assert r.startswith(MISSING), r
        w("driftwood/composed/HEADER.yaml", {"perspective": "driftwood",
                                             "exposure": {"total": 1, "currency": "GBP"}})
        assert refusal_for_pin(drift, "driftwood", "feed", "exposure", "v1.1.0") is None
        os.remove(os.path.join(drift, "composed", "HEADER.yaml"))
        r = refusal_for_pin(drift, "driftwood", "feed", "exposure", "v1.1.0")
        assert r and "no composed/HEADER.yaml" in r, r

        # controls / implementations: the path is the whole test
        plat = os.path.join(tmp, "platform")
        w("platform/party.yaml", {"party": "platform", "roles": ["publisher"], "publishes": [
            {"kind": "implementations", "name": "policy", "path": "versions"}]})
        r = refusal_for_pin(plat, "platform", "implementations", None, "2.0.1")
        assert r and "has no versions for the implementations" in r, r
        os.makedirs(os.path.join(plat, "versions"))
        assert refusal_for_pin(plat, "platform", "implementations", None, "2.0.1") is None

        # a tree with no party.yaml declares nothing to grade: silent by default, and a
        # refusal for a caller that has already established this is a real party's release
        nowhere = os.path.join(tmp, "nowhere")
        assert refusal_for_pin(nowhere, "nowhere", "feed", "x", "v1") is None
        r = refusal_for_pin(nowhere, "nowhere", "feed", "x", "v1", require_declaration=True)
        assert r and "carries no party.yaml" in r, r

    print("ok  pin_content selfcheck: an envelope major, a missing major, an undeclared feed, "
          "an exposure section present and absent, a missing HEADER.yaml, an implementations "
          "path present and absent, and a tree with no party.yaml all grade as the rule says")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        selfcheck()
        raise SystemExit(0)
    print(__doc__)
