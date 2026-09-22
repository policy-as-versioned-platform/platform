#!/usr/bin/env bash
# Beat (ticket 26, ADR-0022; re-aimed by eco-system ticket 113, 2026-09-22).
#
# `infra` is a ROLE declaration, not a rung. The platform declares its three
# substrate Namespaces -- kube-system, flux-system and kyverno -- at
# `posture.acme.io/tier: infra`, and only a `platform`-role party may. No
# served cage-tier body reads the word, by decision (ticket 113): a rung is a
# cage with dials, and any `infra` dial row would either repeat `isolated` or
# be looser than it, which is an exemption bought by choosing a Namespace.
# What the declaration does is NAME the substrate, and this check reads it to
# know which Namespaces to guard. Four proofs:
#
#   1. DECLARATION: kube-system, flux-system and kyverno each carry
#      `posture.acme.io/tier: infra` on their own Namespace manifest, in the
#      platform's own namespaces.yaml files. No allowlist anywhere.
#   2. ENTITLEMENT: the party declaring them (platform/party.yaml) carries
#      the `platform` role (ADR-0022).
#   3. THE SUBSTRATE IS OUTSIDE THE CAGE, BY MATCH CONDITION. CoreDNS, Flux's
#      controllers and Kyverno's own pods claim no policy version. What keeps
#      them out of the cage is not the `infra` label: it is that
#        a. every served cage-tier body carries the `claims-a-policy-version`
#           matchCondition, so a pod with no claim is never matched, and
#        b. none of the substrate Namespaces is governed, so
#           `governed-namespace-requires-claim` (which cages an UNCLAIMED pod
#           on the bottom rung) never reaches them either.
#      Proof 3a reads PLACEMENT as well as text: the file must be one
#      MutatingPolicy document, and the gate must be an item of that
#      policy's one spec.matchConditions list, equal to the claim test as a
#      whole. A second policy document, or the gate's words parked in an
#      annotation, each left the text in the file while the engine caged
#      CoreDNS (second review of PR 28, 2026-09-22).
#      Break either one and every substrate pod lands on `isolated` -- no
#      ingress, no egress -- and the cluster stops. That is the live hazard,
#      and this is the tripwire for it. Until 2026-09-22 this proof guarded a
#      different configuration: "pull an infra declaration while the default
#      reads isolated". No served body produces that outcome, because no body
#      reads `infra` and an unclaimed pod is skipped with the label or without
#      it (measured under kyverno 1.18.2 by the hub's
#      tests/test_cage_ladder_holes.py). The old proof passed on a hazard that
#      did not exist.
#   4. A CLAIMING POD IN THE SUBSTRATE FALLS CLOSED. A pod that DOES claim a
#      version in one of those Namespaces is cage-tier's. `infra` is not in the
#      body's membership test, so it gets the body's ungoverned else-branch.
#      That must be `isolated`, the rung the ladder gives whatever it cannot
#      place. Under 4.0.0 it is `baseline`, the LOOSEST rung, so anyone who can
#      deploy into the substrate can run a claiming workload with the lightest
#      cage on the ladder. This proof names every served body that still does
#      that and FAILS until none does. A body that starts reading `infra` also
#      fails here, by name: that is a new decision, not a shape to guess at.
#
# "Served" means what is delivered to a cluster: each line distribution/
# versions.yaml DECLARES, the graded/ authoring copy the next line is cut
# from, and each adopter's composed copy. The retired 1.x-3.x trees and the
# vselfcheck fixture are frozen and delivered nowhere, so they are not read.
#
# THREE served body shapes exist, and proof 4 reads all three:
#   a. the pre-namespaceObject flat CEL,
#      `...['posture.acme.io/tier'].orValue('<default>')` -- the retired trees;
#   b. the namespaceObject ternary `nsGoverned ? 'isolated' : '<default>'` --
#      4.0.0, vselfcheck and every adopter composed copy pinned to 4.0.0;
#   c. the COLLAPSED else-branch, `? variables.nsTier : '<default>'` --
#      graded and 5.0.0 since 2026-09-04 (ticket 63).
# A shape this check cannot see reads None, and None is an offender in
# proof 4, never a safe guess.
#
# COMMENTS ARE STRIPPED before any of that (ticket 63): the flip's own
# changelog comment quoted the shape it replaced and was read as shape (b).
#
# Wholly offline: reads YAML/text off disk, touches no cluster. Never turns
# absence of a served copy into a pass -- at least one must be found.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/.." && pwd)"
ESTATE="$(cd "$PLATFORM/.." && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*"; exit 3; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || skip "python3 required"
[ -f "$PLATFORM/party.yaml" ] || skip "platform/party.yaml not found"

# The selfcheck is what proves the parsers and both substrate proofs still
# BITE; run it from the no-argument path, so a regression in the checker
# cannot ship unnoticed behind a green real run (the gate calls this script
# with no args).
if [ -z "${1:-}" ]; then
  say "0. selfcheck: the parsers and the substrate proofs bite (and a COMMENT declares nothing)"
  bash "$0" --selfcheck >/dev/null || fail "the selfcheck did not bite -- the checker itself has regressed"
fi

python3 - "$PLATFORM" "$ESTATE" "${1:-}" <<'PY'
import glob, os, re, sys

platform, estate, selfcheck = sys.argv[1], sys.argv[2], sys.argv[3] == "--selfcheck"
INFRA_NS = ["kube-system", "flux-system", "kyverno"]
LABEL = "posture.acme.io/tier"
GOVERNED = "policy-as-versioned.dev/governed"
FALLS_CLOSED = "isolated"
# The one matchCondition that keeps an unclaimed pod out of cage-tier. Read as
# the expression the served bodies carry, whitespace-insensitive.
CLAIM_GATE = ("object.metadata.?labels['policy-as-versioned.dev/policy-version']"
              ".orValue('') != ''")


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def strip_comments(text):
    """A `#` that starts a line or follows whitespace is a comment; a `#`
    inside a value would be part of the token, and no label or CEL here has
    one. Prose about a policy is not the policy (ticket 63, 2026-08-28)."""
    return re.sub(r"(?m)(?:^|(?<=\s))#.*$", "", text)


def parse_namespace_docs(text):
    """No pyyaml dependency assumed on the estate's plain python3 -- these
    manifests are flat `Namespace` docs with a one-line flow map (or a small
    indented block) for labels. Returns {name: {label: value, ...}} for every
    `kind: Namespace` document. COMMENTS ARE STRIPPED FIRST: engine/
    namespaces.yaml's own header comment contains the words
    `posture.acme.io/tier: infra`, and until 2026-08-28 prose satisfied the
    declaration."""
    docs = {}
    for doc in re.split(r"^---\s*$", text, flags=re.M):
        doc = strip_comments(doc)
        if "kind: Namespace" not in doc:
            continue
        m = re.search(r"^\s*name:\s*(\S+)", doc, re.M)
        if not m:
            continue
        name = m.group(1).strip().strip('"').strip("'")
        lm = re.search(r"^\s*labels:\s*(?:\{(?P<flow>[^}]*)\}|\n(?P<block>(?:[ \t]+\S.*\n?)+))",
                       doc, re.M)
        chunk = ""
        if lm:
            chunk = lm.group("flow") or lm.group("block") or ""
        labels = dict(re.findall(r"([a-zA-Z0-9.\-_/]+)\s*:\s*\"?([a-zA-Z0-9.\-_]+)\"?", chunk))
        docs[name] = labels
    return docs


def substrate_labels(platform_dir):
    """{name: labels} for each of INFRA_NS the platform's own namespaces.yaml
    files declare (access, engine, identity). Read per name, straight off the
    manifests; no namespace LIST is built or emitted (ADR-0018 §1)."""
    found = {}
    for plane in ("access", "engine", "identity"):
        p = os.path.join(platform_dir, plane, "namespaces.yaml")
        if not os.path.isfile(p):
            continue
        for name, labels in parse_namespace_docs(open(p).read()).items():
            if name in INFRA_NS:
                found[name] = labels
    return found


def declared_infra(platform_dir):
    """Proof 1: every one of INFRA_NS carries posture.acme.io/tier: infra."""
    found = {n: l.get(LABEL) for n, l in substrate_labels(platform_dir).items()}
    missing = [n for n in INFRA_NS if found.get(n) != "infra"]
    return missing, found


def platform_role_ok(platform_dir):
    """Proof 2: platform/party.yaml's roles[] includes 'platform'."""
    text = open(os.path.join(platform_dir, "party.yaml")).read()
    m = re.search(r"^roles:\s*\[([^\]]*)\]", text, re.M)
    if not m:
        return False
    return "platform" in [r.strip() for r in m.group(1).split(",")]


def declared_versions(platform_dir):
    """The lines distribution/versions.yaml DECLARES -- the ones Flux
    delivers. Comments stripped: the file's changelog prose names versions
    too."""
    p = os.path.join(platform_dir, "distribution", "versions.yaml")
    if not os.path.isfile(p):
        return []
    return re.findall(r"\{\s*version:\s*\"([^\"]+)\"", strip_comments(open(p).read()))


def served_cage_tier_files(estate_dir, platform_dir):
    """Every cage-tier body that is delivered somewhere: each declared line,
    the graded/ authoring copy, and each adopter's composed copy. Returns (found, missing):
    a line versions.yaml declares whose body is absent is named in `missing`, never dropped,
    because the gate cannot vouch for a body it did not read."""
    out, missing = [], []
    for v in declared_versions(platform_dir):
        p = os.path.join(platform_dir, "distribution", "policies", f"v{v}", "cage-tier.yaml")
        if os.path.isfile(p):
            out.append(p)
        else:
            missing.append(v)
    g = os.path.join(platform_dir, "graded", "policies", "cage-tier.yaml")
    if os.path.isfile(g):
        out.append(g)
    out.extend(sorted(glob.glob(os.path.join(estate_dir, "*", "composed", "policies", "*",
                                             "cage-tier.yaml"))))
    return out, missing


def policy_body(text):
    """A served policy body with its COMMENTS REMOVED and its rendered escapes
    unfolded. A rendered version tree writes each CEL expression as one
    double-quoted YAML scalar with literal backslash-n escapes, the authoring
    copy uses a block scalar with real newlines; unfolding makes one set of
    regexes read both."""
    return strip_comments(text).replace("\\n", "\n")


def indent_of(line):
    return len(line) - len(line.lstrip())


def block_after(lines, i):
    """The lines under the key on `lines[i]`: every following line up to the first non-blank one
    indented less than the key, or at the key's indent and not a `- ` list item (YAML lets a
    block sequence sit at its parent key's indent, which is how a rendered body writes it)."""
    ind = indent_of(lines[i])
    out = []
    for line in lines[i + 1:]:
        if line.strip():
            d = indent_of(line)
            if d < ind or (d == ind and not line.lstrip().startswith("-")):
                break
        out.append(line)
    return out


def yaml_documents(text):
    """The non-empty YAML documents in a file, split on `---` lines. Comments are already gone."""
    return [d for d in re.split(r"(?m)^---(?:[ \t].*)?$", text) if d.strip()]


def claim_gate_expressions(lines):
    """Every `claims-a-policy-version` expression among the ITEMS of a matchConditions block,
    read WHOLE. Only an item line counts (a `- name:` at the block's item indent), so text nested
    inside another item is not an entry. The value runs from `expression:` to the first non-blank
    line indented no deeper than the `expression:` key, so a plain one-line scalar, its
    continuation lines and a `>-` block scalar all come back entire. Reading only a prefix let
    `<gate> || true` pass as the gate (review of PR 28)."""
    items = [indent_of(l) for l in lines if l.strip()]
    item_ind = items[0] if items else -1
    out = []
    for i, line in enumerate(lines):
        if indent_of(line) != item_ind:
            continue
        if not re.match(r"^\s*-\s*name:\s*['\"]?claims-a-policy-version['\"]?\s*$", line):
            continue
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j >= len(lines):
            out.append("")
            continue
        m = re.match(r"^(?P<ind>\s*)expression:\s?(?P<rest>.*)$", lines[j])
        if not m or len(m.group("ind")) <= item_ind:
            out.append("")
            continue
        ind = len(m.group("ind"))
        rest = m.group("rest").strip()
        parts = [] if re.fullmatch(r"[>|][-+]?", rest) else [rest]
        k = j + 1
        while k < len(lines):
            nxt = lines[k]
            if nxt.strip() and indent_of(nxt) <= ind:
                break
            parts.append(nxt.strip())
            k += 1
        expr = " ".join(p for p in parts if p)
        if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in "'\"":
            expr = expr[1:-1]
        out.append(expr)
    return out


def claim_gate_problem(text):
    """Proof 3a, as a pure function over a body's text. None when the body is ONE MutatingPolicy
    whose one `spec.matchConditions` list carries the `claims-a-policy-version` entry EXACTLY as
    the claim test, nothing added before or after it; otherwise the reason it is not.

    Placement is read, not just text (second review of PR 28, 2026-09-22): a second policy
    document in the file with no gate, or the gate's words parked in an annotation while the real
    matchCondition admits every pod, each let the engine cage an unclaimed CoreDNS pod at
    `isolated` while a whole-file search still found the gate. Extra matchConditions are allowed:
    the engine ANDs them, so they only narrow. The expression is compared whitespace-insensitively,
    so the authoring block scalar and the rendered one-line form both match. Comments are stripped
    first; the `\\n` escapes are NOT unfolded here, so a string cannot forge a key line."""
    docs = yaml_documents(strip_comments(text))
    if len(docs) != 1:
        return f"{len(docs)} YAML documents, not one policy"
    lines = docs[0].split("\n")
    kinds = [m.group(1) for l in lines for m in [re.match(r"^kind:\s*(\S+)\s*$", l)] if m]
    if kinds != ["MutatingPolicy"]:
        return f"top-level kind {kinds}, not one MutatingPolicy"
    specs = [i for i, l in enumerate(lines) if re.match(r"^spec:\s*$", l)]
    if len(specs) != 1:
        return f"{len(specs)} top-level spec blocks, not one"
    spec = block_after(lines, specs[0])
    child = min((indent_of(l) for l in spec if l.strip()), default=0)
    keys = [i for i, l in enumerate(spec)
            if indent_of(l) == child and re.match(r"^\s*matchConditions:", l)]
    if len(keys) != 1:
        return f"{len(keys)} spec.matchConditions keys, not one"
    if not re.match(r"^\s*matchConditions:\s*$", spec[keys[0]]):
        return "spec.matchConditions is not a block list"
    exprs = claim_gate_expressions(block_after(spec, keys[0]))
    if not exprs:
        return "no claims-a-policy-version entry in spec.matchConditions"
    squash = lambda s: re.sub(r"\s+", "", s)
    if any(squash(e) != squash(CLAIM_GATE) for e in exprs):
        return "claims-a-policy-version is not exactly the claim test"
    return None


def carries_claim_gate(path):
    """Proof 3a over a file. A body without the gate, with it loosened, or with it anywhere but
    the one policy's own matchConditions, matches an UNCLAIMED pod -- CoreDNS included."""
    return claim_gate_problem(open(path).read()) is None


def unlabelled_default(path):
    """The tier an UNGOVERNED namespace falls to when this body has no tier
    opinion for it. Three shapes, checked in the order a served copy migrates
    through (collapsed, ternary, flat). None if none matches."""
    text = policy_body(open(path).read())
    m = re.search(r"\?\s*variables\.nsTier\s*:\s*'([a-zA-Z]+)'", text)
    if m:
        return m.group(1)
    m = re.search(r"nsGoverned\s*\?\s*'isolated'\s*:\s*'([a-zA-Z]+)'", text)
    if m:
        return m.group(1)
    m = re.search(r"posture\.acme\.io/tier'\]\.orValue\('([a-zA-Z]+)'\)", text)
    return m.group(1) if m else None


def reads_infra(path):
    """True when the body itself (not its prose) mentions `infra`. Ticket 113
    decided no served body does; one that does has a rung this check cannot
    read off the else-branch."""
    return re.search(r"\binfra\b", policy_body(open(path).read())) is not None


def substrate_rung(path):
    """Proof 4: the rung a pod that CLAIMS a version gets in an ungoverned
    `infra` Namespace under this body. `infra` is outside the membership
    test, so it is the ungoverned else-branch. 'reads-infra' if the body now
    reads the word, None for a shape this check cannot see."""
    if reads_infra(path):
        return "reads-infra"
    return unlabelled_default(path)


def outside_the_cage(claim_gated, substrate):
    """Proof 3, as a pure function: the served bodies that match an unclaimed
    pod, and the substrate Namespaces that are governed. Both lists empty is
    the only PASS."""
    ungated = sorted(f for f, ok in claim_gated.items() if not ok)
    governed = sorted(n for n, labels in substrate.items() if labels.get(GOVERNED) == "true")
    return ungated, governed


def falls_closed(rungs):
    """Proof 4, as a pure function: every body whose substrate rung is not
    `isolated`. None and 'reads-infra' are offenders, never a safe guess."""
    return sorted((f, r) for f, r in rungs.items() if r != FALLS_CLOSED)


if selfcheck:
    import tempfile
    # parse_namespace_docs: flow map, block map, and a comment declares nothing
    docs = parse_namespace_docs(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kyverno\n"
        "  labels: { platform.acme.io/plane: engine, posture.acme.io/tier: infra }\n")
    assert docs["kyverno"]["posture.acme.io/tier"] == "infra", docs
    docs = parse_namespace_docs(
        "# All three Namespaces below carry `posture.acme.io/tier: infra`\n"
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kyverno\n"
        "  labels: { platform.acme.io/plane: engine }\n")
    assert docs["kyverno"].get("posture.acme.io/tier") is None, docs
    docs = parse_namespace_docs(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kyverno\n"
        "  labels:\n    platform.acme.io/plane: engine\n    posture.acme.io/tier: infra\n")
    assert docs["kyverno"]["posture.acme.io/tier"] == "infra", docs

    # proof 3 as a pure function: a clean estate passes, each break fires by name
    assert outside_the_cage({"a": True}, {"kube-system": {LABEL: "infra"}}) == ([], [])
    assert outside_the_cage({"a": False}, {"kube-system": {LABEL: "infra"}}) == (["a"], []), \
        "a body without the claim gate cages CoreDNS and must fire"
    assert outside_the_cage({"a": True}, {"kube-system": {GOVERNED: "true"}}) == ([], ["kube-system"]), \
        "a governed substrate Namespace puts CoreDNS under the unclaimed-pod cage and must fire"
    # proof 4 as a pure function: isolated passes, anything else fires, unknown fires
    assert falls_closed({"a": "isolated"}) == []
    assert falls_closed({"a": "baseline"}) == [("a", "baseline")]
    assert falls_closed({"a": None}) == [("a", None)], "an unread shape is an offender"
    assert falls_closed({"a": "reads-infra"}) == [("a", "reads-infra")], \
        "a body that reads infra is a new decision, not a guess"

    tmp = tempfile.mkdtemp(prefix="verify-infra-")
    body = os.path.join(tmp, "cage-tier.yaml")

    def write(text):
        open(body, "w").write(text)
        return body

    # the claim gate: authoring block scalar, rendered one-line form, missing, and a
    # gate loosened to something that admits the unclaimed. Each fragment is read inside a
    # real policy document, because proof 3a reads placement, not just text.
    def policy(spec, name="cage-tier", meta=""):
        return (f"apiVersion: policies.kyverno.io/v1alpha1\nkind: MutatingPolicy\nmetadata:\n"
                f"  name: {name}\n{meta}spec:\n  matchConstraints:\n    resourceRules: []\n{spec}")

    def gated(spec, **kw):
        return carries_claim_gate(write(policy(spec, **kw)))

    gate_block = ("  matchConditions:\n    - name: claims-a-policy-version\n      expression: >-\n"
                  "        object.metadata.?labels['policy-as-versioned.dev/policy-version']"
                  ".orValue('') != ''\n")
    gate_line = ("  matchConditions:\n  - name: claims-a-policy-version\n    expression: "
                 "object.metadata.?labels['policy-as-versioned.dev/policy-version'].orValue('') != ''\n"
                 "  - name: only-this-policy-version\n    expression: x == '5.0.0'\n")
    any_pod = "  matchConditions:\n    - name: any-pod\n      expression: 'true'\n"
    assert gated(gate_block), "authoring block-scalar gate must be read"
    assert gated(gate_line), "rendered one-line gate must be read"
    assert not gated("  matchConditions: []\n"), "no gate must read as no gate"
    assert not gated(gate_block.replace("!= ''", "!= 'x' || true")), \
        "a gate loosened to admit the unclaimed is not the gate"
    # the real gate kept as a PREFIX and loosened after it: a prefix match read these as the
    # gate while the engine caged an unclaimed pod at isolated (review of PR 28, 2026-09-22)
    assert not gated(gate_block.replace("!= ''", "!= '' || true")), \
        "block scalar: the gate with `|| true` after it admits the unclaimed"
    assert not gated(gate_line.replace("!= ''\n", "!= '' || true\n", 1)), \
        "one-line form: the gate with `|| true` after it admits the unclaimed"
    assert not gated(gate_line.replace("!= ''\n", "!= ''\n      || true\n", 1)), \
        "one-line form: a `|| true` continuation line admits the unclaimed"
    assert not gated(gate_block + "        || true\n"), \
        "block scalar: a `|| true` continuation line admits the unclaimed"
    assert gated(gate_block + "  variables:\n    - name: x\n      expression: y\n"), \
        "the next key after the gate is not part of the gate"
    assert not gated(
        "  # - name: claims-a-policy-version\n  #   expression: >-\n"
        "  #     object.metadata.?labels['policy-as-versioned.dev/policy-version'].orValue('') != ''\n"
        "  matchConditions: []\n"), "a COMMENTED-OUT gate is no gate"
    # PLACEMENT (second review of PR 28, 2026-09-22): each of these carries the gate's exact
    # text somewhere in the file while the engine cages an unclaimed pod, or cannot be read
    shadow = policy(any_pod, name="cage-tier-shadow")
    assert not carries_claim_gate(write(policy(gate_block) + "---\n" + shadow)), \
        "a second policy document without the gate matches every pod"
    assert not carries_claim_gate(write(policy(gate_block) + "--- \n" + shadow)), \
        "a `---` with trailing space still starts a document"
    note = "".join("      " + l + "\n" for l in gate_block.splitlines()[1:])
    assert not gated(any_pod, meta="  annotations:\n    note: |\n" + note), \
        "the gate's words in an annotation are not the policy's matchCondition"
    assert not gated(gate_block + any_pod), "a duplicated matchConditions key is not one gate"
    assert not gated("  matchConstraints2:\n" + gate_block.replace("  ", "    ", 1) + any_pod), \
        "the gate nested under another key is not spec.matchConditions"
    assert not gated("  matchConditions: [{name: claims-a-policy-version, expression: x}]\n"), \
        "a flow-form list is not read, so it is not vouched for"
    assert not gated(gate_block.replace("    - name: claims", "    - name: any-pod\n"
                                        "      expression: 'true'\n"
                                        "      note:\n        - name: claims", 1)), \
        "a gate-shaped line nested inside another item is not an item"
    assert not carries_claim_gate(write(policy(gate_block).replace("kind: MutatingPolicy",
                                                                    "kind: List"))), \
        "a body that is not one MutatingPolicy is not vouched for"

    # unlabelled_default: all three shapes, the danger value, the safe value, prose ignored
    write("    - name: tier\n      expression: >-\n"
          "        variables.nsTier in ['baseline','restricted','quarantine','isolated']\n"
          "          ? variables.nsTier\n"
          "          : (variables.nsGoverned ? 'isolated' : 'baseline')\n")
    assert unlabelled_default(body) == "baseline", "ternary shape: the loose value must be read"
    write("        object.metadata.?labels['posture.acme.io/tier'].orValue('baseline')\n")
    assert unlabelled_default(body) == "baseline", "flat orValue shape must be read"
    write("no tier expression of any known shape in this file\n")
    assert unlabelled_default(body) is None, "an unrecognised shape must read as None"
    collapsed = ("    - name: tier\n      expression: >-\n"
                 "        variables.nsTier in ['baseline', 'restricted', 'quarantine', 'isolated']\n"
                 "          ? variables.nsTier\n"
                 "          : 'isolated'\n")
    write(collapsed)
    assert unlabelled_default(body) == "isolated", "collapsed shape, block scalar"
    write('  - name: tier\n    expression: "variables.nsTier in [\'baseline\', \'restricted\']'
          "\\n  ? variables.nsTier\\n  : 'isolated'\"\n")
    assert unlabelled_default(body) == "isolated", "collapsed shape, rendered \\n form"
    write("    # collapsed from `nsGoverned ? 'isolated' : 'baseline'` on 2026-09-04\n" + collapsed)
    assert unlabelled_default(body) == "isolated", "prose quoting an older shape must not outvote the expression"
    write("# `nsGoverned ? 'isolated' : 'baseline'`\napiVersion: policies.kyverno.io/v1alpha1\n")
    assert unlabelled_default(body) is None, "a body whose ONLY match is a comment declares nothing"

    # substrate_rung: prose about infra is not a reader; a membership test that admits it is
    write("# `infra` is deliberately absent from the dial table\n" + collapsed)
    assert substrate_rung(body) == "isolated", "a COMMENT mentioning infra must not count as a reader"
    write(collapsed.replace("'isolated']", "'isolated', 'infra']"))
    assert substrate_rung(body) == "reads-infra", "a body that admits infra must be named, not guessed"

    # declared_versions reads the array, not the prose
    os.makedirs(os.path.join(tmp, "distribution"))
    open(os.path.join(tmp, "distribution", "versions.yaml"), "w").write(
        "        # { version: \"9.9.9\" } was never declared\n"
        "    - versions:\n        - { version: \"4.0.0\", tag: \"policy/v4.0.0\" }\n"
        "        - { version: \"5.0.0\", tag: \"policy/v5.0.0\" }\n")
    assert declared_versions(tmp) == ["4.0.0", "5.0.0"], declared_versions(tmp)
    # a declared line with no body on disk is NAMED, never dropped from the served set
    os.makedirs(os.path.join(tmp, "distribution", "policies", "v5.0.0"))
    open(os.path.join(tmp, "distribution", "policies", "v5.0.0", "cage-tier.yaml"), "w").write("x\n")
    found, missing = served_cage_tier_files(os.path.join(tmp, "no-estate"), tmp)
    assert [os.path.basename(os.path.dirname(f)) for f in found] == ["v5.0.0"], found
    assert missing == ["4.0.0"], missing
    import shutil
    shutil.rmtree(tmp)
    print("ok   selfcheck: namespace parsing, the claim gate, the governed read, the substrate "
          "rung (all three shapes, a body that reads infra, comments declaring nothing) and the "
          "declared-line read behave as claimed")
    sys.exit(0)

missing, found = declared_infra(platform)
print(f"1. infra declaration: {found}")
if missing:
    fail(f"not declared posture.acme.io/tier: infra for: {', '.join(missing)}")
print("  ok   kube-system, flux-system and kyverno each carry posture.acme.io/tier: infra")

print("2. entitlement: platform/party.yaml roles[] includes 'platform'")
if not platform_role_ok(platform):
    fail("platform/party.yaml does not declare the 'platform' role -- infra declaration is unentitled")
print("  ok   platform/party.yaml carries the platform role")

files, missing = served_cage_tier_files(estate, platform)
if missing:
    fail("versions.yaml declares " + ", ".join(missing) + " but no distribution/policies/v<N>/"
         "cage-tier.yaml exists for it -- a declared line with no body cannot be vouched for")
if not files:
    fail("no served cage-tier.yaml policy body found anywhere -- cannot run the substrate proofs")
rel = lambda f: os.path.relpath(f, estate)

print(f"3. the substrate is outside the cage by match condition, over {len(files)} served bodies")
problems = {f: claim_gate_problem(open(f).read()) for f in files}
ungated, governed = outside_the_cage({f: p is None for f, p in problems.items()},
                                     substrate_labels(platform))
if ungated:
    fail(f"served cage-tier bodies without the claims-a-policy-version gate: "
         f"{', '.join(f'{rel(f)} ({problems[f]})' for f in ungated)} -- every unclaimed substrate pod (CoreDNS, Flux, "
         f"Kyverno) would be caged, and the cluster stops")
if governed:
    fail(f"substrate Namespaces carry {GOVERNED}: \"true\": {', '.join(governed)} -- "
         f"governed-namespace-requires-claim would put every unclaimed pod there on the bottom "
         f"rung, and the cluster stops")
print("  ok   every served body skips an unclaimed pod, and no substrate Namespace is governed")

rungs = {f: substrate_rung(f) for f in files}
print("4. a claiming pod in the substrate falls closed -- the rung each served body gives it:")
for f, r in rungs.items():
    print(f"     {rel(f)}: {r!r}")
offenders = falls_closed(rungs)
if offenders:
    fail(f"a pod that claims a policy version in kube-system, flux-system or kyverno is not caged "
         f"at {FALLS_CLOSED!r} under {len(offenders)} served bodies: "
         f"{', '.join(f'{rel(f)}={r}' for f, r in offenders)} -- `infra` is read by none of them, "
         f"so it is their ungoverned else-branch; this closes when every line that serves it is "
         f"retired (eco-system ticket 113)")
print(f"  ok   every served body cages a claiming substrate pod at {FALLS_CLOSED!r}")

print("PASS: the platform declares kube-system, flux-system and kyverno at infra, entitled by "
      "the platform role; every served cage-tier body skips their unclaimed pods and none of "
      "them is governed; and a pod that claims a version there falls closed to isolated.")
PY
