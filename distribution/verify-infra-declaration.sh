#!/usr/bin/env bash
# Beat (ticket 26, ADR-0022 story 34/35): "the platform declares its own
# Namespaces at the infra tier by role, and that declaration lands -- and
# the truth surface asserts it -- BEFORE the unlabelled-governed-Namespace
# default flips from baseline to isolated." Three proofs:
#
#   1. DECLARATION: kube-system, flux-system and kyverno each carry
#      `posture.acme.io/tier: infra` on their own Namespace manifest, in
#      the platform's own namespaces.yaml files. No allowlist anywhere --
#      each is read straight off the manifest.
#   2. ENTITLEMENT: the party declaring them (platform/party.yaml) carries
#      the `platform` role. Only a platform-role party may declare `infra`
#      (ADR-0022) -- a declaration from any other party renders to
#      `isolated`, so the entitlement is what makes proof 1 mean anything.
#   3. THE ORDERING RULE: scans every served copy of the `cage-tier` policy
#      body (distribution, graded, and each adopter's composed/) for the
#      UNGOVERNED-namespace tier default -- the fallback a Namespace with no
#      `governed: "true"` label renders to (kube-system/flux-system/kyverno
#      included, since none of them are governed). If ANY served copy's
#      default has moved to `isolated` while any of the three infra
#      namespaces is NOT (yet) declared infra, this FAILS LOUDLY -- that gap
#      is exactly what stops CoreDNS landing in isolated the moment the
#      fail-closed default ships. It is a live tripwire, not a historical
#      fact: the flip has now shipped (below), so pulling an infra
#      declaration is what would fire it.
#
#      THREE served shapes exist side by side, and this check must read all
#      three or it goes blind exactly when it matters:
#        a. the pre-namespaceObject flat CEL,
#           `...['posture.acme.io/tier'].orValue('<default>')` -- the
#           retired 2.x/3.x trees;
#        b. the namespaceObject ternary `nsGoverned ? 'isolated' :
#           '<default>'` -- 4.0.0, vselfcheck, and every adopter composed
#           copy still pinned to 4.0.0;
#        c. the COLLAPSED else-branch, `? variables.nsTier : '<default>'` --
#           graded and 5.0.0 since 2026-09-04 (ticket 63). The flip made
#           both arms of (b)'s ternary the same rung, so the ternary and the
#           `nsGoverned` variable it was the only reader of both went away.
#           A shape this check cannot see reads None, never a safe guess.
#
#      COMMENTS ARE STRIPPED before any of that (ticket 63). They were not
#      until 2026-09-04, and the flip's own changelog comment in graded's
#      cage-tier.yaml -- prose quoting the OLD shape, "collapsed from
#      `nsGoverned ? 'isolated' : 'baseline'`" -- was read as shape (b) and
#      reported that already-flipped body as still `baseline`. Same bug this
#      script fixed for parse_namespace_docs on 2026-08-28, one function
#      down: a comment must declare nothing, here too.
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

# The selfcheck is what proves the parser and the ordering rule still BITE; run
# it from the no-argument path, so a regression in the checker cannot ship
# unnoticed behind a green real run (the gate calls this script with no args).
if [ -z "${1:-}" ]; then
  say "0. selfcheck: the parser and the ordering rule bite (and a COMMENT declares nothing)"
  bash "$0" --selfcheck >/dev/null || fail "the selfcheck did not bite -- the checker itself has regressed"
fi

python3 - "$PLATFORM" "$ESTATE" "${1:-}" <<'PY'
import glob, os, re, sys

platform, estate, selfcheck = sys.argv[1], sys.argv[2], sys.argv[3] == "--selfcheck"
INFRA_NS = ["kube-system", "flux-system", "kyverno"]
LABEL = "posture.acme.io/tier"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def parse_namespace_docs(text):
    """No pyyaml dependency assumed on the estate's plain python3 (per the
    brief) -- these manifests are flat `Namespace` docs with a one-line flow
    map for labels, so a small regex walk is the whole job and needs no
    parser. Returns {name: {label: value, ...}} for every `kind: Namespace`
    document in the file.

    COMMENTS ARE STRIPPED FIRST. Until 2026-08-28 the label walk ran over the
    raw document, and engine/namespaces.yaml's own HEADER COMMENT contains the
    words `posture.acme.io/tier: infra` -- so deleting the label from the
    kyverno Namespace's real labels still produced a PASS, read out of prose.
    That made ordering_rule() below, the whole point of this script, permanently
    inert for that namespace. Only the `labels:` mapping is read now, so a
    declaration has to be a declaration."""
    docs = {}
    for doc in re.split(r"^---\s*$", text, flags=re.M):
        # a `#` that starts a line or follows whitespace is a comment; a `#`
        # inside a value would be part of the token, and no label here has one.
        doc = re.sub(r"(?m)(?:^|(?<=\s))#.*$", "", doc)
        if "kind: Namespace" not in doc:
            continue
        m = re.search(r"^\s*name:\s*(\S+)", doc, re.M)
        if not m:
            continue
        name = m.group(1).strip().strip('"').strip("'")
        # Only what sits under `labels:` -- either the one-line flow map these
        # manifests use, or an indented block -- never the whole document.
        lm = re.search(r"^\s*labels:\s*(?:\{(?P<flow>[^}]*)\}|\n(?P<block>(?:[ \t]+\S.*\n?)+))",
                       doc, re.M)
        chunk = ""
        if lm:
            chunk = lm.group("flow") or lm.group("block") or ""
        labels = dict(re.findall(r"([a-zA-Z0-9.\-_/]+)\s*:\s*\"?([a-zA-Z0-9.\-_]+)\"?", chunk))
        docs[name] = labels
    return docs


def declared_infra(platform_dir):
    """Proof 1: read the platform's own namespaces.yaml files (only the
    three this ticket owns -- access, engine, identity) and check every one
    of INFRA_NS carries posture.acme.io/tier: infra. No namespace LIST is
    built or emitted anywhere (ADR-0018 §1) -- this is a read, per name,
    straight off the manifests it was told to check."""
    found = {}
    for plane in ("access", "engine", "identity"):
        p = os.path.join(platform_dir, plane, "namespaces.yaml")
        if not os.path.isfile(p):
            continue
        for name, labels in parse_namespace_docs(open(p).read()).items():
            if name in INFRA_NS:
                found[name] = labels.get(LABEL)
    missing = [n for n in INFRA_NS if found.get(n) != "infra"]
    return missing, found


def platform_role_ok(platform_dir):
    """Proof 2: platform/party.yaml's roles[] includes 'platform' -- the
    only role ADR-0022 entitles to declare infra."""
    text = open(os.path.join(platform_dir, "party.yaml")).read()
    m = re.search(r"^roles:\s*\[([^\]]*)\]", text, re.M)
    if not m:
        return False
    roles = [r.strip() for r in m.group(1).split(",")]
    return "platform" in roles


def served_cage_tier_files(estate_dir):
    pats = [
        "platform/distribution/policies/*/cage-tier.yaml",
        "platform/graded/policies/cage-tier.yaml",
        "*/composed/policies/*/cage-tier.yaml",
    ]
    out = []
    for pat in pats:
        out.extend(sorted(glob.glob(os.path.join(estate_dir, pat))))
    return out


def policy_body(text):
    """A served policy body with its COMMENTS REMOVED and its rendered
    escapes unfolded, ready for the shape regexes below.

    Comments first: a rendered tree and an authoring copy both carry prose,
    and prose about a policy is not the policy. On 2026-09-04 the flip's own
    changelog comment in graded/policies/cage-tier.yaml quoted the shape it
    had just replaced, and unlabelled_default read that quotation instead of
    the live expression -- reporting a body that defaults to `isolated` as
    still `baseline`, which is precisely the direction this tripwire must
    never be wrong in. Then `\\n`: a rendered version tree writes each CEL
    expression as one double-quoted YAML scalar with literal backslash-n
    escapes, while the authoring copy uses a block scalar with real
    newlines. Unfolding makes one set of regexes read both."""
    text = re.sub(r"(?m)(?:^|(?<=\s))#.*$", "", text)
    return text.replace("\\n", "\n")


def unlabelled_default(path):
    """The tier an UNGOVERNED namespace (kube-system/flux-system/kyverno's
    own population) falls to when this served body has no tier opinion for
    it. Three shapes, checked in the order a served copy migrates through:
      1. The COLLAPSED else-branch -- `? variables.nsTier : '<default>'` --
         graded and 5.0.0 since ticket 63 flipped the default. Checked
         first: shape 2's regex cannot match it, but a body carrying both
         (an authoring copy mid-edit) is honestly described by the arm that
         actually runs, which is the collapsed one.
      2. The namespaceObject ternary's else-branch --
         `nsGoverned ? 'isolated' : '<default>'` -- 4.0.0, vselfcheck, and
         every adopter composed copy still pinned to 4.0.0.
      3. The older flat CEL read straight off the pod's own label --
         `...['posture.acme.io/tier'].orValue('<default>')` -- the retired
         2.x/3.x trees, not yet migrated when they were frozen.
    None if this file matches none of them (a shape this check cannot see is
    never treated as safe -- served_cage_tier_files' caller still lists it,
    with its default printed as None, so a genuinely new shape is visible
    in the output rather than silently skipped)."""
    text = policy_body(open(path).read())
    m = re.search(r"\?\s*variables\.nsTier\s*:\s*'([a-zA-Z]+)'", text)
    if m:
        return m.group(1)
    m = re.search(r"nsGoverned\s*\?\s*'isolated'\s*:\s*'([a-zA-Z]+)'", text)
    if m:
        return m.group(1)
    m = re.search(r"posture\.acme\.io/tier'\]\.orValue\('([a-zA-Z]+)'\)", text)
    return m.group(1) if m else None


def ordering_rule(defaults_by_file, missing_infra):
    """THE check this ticket exists for: a served body whose unlabelled
    default is 'isolated' while any infra namespace is undeclared is the
    exact gap that flips CoreDNS/Flux/Kyverno into isolated the instant that
    default ships. Returns the offending (file, default) pairs, or []."""
    if not missing_infra:
        return []
    return [(f, d) for f, d in defaults_by_file.items() if d == "isolated"]


if selfcheck:
    # Pure-function proof of the ordering rule itself, no disk involved:
    # the danger case must fire, and two safe cases must not.
    assert ordering_rule({"a": "isolated"}, ["kube-system"]) == [("a", "isolated")], \
        "isolated default + a missing infra namespace must fail"
    assert ordering_rule({"a": "baseline"}, ["kube-system"]) == [], \
        "baseline default must never fail even with a missing declaration"
    assert ordering_rule({"a": "isolated"}, []) == [], \
        "isolated default is safe once every infra namespace is declared"
    docs = parse_namespace_docs(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kyverno\n"
        "  labels: { platform.acme.io/plane: engine, posture.acme.io/tier: infra }\n"
    )
    assert docs["kyverno"]["posture.acme.io/tier"] == "infra", docs
    # THE COMMENT CASE. engine/namespaces.yaml's real header comment contains
    # the words `posture.acme.io/tier: infra`, and until 2026-08-28 the label
    # walk read the whole document, so prose satisfied the declaration and this
    # script's tripwire was inert. A comment must declare nothing.
    docs = parse_namespace_docs(
        "# All three Namespaces below carry `posture.acme.io/tier: infra`\n"
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kyverno\n"
        "  labels: { platform.acme.io/plane: engine }\n"
    )
    assert docs["kyverno"].get("posture.acme.io/tier") is None, docs
    # and the indented block form of `labels:` is read too
    docs = parse_namespace_docs(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kyverno\n"
        "  labels:\n    platform.acme.io/plane: engine\n    posture.acme.io/tier: infra\n"
    )
    assert docs["kyverno"]["posture.acme.io/tier"] == "infra", docs
    # unlabelled_default must read BOTH served shapes, and the danger value
    # in each -- this is what silently went blind mid-build once the
    # Kyverno half landed the namespaceObject ternary, so it is pinned here.
    tmp = "/tmp/_verify_infra_selfcheck_%d.yaml" % os.getpid()
    open(tmp, "w").write(
        "    - name: tier\n      expression: >-\n"
        "        variables.nsTier in ['baseline','restricted','quarantine','isolated']\n"
        "          ? variables.nsTier\n"
        "          : (variables.nsGoverned ? 'isolated' : 'isolated')\n"
    )
    assert unlabelled_default(tmp) == "isolated", "ternary shape: danger value must be read"
    open(tmp, "w").write(
        "        object.metadata.?labels['posture.acme.io/tier'].orValue('isolated')\n"
    )
    assert unlabelled_default(tmp) == "isolated", "flat orValue shape: danger value must be read"
    open(tmp, "w").write("no tier expression of any known shape in this file\n")
    assert unlabelled_default(tmp) is None, "an unrecognised shape must read as None, not a safe guess"
    # THE COLLAPSED SHAPE (ticket 63). Once both arms of the ternary became
    # `isolated` the ternary went, and with it the only regex this check had.
    # An unread shape is a None, and a None is not an offender -- so without
    # this leg the flip would have shipped invisible to the tripwire that
    # gates it. Both the authoring block scalar and the rendered one-line
    # form with literal \n escapes are pinned, because the served copies use
    # one each.
    open(tmp, "w").write(
        "    - name: tier\n      expression: >-\n"
        "        variables.nsTier in ['baseline', 'restricted', 'quarantine', 'isolated']\n"
        "          ? variables.nsTier\n"
        "          : 'isolated'\n"
    )
    assert unlabelled_default(tmp) == "isolated", "collapsed shape, block scalar: danger value must be read"
    open(tmp, "w").write(
        '  - name: tier\n    expression: "variables.nsTier in [\'baseline\', \'restricted\']'
        "\\n  ? variables.nsTier\\n  : 'isolated'\"\n"
    )
    assert unlabelled_default(tmp) == "isolated", "collapsed shape, rendered \\n form: danger value must be read"
    open(tmp, "w").write(
        "    - name: tier\n      expression: >-\n"
        "        variables.nsTier in ['baseline', 'restricted', 'quarantine', 'isolated']\n"
        "          ? variables.nsTier\n"
        "          : 'baseline'\n"
    )
    assert unlabelled_default(tmp) == "baseline", "collapsed shape: a safe value must be read as itself"
    # A COMMENT DECLARES NOTHING, HERE TOO (ticket 63). The flip's changelog
    # comment quotes the shape it replaced; reading prose reported an
    # already-flipped body as `baseline` -- the tripwire wrong in the one
    # direction it must never be wrong in.
    open(tmp, "w").write(
        "    # collapsed from `nsGoverned ? 'isolated' : 'baseline'` on 2026-09-04\n"
        "    # and the older flat read was ['posture.acme.io/tier'].orValue('baseline')\n"
        "    - name: tier\n      expression: >-\n"
        "        variables.nsTier in ['baseline', 'restricted', 'quarantine', 'isolated']\n"
        "          ? variables.nsTier\n"
        "          : 'isolated'\n"
    )
    assert unlabelled_default(tmp) == "isolated", \
        "prose quoting an older shape must not outvote the expression that actually runs"
    open(tmp, "w").write(
        "# this file's only mention of a default is in prose:\n"
        "# `nsGoverned ? 'isolated' : 'baseline'`\n"
        "apiVersion: policies.kyverno.io/v1alpha1\n"
    )
    assert unlabelled_default(tmp) is None, "a body whose ONLY match is a comment declares nothing"
    os.remove(tmp)
    print("ok   selfcheck: ordering_rule, parse_namespace_docs and unlabelled_default (all "
          "three served shapes, and comments declaring nothing) behave as claimed")
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

files = served_cage_tier_files(estate)
if not files:
    fail("no served cage-tier.yaml policy body found anywhere -- cannot run the ordering check")
defaults = {f: unlabelled_default(f) for f in files}
print(f"3. ordering rule: unlabelled-tier defaults across {len(files)} served cage-tier.yaml bodies:")
for f, d in defaults.items():
    print(f"     {os.path.relpath(f, estate)}: {d!r}")
offenders = ordering_rule(defaults, missing)
if offenders:
    names = ", ".join(f"{os.path.relpath(f, estate)}={d}" for f, d in offenders)
    fail(f"unlabelled-governed-Namespace default is 'isolated' in {names} while infra is "
         f"undeclared for {', '.join(missing)} -- CoreDNS/Flux/Kyverno would fall to isolated")
print("  ok   no served body defaults an unlabelled tier to isolated while infra is undeclared "
      "(currently: infra is fully declared, so this is a live tripwire, not a historical fact)")

print("PASS: the platform's infra declaration covers kube-system, flux-system and kyverno, "
      "entitled by the platform role on party.yaml, and no served policy body's unlabelled "
      "default can flip them to isolated before that declaration lands.")
PY
