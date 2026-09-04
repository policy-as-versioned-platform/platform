#!/usr/bin/env bash
# Ticket 41. The gitsign-verifying source controller, graded.
#
# OFFLINE, always, no cluster and no network:
#   1. the verifier never signs anything -- there is no signing verb in it;
#   2. its pins are not literals -- the shipped gate annotations still equal
#      release.yml's EXPECTED_IDENTITY_REGEXP and EXPECTED_ISSUER;
#   3. the fixture is real material -- byte-equal to `git cat-file tag` of this
#      repo's own signed tag, whenever the tag is present locally;
#   4. it ACCEPTS that real signed tag;
#   4b. it ACCEPTS a real tag whose certificate was issued AFTER its tagger
#      time, within the bound deployment.yaml declares, and REJECTS the same
#      tag past that bound naming the knob (ticket 73, ADR-0027);
#   5. it REJECTS a tampered payload, a tampered signature, a re-signed
#      forgery under the right identity, a wrong identity and a wrong issuer;
#   6. the controller's verdict reaches the objects it gates, and the package
#      builds so the pod mounts the exact program that was just proved;
#   7. the time-box is written down where the person removing it will look.
#
# LIVE tail: is the controller on a cluster, and has the trigger that removes
# it fired? Exit 3 (could-not-look) when no cluster carries the controller --
# which is the honest answer until an org adopts the package.
#
# The one thing that will tell you to delete all of this: the GitRepository
# CRD's spec.verify.mode enum stops being exactly [HEAD, Tag, TagAndHEAD].
# That is what fluxcd/source-controller#1068 landing looks like from the
# cluster, and it makes this script FAIL, on purpose.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/lib.sh"   # skip / substrate_ok / live_tail_skip / pass_line

PKG="$HERE/identity/gitsign-verifier"
VERIFIER="$PKG/verify_gitsign.py"
GATE="$HERE/distribution/verify/gate.yaml"
FIXTURE="$HERE/distribution/verify/testdata/policy-v3.0.0.tag"
RELEASE="$HERE/.github/workflows/release.yml"
# Observed on source-controller v1.9.3 / GitRepository v1, kind-driftwood,
# 2026-08-28: ["head","HEAD","Tag","TagAndHEAD"] -- `head` is the deprecated
# lowercase alias. Every one of them means OpenPGP or SSH. When this list
# grows a sigstore/x509 mode, Flux has learned to do this itself and the
# controller goes in the bin.
FLUX_VERIFY_MODES="head HEAD Tag TagAndHEAD"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok   $*"; }
say() { echo; echo "== $* =="; }

for f in "$VERIFIER" "$GATE" "$FIXTURE" "$RELEASE" "$PKG/fulcio-roots.pem"; do
  [ -f "$f" ] || fail "missing $f"
done
command -v openssl >/dev/null || skip "openssl is not on PATH; the verifier cannot run here"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

say "1. the verifier never signs, re-signs or writes a ref"
# ADR-0023 D3: one signature, the gitsign tag. A cluster-side verifier that
# can sign is a second signer under another name -- the exact thing the SSH
# bridge was rejected for. Grep, not trust.
# The grep this replaced was shell-shaped -- `git tag -s`, `cosign sign` -- and this module calls
# git as a PYTHON LIST, `subprocess.run(["git", "-C", str(repo), "cat-file", ...])`. A real
# `subprocess.run(["git", "tag", "-s", tag])` appended to the file walked straight past it (found
# 2026-08-29). A screen that cannot match the file's own idiom only ever says "no match", so this
# walks the AST for the argv the module actually builds, and keeps the shell grep for the rest.
PYTHONDONTWRITEBYTECODE=1 python3 - "$VERIFIER" <<'PY' || fail "the verifier contains a signing or ref-writing verb; it must only ever read and verify"
import ast, pathlib, sys

src = pathlib.Path(sys.argv[1]).read_text()
# git subcommands that create or move a ref anywhere, local or remote. `fetch` is NOT here: the
# verifier fetches +refs/tags/x:refs/tags/x into its own bare cache, which is how it reads a tag.
GIT_WRITES = {"tag", "commit", "push", "update-ref", "symbolic-ref", "am", "apply", "notes"}
SIGNERS = {"gitsign", "cosign", "gpg", "gpg2", "ssh-keygen", "gpgsm", "smimesign"}
SIGN_TOKENS = {"sign", "clearsign", "sign-blob", "--sign", "--clearsign", "-s", "-S",
               "--gpg-sign", "--local-user", "attest"}
# git's global options come BEFORE the subcommand and some take a value, so the subcommand is
# not argv[1]. Non-literal elements are kept as None rather than dropped: collapsing them moves
# every later token left and made `git -C <repo> cat-file tag` read as `git tag`.
GIT_GLOBAL_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}


def subcommand(argv):
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in GIT_GLOBAL_WITH_VALUE:
            i += 2
        elif tok is None or tok.startswith("-"):
            i += 1
        else:
            return tok
    return None


bad = []
for node in ast.walk(ast.parse(src)):
    if not isinstance(node, ast.Call):
        continue
    if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
        continue
    argv = [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None
            for e in node.args[0].elts]
    if not argv or argv[0] is None:
        continue
    tool, rest = argv[0], {a for a in argv[1:] if a}
    if tool == "git":
        verb = subcommand(argv)
        if verb in GIT_WRITES:
            bad.append((f"git {verb}", argv))
        elif rest & {"-s", "-S", "--sign", "--gpg-sign", "--local-user"}:
            bad.append(("git with a signing flag", argv))
    elif tool in SIGNERS and (not rest or (rest & SIGN_TOKENS) or tool == "ssh-keygen"):
        bad.append((tool, argv))
    elif tool == "openssl" and ({"cms", "smime", "dgst"} & rest) and ("-sign" in rest):
        bad.append(("openssl -sign", argv))
for verb, argv in bad:
    print(f"  FAIL the verifier builds a {verb!r} command: {argv}")
sys.exit(1 if bad else 0)
PY
if grep -nE 'git (tag|commit|push)[^|]*-[sS]|gitsign +sign|gpg +--(sign|clearsign)|ssh-keygen|cosign +sign|openssl +(cms|smime|dgst)[^|]*-sign' "$VERIFIER"; then
  fail "the verifier contains a signing verb; it must only ever read and verify"
fi
ok "no signing or ref-writing verb in verify_gitsign.py, by AST over its own subprocess argv"
grep -q '+refs/tags/{tag}:refs/tags/{tag}' "$VERIFIER" \
  || fail "the verifier does not fetch a tag ref; how does it read the tag object?"
ok "it fetches refs/tags read-only into a bare cache and reads the tag object"

say "2. the pins are release.yml's, not literals"
re_release="$(sed -n 's/^  EXPECTED_IDENTITY_REGEXP: //p' "$RELEASE")"
iss_release="$(sed -n 's/^  EXPECTED_ISSUER: //p' "$RELEASE")"
[ -n "$re_release" ] && [ -n "$iss_release" ] || fail "release.yml carries no identity pins to read"
re_gate="$(sed -n 's|^ *policy-as-versioned.dev/gitsign-identity-regexp: ||p' "$GATE")"
iss_gate="$(sed -n 's|^ *policy-as-versioned.dev/gitsign-issuer: ||p' "$GATE")"
[ "$re_gate" = "$re_release" ] \
  || fail "gate.yaml pins an identity regexp release.yml does not: $re_gate != $re_release"
[ "$iss_gate" = "$iss_release" ] \
  || fail "gate.yaml pins an issuer release.yml does not: $iss_gate != $iss_release"
ok "identity regexp matches release.yml: $re_release"
ok "issuer matches release.yml: $iss_release"

say "3. the fixture is this repo's own signed tag, byte for byte"
if git -C "$HERE" cat-file -e 'policy/v3.0.0^{}' 2>/dev/null; then
  git -C "$HERE" cat-file tag policy/v3.0.0 > "$tmp/live.tag"
  cmp -s "$tmp/live.tag" "$FIXTURE" \
    || fail "testdata/policy-v3.0.0.tag has drifted from the tag object; re-run distribution/verify/extract-tag-fixture.sh"
  ok "fixture == git cat-file tag policy/v3.0.0 ($(wc -c < "$FIXTURE" | tr -d ' ') bytes)"
else
  ok "tag policy/v3.0.0 not in this checkout; proving against the committed fixture only"
fi
grep -q -- '-----BEGIN SIGNED MESSAGE-----' "$FIXTURE" || fail "the fixture carries no signature block"

verify() { python3 "$VERIFIER" verify-object "$1" \
             --identity-regexp "${2:-$re_release}" --issuer "${3:-$iss_release}" 2>&1; }

say "4. it ACCEPTS the real signed tag under the release.yml pins"
out="$(verify "$FIXTURE")" || fail "the real tag was rejected: $out"
grep -q '^VERIFIED: ' <<<"$out" || fail "unexpected output: $out"
echo "  $out"

say "4b. the trust instant: a certificate issued AFTER the tagger time, within the declared bound"
# Ticket 73, ADR-0027. git writes the tag object (and its tagger line) BEFORE gitsign asks Fulcio
# for the certificate, so the certificate's notBefore lands one second after the tagger time on
# about half of correctly signed tags. Chaining at the raw tagger time rejected driftwood v1.1.0
# and ludlow v1.1.0 on the first real lane samples (2026-09-01). The instant is now the later of
# the tagger time and notBefore, allowed only while the gap is within a bound that deployment.yaml
# declares -- read from there, never a literal here -- so the pod and this proof agree on one
# number. The fixture is a REAL racy tag from another party (driftwood's v1.1.0, byte-equal to
# `git cat-file tag v1.1.0` in policy-as-versioned-driftwood/driftwood), verified under pins of
# the same shape release.yml pins for platform: an adopter's own cut-release.yml identity.
RACY="$PKG/testdata/driftwood-v1.1.0.tag"
[ -f "$RACY" ] || fail "missing the racy fixture $RACY"
bound="$(python3 - "$PKG/deployment.yaml" <<'PY'
import sys, yaml
dep = yaml.safe_load(open(sys.argv[1]))
env = {e["name"]: str(e.get("value", "")) for c in dep["spec"]["template"]["spec"]["containers"]
       for e in (c.get("env") or [])}
print(env.get("GITSIGN_TAGGER_SKEW_SECONDS", ""))
PY
)"
[ -n "$bound" ] && [ "$bound" -gt 0 ] 2>/dev/null \
  || fail "deployment.yaml declares no positive GITSIGN_TAGGER_SKEW_SECONDS; the tolerance must live in the verifier's own config"
[ "$bound" -lt 600 ] || fail "GITSIGN_TAGGER_SKEW_SECONDS=$bound is not smaller than a Fulcio certificate's own ten-minute life; that is no bound"
ok "deployment.yaml declares GITSIGN_TAGGER_SKEW_SECONDS=$bound"

# the fixture must actually exercise the race, or this section proves nothing
gap="$(python3 - "$RACY" <<'PY'
import sys, re, base64, calendar, time, subprocess, pathlib, tempfile
raw = pathlib.Path(sys.argv[1]).read_bytes()
i = raw.index(b"-----BEGIN SIGNED MESSAGE-----")
tagger = int(re.search(rb"^tagger .*? (\d{9,11}) [+-]\d{4}$", raw[:i], re.M).group(1))
der = base64.b64decode(b"".join(l for l in raw[i:].splitlines() if not l.startswith(b"-----")))
with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as fh:
    fh.write(der); path = fh.name
certs = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", path, "-print_certs"],
                       capture_output=True, text=True, check=True).stdout
nb = subprocess.run(["openssl", "x509", "-noout", "-startdate"], input=certs,
                    capture_output=True, text=True, check=True).stdout.strip().split("=", 1)[1]
print(calendar.timegm(time.strptime(nb, "%b %d %H:%M:%S %Y GMT")) - tagger)
PY
)"
[ "$gap" -gt 0 ] || fail "the racy fixture's certificate notBefore is not after its tagger time (gap ${gap}s); it does not exercise the race"
ok "fixture: certificate notBefore is ${gap}s after the tagger time, the race the verifier must survive"

re_adopter="${re_release//platform/driftwood}"
[ "$re_adopter" != "$re_release" ] || fail "could not derive an adopter-shaped identity pin from release.yml's"
out="$(GITSIGN_TAGGER_SKEW_SECONDS="$bound" verify "$RACY" "$re_adopter" "$iss_release")" \
  || fail "the racy tag was rejected under the declared bound of ${bound}s: $out"
grep -q '^VERIFIED: ' <<<"$out" || fail "unexpected output: $out"
grep -q 'certificate issued' <<<"$out" || fail "the verdict does not report the second instant: $out"
echo "  $out"
ok "accepted at the later instant, both instants reported"

out="$(GITSIGN_TAGGER_SKEW_SECONDS=0 verify "$RACY" "$re_adopter" "$iss_release")" \
  && fail "with the bound at 0 the racy tag was ACCEPTED; the bound is not applied: $out"
grep -q '^REJECTED: ' <<<"$out" || fail "bound 0 failed for the wrong reason: $out"
grep -q 'GITSIGN_TAGGER_SKEW_SECONDS' <<<"$out" \
  || fail "the rejection over the bound does not name the knob that sets it: $out"
echo "  ok   rejected when the gap exceeds the bound, naming the gap and the knob"
echo "         ${out#REJECTED: }"

# the tolerance moves the instant, never the payload binding: a tampered racy tag stays rejected
python3 - "$RACY" "$tmp/tampered-racy.tag" <<'PY'
import sys, pathlib
raw = pathlib.Path(sys.argv[1]).read_bytes()
i = raw.index(b"-----BEGIN SIGNED MESSAGE-----")
payload = raw[:i].replace(b"MODERATE", b"moderate", 1)
assert payload != raw[:i], "fixture text changed; pick another edit"
pathlib.Path(sys.argv[2]).write_bytes(payload + raw[i:])
PY
out="$(GITSIGN_TAGGER_SKEW_SECONDS="$bound" verify "$tmp/tampered-racy.tag" "$re_adopter" "$iss_release")" \
  && fail "a tampered racy payload was ACCEPTED under the bound: $out"
grep -q '^REJECTED: ' <<<"$out" || fail "tampered racy payload failed for the wrong reason: $out"
echo "  ok   rejected a tampered racy payload under the same bound"

# and gitsign's own verdict on the same bytes, where it is installed: the tolerance must not
# diverge from the reference verifier. gitsign resolves the tag in the current directory, so
# the fixture is written into a throwaway repo as a tag object first.
if command -v gitsign >/dev/null 2>&1; then
  git init -q "$tmp/racy.git"
  racy_sha="$(git -C "$tmp/racy.git" hash-object -t tag -w --stdin < "$RACY")"
  git -C "$tmp/racy.git" update-ref refs/tags/v1.1.0 "$racy_sha"
  if ( cd "$tmp/racy.git" && GITSIGN_REKOR_MODE=offline gitsign verify-tag v1.1.0 \
       --certificate-identity-regexp="$re_adopter" \
       --certificate-oidc-issuer="$iss_release" ) >"$tmp/gitsign-racy.out" 2>&1; then
    ok "gitsign verify-tag agrees: the racy tag is good under the same pins"
  else
    fail "gitsign REJECTS the racy tag this verifier ACCEPTS: $(tail -1 "$tmp/gitsign-racy.out")"
  fi
else
  echo "  note gitsign is not on PATH; the racy-tag differential was not observed on this run."
fi

say "5. it REJECTS everything that is not that"
reject() { # <label> <file> [regexp] [issuer]
  local label="$1"; shift
  local out; out="$(verify "$@")" && fail "$label was ACCEPTED: $out"
  grep -q '^REJECTED: ' <<<"$out" || fail "$label failed for the wrong reason: $out"
  echo "  ok   rejected $label"
  echo "         ${out#REJECTED: }"
}

# a. the signed payload edited -- one byte of the tag message
python3 - "$FIXTURE" "$tmp/tampered-payload.tag" <<'PY'
import sys, pathlib
raw = pathlib.Path(sys.argv[1]).read_bytes()
i = raw.index(b"-----BEGIN SIGNED MESSAGE-----")
payload = raw[:i].replace(b"repair release", b"REPAIR RELEASE", 1)
assert payload != raw[:i], "fixture text changed; pick another edit"
pathlib.Path(sys.argv[2]).write_bytes(payload + raw[i:])
PY
reject "a tampered payload" "$tmp/tampered-payload.tag"

# b. the signature bytes edited -- flip one base64 character inside the block
python3 - "$FIXTURE" "$tmp/tampered-signature.tag" <<'PY'
import sys, pathlib
raw = pathlib.Path(sys.argv[1]).read_bytes()
i = raw.index(b"-----BEGIN SIGNED MESSAGE-----")
lines = raw[i:].split(b"\n")
body = lines[len(lines) // 2]
lines[len(lines) // 2] = bytes([(b + 1) if b in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:-1] else b for b in body])
assert lines[len(lines) // 2] != body, "no character to flip on that line"
pathlib.Path(sys.argv[2]).write_bytes(raw[:i] + b"\n".join(lines))
PY
reject "a tampered signature" "$tmp/tampered-signature.tag"

# c. a forgery: a self-signed certificate carrying the RIGHT identity SAN,
#    re-signing the real payload. This is the attack the identity pin alone
#    does not stop -- only chaining to the pinned Fulcio root does.
if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
     -subj "/CN=forgery" \
     -addext "subjectAltName=URI:https://github.com/policy-as-versioned-platform/platform/.github/workflows/cut-release.yml@refs/heads/main" \
     -addext "extendedKeyUsage=codeSigning" \
     -keyout "$tmp/forge.key" -out "$tmp/forge.crt" >/dev/null 2>&1; then
  python3 - "$FIXTURE" "$tmp/payload.bin" <<'PY'
import sys, pathlib
raw = pathlib.Path(sys.argv[1]).read_bytes()
pathlib.Path(sys.argv[2]).write_bytes(raw[:raw.index(b"-----BEGIN SIGNED MESSAGE-----")])
PY
  openssl cms -sign -in "$tmp/payload.bin" -binary -signer "$tmp/forge.crt" \
    -inkey "$tmp/forge.key" -outform DER -out "$tmp/forge.der" >/dev/null 2>&1
  python3 - "$tmp/payload.bin" "$tmp/forge.der" "$tmp/forged.tag" <<'PY'
import base64, sys, pathlib, textwrap
payload = pathlib.Path(sys.argv[1]).read_bytes()
der = base64.b64encode(pathlib.Path(sys.argv[2]).read_bytes()).decode()
block = "-----BEGIN SIGNED MESSAGE-----\n" + "\n".join(textwrap.wrap(der, 64)) + \
        "\n-----END SIGNED MESSAGE-----\n"
pathlib.Path(sys.argv[3]).write_bytes(payload + block.encode())
PY
  # The forgery's certificate was minted just now, so its notBefore is far past the fixture's
  # tagger time and the check-2 bound alone would refuse it before the chain is ever built. That
  # is a correct refusal, but not the one this case exists to prove: waive the bound here so the
  # rejection is the chain's -- the pinned root, and nothing else, stops a certificate that
  # wears the right identity.
  out="$(GITSIGN_TAGGER_SKEW_SECONDS=1000000000 verify "$tmp/forged.tag")" \
    && fail "a self-signed forgery wearing the right identity was ACCEPTED: $out"
  grep -q '^REJECTED: certificate chain did not verify' <<<"$out" \
    || fail "the forgery was refused by something other than the pinned root chain: $out"
  echo "  ok   rejected a self-signed forgery wearing the right identity, by the chain not the bound"
  echo "         ${out#REJECTED: }"
else
  fail "could not build the forgery case; openssl req refused (-addext unsupported?)"
fi

# d/e. the real, untampered tag under the wrong pins
reject "a wrong identity" "$FIXTURE" '^https://github\.com/policy-as-versioned-ico/ico/.*$' "$iss_release"
reject "a wrong issuer" "$FIXTURE" "$re_release" "https://accounts.google.com"
# f. a pin that is not a pin: `.*` matched every identity while `re.search` was unanchored, so an
#    annotation nobody asserted could open the boundary to anyone. Refused before it is used.
reject "an unanchored identity regexp" "$FIXTURE" '.*' "$iss_release"
reject "an identity regexp anchored at one end only" "$FIXTURE" '^https://github\.com/' "$iss_release"

say "6. differential against gitsign itself"
# The named ceiling of this verifier is the transparency log: it does not check
# the Rekor entry. gitsign does. Where gitsign is installed, the two must agree
# on the same tag -- that is ticket 16's falsifier (b), "cluster-side
# verification passing a tag that identity-pinned CI rejects", watched rather
# than written down. Where it is not installed, say so and do not pretend.
if command -v gitsign >/dev/null 2>&1; then
  # gitsign has no `-C`: it resolves the tag in the CURRENT directory, and the gate runs every
  # verify script from the hub root, where no policy/v3.0.0 exists. It also cannot resolve a
  # ref from inside a git WORKTREE (`reference not found`, observed 2026-09-03 on a ticket
  # worktree of this repo), which read as gitsign REJECTING a tag this verifier accepts --
  # falsifier (b) firing on a could-not-look, the one thing a falsifier must never do. So the
  # fixture bytes are written into a throwaway repo as a tag object and gitsign is run there:
  # the same bytes section 4 proved, in a shape gitsign can always read, whatever this checkout
  # is and whether or not the tag was fetched into it.
  git init -q "$tmp/fixture.git"
  fx_sha="$(git -C "$tmp/fixture.git" hash-object -t tag -w --stdin < "$FIXTURE")"
  git -C "$tmp/fixture.git" update-ref refs/tags/policy/v3.0.0 "$fx_sha"
  if ( cd "$tmp/fixture.git" && GITSIGN_REKOR_MODE=offline gitsign verify-tag policy/v3.0.0 \
       --certificate-identity-regexp="$re_release" \
       --certificate-oidc-issuer="$iss_release" ) >"$tmp/gitsign.out" 2>&1; then
    ok "gitsign verify-tag agrees: policy/v3.0.0 is good under the same pins"
  else
    fail "gitsign REJECTS policy/v3.0.0 under pins this verifier ACCEPTS (falsifier b): $(tail -1 "$tmp/gitsign.out")"
  fi
else
  echo "  note gitsign is not on PATH; the transparency-log differential was not observed on this run."
fi

say "7. the controller's verdict reaches the objects it is supposed to gate"
# The four checks above are the crypto; this is the plumbing. A stub API
# server records every patch while one good source and one tampered source go
# through reconcile_one, so the annotation keys, the gate path and the
# suspend/release branches are observed rather than hoped for. The tag object
# is the real fixture, in a local bare repo, so nothing here needs a network.
PYTHONDONTWRITEBYTECODE=1 python3 - "$PKG" "$FIXTURE" "$tmp" "$re_release" "$iss_release" \
    "$RACY" "$re_adopter" "$bound" <<'PY'
import os, sys, subprocess, pathlib, importlib.util
pkg, fixture, tmp, regexp, issuer, racy, re_adopter, bound = sys.argv[1:9]
spec = importlib.util.spec_from_file_location("vg", pathlib.Path(pkg) / "verify_gitsign.py")
vg = importlib.util.module_from_spec(spec); spec.loader.exec_module(vg)

# the trust-instant arithmetic on its own (ADR-0027): the later instant within the bound, the
# tagger time when the certificate is not later, a refusal that names the knob past the bound
assert vg.trust_instant(100, 100, 0) == 100 and vg.trust_instant(100, 90, 0) == 100
assert vg.trust_instant(100, 101, 1) == 101 and vg.trust_instant(100, 160, 60) == 160
for tagger, nb, skew in ((100, 101, 0), (100, 161, 60)):
    try:
        vg.trust_instant(tagger, nb, skew)
    except vg.Rejected as e:
        assert vg.ENV_TAGGER_SKEW in str(e) and f"{nb - tagger}s" in str(e), e
    else:
        raise AssertionError(f"gap {nb - tagger} over bound {skew} was not refused")
os.environ[vg.ENV_TAGGER_SKEW] = "x"
try:
    vg.declared_tagger_skew()
except vg.CouldNotLook:
    pass
else:
    raise AssertionError("a tolerance that is not a number was read as one")
os.environ[vg.ENV_TAGGER_SKEW] = bound
assert vg.declared_tagger_skew() == int(bound)
print(f"  ok   trust_instant: later-of within the bound, refused past it, a bad declaration is could-not-look")

repo = pathlib.Path(tmp) / "tagrepo.git"
subprocess.run(["git", "init", "--bare", "-q", str(repo)], check=True)
sha = subprocess.run(["git", "-C", str(repo), "hash-object", "-t", "tag", "-w", "--stdin"],
                     stdin=open(fixture, "rb"), capture_output=True, text=True, check=True).stdout.strip()
subprocess.run(["git", "-C", str(repo), "update-ref", "refs/tags/policy/v3.0.0", sha], check=True)
vg.fetch_tag = lambda url, tag, cache: repo          # the fetch is not what is under test

class StubK8s:
    def __init__(self): self.patches = {}
    def call(self, path, *a, **k): return {"metadata": {"annotations": {}}, "spec": {}}
    def patch(self, path, body): self.patches.setdefault(path, []).append(body)

def source(name, tag="policy/v3.0.0"):
    return {"metadata": {"name": name, "namespace": "flux-system", "annotations": {
        vg.ANN_IDENTITY: regexp, vg.ANN_ISSUER: issuer,
        vg.ANN_GATES: "flux-system/platform-policy"}},
        "spec": {"url": "https://example.invalid/x", "ref": {"tag": tag}}}

k = StubK8s()
ok, why = vg.reconcile_one(k, source("good"), pathlib.Path(tmp) / "cache")
assert ok, why
gr = k.patches[vg.GITREPO % ("flux-system", "good")][0]["metadata"]["annotations"]
assert gr[vg.ANN_VERIFIED] == "true", gr
assert vg.KUSTOMIZATIONS % ("flux-system", "platform-policy") not in k.patches, \
    "a VERIFIED source touched the gate; it should have left it alone"
print("  ok   verified source: annotates gitsign-verified=true, leaves the gate alone")

# the racy tag through the controller, under the declared bound: verified, and the reason the
# object carries names both instants so a reader of the annotation sees why they differ
racy_sha = subprocess.run(["git", "-C", str(repo), "hash-object", "-t", "tag", "-w", "--stdin"],
                          stdin=open(racy, "rb"), capture_output=True, text=True, check=True).stdout.strip()
subprocess.run(["git", "-C", str(repo), "update-ref", "refs/tags/v1.1.0", racy_sha], check=True)
def adopter(name, tag="v1.1.0"):
    o = source(name, tag); o["metadata"]["annotations"][vg.ANN_IDENTITY] = re_adopter; return o
k = StubK8s()
ok, why = vg.reconcile_one(k, adopter("racy"), pathlib.Path(tmp) / "cache")
assert ok is True, why
assert "certificate issued 1s later" in why, why
assert k.patches[vg.GITREPO % ("flux-system", "racy")][0]["metadata"]["annotations"][vg.ANN_VERIFIED] == "true"
print("  ok   racy source: verified under the declared bound, reason carries both instants")

# and with no bound declared, the strict form: the same tag is REJECTED and the gate suspended,
# with the reason naming the knob -- the pre-ADR-0027 behaviour, kept as the default on purpose
del os.environ[vg.ENV_TAGGER_SKEW]
k = StubK8s()
ok, why = vg.reconcile_one(k, adopter("racy-strict"), pathlib.Path(tmp) / "cache")
assert ok is False and vg.ENV_TAGGER_SKEW in why, (ok, why)
assert k.patches[vg.KUSTOMIZATIONS % ("flux-system", "platform-policy")][0]["spec"]["suspend"] is True
os.environ[vg.ENV_TAGGER_SKEW] = bound
print("  ok   racy source with no bound declared: rejected, gate suspended, reason names the knob")

# a tolerance that is not a number is the instrument mis-declared: could-not-look, never a verdict
os.environ[vg.ENV_TAGGER_SKEW] = "sixty"
k = StubK8s()
ok, why = vg.reconcile_one(k, adopter("racy-misdeclared"), pathlib.Path(tmp) / "cache")
assert ok is None, (ok, why)
assert k.patches[vg.GITREPO % ("flux-system", "racy-misdeclared")][0]["metadata"]["annotations"][vg.ANN_VERIFIED] == "unknown"
assert vg.KUSTOMIZATIONS % ("flux-system", "platform-policy") not in k.patches
os.environ[vg.ENV_TAGGER_SKEW] = bound
print("  ok   a mis-declared tolerance: records unknown and moves no gate")

# now the same source with the tag object tampered under it
raw = pathlib.Path(fixture).read_bytes()
i = raw.index(b"-----BEGIN SIGNED MESSAGE-----")
bad = subprocess.run(["git", "-C", str(repo), "hash-object", "-t", "tag", "-w", "--stdin"],
                     input=raw[:i].replace(b"repair release", b"REPAIR RELEASE", 1) + raw[i:],
                     capture_output=True, check=True).stdout.decode().strip()
subprocess.run(["git", "-C", str(repo), "update-ref", "refs/tags/policy/v3.0.0", bad], check=True)
k = StubK8s()
ok, why = vg.reconcile_one(k, source("bad"), pathlib.Path(tmp) / "cache")
assert not ok, "a tampered tag was accepted"
gate = k.patches[vg.KUSTOMIZATIONS % ("flux-system", "platform-policy")][0]
assert gate["spec"]["suspend"] is True, gate
assert gate["metadata"]["annotations"][vg.ANN_SUSPENDED_BY] == "true", gate
print("  ok   rejected source: suspends flux-system/platform-policy and marks it its own")

# and the release: the same gate, already held by us, once verification passes
subprocess.run(["git", "-C", str(repo), "update-ref", "refs/tags/policy/v3.0.0", sha], check=True)
class Held(StubK8s):
    def call(self, path, *a, **k):
        return {"metadata": {"annotations": {vg.ANN_SUSPENDED_BY: "true"}}, "spec": {"suspend": True}}
k = Held()
ok, _ = vg.reconcile_one(k, source("good"), pathlib.Path(tmp) / "cache")
gate = k.patches[vg.KUSTOMIZATIONS % ("flux-system", "platform-policy")][0]
assert ok and gate["spec"]["suspend"] is False and gate["metadata"]["annotations"][vg.ANN_SUSPENDED_BY] is None
print("  ok   released: a gate this controller suspended is released when the tag verifies again")

# a suspend a HUMAN took is not ours to release
class Human(StubK8s):
    def call(self, path, *a, **k): return {"metadata": {"annotations": {}}, "spec": {"suspend": True}}
k = Human()
vg.reconcile_one(k, source("good"), pathlib.Path(tmp) / "cache")
assert vg.KUSTOMIZATIONS % ("flux-system", "platform-policy") not in k.patches, \
    "the controller un-suspended a Kustomization it did not suspend"
print("  ok   a suspend the controller did not take is left alone")

# could-not-look is not a verdict. Returning True on a fetch failure printed
# `VERIFIED -- could not fetch ...` in the controller's log and left a stale true annotation
# standing, with every gated Kustomization unsuspended: a fail-open on the only cluster-side
# verification the estate has.
def unreachable(url, tag, cache):
    raise subprocess.CalledProcessError(128, ["git", "fetch"], stderr=b"could not resolve host")
vg.fetch_tag = unreachable
k = StubK8s()
ok, why = vg.reconcile_one(k, source("unreachable"), pathlib.Path(tmp) / "cache")
assert ok is None, f"a fetch failure graded {ok!r}; could-not-look is not a verdict"
gr = k.patches[vg.GITREPO % ("flux-system", "unreachable")][0]["metadata"]["annotations"]
assert gr[vg.ANN_VERIFIED] == "unknown", gr
assert vg.KUSTOMIZATIONS % ("flux-system", "platform-policy") not in k.patches, \
    "a controller that could not look moved a gate"
print("  ok   could not look: records unknown, never true, and moves no gate either way")
PY

say "8. the package builds, and the pod mounts the program proved above"
if command -v kubectl >/dev/null 2>&1; then
  kubectl kustomize "$PKG" > "$tmp/built.yaml" 2>"$tmp/built.err" \
    || fail "kustomize build of the package failed: $(tail -1 "$tmp/built.err")"
  python3 - "$tmp/built.yaml" "$VERIFIER" <<'PY'
import sys, yaml, pathlib
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
cm = next(d for d in docs if d["kind"] == "ConfigMap")
dep = next(d for d in docs if d["kind"] == "Deployment")
ref = dep["spec"]["template"]["spec"]["volumes"][0]["configMap"]["name"]
assert ref == cm["metadata"]["name"], \
    f"the pod mounts {ref!r} but the generator made {cm['metadata']['name']!r}"
assert cm["data"]["verify_gitsign.py"] == pathlib.Path(sys.argv[2]).read_text(), \
    "the ConfigMap's copy of the program is not the file this script just proved"
assert "fulcio-roots.pem" in cm["data"], "the pinned trust root is not delivered to the pod"
print(f"  ok   one program, one copy: {cm['metadata']['name']} carries the proved bytes")
PY
else
  echo "  note kubectl is not on PATH; the kustomize build was not observed on this run."
fi

say "9. the time-box is written where the remover will look"
for f in "$PKG/deployment.yaml" "$PKG/README.md" "$HERE/distribution/verify/README.md"; do
  grep -q 'source-controller#1068' "$f" || fail "$f does not name the removal trigger (#1068)"
done
grep -q 'verify-source-verification.sh' "$PKG/deployment.yaml" \
  || fail "the manifest does not name the script that goes red when the time-box ends"
ok "the manifests and both READMEs name #1068 and this script"

say "10. live: does a cluster carry the controller, and has the trigger fired?"
if substrate_ok "$CLUSTER"; then
  modes="$(timeout 30 kubectl --context "$CTX" get crd gitrepositories.source.toolkit.fluxcd.io \
    -o jsonpath='{.spec.versions[?(@.name=="v1")].schema.openAPIV3Schema.properties.spec.properties.verify.properties.mode.enum[*]}' 2>/dev/null || true)"
  if [ -n "$modes" ] && [ "$(echo $modes)" != "$FLUX_VERIFY_MODES" ]; then
    echo "FAIL: GitRepository.spec.verify.mode is now [$modes], not [$FLUX_VERIFY_MODES]."
    echo "FAIL: Flux's own verification has changed -- read fluxcd/source-controller#1068,"
    echo "FAIL: move the pins onto spec.verify and DELETE identity/gitsign-verifier."
    exit 1
  fi
  ok "spec.verify.mode is still [$modes] -- Flux still cannot verify a gitsign tag"
  have="$(timeout 30 kubectl --context "$CTX" -n flux-system get deploy gitsign-verifier \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  if [ -z "$have" ] || [ "$have" = "0" ]; then
    live_tail_skip "no gitsign-verifier Deployment ready on kind-$CLUSTER; nothing verifies this cluster's sources"
  else
    ok "gitsign-verifier is running on kind-$CLUSTER ($have ready)"
    # The verdict is read WITH its pin and its timestamp, not on its own. Three things were
    # invisible when this read only `gitsign-verified`: an `unknown` (the controller could not
    # fetch), a verdict from a controller that stopped hours ago, and a verdict reached against an
    # identity regexp nobody asserted -- the pin is asserted on the SHIPPED example gate.yaml in
    # check 2 above, and it is the LIVE annotation the controller actually applies.
    timeout 30 kubectl --context "$CTX" get gitrepository -A -o json >"$tmp/gitrepos.json" 2>/dev/null \
      || live_tail_skip "the controller is running but the GitRepositories could not be listed"
    set +e
    PYTHONDONTWRITEBYTECODE=1 python3 - "$tmp/gitrepos.json" "$PKG/deployment.yaml" \
      "$re_release" "$iss_release" >"$tmp/live.out" 2>&1 <<'PY'
import calendar, json, re, sys, time, yaml

items = json.load(open(sys.argv[1]))["items"]
dep = yaml.safe_load(open(sys.argv[2]))
re_release, iss_release = sys.argv[3], sys.argv[4]
A = "policy-as-versioned.dev/"

# The staleness bound is the controller's OWN loop interval, read from the manifest that ships
# beside it, times ten. A verdict older than that is not a verdict about now: the controller has
# stopped, and gitsign-verified-at was written and never read by anything until this.
env = {e["name"]: str(e.get("value", "")) for c in dep["spec"]["template"]["spec"]["containers"]
       for e in (c.get("env") or [])}
interval = int(env.get("INTERVAL") or 60)
bound = max(10 * interval, 300)

watched = [o for o in items if (o["metadata"].get("annotations") or {}).get(A + "gitsign-identity-regexp")]
if not watched:
    print("SKIP: no GitRepository on this cluster carries a gitsign identity pin, so the "
          "controller is watching nothing and there is no verdict to read")
    sys.exit(3)

now = time.time()
fails, skips = [], []
for o in watched:
    ann = o["metadata"]["annotations"]
    who = f"{o['metadata']['namespace']}/{o['metadata']['name']}"
    url = str((o.get("spec") or {}).get("url", ""))
    regexp = str(ann.get(A + "gitsign-identity-regexp", ""))
    issuer = str(ann.get(A + "gitsign-issuer", ""))
    verdict = ann.get(A + "gitsign-verified")
    at = str(ann.get(A + "gitsign-verified-at", ""))

    # The pin, where the controller applies it. Anchored at both ends or it pins nothing; naming
    # the publisher's own repository or it verified somebody else's workflow identity; and for
    # platform's own source, byte-equal to what release.yml pins.
    if not (regexp.startswith("^") and regexp.endswith("$")):
        fails.append(f"{who}: the live identity regexp {regexp!r} is not anchored at both ends")
        continue
    party = (re.match(r"^https://github\.com/policy-as-versioned-([a-z0-9-]+)/", url) or [None, ""])[1]
    if party and f"policy-as-versioned-{party}/{party}" not in regexp.replace("\\", ""):
        fails.append(f"{who}: the live identity regexp does not name {party}'s own repository: {regexp}")
        continue
    if party == "platform" and regexp != re_release:
        fails.append(f"{who}: the live identity regexp is not the one release.yml pins: {regexp}")
        continue
    if issuer != iss_release:
        fails.append(f"{who}: the live issuer {issuer!r} is not release.yml's {iss_release!r}")
        continue

    if verdict is None:
        skips.append(f"{who}: the controller has written no verdict yet")
        continue
    if verdict == "false":
        fails.append(f"{who}: failed verification and is gated -- {ann.get(A + 'gitsign-verify-reason', '')}")
        continue
    if verdict == "unknown":
        skips.append(f"{who}: the controller COULD NOT LOOK -- {ann.get(A + 'gitsign-verify-reason', '')}; "
                     f"its gate stays as it was and this is not a pass")
        continue
    try:
        # calendar.timegm, not time.mktime + time.timezone: `at` is UTC ("...Z") and
        # time.mktime interprets its argument as LOCAL time, so the mktime+timezone fix-up is
        # wrong by exactly the DST offset whenever the host is on summer time (found 2026-08-31,
        # BST: a verdict written 90s ago read as 60 min old and SKIPped a fresh, correct verify).
        # timegm treats the struct_time as UTC directly -- no local zone, no DST, involved at all.
        age = now - calendar.timegm(time.strptime(at, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        skips.append(f"{who}: verdict {verdict!r} carries no readable gitsign-verified-at, so its age is unknown")
        continue
    if age > bound:
        skips.append(f"{who}: verdict {verdict!r} was written {age / 60:.0f} min ago, past "
                     f"{bound / 60:.0f} min (10 x the controller's own {interval}s interval) -- "
                     f"the controller has stopped and this verdict is not about now")
        continue
    print(f"  ok   verified {who} at {at} ({age / 60:.0f} min old) against {party or 'its'} own pinned identity")

for line in fails + skips:
    print(f"  {'FAIL' if line in fails else 'note'} {line}")
if fails:
    print(f"FAIL: {fails[0]}")
    sys.exit(1)
if skips:
    print(f"SKIP: {skips[0]}")
    sys.exit(3)
sys.exit(0)
PY
    live_rc=$?
    set -e
    cat "$tmp/live.out"
    case "$live_rc" in
      0) : ;;
      3) live_tail_skip "$(sed -n 's/^SKIP: //p' "$tmp/live.out" | tail -1)" ;;
      *) fail "$(sed -n 's/^FAIL: //p' "$tmp/live.out" | tail -1)" ;;
    esac
  fi
else
  live_tail_skip "$SUBSTRATE_REASON"
fi

pass_line "the gitsign verifier accepts this repo's own signed tag under release.yml's pins, and a \
real racy tag whose certificate postdates its tagger time within the declared ${bound}s bound; it \
rejects that tag past the bound, a tampered payload, a tampered signature, a self-signed forgery, a \
wrong identity and a wrong issuer; the controller's time-box names fluxcd/source-controller#1068"
