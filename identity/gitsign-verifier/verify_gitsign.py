#!/usr/bin/env python3
"""Identity-pinned gitsign verification of a git tag, and the controller that
runs it at the Flux source boundary.

WHY THIS EXISTS. The gitsign tag is the only signature in this estate
(ADR-0012, ADR-0019, ADR-0023 D3). Flux's own `GitRepository.spec.verify`
cannot verify it: source-controller v1.9.3 speaks OpenPGP and SSH only and
answers `unsupported signature type: x509` on a real gitsign tag
(observed live on kind-driftwood, 2026-08-28 -- see
../../distribution/verify/PRECONDITION-h6-12.md). fluxcd/source-controller#1068
is the upstream fix and is open. Until it lands, THIS verifies the tag,
identity-pinned, and gates the dependent Kustomization.

WHAT IT NEVER DOES. It never signs, re-signs, tags, pushes or writes to any
git repository. It only fetches and reads. There is no signing key anywhere in
this package -- see verify-source-verification.sh, which greps for one.

THE FOUR CHECKS, all of which must pass:
  1. the CMS/PKCS#7 signature block on the tag object verifies over the tag's
     own payload (the tag object with the signature block removed -- exactly
     what `git verify-tag` signs);
  2. the signer certificate chains to the pinned Fulcio root, evaluated at the
     tag's OWN tagger timestamp, which is inside the signed payload and so
     cannot be moved without breaking check 1. A Fulcio cert lives ten
     minutes, so "valid now" is never the question; "valid when this tag says
     it was made" is;
  3. the certificate's URI SAN matches the pinned identity regexp;
  4. the certificate's Fulcio issuer extension equals the pinned issuer.

Checks 3 and 4 are the same two values `release.yml` pins
(EXPECTED_IDENTITY_REGEXP, EXPECTED_ISSUER). They are NEVER literals here:
they arrive on the GitRepository object as annotations, and
verify-source-verification.sh asserts the shipped example annotation still
equals what release.yml carries.

ponytail: the ceiling is the transparency log. This does NOT verify the Rekor
signed entry timestamp or an inclusion proof, so a signer who obtained a
Fulcio certificate for the pinned identity and never logged it would pass here
and fail `gitsign verify-tag`. Closing it means either shelling out to the
pinned gitsign binary (which needs a built image, and this controller is
time-boxed to die before it earns one) or Flux #1068 landing and this whole
directory being deleted. verify-source-verification.sh runs `gitsign
verify-tag` against the same fixture as a differential whenever gitsign is on
PATH, which is how the gap gets watched rather than merely written down.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIG_BEGIN = b"-----BEGIN SIGNED MESSAGE-----"

# The annotation contract. An adopter puts the first three on its GitRepository;
# the controller writes the rest back as the record of what it observed.
A = "policy-as-versioned.dev/"
ANN_IDENTITY = A + "gitsign-identity-regexp"
ANN_ISSUER = A + "gitsign-issuer"
ANN_GATES = A + "gitsign-gates"          # "ns/name,ns/name" Kustomizations
ANN_VERIFIED = A + "gitsign-verified"
ANN_REASON = A + "gitsign-verify-reason"
ANN_AT = A + "gitsign-verified-at"
ANN_SUSPENDED_BY = A + "gitsign-suspended"

# Fulcio's roots ship beside this file so the container mounts one ConfigMap
# and needs no network to know what a sigstore certificate is.
ROOTS = HERE / "fulcio-roots.pem"
INTERMEDIATES = HERE / "fulcio-intermediates.pem"

OID_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1"
OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"


class Rejected(Exception):
    """The signature is not acceptable. The message is the reason, and the
    reason is what the controller records on the object."""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=kw.pop("text", True), **kw)


def split_tag_object(raw: bytes) -> tuple[bytes, bytes]:
    """A signed git tag object is payload + signature block. git signs exactly
    the bytes before the block, so that split IS the contract."""
    i = raw.find(SIG_BEGIN)
    if i < 0:
        raise Rejected("tag object carries no signature block "
                       "(unsigned, or a lightweight tag pointing straight at a commit)")
    return raw[:i], raw[i:]


def tagger_epoch(payload: bytes) -> int:
    """The tagger line's unix timestamp, read out of the SIGNED payload. This
    is the instant the chain is evaluated at (check 2). It is inside the
    signature, so moving it invalidates check 1."""
    m = re.search(rb"^tagger .*? (\d{9,11}) [+-]\d{4}$", payload, re.M)
    if not m:
        raise Rejected("tag object has no tagger timestamp to evaluate the certificate at")
    return int(m.group(1))


def signature_der(block: bytes) -> bytes:
    import base64
    body = b"".join(l for l in block.splitlines() if not l.startswith(b"-----"))
    try:
        return base64.b64decode(body, validate=True)
    except Exception as e:
        raise Rejected(f"signature block is not valid base64: {e}")


def signer_certificate(der: Path) -> str:
    p = _run(["openssl", "pkcs7", "-inform", "DER", "-in", str(der), "-print_certs"])
    if p.returncode != 0 or "BEGIN CERTIFICATE" not in p.stdout:
        raise Rejected("signature carries no signer certificate "
                       f"(openssl pkcs7: {p.stderr.strip().splitlines()[-1] if p.stderr.strip() else 'no output'})")
    start = p.stdout.index("-----BEGIN CERTIFICATE-----")
    end = p.stdout.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----\n")
    return p.stdout[start:end]


def certificate_claims(cert_pem: str) -> dict:
    """The two pinned claims, read from the certificate: the URI SAN (who
    signed) and the Fulcio issuer extension (which OIDC provider vouched)."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(cert_pem)
        path = fh.name
    try:
        p = _run(["openssl", "x509", "-in", path, "-noout", "-text"])
    finally:
        os.unlink(path)
    if p.returncode != 0:
        raise Rejected("signer certificate does not parse")
    lines = p.stdout.splitlines()
    identity = issuer = None
    for n, line in enumerate(lines):
        if "Subject Alternative Name" in line:
            for uri in re.findall(r"URI:(\S+)", lines[n + 1] if n + 1 < len(lines) else ""):
                identity = uri
        for oid in (OID_ISSUER_V1, OID_ISSUER_V2):
            if line.strip().rstrip(":") == oid and n + 1 < len(lines):
                value = lines[n + 1].strip()
                # the v2 extension is a DER-wrapped UTF8String; the v1 one is raw.
                value = value[value.index("http"):] if "http" in value else value
                if oid == OID_ISSUER_V1 or issuer is None:
                    issuer = value
    if not identity:
        raise Rejected("signer certificate has no URI SAN, so there is no identity to pin")
    if not issuer:
        raise Rejected("signer certificate has no Fulcio issuer extension "
                       f"({OID_ISSUER_V1}/{OID_ISSUER_V2}); it is not a sigstore certificate")
    return {"identity": identity, "issuer": issuer}


def verify_tag_object(raw: bytes, identity_regexp: str, issuer: str,
                      roots: Path = ROOTS, intermediates: Path = INTERMEDIATES) -> dict:
    """The whole check. Returns the observed facts, or raises Rejected with
    the one reason it failed on."""
    payload, block = split_tag_object(raw)
    at = tagger_epoch(payload)
    der = signature_der(block)
    if not roots.exists():
        raise Rejected(f"no pinned Fulcio root at {roots}; refusing to verify against nothing")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "payload").write_bytes(payload)
        (td / "sig.der").write_bytes(der)
        cmd = ["openssl", "cms", "-verify", "-inform", "DER", "-in", str(td / "sig.der"),
               "-content", str(td / "payload"), "-binary", "-purpose", "any",
               "-CAfile", str(roots), "-attime", str(at), "-out", os.devnull]
        if intermediates.exists():
            cmd += ["-certfile", str(intermediates)]
        p = _run(cmd)
        if p.returncode != 0:
            why = (p.stderr.strip().splitlines() or ["openssl gave no reason"])[-1]
            raise Rejected(f"signature or certificate chain did not verify at tagger time {at}: {why}")
        claims = certificate_claims(signer_certificate(td / "sig.der"))

    # An unanchored pattern matches a SUBSTRING of any identity, so `.*` and
    # `platform` both "pin" everything. The regexp arrives on the object, so a
    # pattern that pins nothing is refused before it is used, not after.
    if not (identity_regexp.startswith("^") and identity_regexp.endswith("$")):
        raise Rejected(f"the pinned identity regexp {identity_regexp!r} is not anchored at both "
                       f"ends; an unanchored pattern matches a substring of any identity and pins "
                       f"nothing")
    if not re.fullmatch(identity_regexp, claims["identity"]):
        raise Rejected(f"signer identity {claims['identity']!r} does not match the pinned "
                       f"regexp {identity_regexp!r}")
    if claims["issuer"] != issuer:
        raise Rejected(f"signer issuer {claims['issuer']!r} is not the pinned issuer {issuer!r}")
    return {"identity": claims["identity"], "issuer": claims["issuer"], "signed_at": at}


def read_tag_object(repo: Path, tag: str) -> bytes:
    p = subprocess.run(["git", "-C", str(repo), "cat-file", "tag", tag], capture_output=True)
    if p.returncode != 0:
        raise Rejected(f"{tag!r} is not an annotated tag object in {repo}: "
                       f"{p.stderr.decode().strip()}")
    return p.stdout


def fetch_tag(url: str, tag: str, cache: Path) -> Path:
    """Fetch ONLY the tag ref, into a bare cache. Read-only by construction:
    no remote is ever written to, no ref is ever created outside this cache."""
    cache.mkdir(parents=True, exist_ok=True)
    if not (cache / "HEAD").exists():
        subprocess.run(["git", "init", "--bare", "-q", str(cache)], check=True)
    subprocess.run(["git", "-C", str(cache), "fetch", "--depth=1", "-q", url,
                    f"+refs/tags/{tag}:refs/tags/{tag}"], check=True)
    return cache


# --------------------------------------------------------------------------
# the controller
# --------------------------------------------------------------------------

class K8s:
    """Enough Kubernetes for one controller: list, get, merge-patch. stdlib
    only -- a dependency for three verbs would be a dependency for nothing."""

    def __init__(self):
        root = "/var/run/secrets/kubernetes.io/serviceaccount"
        self.host = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"],
                                       os.environ.get("KUBERNETES_SERVICE_PORT", "443"))
        self.token = Path(root, "token").read_text().strip()
        import ssl
        self.ctx = ssl.create_default_context(cafile=f"{root}/ca.crt")

    def call(self, path: str, method: str = "GET", body: dict | None = None,
             content_type: str = "application/json") -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.host + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        if data:
            req.add_header("Content-Type", content_type)
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            return json.loads(r.read() or b"{}")

    def patch(self, path: str, body: dict) -> dict:
        return self.call(path, "PATCH", body, "application/merge-patch+json")


GITREPOS = "/apis/source.toolkit.fluxcd.io/v1/gitrepositories"
GITREPO = "/apis/source.toolkit.fluxcd.io/v1/namespaces/%s/gitrepositories/%s"
KUSTOMIZATIONS = "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/%s/kustomizations/%s"


def reconcile_one(k8s: K8s, obj: dict, cache_root: Path) -> tuple[bool | None, str]:
    """Verify one annotated GitRepository. Returns the tri-state verdict and its reason:
    True verified, False rejected, None could-not-look. Could-not-look is never True."""
    meta, spec = obj["metadata"], obj["spec"]
    ns, name = meta["namespace"], meta["name"]
    ann = meta.get("annotations") or {}
    tag = (spec.get("ref") or {}).get("tag")
    try:
        if not tag:
            raise Rejected("GitRepository is annotated for gitsign verification but pins no "
                           "spec.ref.tag; there is no tag object to verify")
        repo = fetch_tag(spec["url"], tag, cache_root / f"{ns}_{name}.git")
        facts = verify_tag_object(read_tag_object(repo, tag),
                                  ann[ANN_IDENTITY], ann[ANN_ISSUER])
        ok, reason = True, "%s signed by %s at %d" % (tag, facts["identity"], facts["signed_at"])
    except Rejected as e:
        ok, reason = False, f"{tag}: {e}"
    except subprocess.CalledProcessError as e:
        # Could not look: an unreachable remote, a DNS failure, a deleted ref. This is NOT a
        # verdict, and it must not read as one -- returning True here printed
        # `VERIFIED -- could not fetch ...` in the controller's own log and left a stale
        # `gitsign-verified: "true"` standing on the object indefinitely, which is a fail-open on
        # the only cluster-side verification the estate has. Record the not-looking, plainly.
        ok, reason = None, f"could not fetch {tag}: {e}"

    k8s.patch(GITREPO % (ns, name),
              {"metadata": {"annotations": {
                  ANN_VERIFIED: {True: "true", False: "false", None: "unknown"}[ok],
                  ANN_REASON: reason[:250],
                  ANN_AT: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}})

    for gate in [g.strip() for g in (ann.get(ANN_GATES) or "").split(",") if g.strip()]:
        gns, _, gname = gate.partition("/")
        gate_path = KUSTOMIZATIONS % (gns or ns, gname or gate)
        try:
            current = k8s.call(gate_path)
        except Exception as e:                      # noqa: BLE001 -- report, never crash the loop
            print(f"  gate {gate}: cannot read ({e})", flush=True)
            continue
        held = (current["metadata"].get("annotations") or {}).get(ANN_SUSPENDED_BY) == "true"
        if ok is None:
            # A gate this controller is holding stays held while it cannot look. Releasing on a
            # fetch failure is the fail-open; suspending on one would let a network blip stop a
            # cluster, so a gate that is NOT held is left alone too.
            print(f"  gate {gate}: left {'suspended' if held else 'as it is'} -- {reason}",
                  flush=True)
            continue
        if not ok and not current["spec"].get("suspend"):
            k8s.patch(gate_path, {"spec": {"suspend": True},
                                  "metadata": {"annotations": {ANN_SUSPENDED_BY: "true",
                                                               ANN_REASON: reason[:250]}}})
            print(f"  gate {gate}: SUSPENDED -- {reason}", flush=True)
        elif ok and held:
            k8s.patch(gate_path, {"spec": {"suspend": False},
                                  "metadata": {"annotations": {ANN_SUSPENDED_BY: None,
                                                               ANN_REASON: reason[:250]}}})
            print(f"  gate {gate}: released -- {reason}", flush=True)
    return ok, reason


def controller(interval: int) -> int:
    k8s = K8s()
    cache_root = Path(os.environ.get("GITSIGN_CACHE", "/tmp/gitsign-cache"))
    while True:
        try:
            items = k8s.call(GITREPOS).get("items", [])
        except Exception as e:                      # noqa: BLE001
            print(f"cannot list GitRepositories: {e}", flush=True)
            time.sleep(interval)
            continue
        watched = [o for o in items
                   if (o["metadata"].get("annotations") or {}).get(ANN_IDENTITY)
                   and (o["metadata"].get("annotations") or {}).get(ANN_ISSUER)]
        print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
              f"{len(watched)}/{len(items)} GitRepositories carry gitsign pins", flush=True)
        for obj in watched:
            ok, reason = reconcile_one(k8s, obj, cache_root)
            print(f"  {obj['metadata']['namespace']}/{obj['metadata']['name']}: "
                  f"{ {True: 'VERIFIED', False: 'REJECTED', None: 'COULD-NOT-LOOK'}[ok] } "
                  f"-- {reason}", flush=True)
        time.sleep(interval)


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def pins(p):
        p.add_argument("--identity-regexp", required=True)
        p.add_argument("--issuer", required=True)
        p.add_argument("--roots", type=Path, default=ROOTS)
        p.add_argument("--intermediates", type=Path, default=INTERMEDIATES)

    v = sub.add_parser("verify-object", help="verify a `git cat-file tag` dump on disk")
    v.add_argument("tag_object", type=Path)
    pins(v)

    t = sub.add_parser("verify-tag", help="verify a tag in a local or remote repository")
    t.add_argument("--repo", type=Path, help="an existing checkout; omit to fetch --url")
    t.add_argument("--url", help="remote to fetch the tag ref from, read-only")
    t.add_argument("--tag", required=True)
    t.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "gitsign-cache")
    pins(t)

    c = sub.add_parser("controller", help="watch annotated GitRepositories and gate their Kustomizations")
    c.add_argument("--interval", type=int, default=60)

    args = ap.parse_args(argv)
    if args.cmd == "controller":
        return controller(args.interval)

    try:
        if args.cmd == "verify-object":
            raw = args.tag_object.read_bytes()
        else:
            repo = args.repo or fetch_tag(args.url, args.tag, args.cache / "repo.git")
            raw = read_tag_object(repo, args.tag)
        facts = verify_tag_object(raw, args.identity_regexp, args.issuer,
                                  args.roots, args.intermediates)
    except Rejected as e:
        print(f"REJECTED: {e}")
        return 1
    print("VERIFIED: signed by {identity} (issuer {issuer}) at {signed_at}".format(**facts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
