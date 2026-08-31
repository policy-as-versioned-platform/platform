# H6-12: does Flux mode `Tag` still verify when `spec.ref.commit` is set?

Ticket 16 Q4 made this the precondition for ticket 41: *"the build must first
test whether mode `Tag` verifies when `spec.ref.commit` is set to a commit that
is not the tag's target, because that is what platform's fan-out sources do
today; if it does not, the ancestor-pin design (GAPS 3.27) must change."*

Tested live on **2026-08-28** on the **kind-driftwood** cluster,
source-controller **v1.9.3** (`ghcr.io/fluxcd/source-controller:v1.9.3`),
GitRepository **v1**, `--watch-all-namespaces=true`. Three GitRepository
objects in a throwaway `gitsign-probe` namespace, all against the real remote
`https://github.com/policy-as-versioned-platform/platform`, all with the same
real, gitsign-signed tag. The namespace was deleted afterwards; nothing in
`flux-system` was touched.

Material, from the platform repo itself:

| thing | value |
|---|---|
| tag | `policy/v3.0.0` |
| tag **object** | `732b4b3cf50f81ec5b55d00f86e261ce55594519` |
| tag **target commit** | `e34ae7f5d38feede2c30ef45037ec9af0d3f43b3` |
| commit `distribution/versions.yaml` pins for it | `fa862b710fe34b475aba54f926a95164f003b0c1` (an ancestor, not the target) |

The verification Secret held one throwaway `ssh-ed25519` public key. The point
was never whether it would verify -- the tag is CMS/x509-signed, so no SSH or
OpenPGP key can ever verify it -- but **whether Flux looks at the tag object at
all** once a commit is pinned.

## What Flux did

**p1 — `ref: {tag}`, `verify: {mode: Tag}`**

```
Ready=False  InvalidTagSignature
SourceVerified=False  InvalidTagSignature
  signature verification of tag 'policy/v3.0.0@732b4b3cf50f81ec5b55d00f86e261ce55594519'
  failed: unsupported signature type: x509
```

Flux resolved and read the real tag object, then refused it because it cannot
speak x509/CMS. This is fluxcd/source-controller#1068 in one line, observed
rather than cited.

**p2 — `ref: {tag, commit}` (the ancestor), `verify: {mode: Tag}`**

```
Stalled=True  InvalidVerificationMode
Ready=False   InvalidVerificationMode
SourceVerified=False  InvalidVerificationMode
  cannot verify tag object's signature if a tag reference is not specified
```

**Stalled**, not retrying, never Ready. With `spec.ref.commit` set, Flux does
not treat the ref as a tag reference at all: mode `Tag` is not weakened, it is
rejected outright and the source produces no artifact.

**p3 — `ref: {tag, commit}` (the ancestor), no `verify:`**

```
Ready=True  Succeeded
  stored artifact for revision 'sha1:fa862b710fe34b475aba54f926a95164f003b0c1'
```

The commit wins over the tag, the ancestor is what gets served, and the tag
object is never fetched.

## What that decides

1. **The ancestor-pin design and Flux's own tag verification are mutually
   exclusive.** Not "the check is weaker" -- p2 stalls the source dead. Any
   source this estate wants signature-checked at the boundary must pin a tag
   and only a tag. `gate.yaml` says so on the `spec.ref` block, and the
   `{tag, commit}` pair Renovate maintains stays a git-side fact rather than a
   `spec.ref.commit`.
2. **D3 was the right call independently of that.** Even with no commit pinned
   (p1) Flux cannot verify a gitsign tag. An SSH or OpenPGP bridge would have
   worked here -- and would have been a second signer under another name.
   The controller verifies the signature that already exists.
3. **The controller must fetch the tag object itself.** p3 shows the artifact
   Flux serves need not descend from the tag at all, so verifying "whatever
   Flux fetched" would verify nothing. `verify_gitsign.py` fetches
   `refs/tags/<tag>` read-only and verifies that object.
4. **GAPS 3.27 is now a decided constraint, not an open question**, for every
   source under this controller. It says nothing about platform's internal
   `policy/v*` fan-out sources, which keep their ancestor pins until someone
   decides otherwise -- and which therefore get no boundary verification while
   they do.

## Reproducing it

```bash
kubectl --context kind-driftwood create ns gitsign-probe
kubectl --context kind-driftwood -n gitsign-probe create secret generic probe-key \
  --from-file=probe.sshpub=/path/to/any.pub
kubectl --context kind-driftwood apply -f - <<'EOF'   # the three objects above
EOF
kubectl --context kind-driftwood -n gitsign-probe get gitrepository -o yaml
kubectl --context kind-driftwood delete ns gitsign-probe
```
