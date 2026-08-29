# distribution/verify — verification at the Flux source boundary

Where `distribution/` says *which* policy version a cluster runs, this says
*whether the cluster may believe where it came from*. Three things live here
and nothing here is reconciled:

| file | what it is |
|---|---|
| `PRECONDITION-h6-12.md` | the live experiment that decided the design: what Flux actually does with mode `Tag`, with and without `spec.ref.commit`, observed on kind-driftwood on 2026-08-28 |
| `gate.yaml` | the source-boundary contract as one worked example — the annotations an org copies onto its own `GitRepository` and `Kustomization` |
| `testdata/*.tag` | real gitsign-signed tag objects from this repo's own tags, committed so the offline proof needs neither network nor fetched tags. Derived by `extract-tag-fixture.sh`, never hand-written |

The verifier itself is `../../identity/gitsign-verifier/`, shipped as a member
of the identity substrate package. The graded check is
`../../verify-source-verification.sh`.

## The two rules that came out of the experiment

1. **A source under this controller pins a tag and only a tag.** With
   `spec.ref.commit` set, Flux serves the pinned commit and never fetches the
   tag object, so there is no signature at the boundary to verify — and Flux's
   own mode `Tag` stalls the source outright. The `{tag, commit}` pair
   Renovate maintains stays a git-side fact; it does not go into `spec.ref` on
   a verified source. This does not reach platform's internal `policy/v*`
   fan-out sources, whose ancestor pins (GAPS 3.27,
   `cut-release-update-array-commit.sh`) stand — and which therefore get no
   boundary verification while they do.
2. **`spec.verify` stays absent.** Flux 2.9 speaks OpenPGP and SSH only.
   Pointing it at a gitsign tag does not weaken the check, it takes the source
   down with `unsupported signature type: x509`. No key re-signs any ref
   (ADR-0023 D3).

## The time-box

This whole boundary mechanism is temporary. It ends when
**fluxcd/source-controller#1068** lands, or when `GitRepository.spec.verify`
grows a sigstore/x509 mode by any other route — one observation either way:
the CRD's `spec.verify.mode` enum stops being exactly
`[HEAD, Tag, TagAndHEAD]`.

**`platform/verify-source-verification.sh` goes red when it does**, and says
what to do: move the pins onto `spec.verify`, delete
`identity/gitsign-verifier/`, drop the annotations from `gate.yaml` and from
every adopter's `gitops/`. That script is the only subscriber this estate has
to #1068.
