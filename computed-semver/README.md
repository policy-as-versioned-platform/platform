# platform / computed-semver — ticket cs-01: can the premise be rederived?

Before designing a release gate that computes a policy version's bump from
observed verdict movement, this proves the idea works on answers already
known. The old faithful-floor estate (now the sibling `policy` org repo) cut
a real, signed release line and **live-proved** each bump by hand:

- `2.0.0` — major: `require-department-label` promoted Audit → Deny.
- `2.1.1` — the enum on `require-known-department-label` widened `+legal`
  (patch in isolation), and `require-owner-annotation` was added (minor).

`corpus/` holds those policy bodies and fixtures as **fixed input**, copied
verbatim from `policy-as-versioned-flux/policy` at `v1.0.0` / `v2.0.0` /
`v2.0.1` / `v2.1.1` (each file's header cites its exact source path and tag;
two fixtures — `legal-department.yaml` and `no-owner.yaml` — are authored
here, not copied, because no committed fixture in that repo exercises them;
see their headers for why). `rederive_bumps.py` evaluates adjacent version
pairs offline with the real `kyverno apply` CLI — the same primitive
[`../shift-left/verify-shift-left.sh`](../shift-left/verify-shift-left.sh)
already runs — and derives major/minor/patch from observed admission
movement, per `CONTEXT.md`'s "Policy version" definition as sharpened by
[ticket 02](/.scratch/computed-semver/issues/02-what-counts-as-a-verdict.md)
(compliant == admitted; an Audit rule that fires reports but does not
refuse).

## Run it

```sh
./verify-rederive-bumps.sh
```

SKIPs (exit 3, could-not-look) if the `kyverno` CLI isn't installed: exit 0
would be graded PASS by `talk/verify-all.sh`, a green on the absence of the
instrument. `./verify-rederive-bumps.sh --selfcheck` runs that branch on a
machine that does have the CLI, by re-running the script with kyverno
unreachable and requiring exit 3 (`lib.sh`'s `selfcheck_absent`); the normal
run does the same before it looks.

## Result

All three known-good bumps rederive exactly, per named policy. At the
whole-body level (`CONTEXT.md`: "a policy version covers the whole body"),
the real `v2.0.1 → v2.1.1` release bundles a minor addition and a patch
widening into one tag; combining rules take the more significant change, so
the release-level bump is **minor**, not the "patch" label the ticket's own
bullet points attach to `2.1.1` in isolation — see the script's own printed
"honest finding" for the full account, including that the real tag's decimal
(minor bumped, patch held instead of reset) doesn't follow textbook
bump-and-reset semver, which `CONTEXT.md` doesn't actually specify either way.

**The one bump this method cannot get from verdict movement alone: minor.** A
brand-new Audit-only policy produces zero admitted/refused transitions for
any fixture by construction (Audit never refuses) — there is nothing to
observe on a fixed corpus. It is detectable only by a **structural diff**
(a policy name present in the new version, absent in the old) combined with
reading its `validationActions`. The script's `demo_pooled_exit_is_not_admission`
step proves the trap empirically: a plain, pooled `kyverno apply` exit code
across a mixed Audit+Deny policy set disagrees with the real admission
outcome whenever the only CEL failure is on an Audit policy.

## Supported engines: every cell a declaration names (ecosystem tickets 71 and 146)

Hub ADR-0033: **a policy line supports exactly the engines in its `tested_engines`**, and on each
of them every body the line serves compiles and passes its fixtures. That is a runtime support
claim, and composition prices an adopter whose declared engine a line does not list (ticket 148).
No `1.18.x`, `>=1.18`, Kubernetes version or neighbouring patch is inferred. The machinery the
composer renders declares its own engines in `distribution/machinery.yaml`.

`tested_engines` is `{ scope: every-served-body-v1, kyverno: [<exact versions>] }`. The scope
names what was graded. The first scope, `published-cage-fixtures-v1` (ticket 71, PR 26), graded
the cage-tier and cage-netpol fixtures only; the grader refuses it by name, so an old
declaration cannot pass under the wider meaning. 5.0.0 was graded under the new scope before the
new scope was written on its element.

`engine_compatibility.check(repo, engines, ref)` is the public seam, and
`verify-cage-engine.sh` runs it. A **cell** is one subject (a line, or the machinery) on one
engine, and one run grades every cell:

- the caller hands in one binary per engine; each is identified by running it, never by its
  path. The hub's truth run installs every row of `engine/kyverno/engine-table.yaml` by checksum
  and names the directory in `KYVERNO_ENGINE_DIR`;
- a cell a subject lists with no binary reads could-not-look;
- a binary for an engine no subject lists is reported as extra, never read as support;
- the report prints the whole matrix, one row per subject and one column per engine.

Exit 0 means every cell passed; 1 an observed failure; 3 a missing or unmeasured input (an
undeclared or retired scope, a listed engine with no binary, an unavailable tag).

For each subject the grader reads one commit (`--ref`, HEAD by default):

- a **cut** line is graded on its annotated `policy/vX.Y.Z` tag, whose policy subtree must equal
  the array commit's;
- an **uncut** line that carries `tested_engines` is a **candidate**, graded on the tree of the
  commit being graded, which is the commit that declares it;
- every Kyverno policy in the line's `distribution/policies/v<version>/` tree is a **body**. Each
  is graded against `engine-fixtures/v<version>/<body>/` at the graded commit, with only its
  `policies:` pointed at the served bytes; or, for cage-tier and cage-netpol, against the line
  tree's own `graded/tests/<family>`, adapting only policy/rule identifiers, claim version labels
  and PriorityClass suffixes (the format the tagged 5.0.0 fixtures carry). A body with neither
  fails. A fixture folder may also carry `generates.yaml`: for each trigger, the documents the
  body must generate, compared as parsed YAML after `kyverno apply`, with `[]` for "generates
  nothing" (ADR-0033 point 6);
- the **machinery** is what `compose/composition.py`'s `machinery_members()` renders from the
  graded commit, each member against `engine-fixtures/machinery/<member>/`.

The one row served today is policy 5.0.0 (4.0.0 retired on 2026-09-24). Its five bodies pass on
1.18.2 with 13 cage-tier, 11 cage-netpol, 6 require-nonroot, 5 stamp-posture and 5
posture-trust-boundary assertions, and the seven machinery bodies pass beside it. The records
each row carries: Git tree identities, a SHA256 manifest of the policy files and of the fixtures,
each binary's SHA256 and reported version, assertion counts and output digests, and the policy
API versions, alpha and beta entries named.

Under 1.19.1, the ticket 71 diagnosis (`.scratch/ecosystem/research/kyverno-1.19-cage-diagnosis/`
in the hub) found the 5.0.0 cage-tier body does not compile, and two cage-netpol `skip` rows read
"Fail / Not found" because Kyverno 1.19 returns no result for a GeneratingPolicy that does not
match. It found no generation difference: under the offline CLI the generated NetworkPolicies are
the same on both engines. Ticket 54's prose report of one on 1.19.0 was not reproduced, and 1.19.0
did not run. The fix is a new line (ticket 149), because tagged bodies never change.

### The cut is graded before it is signed

This reverses what this section said before ticket 146: the grader was "deliberately not wired as
a new-policy pre-cut gate". It is one now (ADR-0033 point 4). `cut-release.yml` installs every
engine in the table and runs this grader on the dispatch commit after the publisher gate and
before any commit or tag. A candidate line is graded on that commit, and every other cell is
graded with it, so a tag is signed only after every cell passes. After the cut the element
carries `commit`, and the grade reads the tag.

An engine bump is not a policy version (ADR-0033 point 5). Adding an engine to a line's list is a
metadata change whose PR must pass the new cells; removing one narrows support and is priced at
the adopter's next composition. `.github/scripts/cut-release-update-array-commit.sh` keeps a
`tested_engines` it finds before the cut (ticket 146 item 8).

Limits: the offline CLI only, so no Kubernetes admission, no background controller and no live
reach. A fixture proves what its rows assert. `kyverno test` does not evaluate a
`namespaceSelector` and evaluates every resource as a CREATE, so the machinery's two UPDATE-only
holds are graded on compiling (see `engine-fixtures/machinery/README.md`). Line fixtures are read
from the graded commit rather than the tag, because they can be written after the cut; the row
records both. The grader does not verify tag signatures; that remains the provenance instrument.
A binary's authenticity rests on the checksum its installer checked against the engine table.
