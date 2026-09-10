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

## Exact-engine fixture evidence (ecosystem ticket 71)

Delegated under hub ADR-0025: `distribution/versions.yaml`'s cut policy elements
carry `tested_engines`, scoped to `published-cage-fixtures-v1`, initially Kyverno
**1.18.2 only**. This is a declaration to test specific offline fixtures, not a
runtime support range. No `1.18.x`, `>=1.18`, Kubernetes version, live controller
behavior or GA API status is inferred. Ticket 54 records historical failures on
1.19.0, including a generation difference after its compilation probe; this
change neither repairs nor declares support for 1.19.

`engine_compatibility.check(repo, binary)` is the public seam. The existing
`verify-cage-engine.sh` runs its fixture tests and this gate, keeping the check
in the already registered computed-semver family. Exit 0 means all declared
rows in this scoped matrix passed; 1 means an observed failure; 3 means missing
or unmeasured input. An absent declaration, unavailable binary, uncut line or
extra engine version that this invocation has not tested cannot pass.

For each cut line the gate:

- resolves the annotated `policy/vX.Y.Z` tag and records its peeled commit;
- requires the tag's policy subtree to equal the array-pinned commit's subtree;
- extracts the policy bytes and historical graded fixtures from that actual
  tag, never from working-tree policy files;
- adapts only policy/rule identifiers, claim version labels and PriorityClass
  name suffixes so the historical authoring fixtures exercise the released
  version-scoped bodies; generation inputs also receive the version claim;
- runs the real CLI's cage-tier mutation and cage-netpol generation matrices,
  preserving the published expected security fields and network rules;
- records Git policy/fixture tree identities, a SHA256 policy-file manifest,
  executable SHA256 and reported version, assertion counts and output digests;
- inventories the policy API versions, including alpha/beta entries explicitly.

The two current rows (policy 4.0.0 and 5.0.0) each exercise 13 mutation and 11
generation assertions under 1.18.2. Expected `skip` assertions prove deliberate
out-of-scope cases; an empty or zero-assertion execution does not prove anything
and is refused. The local orchestration tests use an explicitly synthetic CLI
and temporary Git tags; the real matrix run supplies the engine evidence.

### Contract and release boundary

`tested_engines` is additive test metadata. The policy bodies, accepted policy
versions, release tags, array commits and declared `bump` values are unchanged.
It does not add a runtime-support promise that the behavior classifier would
silently ignore. No new computed policy bump is asserted, overridden or forced
to `none`. The current array reader continues to enumerate the same lines, and
the registered compatibility check independently grades the added declaration.

This gate observes already published lines. It is deliberately **not** wired as
a new-policy pre-cut gate requiring that candidate's tag before it can exist.
Extending the publisher's pre-cut contract to candidate engine matrices, or
removing/adding a promised runtime support window, is separate work: it needs
candidate-tree evidence and explicit support-window comparison alongside the
existing `gate.run_gate`/`comparison_window`, not a guessed policy bump. Any
1.19 policy repair must go through the normal computed-semver and release
review; existing tagged bodies remain immutable. No release is authorized by
this metadata edit.

Limits: this is not a complete policy validation matrix, Kubernetes admission
proof, live reach/recage proof or observation of an adopter's actual engine.
The current sampling workflow's declared engine and an observed installed
engine are different facts. The gate does not verify tag signatures itself;
that remains the existing provenance instrument. The CLI digest identifies
what executed; its download authenticity remains the caller's pinned checksum.
No unsupported-pairing price, calibration, monetary threshold or owner runtime
declaration is supplied. This completes only ticket 71's bounded offline
matrix subtask, not its full runtime-support and pricing question.
