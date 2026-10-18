# Modeled quote conditions

`compose()` assesses a nonempty quote condition list after computing the current
premium-free exposure. It preserves the booked premium, attachment, limit, quote
dates and original `priced_against`. The additional `conditional_cost_view` is a
technical assessment of the declared served subjects. Its effective premium is
the conditional/TCoR **premium component**, not a retained-loss estimate, bill,
legal coverage determination or actual transfer credit.

For `served-policy-conditions/v1`, one applicable current failure breaches a
condition. A nonempty complete matrix of passes meets it technically. Missing,
skipped, warned, unsupported or incomplete evidence stays `unobserved`; counted
implementation claims and a finding's aggregate `satisfied` label never meet it.
An unknown condition makes the effective conditional cost unknown, while the
signed contract premium remains visible. A breached `void` means
`fully-retained`, without inventing a retained-loss amount. Each distinct
breached `uplift` contributes its exact quoted amount once. A foreign currency
requires the existing dated FX converter and feed, bound to the measured source's
signed FX pin. Actual billing changes only through signed re-quote and adoption.

## Selecting evidence

An adopter may supply `insurance/condition-observation.yaml`. It is a closed
object; these are its complete fields and types:

| Field | Contract |
| --- | --- |
| `schema` | integer `1`; booleans do not count as integers |
| `profile` | `served-policy-conditions/v1` |
| `party` | exact insured party under composition |
| `repository` | exact canonical GitHub `owner/repository`, matching adopter origin |
| `examined_at` | explicit `YYYY-MM-DDTHH:MM:SSZ` instant |
| `quote` | exactly `source`, `name`, `version`, `parent_sha`, `payload_sha256` |
| `baseline` | exactly `original_commit`, `source_commit`, `run_id`, `attempt`, `appends` |

The quote binding identifies the actual source/name/selected feed version, its
resolved payload commit and SHA256 of the complete raw quote envelope. The
payload commit may differ from the signed carrier tag's target; the payload
commit must be its ancestor and the consumed quote bytes must match both objects.
No directory name or current HEAD supplies a missing quote tag.

`baseline` uses full 40-character commits, positive integer run/attempt, and
exactly three append SHA256 values (64 lowercase hexadecimal characters):
`drift/samples.jsonl`, `drift/workload-samples.jsonl`,
`drift/oscal-samples.jsonl`. The selector grants no admission. The shared strict
scheduled-original reader independently verifies the official repository/default
branch/run/attempt/workflow/event/source, public and local ancestry, original's
single source parent, source-bound scheduled certificate, exact three-path
append, prefix, row counts, digests, current committed bytes and original blame.
A missing selector is unobserved. A present malformed or unauthentic instrument
refuses by name; it cannot provide a favorable result.

Each row must fall within the exact attempt's `run_started_at` through
`updated_at`, within the signed quote's inclusive validity dates, and no more
than 48 hours before the explicit examined instant. The instant must also fall
within the quote dates. A missing attempt start refuses; the run's earlier
`created_at` cannot substitute for it. The composer reads no wall clock. The
result means **as of that explicit instant**, never a claim of present freshness.

## Exact context and scope

The quoted exposure digest and known parent versions must match the current
premium-free exposure and parents. The real quoted self tag must contain that
exposure and pass the existing signed-release verifier. The authenticated source
header must carry the current parent/exposure context. Authored party, GitOps,
inventory, deployment and overlay files must agree in bytes and file set.

The measured source's exact apps and composed tag/commit pins must authenticate.
All actual composed policy bodies must match the current rendered set. Every
listed apps resource must be accounted for: regular Git files with object
documents; Namespace and ConfigMap documents are nonworkload inputs, and this
profile supports explicitly versioned Pods in the declared governed namespaces.
Other workload kinds, nested manifest references, scalar or empty resources and
ambiguous names remain unobserved. Each Pod's manifest, name, images and policy
claim must match its authentic observed workload row; absent/false `observed` or
an older caged policy version cannot supply a result.

The implementation publisher's component definition and its exact inherited
catalogue are read from the source's signed carrier pins, with consumed bytes
checked against the parent objects and current tree. `(source,id)` identifies a
control; `Check_Id` mappings define every required current policy/version and
subject cell. Ambiguous/foreign mappings, unknown controls or absent publishers
remain unobserved. Raw observation instances and full policy names are retained,
including repeated UUIDs across policy versions. Subject UUIDs must be coherent,
policy-version properties must match names, and each applicable observation must
link to its mapped finding/control. An old pass or aggregate finding cannot erase
a current failure. This profile does not infer an entire organization's control
fulfillment from a policy result.

The authenticated source header's governed namespaces define this profile's
scope. Probe, reference and infrastructure observations outside that set cannot
fill any required cell or create an insured breach. An unexplained observed
workload inside the governed set makes the scoped matrix incomplete; it is not
silently discarded. This scope is derived from the signed source declarations,
not an adopter-supplied exclusion list.

## Replay

A new `quote-assessment-schema: 1` header marker enables this assessment. Empty
condition lists add neither a view nor a marker. Historical artifacts lacking
the marker retain their historical absence on replay; a present unsupported
marker refuses. Enabled replay repeats authentication of the same immutable
original and context; there is no cached-success, response override or
`admitted: true` interface. An unavailable verification instrument refuses.
The handbook consumes the assessed effective cost and retention state, and normal
composition verification re-derives those bytes. No actual selector or claim of
real fulfillment is installed by this feature.
