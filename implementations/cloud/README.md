# Cloud implementations package (ticket 151)

The platform owns the RDS/S3 members and their `component-definition.json` control claims.
The separate source path is `implementations/cloud`, published on `cloud/v<semver>` by the
dispatch-only `cloud-release.yml`. It has its own VERSION and engine cells; it changes no
frozen `distribution/policies` tree or declared Pod line. This is a prepared package: no
cloud tag, release, provider or AWS resource was created by this implementation.

`crossplane-dials.yaml` is the single table rendered into CEL. A governed Namespace selects
the rung; forged CR labels cannot select it. A missing/unknown Namespace tier, `infra`, a
missing claim or an orphan claim selects isolated. The served-claims array makes versioned
copies disjoint, while every unserved population takes the bottom rung. Mutations are
tighten-only and idempotent: public RDS access closes, storage encryption stays on, Multi-AZ
and backup retention only rise; supported KMS encryption and unrelated fields are retained.
Audit policies report the original intent. There is no Deny gate or pause/Observe switch.

The isolated service dials equal quarantine. Pod CPU, eviction, WAF and NetworkPolicy dials
have no projection onto these CRs, and this package does not claim AWS network isolation.
An encryption configuration CR is its subject: an absent configuration on a Bucket is
not observed here. Storage encryption on an already provisioned RDS instance may be an
immutable cloud setting; no provider reconciliation is part of this admission proof.

Run `KYVERNO_ENGINE_DIR=<local binaries> ./verify-cloud-package.sh`. The real CLI replays
every fixture on exact 1.18.2 and 1.19.1, checks mutated fields and idempotency, and grades
the Audit outcomes separately. `vendor-crds/` contains the two original upstream v2.6.0
documents, pinned to commit `857b535dd0eb9b8242ad9d7c4e54aaa3e4616d60` and SHA256 in
`provider-crds.yaml`. Replay and composition verify those bytes and their field shapes.
The old preserve-unknown fixtures are negative controls, not vendor schema evidence.
CLI oldObject/status exclusion compiles;
the CLI supplies no oldObject, so the status-only runtime behavior is not claimed as tested.

`render.py --claim <served claim> --served-claims <all composed claims> --source-commit
<full SHA> --output <tree>` renders the package without publication. Tuppence's `gitops/cloud/
prepare.py` extracts an exact identity-verified cloud tag and emits the cloud-only composed
paths from its `composition.build()` module. The ordinary compiler invokes that same module
when an adopter declares `gitops/cloud/platform-cloud-pin.yaml`, so compose and verify both
reproduce every cloud YAML and receipt. This is a separate pin, not an implementation-major
or engine move. It must be used with a genuine compiler release containing the optional adapter.
The incumbent snapshot is checked against its source receipt; only its declared namespace and
policy-claim mapping changes. Provider controllers and credentials remain absent.

The hub's `verify/cloud-plane/verify-cloud-plane.sh` grades actual delivery and server
admission separately. It first requires a modern step-4 PASS from an immutable signed clock
commit on the hub's origin/main, with its own recorded TRUTH line and capture. A local replay,
current capture or fixture line cannot activate the cloud plane. Missing trigger or a signed
tuppence tag that lacks a cloud path is an explicit declared wait, never a pass.
