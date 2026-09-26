# Machinery fixtures, one folder per member (eco-system ticket 146 item 4)

Each folder grades one policy that `compose/composition.py`'s `machinery_members()` renders.
`computed-semver/engine_compatibility.py` renders the machinery from the commit it grades, writes
each member's body to a file and grades it on every engine `distribution/machinery.yaml` lists. A
member with no folder here fails its cell. A folder carries either or both of:

- `kyverno-test.yaml`: the grader points `policies:` at the rendered body and changes nothing
  else. Every row must name the member, and a body the CLI can evaluate needs a row that asserts
  pass or fail.
- `generates.yaml`: for each trigger, the documents the body must generate, compared as parsed
  YAML after `kyverno apply` with that one resource. `[]` is a "generates nothing" check.

What the offline CLI cannot reach, measured on 1.18.2 on 2026-09-26:

- `kyverno test` does not evaluate `matchConstraints.namespaceSelector`: a selector that matches
  nothing still passes every row. The governed-namespace folders grade what the body does to a pod
  it matches, not its namespace scoping, which
  `distribution/verify-governed-namespace-guard.sh` proves structurally.
- `kyverno test` evaluates every resource as a CREATE, so an UPDATE-only body never matches. The
  two holds are graded on compiling: a planted compile error fails the run. What they write is
  measured by `distribution/verify-governed-namespace-guard.sh` step 5.
- A generator that does not match reads Pass / Excluded on 1.18.2, even on a row that expects a
  generated resource, and returns no result on 1.19 (upstream PR #16505). So the bottom-rung
  generator is graded by `generates.yaml`, never by `kyverno test` rows (hub ADR-0033 point 6).

Some rows name a served version, `5.0.0`, because the orphan allow-list is ranged from the array.
When the array stops serving 5.0.0 those rows change with it.
