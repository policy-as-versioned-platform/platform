# platform / shift-left — the CI ±1 check (ticket 12)

Catches an Audit→Deny flip **before merge**, not at deploy. Runs the real
`kyverno apply` offline against a workload manifest, no cluster required.

## What it does

1. Reads the workload's `policy-as-versioned.dev/policy-version` label — the
   version it targets.
2. Resolves that version's **supported window (±1 major line, by semver, not array position)** off `distribution/versions.yaml`'s
   array — the *same* array [`render-orphan-guard.py`](../distribution/render-orphan-guard.py)
   renders the live orphan-guard from. No second source of truth.
3. Runs `kyverno apply` for every policy version in the window against the
   workload.

`kyverno apply` reports the CEL pass/fail verdict independent of whether
`spec.validationActions` says `Audit` or `Deny` — Audit only changes what a
*live* cluster does with a fail (report vs block). So a workload that fails
here would be denied the moment its version is promoted Audit→Deny (ADR-0006:
promotion is editorial, never a timer) — this check catches that flip pre-merge.

## Run it

```sh
python3 ci-check.py --resource fixtures/workload-compliant.yaml   # exit 0
python3 ci-check.py --resource fixtures/workload-flip.yaml \
  --versions-file "$(python3 flip_window.py)"                      # exit 1 -- the flip
./verify-shift-left.sh                                            # all offline proofs
```

With one declared major line there is no served neighbour to flip onto.
[`flip_window.py`](flip_window.py) then prints NOTHING-TO-FLIP on stderr and
hands back the planted two-line window
[`fixtures/flip-window.yaml`](fixtures/flip-window.yaml) instead of
`distribution/versions.yaml`. `verify-shift-left.sh` also requires the flip
fixture to pass its own target and fail a neighbour. A fixture that fails its
own target is a plain failure, not a caught flip.

## The engine (eco-system ticket 148, hub ADR-0033 point 7)

Each line in the window runs only on an engine that line supports. The engine is the adopter's
own declaration, `gitops/engine/kyverno.yaml` at the top of the git repository the resource
belongs to, or the file `--engine-declaration` names. [`../engine/declaration.py`](../engine/declaration.py)
reads it, the same reader composition uses. A line supports the engines its element of the
versions file lists in `tested_engines`, read by the engine grader's own rule.

- A line in the window that does not list the declared engine prints `UNSUPPORTED PAIRING @ v<x>`
  with the reason. It is not run, so it is neither a compile error nor a pass, and the verdict
  line names it as not run and not passed.
- The kyverno CLI on PATH must report the declared version before any line runs.
- Exit 0: the target line ran and passed, and every other line that ran passed. Exit 1: a line
  that ran would deny the workload. Exit 3, could not look: no declared engine, a declaration that
  does not read, a CLI of another version, or a target line that does not support the declared
  engine. An unsupported neighbour does not change the exit, because a refusal is not the answer
  to an unsupported pairing (ADR-0033 rejected it); it is named.

The fixtures here belong to no adopter, so the beats hand `ci-check.py`
[`fixtures/engine/kyverno.yaml`](fixtures/engine/kyverno.yaml), a declaration of 1.18.2 with the
engine table's figures. The planted flip window lists `tested_engines` on both lines, and says
that 4.0.0's is planted. `verify-shift-left.sh` also plants an undeclared engine, a malformed
declaration, an engine the target does not support, a neighbour that supports no engine, a CLI of
another version and an adopter repository that declares its own engine.

[`ci-workflow.example.yml`](ci-workflow.example.yml) shows the shape an
institution repo's own `.github/workflows/` wires this into — each
institution owns its own CI; this repo only owns the check it calls.
