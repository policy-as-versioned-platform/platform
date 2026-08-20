# policy-as-versioned-platform

**GitHub org:** [`policy-as-versioned-platform`](https://github.com/policy-as-versioned-platform) ·
**Role:** publisher, risk-bearer · **Licence:** [Apache-2.0](LICENSE)

Part of the *Policy as Versioned Code* estate: a shared platform, two regulators, three regulated
institutions, each its own independent GitHub organisation, exchanging signed, versioned
dependencies. Full thesis, design decisions (ADRs) and the other five parties:
[policy-as-versioned-flux](https://github.com/policy-as-versioned-flux/policy-as-versioned-flux).

**The shared discipline** — the governance machinery every institution inherits
as a *pinned, signed dependency* (the `config-base` pattern, one level up), so
the same apparatus is inherited rather than copy-pasted per institution.

What lives here (built across later tickets — this is the skeleton):

- **Flux distribution templates** — `ResourceSet` version fan-out, signed
  `GitRepository`, prune-on-retire, drift-heal, `dependsOn`/health, the
  notification event spine. *(ticket 03)*
- **FAIR risk engine** — `(min,mode,max)` → beta-PERT → Monte-Carlo → ALE ·
  VaR₉₅ · TVaR + risk load. *(ticket 01)*
- **the cage → OSCAL `risk`/POA&M up-flow** — a one-off that fails a check is
  caged, priced, never exempted (no ledger; banned outright, see `CONTEXT.md`).
- **shift-left harness** — ±1 version-skew off the `ResourceSet` array.
- **war-gamer + AI-Wardley** — collect → war-game → signed policy PR
  (propose-never-dispose).

The platform governs **itself** under the same risk model (Kyverno/Flux/platform
in scope) — it passes its own test. This is the **reflexive** part of the role
composition: `platform` is a **publisher** to the five other parties, and also
a **risk-bearer** in its own right, carrying a strict £10k appetite band
(`risk/appetite.json`, org `platform`, `root_of_trust: true`) rather than
standing outside the apparatus it ships.
