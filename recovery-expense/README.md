# Prospective direct recovery-expense collection

This module collects the accepted 2027 pilot's direct incremental security-incident response/restoration expense. It supports one institutional case per driftwood, tuppence and ludlow, GBP, UTC `[2027-01-01,2028-01-01)`. `pilot-2027.json` records the prospective owner choice, `-1000` empirical-CRPS policy bar and minimum three final complete cases. It contains no expenses, registrations or outcomes. Three is an operational minimum, not a statistical power claim.

The collection accounting policy requires each institution's actual cost-centre inventory, pre-agreed exact-decimal labour charge-out rate and shared operator/control disclosure. There are no inferred rates, cost-centre defaults or proxy revenue/fine amounts. The matching publisher candidate bundle supplies that policy and binds its canonical SHA256 in the model payload and profile. Annual source construction refuses a different profile/policy digest. No adopter party document is edited by this module.

## Append-only source records

`collection.schema.json` describes policy, ledger rows, independent annual closure and 30-day process assessment. The Python module additionally checks exact arithmetic, dates, full raw-line hash-chain, evidence bytes, source allocation and finality; passing a JSON schema alone establishes none of those facts.

A ledger is newline-terminated JSONL, starting sequence 1 with `previous_sha256: null`. Every later row hashes the preceding exact raw JSON line without its newline. Existing rows are never rewritten by `append`. A local exclusive file lock and append-only file descriptor protect a checked append. A changed previous line, repeated identity or unfinished line refuses.

Rows retain incident and entry identities, incurred/recorded timestamps, institution/cost centre, category, source expense identity, exact allocation and independent evidence reference. Evidence references carry their actual HTTPS URI, custodian, local relative file and SHA256. The tool verifies the supplied file's bytes and stated arithmetic; it cannot prove that a worklog, invoice or custodian assertion is authentic. Genuine independent reconciliation and signed source admission remain necessary.

* `incremental-response-labour` uses attributable worklog hours times the explicit agreed rate. `incremental-restoration-invoice` uses an actual attributable incremental vendor/restoration cost; it cannot fabricate labour fields.
* Shared costs retain one source identity and evidence document. Allocations across the full three-institution ledger cannot exceed that source cost. Final annual closure requires full reconciliation. Repeated evidence cannot be aliased as a second expense; a duplicate row must explicitly link the exact earlier allocation and contributes no second amount.
* `incident-register` records a real incident without assigning a cost. Its monetary/source-allocation fields are null. This permits costless or not-yet-reconciled incidents to remain visible without inventing a zero expense or calling them non-events.

Routine controls/already-budgeted operating costs, invented missed sales/fines/premiums/customer or patient losses, forecast-generated outcomes, synthetic tests and double-counted shared costs are outside the collection. Use separately attributable evidence documents for source cost items; the tool does not interpret arbitrary invoice PDFs into accounting amounts.

## Public interface

```
python3 recovery-expense/collection.py check \
  --ledger /records/incident-ledger.jsonl --policy /records/collection-policy.json \
  --evidence-root /records/evidence
python3 recovery-expense/collection.py append \
  --ledger /records/incident-ledger.jsonl --policy /records/collection-policy.json \
  --record /records/next-actual-entry.json --evidence-root /records/evidence
python3 recovery-expense/collection.py process \
  --ledger /records/incident-ledger.jsonl --policy /records/collection-policy.json \
  --record /records/actual-process-assessment.json --evidence-root /records/evidence
python3 recovery-expense/collection.py resolve-source \
  --ledger /records/incident-ledger.jsonl --policy /records/collection-policy.json \
  --profile /records/actual-matching-publisher-profile.json \
  --record /records/actual-independent-year-end-closure.json --evidence-root /records/evidence
```

Create the initial empty ledger deliberately as a local data-collection file. `check` always returns a collection-only result with null annual amount and score. `process` requires an explicit independently evidenced completed 30-day window; its result is never eligible as an annual case and carries no annual amount or score. It validates collection process only. No assessment or completeness assertion is generated from elapsed time or empty logs.

`resolve-source` requires year-end reconciliation, explicit final and complete flags, the exact ledger hash, covered cost centres, reconciled incident/source inventory, and no unresolved/disputed items. Records unavailable at publication, early closure and incompletely allocated costs refuse. A case with no expense records yields no amount unless actual independent closing evidence explicitly establishes its state: an empty ledger needs a non-events attestation, while recorded incidents with no incremental cost need a distinct no-additional-expense attestation. Those states are never conflated or inferred by this module.

The constructed `recovery-expense/resolution-source-v1` has exact decimal `/amount` and Boolean `/final` and `/complete`, alongside its real accounting/evidence provenance. It must subsequently be committed and signed by the declared independent platform resolver through ordinary review/release, then supplied to the existing NIST `build-resolution` source-bound SDK. This module creates no signed registration, source authority, scorer report or outcome authentication and never calls FAIR, crypto, a cluster or an external data fetch.

Pure regressions are `python3 -B -m unittest discover -s recovery-expense -p test_collection.py -v`. Fixtures and timestamps are explicitly synthetic. Source-test success is no world observation, runtime risk join, calibration result, mitigation claim or financial/cage credit.

The matching prospective forecast target is the separate `feeds/recovery-expense` family. Its payload and profile bind the same canonical collection-policy digest used here. A signed context may add that shadow edge while retaining all institutional threat/fine selections. Platform intrinsically excludes the exact shadow feed from ordinary prices, switching costs and financial dates, independently of whether a report policy exists. Collector source amounts are outcomes only after the real resolver publication and unchanged SDK admission; they never substitute for an institutional threat/fine headline.

Recognition is by the actual expense-incurred UTC subject-year, including eligible carry-in recovery work, and excluding carry-out cost. Frequency counts incidents with eligible recovery activity inside that expense year; severity includes only their within-year eligible direct expense. Incident onset, payment and recording dates do not silently replace that recognition rule. No lifetime severity is compared to a partial-year ledger.
