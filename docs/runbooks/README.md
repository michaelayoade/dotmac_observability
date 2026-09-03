# Runbooks

**Two runbooks are written**, and every other one listed below is still owed.

The two added by ADR-0011 are the rule biting rather than an oversight. The
ingestion contract's `procedure_ref` fields point HERE, at the register that
says the procedure is owed and what it must answer, rather than at a filename
that does not resolve — and `tests/architecture/test_ingestion_procedures.py`
fails the build if any `procedure_ref` stops resolving to a tracked file. A
dangling reference in an alert annotation is the same failure as untested
prose, discovered at the same moment.

`retire-a-target.md` landed in the same change as the capability it describes,
`dotmac-observability inventory-supersede`.
`migrate-the-capture-format.md` landed in the same change as
`inventory-classify`, `inventory-migrate` and the `migrate-capture` branch of
the supersession workflow (ADR-0008). Both are the rule below working as
intended rather than exceptions to it.

The rest stay unwritten because the capabilities they describe do not exist. A
runbook for a capability that does not exist is untested prose that an operator
finds at the worst possible moment and follows.

The rule is: **a runbook lands in the same PR as the capability it describes,
never before.** A procedure is written against real command output, real
failure modes and real timings from the rehearsal that proved it, not against
an intention.

## Owed runbooks

| Runbook | Lands with | Must answer |
| --- | --- | --- |
| `promotion.md` | PR 6 | How a reviewed `main` SHA becomes an accepted release on a named host, stage by stage through `FETCHED` to `ACCEPTED`, and what evidence each stage produces |
| `rollback.md` | PR 6 | How to restore the exact preceding release, how to confirm it is the one that was running, and what to do when `release.previous` is null |
| `drift-reconciliation.md` | PR 6 | How to read a disagreement between desired state, live state and the last verified receipt, which of the three moved, and how to revert a host edit rather than adopt it (`AGENTS.md` rule 2) |
| `canary-failure.md` | PR 5 | What a canary that fired but was not delivered at the receiver means, how to distinguish it from a canary that never fired, and why an outbound 200 is not delivery evidence |
| `receiver-credential-rotation.md` | PR 6 | How to rotate a value in OpenBao and place the new secret file on the host, which receivers are affected, and how to prove delivery still works afterwards |
| `add-a-product-bundle.md` | PR 8 | What a product must publish, which digests go into the bundle lock, and how the first promotion of a new bundle is verified |
| `prove-a-deadman-fires.md` | PR 5 (disposable-host rehearsal) | How each deadman's planted condition is applied on a disposable host, how the positive control in the same pass is run, and how `last_proved` and `deadman.unproved_declared` in `inventory/ingestion.toml` are moved together |
| `rebuild-the-audit-projection.md` | the projection itself (`projection.status = "live"`) | How the projection is rebuilt from application audit rows, how `compare_rebuild` is fed from both sides, and how a `MATCHED` verdict and its `last_rebuilt` date are recorded — a verdict the contract refuses while no rebuild exists |


Each of these corresponds to a capability that does not exist today. Where a
rule already exists but its enforcement does not, `AGENTS.md` says so per rule,
and `docs/ARCHITECTURE.md` §"Delivery train" holds the schedule.
