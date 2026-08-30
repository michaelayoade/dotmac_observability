# Runbooks

**One runbook is written**, and every other one listed below is still owed.

`retire-a-target.md` landed in the same change as the capability it describes,
`dotmac-observability inventory-supersede`. That is the rule below working as
intended rather than an exception to it.

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


Each of these corresponds to a capability that does not exist today. Where a
rule already exists but its enforcement does not, `AGENTS.md` says so per rule,
and `docs/ARCHITECTURE.md` §"Delivery train" holds the schedule.
