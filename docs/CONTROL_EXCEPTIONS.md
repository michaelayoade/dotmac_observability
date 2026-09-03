# Control exceptions — regions that are UNMONITORED, not exempt

Starter ADR-0018, adopted here as AGENTS.md rule 15: a guard exemption states
an enforceable premise, or the region is unmonitored rather than exempt. This
file is the ledger of the second kind. Every entry names a hard rule that is
currently a stated review discipline with no detector behind it, and the PR
that will give it one.

Three distinctions this file exists to keep apart:

* **Enforced** — a named test, contract or Make target fails when the rule is
  broken. Those rules are not listed here.
* **Unmonitored** — nobody has written the detector yet. Listed here. A rule in
  this state must never be described as enforced, in a PR body, a receipt or a
  release note.
* **Grandfathered** — a known violation deliberately tolerated. There are none,
  and the distinction is recorded so a future entry cannot quietly borrow the
  word "exception" to mean "accepted breach".

`tests/architecture/test_control_exceptions.py` reads this table and AGENTS.md
together as a **two-directional ratchet**. It fails when a rule declares
`none yet` without a row here, when a row survives after its rule became
enforced, and when the count below disagrees with the table. The downward
direction is the one that matters: a ledger that only ever grows is a backlog,
while one that must shrink deliberately is a plan.

declared-unmonitored: 8

> **Down three, on evidence.** Rules 10, 11 and 12 left this table with the
> promotion executor: `live_verify.py` counts rules that exist and evaluate
> rather than treating absence as health, `promote.py` captures the previous
> release before activation and rolls back on every failure from `STAGED`
> onward, and `drift.py` compares three artifacts and refuses to present a
> two-artifact answer as a three-artifact one.
>
> Two rows STAYED and had their reasons rewritten, which is the more useful
> half of this edit. Rule 2's comparison now exists and nothing schedules it
> against the live host; rule 3's executor now refuses an inexact revision and
> an unproven one, and nothing verifies the oracle it is handed. Both are
> closer than they were and neither is enforced, and moving a row on "closer"
> is how a ledger stops meaning anything.
>
> **Down one, on evidence.** Rule 18's row left this table: ADR-0006 gave it
> two detectors, one structural and one a scan. Rule 20 arrived already
> enforced rather than deferred, which is worth a sentence because the first
> draft of it was not.
>
> That draft made this repository the OWNER of a deployment-authorization
> contract, and the row would have read `none yet (PR 6)` — a gap opened on the
> way to closing one. The correction moved ownership to
> `dotmac-deployment-control`, where it already lived, and what is left here is
> a boundary: this repository authorizes nothing and attests no approval to
> itself. A boundary is checkable today, so it is checked today.

| rule | subject | why there is no detector yet | monitored by |
| --- | --- | --- | --- |
| 2 | No direct production file editing | The comparison exists (`drift.compare`) and the receipt exists. What does not exist is anything that READS the live host, because that is the promotion facility's job and the facility is not released — so no hand edit can currently fail anything. | Foundation facility |
| 3 | Promotion targets an exact protected-main SHA | The executor refuses a revision that is not an exact commit and one with no external oracle reference. Nothing yet verifies that the oracle actually resolved protected main; only the workflow holding that token can, and it cannot run until the facility exists. | promotion lane |
| 4 | Bundles are immutable and digest-pinned | The lock contract exists and is schema-enforced; nothing yet FETCHES an artifact, so the digest comparison has no input to run against. | PR 3C |
| 5 | Product rules stay product-owned | Enforcing this means byte-comparing a fetched bundle against its recorded digest. Same missing input as rule 4. | PR 3C |
| 6 | No duplicate alert or recording rule names, no incompatible label vocabularies | The check operates over the union of loaded bundles. No bundle is loaded yet. | PR 3C |
| 8 | Every rule carries owner, severity, summary, runbook and producer proof | Producer proof compares an alert expression against the product's metrics manifest. Neither the manifest fetch nor the expression parser exists yet. | PR 3C |
| 33 | Rejection is applied at the ingestion boundary | The policy is complete, gated, and proved against planted material the loader runs the classifier over — but nothing applies it to BYTES ON THE WIRE. No ingestion-edge stage is deployed, so a sender shipping an Authorization header today reaches the store; what fails is the build, if the rule stops refusing the planted probe. The two halves are worth keeping apart: the decision is owned and checked, the enforcement point is not built. | ingestion-edge lane |
| 19 | Declared exposure and address family on every published surface | The guard belongs to the reusable contract, which `dotmac-deployment-foundation` owns and has not released yet. Writing a local detector would fork the rule from its owner and produce two answers to the same question. | Foundation adoption |

## Gaps in the ESTATE, not in enforcement

A different register, deliberately kept apart from the table above. Those rows
are hard rules with no detector. These are things this control plane does not
currently observe, each with a reason and an owner — and each is a place where
somebody could reasonably assume coverage that does not exist. They are not
counted by `declared-unmonitored`, which counts rules.

The first column is a subject rather than a rule number, which is also what
keeps the two-directional ratchet from reading these as rule rows.

| gap | measured | why it is not closed here | owner |
| --- | --- | --- | --- |
| Log ingestion LAG is not measured | 2026-09-03 | Loki publishes no ingestion-lag gauge. The truthful measurement is a delivery canary stamped at send and compared at read, which needs something able to inject into the fleet and read back — the promotion facility (ADR-0010). `inventory/ingestion.toml` declares `lag_unmeasured` rather than naming a plausible metric, because an expression over a series nothing emits renders a rule that can never fire. | delivery-canary lane |
| No watcher outside this host | 2026-09-03 | Neither deadman can detect the evaluator being DEAD, because the evaluator is what evaluates them. The alternative — an always-firing heartbeat routed to a dead-man's-switch service — was refused: `routing/` declares no such receiver, so the rule would page continuously and be silenced inside a week, which is worse than the gap. | fleet lane |
| No trace store | 2026-09-03 | `fleet/alloy/config.alloy` exports traces to an OTLP endpoint and `inventory/bundle.toml` rosters no Tempo. The ingestion contract therefore declares no `traces` stream and no span attributes: declaring either would produce alerts over a store that does not exist. Whether traces should be received at all is a decision, not an omission to be tidied. | Michael |
| Grafana and promtail are rostered and unscraped | 2026-09-03 | Alertmanager was in the same state and is scraped by this change, because the notification-path deadman reads its series. These two are left because nothing reads theirs, and adding a job whose series nothing consumes is the other half of the same mistake — the shape `RESOLUTION-UNUSED` already refuses in the other direction. | this repository, when a reader exists |
| The audit projection does not exist | 2026-09-03 | `projection.status = "planned"`, so no lag alert is rendered. Its retention bound, its non-authority notice and its `UNMEASURED` rebuild verdict are declared and gated anyway, because those are the decisions that get argued about rather than declared once a thing is running and somebody depends on it. | product/kernel lanes, then this one |

## Rules that ARE enforced today

Recorded so the ratchet has something to shrink towards, and so a reader can
tell at a glance which half of AGENTS.md currently bites.

| rule | enforced by |
| --- | --- |
| 1 | `tests/architecture/test_no_secret_material.py`, `tests/mutations/test_secret_detector_bites.py`, `make secret-scan` |
| 18 | `tests/architecture/test_public_inventory_carries_no_private_material.py`, `tests/mutations/test_private_material_detector_bites.py`, `make private-scan`, and structurally by the closed public contracts |
| 20 | `tests/architecture/test_authorization_is_not_owned_here.py` |
| 7 | `tests/unit/test_routing_coverage.py` |
| 9 | `tests/unit/test_federation_rename.py` |
| 13 | `tests/unit/test_render_determinism.py`, `make render-check` |
| 14 | `tests/architecture/test_repository_contract.py` |
| 15 | `tests/architecture/test_control_exceptions.py`, `tests/mutations/` |
| 17 | branch protection on `main`: linear history, no force-push, no deletion, pull request required |
| 16 | `.dotmac/standards-profile.json`, `.github/workflows/engineering-standards.yml` |
| 21 | `tests/unit/test_private_inventory_supersede.py`, `tests/unit/test_supersession_request.py`, `tests/architecture/test_supersession_workflow_cannot_leak.py` |
| 22 | `tests/unit/test_bundle.py`, `tests/mutations/test_bundle_gates_bite.py`, and structurally by `contracts/bundle.schema.json` |
| 23 | `tests/unit/test_bundle.py`, `tests/mutations/test_bundle_gates_bite.py` |
| 24 | `tests/unit/test_bundle.py`, and structurally by `contracts/bundle.schema.json` requiring both predicates |
| 25 | `tests/unit/test_bundle.py`, and CI's `rotation-proof` job running `scripts/rotation_proof.py` with three negative controls |
| 26 | `tests/unit/test_bundle.py` |
| 27 | `tests/unit/test_capture_migration.py`, `tests/architecture/test_supersession_workflow_cannot_leak.py` |
| 28 | `tests/architecture/test_ci_matches_the_makefile.py` |
| 29 | Stated verdict discipline, recorded in `docs/inventories/observer-as-built.md` §17 — see the note below |
| 30 | `GATE-INTEGRITY-NOT-DELTA` in `validate._bundle_findings`, `tests/unit/test_bundle.py` |
| 31 | `tests/architecture/test_supersession_workflow_cannot_leak.py` |
| 32 | `tests/architecture/test_ci_matches_the_makefile.py`, `tests/architecture/test_supersession_workflow_cannot_leak.py` |
| 10 | `src/dotmac_observability/live_verify.py`, `tests/unit/test_live_verify.py`, `tests/mutations/test_live_verify_bites.py` |
| 11 | `src/dotmac_observability/promote.py`, `tests/unit/test_promotion_executor.py` |
| 12 | `src/dotmac_observability/drift.py`, `contracts/live-observation.schema.json`, `tests/unit/test_drift.py` |
| 34 | `ingestion.integrity_state`, `render._ingestion_rules`, `tests/unit/test_ingestion.py`, `tests/mutations/test_ingestion_gates_bite.py` |
| 35 | `validate._ingestion_findings` (`DEADMAN-UNPROVED-COUNT`, `DEADMAN-NOT-META`), `tests/architecture/test_ingestion_procedures.py`, `tests/mutations/test_ingestion_gates_bite.py` |
| 36 | `contracts/telemetry-ingestion.schema.json` (`authoritative` is a `const false`), `ingestion.compare_rebuild`, `validate._ingestion_findings`, `tests/mutations/test_ingestion_gates_bite.py` |

> **Up one, on evidence.** ADR-0011 added four rules and closed three of them
> outright; rule 33's second half is the one that could not be closed. Its
> policy, its planted proofs and its positive controls all bite in `make check`,
> and the runtime stage that would apply the policy to bytes on the wire does
> not exist. Recording the enforced half as enforced and the unbuilt half as
> unmonitored is the whole discipline: a rule counted as closed because most of
> it works is a rule nobody looks at again.

> **Rule 29 is the one entry above that is NOT a detector**, and saying so is
> the point of this file. No test can decide whether a summary sentence
> overclaims; what a test can do is refuse the shapes that make overclaiming
> easy, which is what rules 30 to 32 do. Rule 29 is stated review discipline
> over the wording of a verdict, and it is recorded here as such rather than
> being listed among the enforced rules it sits beside.
>
> It is not in the unmonitored table either, because that table is for rules
> whose detector is merely *not written yet*, each with the PR that will write
> it. There is no PR that will write this one.

> **Rule 25's enforcement is worth reading twice**, because it is the only
> check in this repository that runs external programs and the only one whose
> value is entirely in its negative half. A rotation that succeeds proves
> little: the same result would come back from a checker looking at the wrong
> file. The three deliberately broken stanzas — no owner, no mode, no
> post-rotation reopen — must each FAIL, and `scripts/rotation_proof.py`
> reports "THE PROOF PASSED WITH A BROKEN CONTRACT" and exits non-zero if any
> of them does not.
>
> `tests/architecture/test_ci_matches_the_makefile.py` guards the guard: each
> control locates itself in the rendered stanza by exact string, and a
> renderer change that reworded the stanza would make every control mutate
> nothing and every deliberate failure stop happening.
