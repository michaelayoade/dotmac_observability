# ADR-0010: The promotion executor here, the facility contract elsewhere

- **Status:** Accepted
- **Date:** 2026-09-01 (amended 2026-09-02)
- **Related:** ADR-0002 (immutable releases), ADR-0006 (private inventory),
  ADR-0008 (the bundle); `AGENTS.md` rules 2, 3, 10, 11, 12, 17, 20, 23, 24,
  29, 30; `docs/inventories/observer-as-built.md` §17; Starter ADR-0070
  (`dotmac-deployment-foundation` is a stateless universal facility)

## Context

`docs/ARCHITECTURE.md` has specified a promotion state machine since PR 1 —
`FETCHED`, `VALIDATED`, `REHEARSED`, `STAGED`, `RELOADED`, `VERIFIED`,
`ACCEPTED` — and said of it, in the same paragraph, "none of this is
implemented". The receipt contract was accepted with no writer. Live state,
which `AGENTS.md` rule 12 names as one of three independently comparable
artifacts, was not an artifact at all: it was a procedure, "read these APIs in
this order", which cannot be compared later, attached to a ticket, or replayed
against a different desired state.

Meanwhile the verdict this programme has to be able to reach —
`deployed_repaired` rather than `rendered_guarded` — was six conditions written
in a census document and held apart by discipline alone.

The obvious way to close the gap is to write a promotion tool: something that
renders, ships the bytes over SSH, swaps a symlink, reloads the evaluators and
reads them back. That is rejected below.

## Decision

**This repository owns the promotion DECISION and owns no host effect.**

`promote.promote` is the state machine. It owns the order, the refusals, the
rollback decision and the receipt. Every host effect is a method on
`promote.PromotionFacility`, a Protocol declared here and implemented by
`dotmac-deployment-foundation`.

`live_verify.py` compares a read-back with the desired state and reports the
six conditions and the verdict they add up to. It performs no I/O:
it takes a parsed `observability-live-observation.v2` document.

`receipt.py` builds a receipt from what was observed and refuses one that
claims more than it proved. `drift.py` compares the three artifacts and reports
which pair disagrees.

Three consequences follow, and each is the reason for the split rather than a
side effect of it.

**Every stage is testable with no host.** The state machine, its refusals and
every rollback path run against a recording double in
`tests/unit/test_promotion_executor.py`. A promotion executor that could only
be exercised against a live host would be exercised rarely, and the properties
it guarantees are the ones that must not be wrong.

**There is one answer to how a release reaches a host.** A transport grown here
would be a second one, and the second answer is the one that never gets the
fixes.

**A verdict cannot be asserted, only derived.** `Verification.verdict` is a
property over all six conditions and refuses to be constructed from fewer;
`receipt_findings` refuses an `accepted` outcome while the verification holds
at `rendered_guarded`.

### Live state becomes a contract

`contracts/live-observation.schema.json`. Every field is a count, a boolean, a
digest, an enum, a logical name or a timestamp — the discipline the receipt
already keeps, for the same reason. There is deliberately **no field an
endpoint, port, scrape URL, credential basename or error string can be typed
into**: `last_error` carries the target's address in most real failures, and
one such field would undo rule 18 for the whole document. Target failure is
therefore a health enum, and the address is established from the private
inventory whose digest the receipt already carries.

### Why a reset cannot pass

Condition 3 is "the rejected-sample increase is zero **without resetting the
counter**". `counter == 0` is satisfiable four ways and only one of them is a
repair, so each of the other three is a refusal:

| Shape | Finding |
| --- | --- |
| counter went backwards | `INTEGRITY-COUNTER-RESET` |
| the evaluator process restarted between the readings | `INTEGRITY-PROCESS-RESTARTED` |
| the baseline is zero | `INTEGRITY-BASELINE-ZERO` |
| the window is shorter than the gate's own | `INTEGRITY-WINDOW-TOO-SHORT` |
| no baseline was supplied | `INTEGRITY-BASELINE-ABSENT` |

The second is the one worth stating separately. A counter that was reset and
has climbed back PAST the baseline passes a value comparison and reports a
healthy delta over exactly the period every sample was dropped. Only
`process_start_time_seconds`, read in the same pass, separates it from a
genuine no-change — which is why the observation carries it and why it is not
optional.

### Why IPv6 needs its own positive control

Condition 5 requires a probe per surface **per address family**, each carrying
a positive control nested inside it. On this fleet IPv4 to a container publish
is DNAT'd through `FORWARD` and therefore `DOCKER-USER`, while IPv6 published
by the userland `docker-proxy` terminates on `INPUT` and never traverses
`DOCKER-USER` — seven IPv6 DROP rules were found in that chain, where no such
packet arrives, so every port they named read as closed and was open. A v4-only
pass has therefore passed over a live v6 exposure more than once.

Three properties make that unrepresentable rather than discouraged. The chain a
probe SHOULD have observed is derived from the surface's kind and family, never
taken from the observation (`PROBE-CHAIN-INERT`). A `dual_stack` surface
produces two slots and a missing one is `PROBE-FAMILY-MISSING`, not a shorter
pass. And the positive control is nested INSIDE each probe rather than listed
alongside them, so an IPv6 probe structurally cannot borrow an IPv4 control —
without a working control, a refusal proves the prober ran, not that access is
shut.

## What `dotmac-deployment-foundation` must provide

Stated as a contract so the Foundation lane implements it without re-deriving
it. Measured against `packages/dotmac-deployment-foundation/` in
`dotmac_starter_mt` at `0.3.0a1` (declared-unpublished; `0.2.0a2` is the newest
installable version).

### What already exists there and is reusable

| Capability | Where |
| --- | --- |
| An effects Protocol and an executor over a plan | `engine/run.py:88`, `engine/run.py:230`, `engine/run.py:334` |
| Rollback step derivation | `engine/plan.py:618` |
| Deterministic rendering plus a byte-comparing `render --check` | `cli.py:154` |
| Host-lease and rehearsal-receipt records | `lease.py:81`, `rehearsal.py:301` |
| Exposure observation and verification, both families, `iptables-save` parsing | `exposure.py:726`, `exposure.py:1033`, `providers/exposure_host.py:139` |
| An injectable command runner — the transport seam | `providers/compose_host.py:245` |
| `IngressPolicy.v1` | `ingress.py:58` (only in the unpublished `0.3.0a1`) |

### What is absent and must be built

1. **A release-directory transport and activation.** The shipped executor's
   "switch" is `docker compose up -d --force-recreate` against a re-rendered
   Compose file (`providers/compose_host.py:1065`). Nothing stages a directory,
   nothing swaps a pointer. `stage(tree, target=...)` must write the whole
   rendered tree to a new immutable release directory and activate it by
   swapping the pointer the mounts resolve through — never file by file. A
   single-file bind mount is bound to an inode, which is how the Observer host
   became append-only by hand (ADR-0002).

2. **A previous-release-pointer READER.** `previous_image` is supplied by the
   caller today (`engine/plan.py:255`); nothing on the host is consulted.
   `stage` must return `StagedRelease(current, previous)` with `previous` read
   from the host before activation. `null` is legitimate exactly once, on a
   host that has never held a release.

3. **A remote transport.** No SSH, rsync, scp, paramiko or fabric exists in the
   package; the only implementation in the whole Starter repository is a script
   outside it (`scripts/exposure_rehearsal_runner.py:126`) and is not
   installed. The `runner:` seam is the intended insertion point.

4. **A service reload that is not Nginx.** `NginxInstaller.install()` is the
   only reload primitive (`providers/compose_host.py:1343`) and is not wired
   into the executor. `reload(target=..., release=...)` must make Prometheus
   take the new configuration over `--web.enable-lifecycle` without recreating
   the container and losing the scrape window, and reload Alertmanager.

5. **A read-back that produces `observability-live-observation.v2`.** Nothing
   in the package queries Prometheus or Alertmanager; its only network call is
   a readiness GET (`providers/compose_host.py:132`). `observe` must return a
   document satisfying that contract:

   | Block | Source |
   | --- | --- |
   | `tree` | every file under the active release, path and sha256, COMPLETE |
   | `targets` | `/api/v1/targets`, one entry per active target, job and health only |
   | `rules` | `/api/v1/rules`, group, name and evaluation health |
   | `routes` | the resolved Alertmanager route tree, by declared route id |
   | `integrity` | one reading per counter named in `ObservationRequest.integrity_counters` — ALL of them — each with `process_start_time_seconds` from the same read |
   | `canary` | fired, delivered AT THE RECEIVER with an evidence reference, recovered |
   | `probes` | one per `ObservationRequest.probe_slots` entry, with the chain observed and a positive control |

6. **`rollback` returns a read-back.** Its signature is
   `rollback(target, release) -> LiveState`, and the return type is the
   contract: a rollback returning `None` lets "the command did not raise" stand
   in for "the host recovered". The returned observation must carry a
   `rollback` block naming the restored pointer and the digest actually read
   back, or the executor records `ROLLBACK-UNOBSERVED`.

7. **A rehearsal on a disposable host.** `rehearse(tree, request)` applies the
   whole release to a disposable host and returns the same observation
   document. The rehearsal-receipt and host-lease records already exist and
   should carry it.

8. **`ExecutionPlanDigestV1`, recomputed before execution.** The fleet ruling
   of 2026-09-01 (Starter `AGENTS.md` rule 49) makes
   `ExecutionPlanDigestV1 = sha256(canonical FoundationExecutionPlanV1 bytes)`
   the middle term of the receipt binding, owned by the Foundation and merely
   frozen by Control. The facility renders that document, computes the digest,
   and **recomputes it immediately before executing**. A mismatch means the
   PLAN CHANGED, and the refusal must say so: if a mismatch could also mean
   "two canonicalizers disagreed", the fix a reader reaches for is a
   normalizer, which is how the original Control/Foundation divergence became
   permanent. Nothing here re-derives it — this repository records it and
   compares it as an opaque string (`RECEIPT-EXECUTION-PLAN-DIGEST`).

9. **An installable `IngressPolicy.v1`.** `0.3.0a1` is declared-unpublished and
   held; `0.2.0a2` does not carry the contract. This repository's rule 19 stays
   unmonitored until a version carrying it is publishable and pinnable.

### What the Foundation must NOT provide

Any judgement about whether the promotion succeeded. Health thresholds, target
expectations, the verdict, the receipt's honesty checks and the six conditions
are this repository's, because they are statements about THIS control plane.
The facility reports what it observed and performs what it was told.

## The approval gate proves itself

Measured 2026-09-01: this repository has **zero environments configured** while
two workflows name one. A job naming an environment that does not exist does
not wait for anybody — GitHub creates it implicitly with no protection rules
and the job proceeds — so `environment: observability-promotion` is a comment
until somebody configures it, and the existing supersession workflow says as
much about its own `private-inventory` environment in a comment that turns out
to be describing nothing.

`promote.yml`'s hosted pre-dispatch job therefore queries the environment and
refuses when it does not exist, and refuses again when it exists with no
`required_reviewers` rule. An unprotected environment and no environment behave
identically; only one of them looks configured.

Two operational facts stand alongside it. The dedicated runner
`control-runner-observability` IS registered and online with the exact label
set. None of the OpenBao bindings — `OPENBAO_ADDR`,
`OPENBAO_INVENTORY_READER_TOKEN`, `OPENBAO_INVENTORY_WRITER_TOKEN`,
`OBSERVABILITY_PRIVATE_INVENTORY_{MOUNT,PATH,FIELD}` — nor
`OBSERVABILITY_HOST_BINDING` is configured, so the private inventory cannot be
read, migrated or superseded, and a promotion cannot resolve.

## Consequences

`AGENTS.md` rules 10, 11 and 12 move from unmonitored to enforced, and
`docs/CONTROL_EXCEPTIONS.md` drops from ten declared-unmonitored rows to seven.

Rules 2 and 3 stay unmonitored with rewritten reasons, and that is deliberate.
Rule 2's comparison now exists and nothing schedules it against the live host;
rule 3's executor refuses an inexact revision and an unproven one, and nothing
verifies the oracle it is handed. Both are closer than they were and neither is
enforced. Moving a row on "closer" is how a ledger stops meaning anything.

`contracts/promotion-receipt.schema.json` is amended twice, and both amendments
are corrections rather than additions.

`plan_digest` becomes `^sha256:[0-9a-f]{64}$`. The owner emits its digest in
that canonical form and explicitly forbids a consumer from stripping the
prefix; the receipt's own description already said that where the two disagree
the owner is right and this is the defect. A contract demanding bare hex would
force every adopter to fork a digest parser, and a forked parser surfaces later
as a false "the plan changed" nobody can explain.

`release`, `live`, `canary` and the six `validation` results move out of the
unconditional required list into `allOf` branches on `outcome`. A receipt is
written for a FAILURE too, and a promotion that failed at fetch has no release
directory, no read-back, no canary and never reached the evaluator toolchain.
Requiring those blocks forced a failed receipt to carry fabricated ones — zeros
that read as "0 of 0 targets up", and six `passed: false` entries recording
checks that never ran. Both are the absence-is-not-evidence mistake wearing the
other way round, and the second is worse: it manufactures six failures. An
absent check now means "did not run", exactly as a null `run_ref` already did.

An `accepted` receipt still requires the release, the live block, the canary
and all six checks; a `rolled-back` one still requires the release and the
rollback record. Nothing an outcome actually asserts became optional.

`authorization.execution_plan_digest` is added to the receipt as an OPTIONAL
field, and it is deliberately a different value from `plan_digest`.
`plan_digest` answers which approved plan record was executed;
`ExecutionPlanDigestV1` answers what the Foundation actually rendered and
re-derived before executing it. Conflating the two is not hypothetical — it
shipped across this fleet as a binding that could not be equal for any input
while reading as correct on both sides. Optional rather than required because
Control's `execution_plan_digest` column and the Foundation version that
renders the document are both unpublished; a required field would bind this
contract to something nothing can yet produce.

Two things this repository cannot check are recorded here rather than left
implicit. The receipt requires `images` to equal the approved plan's image set,
and the deployment control plane's plan record carries **no image field** — the
images live inside its opaque `spec`. Until that is exposed, `authorized_images`
is supplied by the promotion caller and the comparison proves the caller
consistent with itself. And there is **no read API** for an approved plan there:
no fetch-by-digest and no verify-approved route, only a write path that compares
an expected digest during authorization. An Observability promotion is therefore
HANDED an authorization; it cannot independently confirm one.


## Amendment 2026-09-02: the facility exists, and the contract it exposed two holes in

Michael ruled on four open questions. Recorded here because three of them are
statements about THIS repository's boundaries and the fourth is what makes the
first three testable.

1. `dotmac_observability` owns the monitoring bundle, the promotion workflow
   and **monitoring-specific verification**.
2. The Foundation owns generic execution, rollback and target read-back.
   **This repository must not create a second executor.**
3. **Deployment Control is the only authority for approved-plan standing and
   `authorized_images`.** A workflow input cannot substitute for
   `ApprovedPlanLookup`.
4. A real protected GitHub production environment with a named required
   reviewer; narrowly scoped OpenBao identities; `OBSERVABILITY_HOST_BINDING`.

### The approval gate is no longer a comment

Both environments now exist and were read back from the GitHub API rather than
asserted: `private-inventory` and `observability-promotion`, each with
`michaelayoade` as a required reviewer and a custom deployment-branch policy
naming exactly `main`. `promote.yml`'s pre-dispatch refusals were NOT relaxed
to achieve this — they stop firing because the gate became real, which is the
only acceptable way for a refusal to stop firing.

`observability-promotion` **is** the production environment decision 4 asks
for; `promote.yml` promotes to the named production host and gates on that
environment. A third environment was deliberately not invented.

`prevent_self_review` is `false` and stays there while there is one reviewer:
with a single reviewer who is also the dispatcher, `true` makes every promotion
un-approvable. The gate is a genuine blocking pause; it is not an independent
second party, and only a second reviewer would make it one. That limitation is
recorded rather than papered over.

### Binding to the facility, and why nothing imports it yet

`dotmac_deployment_foundation.observability_promotion` exists and is merged
(Starter `a203b6e6`, declaring `0.3.0a4`). It supplies immutable staging, the
previous-pointer read and its preservation, exact-byte transport, atomic
activation, both reloads, the complete read-back, exact rollback, and the
restored read-back after it — the nine things this ADR said were absent.

`promote.PromotionFacility` stays a Protocol this repository declares and does
not implement, and the binding will be an adapter over that Protocol. There is
no second executor and there will not be one.

**It is not imported yet, and that is rule 26 rather than reluctance.**
`0.3.0a4` is recorded in Starter's own publication baseline as *"DECLARED,
NEVER BUILT"*, and the newest published tag is
`dotmac-deployment-foundation-v0.2.0a2`. A version present in a `pyproject.toml`
or on `main` is not evidence it is published or pinnable, and this repository
does not get to be the exception. The same holds for decision 3: Control's
`find_approved_plan(db, *, plan_digest, expected_execution_plan_digest=None)
-> ApprovedPlanLookup` is merged at `4e3cbd78` and unreleased, newest tag
`dotmac-deployment-control-v0.1.0a2`. Both are designed against and pinned when
a tag exists.

### The two findings the facility's author left here

Both are defects in the contract THIS repository owns, which is why the
facility could not fix either one and correctly refused to try.

**A read-back must carry every counter, not the first.**
`live_verify.integrity_counters` derives its list from the gates' own integrity
predicates, so a bundle whose gates watch several counters names several. The
v1 `integrity` block held exactly one object. A facility handed several had two
options and both were wrong: read `counters[0]` and file a document that reads
as a COMPLETE read-back while the unread counters are precisely what the
remaining alert gates assert about, or refuse the promotion outright. The
subset is the worse failure because it is indistinguishable from a genuine full
pass — so v1's shape forced a correct facility to refuse.

`integrity` is now an array with one reading per declared counter, and the
verifier compares SETS: a declared counter with no reading is
`INTEGRITY-COUNTER-UNREAD`, a reading no gate watches is
`INTEGRITY-COUNTER-UNWATCHED`. Readings are paired by counter name before they
are compared, which retires `INTEGRITY-COUNTER-MISMATCH` — that guard existed
because v1 could compare two unrelated series, and the mismatch is now
unrepresentable rather than merely detected.

**A null digest must say which null it is.** A tree digest is order-dependent
and a directory read-back has no inherent order, so the order comes from a
`ReleaseTreeManifest.v1` held outside the release directory. That leaves two
very different facts sharing one `restored_digest: null`: the manifest was lost
(the bytes were read, the restore may have been exact, and it is merely
UNPROVABLE) or the pointer came back empty (there was no tree, and the host is
running the wrong release). The verifier read both as condition 6 unproven,
which is safe and stays safe — but it sent an operator hunting for a lost file
when the host was on the wrong release, and the reverse.

`rollback.digest_absence` now carries `ordering_manifest_absent` or
`nothing_restored`, is required, and is null exactly when a digest is present.
The verifier emits `ROLLBACK-ORDER-UNKNOWN` and `ROLLBACK-RESTORED-NOTHING`
respectively. Neither passes; the point is that they are told apart, and a test
asserts the two produce DIFFERENT findings rather than only that each fails.

### Consequences of the amendment

The contract is `observability-live-observation.v2`. Nothing published consumes
v1 — this repository is `Private :: Do Not Upload` and the only producer is a
Foundation version that was never built — so the version moves without a
compatibility window. The Foundation must emit v2, and until it does a
multi-counter bundle refuses loudly. That refusal is correct: it is the shape
that was making a correct facility choose between refusing and lying.

## Alternatives considered

**Write a promotion tool here.** Fastest, and it makes this repository a second
deployment system. Every fix to staging, transport or activation would then
exist twice on this fleet and diverge. Rejected by the ownership table this
repository has held since ADR-0001.

**Let `live_verify` read the APIs itself.** Simpler to run and much harder to
test: every one of the six conditions would need a live evaluator, so they
would be exercised rarely. Rejected — the split is what makes a reset, a
missing IPv6 probe and an unobserved rollback each a test.

**Keep the six conditions as review discipline.** They already were, and rule
29 already stated them. A condition nothing evaluates is a condition somebody
eventually reports as met.

**Model live state as a Python object only.** It would work for the verifier
and defeat rule 12: an artifact that exists only in memory during one run
cannot be compared with a receipt written a fortnight ago.
