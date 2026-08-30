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

declared-unmonitored: 10

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
| 2 | No direct production file editing | Detecting a hand edit means reading the live host and comparing it with the last receipt, and neither the live reader nor the receipt exists yet. | PR 6 |
| 3 | Promotion targets an exact protected-main SHA | There is no promotion lane to constrain. Asserting the rule against a lane that does not exist would be a check that passes vacuously. | PR 6 |
| 4 | Bundles are immutable and digest-pinned | The lock contract exists and is schema-enforced; nothing yet FETCHES an artifact, so the digest comparison has no input to run against. | PR 3C |
| 5 | Product rules stay product-owned | Enforcing this means byte-comparing a fetched bundle against its recorded digest. Same missing input as rule 4. | PR 3C |
| 6 | No duplicate alert or recording rule names, no incompatible label vocabularies | The check operates over the union of loaded bundles. No bundle is loaded yet. | PR 3C |
| 8 | Every rule carries owner, severity, summary, runbook and producer proof | Producer proof compares an alert expression against the product's metrics manifest. Neither the manifest fetch nor the expression parser exists yet. | PR 3C |
| 10 | "Rule inactive" is not recovery evidence | This is a property of the live verifier, which is written against a running evaluator on the disposable host. | PR 5 |
| 11 | Promotion failure restores the exact preceding release | Requires the staging and activation machinery. | PR 6 |
| 12 | Desired, live and receipt states are independently comparable | Desired state exists. Live state and receipts do not. | PR 6 |
| 19 | Declared exposure and address family on every published surface | The guard belongs to the reusable contract, which `dotmac-deployment-foundation` owns and has not released yet. Writing a local detector would fork the rule from its owner and produce two answers to the same question. | Foundation adoption |

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
