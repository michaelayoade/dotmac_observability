"""The state machine: its order, its refusals, and where rollback begins.

Every test drives :func:`promote` against a recording double of the promotion
facility. That double is the point of the design being a Protocol: no stage of
this state machine needs a host, a container or a daemon to be exercised, so
"no stage is skippable" and "a failure after staging rolls back" are properties
with tests rather than sentences in an architecture document.

The double records the calls it received in order. Several tests assert over
that list rather than over the outcome, because the outcome cannot distinguish
"rolled back" from "reported a rollback and did nothing".
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence

import pytest

from dotmac_observability.live_verify import LiveState
from dotmac_observability.promote import (
    STATES,
    AssertedRevision,
    FetchedBundle,
    ObservationRequest,
    PromotionOutcome,
    StagedRelease,
    promote,
)
from dotmac_observability.receipt import (
    OUTCOME_ACCEPTED,
    OUTCOME_FAILED,
    OUTCOME_ROLLED_BACK,
    Authorization,
    CheckResult,
    Runs,
    receipt_findings,
)
from dotmac_observability.render import RenderedTree
from tests.conftest import CONTRACTS
from tests.unit.observations import (
    AUTHORIZATION,
    BUNDLES,
    CURRENT_RELEASE,
    IMAGES,
    INVENTORY,
    PASSED,
    PLAN_DIGEST,
    PREVIOUS_DIGEST,
    PREVIOUS_RELEASE,
    RESOLUTION,
    REVISION,
    RUNS,
    STATE,
    baseline,
    passing,
)

TARGET = STATE.control_plane.host.target_id
ASSERTED = AssertedRevision(revision=REVISION, oracle_ref="workflow-run/9")

FETCHED = tuple(
    FetchedBundle(
        product=bundle.product,
        source_revision=bundle.source_revision,
        rules_sha256=bundle.rules_sha256,
        rule_count=bundle.rule_count,
    )
    for bundle in BUNDLES
)


class Recorder:
    """A promotion facility that records what it was asked to do.

    Every host effect is a method here and a no-op in fact, which is what lets
    the executor's ORDER be the subject of a test. `fail_at` names the state
    whose method raises, so one parameter reproduces a failure at any point in
    the machine.
    """

    def __init__(
        self,
        *,
        fail_at: str | None = None,
        checks: Mapping[str, CheckResult] | None = None,
        rehearsal: LiveState | None = None,
        live: LiveState | None = None,
        previous: str | None = PREVIOUS_RELEASE,
        restored: LiveState | None = None,
        rollback_raises: bool = False,
    ) -> None:
        self.calls: list[str] = []
        self.requests: list[ObservationRequest] = []
        self.rolled_back_to: list[str] = []
        self._fail_at = fail_at
        self._checks = dict(PASSED) if checks is None else dict(checks)
        self._rehearsal = passing() if rehearsal is None else rehearsal
        self._live = passing() if live is None else live
        self._previous = previous
        self._restored = passing() if restored is None else restored
        self._rollback_raises = rollback_raises

    def _record(self, state: str) -> None:
        self.calls.append(state)
        if self._fail_at == state:
            raise RuntimeError(f"the facility failed at {state}")

    def fetch(self, revision: AssertedRevision) -> Sequence[FetchedBundle]:
        self._record("FETCHED")
        assert revision.revision == REVISION
        return FETCHED

    def check_configuration(self, tree: RenderedTree) -> Mapping[str, CheckResult]:
        self._record("VALIDATED")
        return self._checks

    def rehearse(self, tree: RenderedTree, request: ObservationRequest) -> LiveState:
        self._record("REHEARSED")
        self.requests.append(request)
        return self._rehearsal

    def stage(self, tree: RenderedTree, *, target: str) -> StagedRelease:
        self._record("STAGED")
        return StagedRelease(current=CURRENT_RELEASE, previous=self._previous)

    def reload(self, *, target: str, release: str) -> None:
        self._record("RELOADED")

    def observe(self, *, target: str, request: ObservationRequest) -> LiveState:
        self._record("VERIFIED")
        self.requests.append(request)
        return self._live

    def rollback(self, *, target: str, release: str) -> LiveState:
        self.calls.append("ROLLBACK")
        self.rolled_back_to.append(release)
        if self._rollback_raises:
            raise RuntimeError("the restore failed")
        return self._restored

    def accept(self, *, target: str, release: str) -> None:
        self._record("ACCEPTED")


def run(
    facility: Recorder,
    *,
    named_target: str = TARGET,
    revision: AssertedRevision = ASSERTED,
    authorization: Authorization = AUTHORIZATION,
    first_promotion: bool = False,
    runs: Runs = RUNS,
) -> PromotionOutcome:
    return promote(
        facility,
        STATE,
        RESOLUTION,
        INVENTORY,
        named_target=named_target,
        revision=revision,
        authorization=authorization,
        authorized_images=IMAGES,
        baseline=baseline(),
        previous_digest=PREVIOUS_DIGEST,
        first_promotion=first_promotion,
        runs=runs,
        started_at="2026-09-01T11:59:00+00:00",
        finished_at="2026-09-01T12:00:00+00:00",
    )


def codes(outcome: PromotionOutcome) -> set[str]:
    return {finding.code for finding in outcome.findings}


# ── The forward path ────────────────────────────────────────────────────────


def test_a_clean_promotion_passes_through_every_state_in_order():
    facility = Recorder()
    outcome = run(facility)
    assert outcome.outcome == OUTCOME_ACCEPTED, [f.render() for f in outcome.findings]
    assert outcome.states == STATES
    assert facility.calls == list(STATES)
    assert "ROLLBACK" not in facility.calls


def test_the_states_this_executor_walks_are_the_documented_ones():
    """Sensitivity: the test above compares against `STATES`, so `STATES` must be right."""
    architecture = (
        "FETCHED",
        "VALIDATED",
        "REHEARSED",
        "STAGED",
        "RELOADED",
        "VERIFIED",
        "ACCEPTED",
    )
    assert architecture == STATES


def test_a_clean_promotion_writes_a_receipt_that_passes_its_own_validator():
    outcome = run(Recorder())
    assert outcome.receipt is not None
    findings = receipt_findings(
        outcome.receipt,
        contracts=CONTRACTS,
        first_promotion=False,
        verification=outcome.verification,
        authorized_images=IMAGES,
        authorized_plan_digest=PLAN_DIGEST,
    )
    assert findings == (), [finding.render() for finding in findings]


def test_the_observation_request_covers_every_declared_surface_and_family():
    """The executor derives what to probe; the facility does not choose."""
    facility = Recorder()
    run(facility)
    assert facility.requests
    slots = facility.requests[-1].probe_slots
    assert {family for _, family in slots} == {"ipv4", "ipv6"}
    assert len(slots) == 2 * len(STATE.bundle.exposure.surfaces)


def test_the_observation_request_names_the_counter_the_gate_asserts_about():
    facility = Recorder()
    run(facility)
    counters = facility.requests[-1].integrity_counters
    assert counters
    assert all("_total" in counter for counter in counters)


# ── Refusals before anything is fetched ─────────────────────────────────────


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"named_target": ""}, "PROMOTION-TARGET-UNNAMED"),
        ({"named_target": "some-other-host"}, "PROMOTION-TARGET-MISMATCH"),
        (
            {"revision": AssertedRevision(revision="main", oracle_ref="workflow-run/9")},
            "PROMOTION-REVISION-NOT-EXACT",
        ),
        (
            {"revision": AssertedRevision(revision=REVISION, oracle_ref="")},
            "PROMOTION-REVISION-UNPROVEN",
        ),
        (
            {"authorization": Authorization(plan_digest="", approval_decision_ref="")},
            "PROMOTION-UNAUTHORIZED",
        ),
    ],
)
def test_a_precondition_refusal_touches_the_host_not_at_all(kwargs, code):
    facility = Recorder()
    outcome = run(facility, **kwargs)
    assert code in codes(outcome)
    assert facility.calls == [], "a refused promotion called the facility"
    assert outcome.states == ()


# ── Failure before staging: no rollback, because nothing changed ────────────


def test_a_configuration_the_toolchain_refuses_stops_before_staging():
    failed = dict(PASSED)
    failed["amtool_config"] = CheckResult(passed=False, detail="refused")
    facility = Recorder(checks=failed)
    outcome = run(facility)
    assert "PROMOTION-VALIDATION-FAILED" in codes(outcome)
    assert outcome.states == ("FETCHED", "VALIDATED")
    assert "STAGED" not in facility.calls
    assert "ROLLBACK" not in facility.calls


@pytest.mark.parametrize("stage", ["FETCHED", "VALIDATED", "REHEARSED"])
def test_a_failure_before_staging_does_not_roll_anything_back(stage):
    facility = Recorder(fail_at=stage)
    outcome = run(facility)
    assert outcome.outcome == OUTCOME_FAILED
    assert "ROLLBACK" not in facility.calls
    assert outcome.rolled_back_to is None


def test_a_rehearsal_that_does_not_hold_stops_the_promotion():
    broken = dataclasses.replace(passing(), tree=())
    facility = Recorder(rehearsal=broken)
    outcome = run(facility)
    assert "TREE-NOT-READ" in codes(outcome)
    assert "STAGED" not in facility.calls


def test_every_failure_still_produces_a_receipt():
    """A promotion that leaves no record is indistinguishable from one nobody ran."""
    for stage in ("FETCHED", "VALIDATED", "REHEARSED", "STAGED", "RELOADED", "VERIFIED"):
        outcome = run(Recorder(fail_at=stage))
        assert outcome.receipt is not None, f"no receipt for a failure at {stage}"
        assert outcome.receipt["outcome"] in {OUTCOME_FAILED, OUTCOME_ROLLED_BACK}


def test_a_receipt_for_a_pre_readback_failure_carries_no_fabricated_counts():
    outcome = run(Recorder(fail_at="FETCHED"))
    assert outcome.receipt is not None
    assert "live" not in outcome.receipt
    assert "canary" not in outcome.receipt
    findings = receipt_findings(outcome.receipt, contracts=CONTRACTS, first_promotion=False)
    assert findings == (), [finding.render() for finding in findings]


# ── Failure after staging: rollback to the captured pointer ─────────────────


@pytest.mark.parametrize("stage", ["RELOADED", "VERIFIED"])
def test_a_failure_after_staging_restores_the_captured_previous_release(stage):
    facility = Recorder(fail_at=stage)
    outcome = run(facility)
    assert "ROLLBACK" in facility.calls
    assert facility.rolled_back_to == [PREVIOUS_RELEASE]
    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert outcome.rolled_back_to == PREVIOUS_RELEASE


def test_a_verification_that_does_not_reach_the_verdict_rolls_back():
    degraded = passing()
    degraded = dataclasses.replace(
        degraded,
        targets=(dataclasses.replace(degraded.targets[0], health="down"), *degraded.targets[1:]),
    )
    facility = Recorder(live=degraded)
    outcome = run(facility)
    assert "TARGET-UNHEALTHY" in codes(outcome)
    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert facility.rolled_back_to == [PREVIOUS_RELEASE]
    assert "ACCEPTED" not in facility.calls


def test_a_rollback_that_returns_no_read_back_is_not_recorded_as_a_rollback():
    """A command that returned is not a host that recovered."""
    unobserved = dataclasses.replace(passing(), rollback=None)
    facility = Recorder(fail_at="VERIFIED", restored=unobserved)
    outcome = run(facility)
    assert "ROLLBACK-UNOBSERVED" in codes(outcome)
    assert outcome.outcome == OUTCOME_FAILED


def test_a_rollback_that_itself_fails_stays_a_failure():
    facility = Recorder(fail_at="VERIFIED", rollback_raises=True)
    outcome = run(facility)
    assert "ROLLBACK-RAISED" in codes(outcome)
    assert outcome.outcome == OUTCOME_FAILED
    assert outcome.rolled_back_to is None


def test_staging_that_captured_no_previous_pointer_stops_and_says_so():
    facility = Recorder(previous=None)
    outcome = run(facility)
    assert "PROMOTION-NO-ROLLBACK-TARGET" in codes(outcome)
    assert "ROLLBACK-IMPOSSIBLE" in codes(outcome)
    assert "RELOADED" not in facility.calls


def test_the_first_promotion_may_legitimately_have_no_previous_pointer():
    facility = Recorder(previous=None)
    outcome = run(facility, first_promotion=True)
    assert "PROMOTION-NO-ROLLBACK-TARGET" not in codes(outcome)
    assert "RELOADED" in facility.calls


# ── Acceptance is a host effect too ─────────────────────────────────────────


def test_a_failure_at_acceptance_rolls_back_like_any_other():
    facility = Recorder(fail_at="ACCEPTED")
    outcome = run(facility)
    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert facility.rolled_back_to == [PREVIOUS_RELEASE]
    assert "ACCEPTED" not in outcome.states
