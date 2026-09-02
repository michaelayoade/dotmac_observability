"""The six conditions, each with a pass and the failure it exists to catch.

Every test here builds a COMPLETE passing observation and then breaks exactly
one thing. That shape is deliberate: a test that constructs a minimal
observation and asserts one finding cannot tell a check that bites from a check
whose other inputs happened to be absent, and the whole value of this verifier
is in the cases where five conditions hold and one does not.

The first test is therefore the load-bearing one. If the unbroken observation
ever stops producing ``deployed_repaired``, every negative test below starts
passing for the wrong reason.
"""

from __future__ import annotations

import dataclasses

import pytest

from dotmac_observability.live_verify import (
    CONDITIONS,
    VERDICT_DEPLOYED_REPAIRED,
    VERDICT_RENDERED_GUARDED,
    IntegrityReading,
    LiveState,
    LiveTarget,
    TreeEntry,
    Verification,
    chain_for,
    declared_probe_slots,
    live_state,
    observation_document,
    verify,
)
from dotmac_observability.render import render_control_plane, tree_digest
from dotmac_observability.validate import _validate_document
from tests.conftest import CONTRACTS
from tests.unit.observations import (
    COUNTER_VALUE,
    OBSERVED_AT,
    PREVIOUS_DIGEST,
    PROCESS_START,
    RESOLUTION,
    STATE,
    TREE,
    baseline,
    counter_name,
    passing,
)


def run(live: LiveState, *, base: LiveState | None = None) -> Verification:
    return verify(
        STATE,
        RESOLUTION,
        TREE,
        live,
        baseline=baseline() if base is None else base,
        previous_digest=PREVIOUS_DIGEST,
        first_promotion=False,
    )


def codes(verification: Verification) -> set[str]:
    return {finding.code for finding in verification.findings}


# ── The premise every other test rests on ───────────────────────────────────


def test_an_unbroken_observation_reaches_deployed_repaired():
    verification = run(passing())
    assert verification.findings == (), [finding.render() for finding in verification.findings]
    assert verification.verdict == VERDICT_DEPLOYED_REPAIRED
    assert len(verification.conditions) == len(CONDITIONS)


def test_the_verdict_is_a_conjunction_over_all_six_conditions():
    """A partial report cannot be constructed, let alone reach the good verdict."""
    verification = run(passing())
    with pytest.raises(ValueError, match="conjunction"):
        Verification(conditions=verification.conditions[:5])


def test_a_passing_observation_satisfies_its_own_contract():
    """The typed record and the document form agree, and the schema accepts it.

    Without this, the verifier could be exercised forever against a shape the
    facility can never actually produce.
    """
    document = observation_document(passing())
    findings = _validate_document(CONTRACTS, "live-observation", document, "observation")
    assert not findings, [finding.render() for finding in findings]
    assert live_state(document) == passing()


# ── Condition 1: the whole tree ─────────────────────────────────────────────


def test_a_read_back_that_listed_nothing_is_refused_rather_than_matching():
    verification = run(dataclasses.replace(passing(), tree=()))
    assert "TREE-NOT-READ" in codes(verification)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_one_changed_file_out_of_fourteen_fails_the_tree_condition():
    live = passing()
    altered = (TreeEntry(path=live.tree[0].path, sha256="b" * 64), *live.tree[1:])
    verification = run(dataclasses.replace(live, tree=altered))
    assert "TREE-DIFFERS" in codes(verification)


def test_a_missing_file_is_not_the_same_finding_as_a_changed_one():
    live = passing()
    verification = run(dataclasses.replace(live, tree=live.tree[1:]))
    assert "TREE-MISSING" in codes(verification)


def test_a_stale_file_left_in_the_release_directory_is_a_finding():
    live = passing()
    extra = (*live.tree, TreeEntry(path="prometheus/leftover.yml", sha256="c" * 64))
    verification = run(dataclasses.replace(live, tree=extra))
    assert "TREE-UNEXPECTED" in codes(verification)


def test_the_whole_tree_is_compared_not_a_sample():
    """Every rendered path must appear in the comparison, not a chosen few."""
    live = passing()
    assert len(live.tree) == len(TREE)
    for path, _ in TREE:
        assert any(entry.path == path for entry in live.tree)


# ── Condition 2: targets and rules ──────────────────────────────────────────


def test_no_active_targets_is_refused_rather_than_read_as_quiet():
    verification = run(dataclasses.replace(passing(), targets=()))
    assert "TARGETS-NOT-READ" in codes(verification)


def test_one_target_down_fails_the_health_condition():
    live = passing()
    degraded = (dataclasses.replace(live.targets[0], health="down"), *live.targets[1:])
    verification = run(dataclasses.replace(live, targets=degraded))
    assert "TARGET-UNHEALTHY" in codes(verification)


def test_a_job_resolving_to_fewer_targets_than_declared_is_a_finding():
    live = passing()
    verification = run(dataclasses.replace(live, targets=live.targets[1:]))
    assert {"TARGET-COUNT", "TARGET-ABSENT"} & codes(verification)


def test_a_job_scraped_live_and_declared_nowhere_is_a_finding():
    live = passing()
    extra = (*live.targets, LiveTarget(job="dotmac-crm-app", health="up"))
    verification = run(dataclasses.replace(live, targets=extra))
    assert "TARGET-UNDECLARED" in codes(verification)


def test_a_declared_rule_that_no_evaluator_loaded_is_absence_not_health():
    """AGENTS.md rule 10 in one assertion."""
    verification = run(dataclasses.replace(passing(), rules=()))
    assert "RULES-NOT-READ" in codes(verification)


def test_a_loaded_rule_that_fails_to_evaluate_is_not_healthy():
    live = passing()
    broken = tuple(dataclasses.replace(rule, health="err") for rule in live.rules)
    verification = run(dataclasses.replace(live, rules=broken))
    assert "RULE-UNHEALTHY" in codes(verification)


# ── Condition 3: the ingestion delta, and why a reset cannot pass ───────────


def test_a_counter_that_grew_fails_even_with_every_target_up():
    """The exact pair measured on this host: 18/18 green, samples being dropped."""
    live = passing()
    grown = dataclasses.replace(live.integrity[0], value=COUNTER_VALUE + 1)
    verification = run(dataclasses.replace(live, integrity=(grown,)))
    assert "INTEGRITY-INCREASED" in codes(verification)
    assert verification.conditions[1].passed, "targets were healthy; only integrity failed"
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_resetting_the_counter_is_a_refusal_and_never_a_pass():
    live = passing()
    reset = dataclasses.replace(live.integrity[0], value=0)
    verification = run(dataclasses.replace(live, integrity=(reset,)))
    assert "INTEGRITY-COUNTER-RESET" in codes(verification)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_a_reset_that_climbed_back_past_the_baseline_is_caught_by_the_restart():
    """The case a value comparison alone passes.

    The counter was reset, the evaluator has been running long enough for it to
    exceed the old baseline, and every sample in between was dropped. Only the
    process start time separates this from a genuine increase, which is why the
    observation carries it.
    """
    live = passing()
    restarted = IntegrityReading(
        counter=counter_name(), value=COUNTER_VALUE + 5, process_start_time=PROCESS_START + 900
    )
    verification = run(dataclasses.replace(live, integrity=(restarted,)))
    assert "INTEGRITY-PROCESS-RESTARTED" in codes(verification)


def test_a_restart_is_caught_even_when_the_value_looks_perfect():
    live = passing()
    restarted = dataclasses.replace(live.integrity[0], process_start_time=PROCESS_START + 1)
    verification = run(dataclasses.replace(live, integrity=(restarted,)))
    assert "INTEGRITY-PROCESS-RESTARTED" in codes(verification)
    assert "INTEGRITY-INCREASED" not in codes(verification)


def test_a_zero_baseline_is_refused_because_it_makes_the_delta_vacuous():
    base = baseline()
    zeroed = dataclasses.replace(base.integrity[0], value=0)
    live = passing()
    verification = run(
        dataclasses.replace(live, integrity=(dataclasses.replace(live.integrity[0], value=0),)),
        base=dataclasses.replace(base, integrity=(zeroed,)),
    )
    assert "INTEGRITY-BASELINE-ZERO" in codes(verification)


def test_no_baseline_is_never_treated_as_a_baseline_of_zero():
    verification = verify(
        STATE,
        RESOLUTION,
        TREE,
        passing(),
        baseline=None,
        previous_digest=PREVIOUS_DIGEST,
        first_promotion=False,
    )
    assert "INTEGRITY-BASELINE-ABSENT" in codes(verification)


def test_a_delta_measured_over_less_than_the_gate_window_is_not_evidence():
    live = passing()
    verification = run(live, base=dataclasses.replace(baseline(), observed_at=OBSERVED_AT))
    assert "INTEGRITY-WINDOW-TOO-SHORT" in codes(verification)


def test_a_baseline_for_a_different_counter_cannot_be_compared():
    """Matching by NAME makes the old mismatch unrepresentable.

    v1 compared whichever single reading each document held, so two unrelated
    series could be compared and a guard had to notice. Readings are now paired
    by counter name before comparison, so a baseline naming a different counter
    does not produce a bad comparison -- it produces NO comparison, which is
    reported as the declared counter having no baseline reading.
    """
    base = baseline()
    other = dataclasses.replace(base.integrity[0], counter="prometheus_something_else_total")
    verification = run(passing(), base=dataclasses.replace(base, integrity=(other,)))
    assert "INTEGRITY-BASELINE-COUNTER-ABSENT" in codes(verification)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


# ── Condition 3, the v2 shape: every declared counter, not just the first ───

SECOND_COUNTER = "prometheus_target_scrapes_sample_out_of_order_total"


def _two_counter_state():
    """The reference state with one gate widened to watch a second counter."""
    gates = STATE.bundle.gates
    assert gates, "the reference bundle declares no gate"
    widened = dataclasses.replace(
        gates[0],
        integrity=(f"increase({counter_name()}[5m]) + increase({SECOND_COUNTER}[5m]) == 0"),
    )
    bundle = dataclasses.replace(STATE.bundle, gates=(widened, *gates[1:]))
    return dataclasses.replace(STATE, bundle=bundle)


def _reading(counter: str, value: int) -> IntegrityReading:
    return IntegrityReading(counter=counter, value=value, process_start_time=PROCESS_START)


def test_a_read_back_missing_a_declared_counter_is_not_a_complete_pass():
    """The v1 defect, named. A subset must not read as the whole."""
    live = dataclasses.replace(passing(), integrity=())
    verification = run(live)
    assert "INTEGRITY-COUNTER-UNREAD" in codes(verification)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_a_reading_no_declared_gate_watches_is_reported():
    live = passing()
    extra = dataclasses.replace(live, integrity=(*live.integrity, _reading(SECOND_COUNTER, 1)))
    verification = run(extra)
    assert "INTEGRITY-COUNTER-UNWATCHED" in codes(verification)


def test_every_declared_counter_is_compared_and_not_only_the_first():
    """The non-vacuity proof for the v2 shape.

    Two counters are declared. The FIRST is unchanged and the SECOND grew, so
    a verifier that read `counters[0]` and filed the document would report a
    complete, clean read-back over a control plane that is dropping samples.
    The first assertion establishes that the rejected design really does pass
    here; without it this test could not tell a fix from a coincidence.
    """
    state = _two_counter_state()
    first, second = counter_name(), SECOND_COUNTER
    base = dataclasses.replace(
        baseline(),
        integrity=(_reading(first, COUNTER_VALUE), _reading(second, COUNTER_VALUE)),
    )
    live = dataclasses.replace(
        passing(),
        integrity=(_reading(first, COUNTER_VALUE), _reading(second, COUNTER_VALUE + 7)),
    )

    only_the_first_moved = live.integrity[0].value == base.integrity[0].value
    assert only_the_first_moved, "reading counters[0] alone must look clean here"

    verification = verify(
        state,
        RESOLUTION,
        TREE,
        live,
        baseline=base,
        previous_digest=PREVIOUS_DIGEST,
        first_promotion=False,
    )
    assert "INTEGRITY-INCREASED" in codes(verification)
    assert any(
        finding.code == "INTEGRITY-INCREASED" and finding.location == second
        for finding in verification.findings
    ), "the finding must name the counter that actually moved"
    assert verification.verdict == VERDICT_RENDERED_GUARDED


# ── Condition 4: routes and delivery ────────────────────────────────────────


def test_a_declared_route_that_does_not_resolve_live_is_a_finding():
    live = passing()
    verification = run(dataclasses.replace(live, routes=live.routes[1:]))
    assert "ROUTE-ABSENT" in codes(verification)


def test_a_route_landing_on_a_different_receiver_is_a_finding():
    live = passing()
    moved = (dataclasses.replace(live.routes[0], receiver="somewhere-else"), *live.routes[1:])
    verification = run(dataclasses.replace(live, routes=moved))
    assert "ROUTE-RECEIVER-DIFFERS" in codes(verification)


def test_delivery_is_proved_at_the_receiver_not_at_the_outbound_attempt():
    live = passing()
    unproven = dataclasses.replace(live.canary, receiver_evidence_ref=None)
    verification = run(dataclasses.replace(live, canary=unproven))
    assert "CANARY-DELIVERY-UNPROVEN" in codes(verification)


def test_an_undelivered_canary_fails_the_delivery_condition():
    live = passing()
    verification = run(
        dataclasses.replace(live, canary=dataclasses.replace(live.canary, delivered=False))
    )
    assert "CANARY-NOT-DELIVERED" in codes(verification)


def test_a_canary_that_never_cleared_is_a_finding():
    live = passing()
    verification = run(
        dataclasses.replace(live, canary=dataclasses.replace(live.canary, recovered=False))
    )
    assert "CANARY-NOT-RECOVERED" in codes(verification)


# ── Condition 5: both families, each with a positive control ────────────────


def test_the_reference_exposure_declares_two_families_for_every_surface():
    """Sensitivity: the probe tests below only mean something over a dual-stack tree."""
    slots = declared_probe_slots(STATE)
    families = {family for _, family in slots}
    assert families == {"ipv4", "ipv6"}
    assert len(slots) == 2 * len(STATE.bundle.exposure.surfaces)


def test_a_v4_only_probe_pass_cannot_reach_the_good_verdict():
    """The failure this condition exists for, stated as directly as it can be."""
    live = passing()
    v4_only = tuple(probe for probe in live.probes if probe.family == "ipv4")
    verification = run(dataclasses.replace(live, probes=v4_only))
    assert "PROBE-FAMILY-MISSING" in codes(verification)
    missing = {
        finding.location
        for finding in verification.findings
        if finding.code == "PROBE-FAMILY-MISSING"
    }
    assert all(location.endswith("/ipv6") for location in missing)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_no_probes_at_all_is_refused_rather_than_reported_as_clean():
    verification = run(dataclasses.replace(passing(), probes=()))
    assert "PROBES-NOT-READ" in codes(verification)


def test_a_refusal_with_no_working_positive_control_proves_nothing():
    live = passing()
    uncontrolled = tuple(
        dataclasses.replace(probe, control_outcome="unreachable") for probe in live.probes
    )
    verification = run(dataclasses.replace(live, probes=uncontrolled))
    assert "PROBE-CONTROL-FAILED" in codes(verification)


def test_a_rule_observed_in_a_chain_the_traffic_never_traverses_is_a_finding():
    """The seven dead IPv6 rules, as a standing check.

    An IPv6 packet to a container publish terminates on INPUT; a DROP written
    into DOCKER-USER reads as closed and is open.
    """
    live = passing()
    inert = tuple(
        dataclasses.replace(probe, chain="DOCKER-USER") if probe.family == "ipv6" else probe
        for probe in live.probes
    )
    verification = run(dataclasses.replace(live, probes=inert))
    assert "PROBE-CHAIN-INERT" in codes(verification)


def test_the_chain_derivation_differs_between_the_families_it_is_derived_for():
    """Sensitivity for the check above: the two families must not agree.

    If `chain_for` ever returned the same chain for both, the inert-rule test
    would mutate nothing and pass in silence.
    """
    published = [
        surface
        for surface in STATE.bundle.exposure.surfaces
        if surface.kind == "container_published"
    ]
    assert published, "the reference tree declares no container publish"
    surface = published[0]
    assert chain_for(surface, "ipv4") != chain_for(surface, "ipv6")


def test_a_loopback_surface_that_answered_from_outside_is_a_finding():
    live = passing()
    open_surface = tuple(
        dataclasses.replace(probe, outcome="reachable") if probe.expectation == "refused" else probe
        for probe in live.probes
    )
    verification = run(dataclasses.replace(live, probes=open_surface))
    assert "PROBE-UNEXPECTED-REACHABLE" in codes(verification)


def test_a_prober_that_typed_its_own_expectation_is_caught():
    live = passing()
    wrong = tuple(
        dataclasses.replace(probe, expectation="reachable", outcome="reachable")
        for probe in live.probes
    )
    verification = run(dataclasses.replace(live, probes=wrong))
    assert "PROBE-EXPECTATION-WRONG" in codes(verification)


# ── Condition 6: rollback ───────────────────────────────────────────────────


def test_a_rollback_that_was_never_exercised_is_a_plan_not_a_capability():
    verification = run(dataclasses.replace(passing(), rollback=None))
    assert "ROLLBACK-NOT-EXERCISED" in codes(verification)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_a_rollback_that_restored_a_pointer_but_not_the_bytes_is_a_finding():
    live = passing()
    assert live.rollback is not None
    wrong = dataclasses.replace(live.rollback, restored_digest="d" * 64)
    verification = run(dataclasses.replace(live, rollback=wrong))
    assert "ROLLBACK-DIGEST-MISMATCH" in codes(verification)


def test_a_rollback_with_no_recorded_previous_digest_cannot_be_checked():
    live = passing()
    verification = verify(
        STATE,
        RESOLUTION,
        TREE,
        live,
        baseline=baseline(),
        previous_digest=None,
        first_promotion=False,
    )
    assert "ROLLBACK-BASELINE-ABSENT" in codes(verification)


def test_a_lost_ordering_manifest_is_not_reported_as_a_failed_restore():
    live = passing()
    assert live.rollback is not None
    unprovable = dataclasses.replace(
        live.rollback, restored_digest=None, digest_absence="ordering_manifest_absent"
    )
    verification = run(dataclasses.replace(live, rollback=unprovable))
    assert "ROLLBACK-ORDER-UNKNOWN" in codes(verification)
    assert "ROLLBACK-RESTORED-NOTHING" not in codes(verification)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_a_pointer_that_came_back_empty_is_reported_as_a_failed_restore():
    live = passing()
    assert live.rollback is not None
    failed = dataclasses.replace(
        live.rollback, restored_digest=None, digest_absence="nothing_restored"
    )
    verification = run(dataclasses.replace(live, rollback=failed))
    assert "ROLLBACK-RESTORED-NOTHING" in codes(verification)
    assert "ROLLBACK-ORDER-UNKNOWN" not in codes(verification)
    assert verification.verdict == VERDICT_RENDERED_GUARDED


def test_the_two_reasons_a_digest_is_absent_are_told_apart():
    """Both leave condition 6 unproven; they send an operator to different places.

    The safety property is unchanged and deliberately re-asserted: neither
    absence is allowed to pass. What v2 adds is that the OPERATOR can tell a
    lost manifest from a host running the wrong release, which one null could
    not express.
    """
    live = passing()
    assert live.rollback is not None
    lost = run(
        dataclasses.replace(
            live,
            rollback=dataclasses.replace(
                live.rollback, restored_digest=None, digest_absence="ordering_manifest_absent"
            ),
        )
    )
    empty = run(
        dataclasses.replace(
            live,
            rollback=dataclasses.replace(
                live.rollback, restored_digest=None, digest_absence="nothing_restored"
            ),
        )
    )
    assert codes(lost) != codes(
        empty
    ), "one null for two facts is exactly the conflation v2 removes"
    for verification in (lost, empty):
        assert verification.verdict == VERDICT_RENDERED_GUARDED


# ── Identity ────────────────────────────────────────────────────────────────


def test_an_observation_of_a_different_host_does_not_verify_this_one():
    verification = run(dataclasses.replace(passing(), host_target_id="somewhere-else"))
    assert "OBSERVATION-HOST" in codes(verification)


def test_an_observation_of_a_different_environment_does_not_verify_this_one():
    verification = run(dataclasses.replace(passing(), environment="rehearsal"))
    assert "OBSERVATION-ENVIRONMENT" in codes(verification)


# ── The rendered tree the conditions are compared against ───────────────────


def test_the_rendered_digest_is_stable_across_two_renders():
    """Condition 1 compares against a digest, so the digest must not move."""
    assert tree_digest(render_control_plane(STATE, RESOLUTION)) == tree_digest(TREE)
