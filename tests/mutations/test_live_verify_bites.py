"""Sensitivity proofs for the read-back verifier: the naive check passes, ours does not.

AGENTS.md rule 15 — a check that cannot demonstrate it bites is not
enforcement. The unit tests next door break one field and assert the finding,
which proves the code does what it says. These prove something different and
harder: that the OBVIOUS version of each check, the one somebody would write if
they had not been burned, reports the same broken state as healthy.

Each test therefore runs two comparisons over the same input — the naive one
inline, and the real one through :func:`~dotmac_observability.live_verify
.verify` — and asserts they disagree. If a later simplification ever collapses
the real check into the naive one, the disagreement vanishes and this fails,
while every test in `tests/unit/test_live_verify.py` keeps passing.
"""

from __future__ import annotations

import dataclasses

from dotmac_observability.live_verify import (
    VERDICT_DEPLOYED_REPAIRED,
    IntegrityReading,
    LiveState,
    Verification,
    chain_for,
    verify,
)
from dotmac_observability.render import file_digest
from tests.unit.observations import (
    COUNTER_VALUE,
    PREVIOUS_DIGEST,
    PROCESS_START,
    RESOLUTION,
    STATE,
    TREE,
    baseline,
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


def test_the_reference_tree_is_a_meaningful_corpus():
    """Sensitivity for these sensitivity proofs.

    Every test below rests on the reference tree having files, dual-stack
    surfaces and a gate. Over an empty one they would all pass while proving
    nothing.
    """
    assert len(TREE) >= 10
    assert STATE.bundle.gates
    assert any(
        surface.family == "dual_stack" for surface in STATE.bundle.exposure.surfaces
    ), "no dual-stack surface; the address-family proof below would be vacuous"
    assert any(
        surface.kind == "container_published" for surface in STATE.bundle.exposure.surfaces
    ), "no container publish; the chain proof below would be vacuous"


def test_a_counter_only_comparison_passes_the_reset_that_climbed_back():
    """The naive integrity check: `current <= baseline`, therefore no new rejections.

    A counter reset to zero and left running climbs back. Caught while it sits
    exactly at the old baseline, a no-increase comparison sees a perfect pass —
    and every sample dropped between the reset and now is invisible to it.
    Only the process start time, read in the same pass, separates the two.

    The value is deliberately EQUAL to the baseline rather than above it. Above
    it, `INTEGRITY-INCREASED` would fire and the proof would be about the wrong
    check; equal, the only thing that can object is the restart.
    """
    live = passing()
    restarted = IntegrityReading(
        counter=live.integrity[0].counter,
        value=COUNTER_VALUE,
        process_start_time=PROCESS_START + 900,
    )
    mutated = dataclasses.replace(live, integrity=(restarted,))

    # The naive check, written out so the disagreement is visible rather than
    # asserted. It reads the same two documents and reaches the wrong answer.
    naive_passes = mutated.integrity[0].value <= baseline().integrity[0].value
    assert naive_passes, "the mutation must look acceptable to a no-increase comparison"

    verification = run(mutated)
    assert "INTEGRITY-PROCESS-RESTARTED" in codes(verification)
    assert "INTEGRITY-INCREASED" not in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED


def test_a_zero_valued_check_is_satisfied_by_the_reset_it_cannot_detect():
    """The other naive spelling: `counter == 0`, therefore nothing is being dropped.

    Rule 30. A counter is zero after a reset, after a fresh TSDB, and after a
    container restart. Exactly one of the four ways to reach zero is a repair.
    """
    live = passing()
    zeroed = dataclasses.replace(live.integrity[0], value=0)
    mutated = dataclasses.replace(live, integrity=(zeroed,))

    naive_passes = mutated.integrity[0].value == 0
    assert naive_passes, "the mutation must satisfy a zero-valued check"

    verification = run(mutated)
    assert "INTEGRITY-COUNTER-RESET" in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED


def test_a_difference_set_over_an_empty_read_back_reports_no_differences():
    """The naive tree check: compute the differences, report none, call it a match.

    A read-back that failed to list anything produces an empty difference set,
    which is byte-for-byte the result a perfectly matching host produces. That
    is why the empty case is refused rather than compared.
    """
    live = dataclasses.replace(passing(), tree=())

    expected = {path: file_digest(text) for path, text in TREE}
    observed = {entry.path: entry.sha256 for entry in live.tree}
    naive_differences = [
        path for path in expected if observed.get(path) not in (None, expected[path])
    ]
    assert naive_differences == [], "the mutation must produce an empty difference set"

    verification = run(live)
    assert "TREE-NOT-READ" in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED


def test_a_probe_set_that_covers_every_surface_still_misses_a_whole_family():
    """The naive exposure check: every declared surface was probed, so we are done.

    Counting SURFACES rather than surface-and-family is the shape that has
    passed over a live IPv6 exposure on this fleet. Three surfaces, three
    probes, complete-looking, and half the listeners unexamined.
    """
    live = passing()
    v4_only = tuple(probe for probe in live.probes if probe.family == "ipv4")
    mutated = dataclasses.replace(live, probes=v4_only)

    declared_surfaces = {surface.name for surface in STATE.bundle.exposure.surfaces}
    probed_surfaces = {probe.surface for probe in mutated.probes}
    assert probed_surfaces == declared_surfaces, "the mutation must look complete per surface"

    verification = run(mutated)
    assert "PROBE-FAMILY-MISSING" in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED


def test_a_single_chain_derivation_would_accept_a_rule_no_packet_traverses():
    """The naive chain check: the rule exists, so the port is closed.

    `DOCKER-USER` is jumped only from `FORWARD`. An IPv6 packet to a published
    port terminates on `INPUT` and never enters it, so seven DROP rules sat
    there with zero packet counters while every port they named was open.
    """
    live = passing()
    inert = tuple(
        dataclasses.replace(probe, chain="DOCKER-USER") if probe.family == "ipv6" else probe
        for probe in live.probes
    )
    mutated = dataclasses.replace(live, probes=inert)

    # The naive check: a rule was observed in SOME chain, therefore the surface
    # is covered. It has no opinion about which chain, which is the defect.
    assert all(probe.chain for probe in mutated.probes)

    verification = run(mutated)
    assert "PROBE-CHAIN-INERT" in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED


def test_the_chain_derivation_still_distinguishes_the_two_families():
    """If it ever stopped, the proof above would mutate nothing and pass in silence."""
    published = [
        surface
        for surface in STATE.bundle.exposure.surfaces
        if surface.kind == "container_published"
    ]
    surface = published[0]
    assert chain_for(surface, "ipv4") == "DOCKER-USER"
    assert chain_for(surface, "ipv6") == "INPUT"


def test_a_refusal_with_a_dead_prober_looks_exactly_like_a_refusal():
    """The naive probe check: the connection was refused, so the port is shut.

    An unplugged cable, an address family with no route and a prober that never
    ran all present as `refused`. The positive control in the same pass is the
    only thing that separates a measured refusal from an absent measurement.
    """
    live = passing()
    dead = tuple(
        dataclasses.replace(probe, outcome="refused", control_outcome="unreachable")
        for probe in live.probes
    )
    mutated = dataclasses.replace(live, probes=dead)

    naive_passes = all(probe.outcome == probe.expectation for probe in mutated.probes)
    assert naive_passes, "the mutation must satisfy an outcome-only check"

    verification = run(mutated)
    assert "PROBE-CONTROL-FAILED" in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED


def test_counting_rules_that_are_not_firing_reads_a_deleted_rule_as_healthy():
    """AGENTS.md rule 10, as a sensitivity proof.

    A deleted rule, a failed evaluation and a vanished target all present as
    "not firing". A verifier counting quiet rules reports the loudest possible
    green over an evaluator that loaded nothing.
    """
    live = dataclasses.replace(passing(), rules=())

    firing = [rule for rule in live.rules if rule.health == "err"]
    assert firing == [], "the mutation must look quiet"

    verification = run(live)
    assert "RULES-NOT-READ" in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED


def test_an_unexercised_rollback_is_not_reported_as_a_working_one():
    """The naive rollback check: a previous release is recorded, so we can go back.

    A rollback that has never been run is a plan. The receipt is what
    distinguishes the two, and this is the condition a lane skips when the
    forward path worked.
    """
    live = dataclasses.replace(passing(), rollback=None)

    naive_passes = live.release.previous is not None
    assert naive_passes, "the mutation must satisfy a pointer-exists check"

    verification = run(live)
    assert "ROLLBACK-NOT-EXERCISED" in codes(verification)
    assert verification.verdict != VERDICT_DEPLOYED_REPAIRED
