"""Three-way drift, and what the comparison does when it is handed two.

AGENTS.md rule 12 says a design that can only read one of the three artifacts
cannot detect drift. The sharper version, and the one these tests are mostly
about, is that a design that reads TWO can detect a disagreement and cannot say
what it means — so the missing artifact has to be reported rather than worked
around.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence

from dotmac_observability.drift import compare
from dotmac_observability.live_verify import TreeEntry
from dotmac_observability.receipt import OUTCOME_ACCEPTED, build_receipt
from dotmac_observability.validate import Finding
from tests.unit.observations import (
    AUTHORIZATION,
    BUNDLES,
    IMAGES,
    INVENTORY,
    PASSED,
    REVISION,
    RUNS,
    STATE,
    TREE,
    passing,
    verification,
)


def accepted_receipt() -> dict[str, object]:
    return build_receipt(
        outcome=OUTCOME_ACCEPTED,
        state=STATE,
        control_plane_revision=REVISION,
        authorization=AUTHORIZATION,
        inventory=INVENTORY,
        tree=TREE,
        images=IMAGES,
        bundles=BUNDLES,
        live=passing(),
        verification=verification(),
        validation=PASSED,
        runs=RUNS,
        started_at="2026-09-01T11:59:00+00:00",
        finished_at="2026-09-01T12:00:00+00:00",
    )


def codes(findings: Sequence[Finding]) -> set[str]:
    return {finding.code for finding in findings}


# ── All three present and agreeing ──────────────────────────────────────────


def test_three_agreeing_artifacts_produce_a_clean_report():
    report = compare(tree=TREE, live=passing(), receipt=accepted_receipt())
    assert report.findings == (), [finding.render() for finding in report.findings]
    assert report.clean


# ── Fewer than three is incomplete, never clean ─────────────────────────────


def test_a_missing_artifact_is_reported_rather_than_worked_around():
    report = compare(tree=TREE, live=passing(), receipt=None)
    assert "DRIFT-INCOMPARABLE" in codes(report.findings)
    assert not report.clean


def test_a_two_artifact_comparison_that_agrees_is_still_not_clean():
    """The finding that matters most, because this is the one a caller wants to skip."""
    report = compare(tree=TREE, live=passing(), receipt=None)
    assert report.desired_vs_live == ()
    assert not report.clean
    assert [finding.location for finding in report.incomparable] == ["receipt"]


def test_every_absent_artifact_is_named_individually():
    report = compare(tree=None, live=None, receipt=None)
    assert {finding.location for finding in report.incomparable} == {
        "desired",
        "live",
        "receipt",
    }


# ── Which pair disagrees is the diagnosis ───────────────────────────────────


def test_a_host_edit_shows_up_between_desired_and_live():
    live = passing()
    edited = (TreeEntry(path=live.tree[0].path, sha256="b" * 64), *live.tree[1:])
    report = compare(
        tree=TREE, live=dataclasses.replace(live, tree=edited), receipt=accepted_receipt()
    )
    assert codes(report.desired_vs_live) == {"DRIFT-DESIRED-LIVE"}
    assert report.receipt_vs_desired == (), "the receipt still matches the repository"


def test_a_change_after_acceptance_shows_up_between_live_and_receipt():
    live = passing()
    moved = dataclasses.replace(
        live, release=dataclasses.replace(live.release, current="/opt/observability/releases/9")
    )
    report = compare(tree=TREE, live=moved, receipt=accepted_receipt())
    assert codes(report.live_vs_receipt) == {"DRIFT-LIVE-RECEIPT"}
    assert report.desired_vs_live == (), "the bytes on the host still match the repository"


def test_a_promotion_that_never_happened_shows_up_between_receipt_and_desired():
    receipt = accepted_receipt()
    receipt["rendered_digest"] = "c" * 64
    report = compare(tree=TREE, live=passing(), receipt=receipt)
    assert codes(report.receipt_vs_desired) == {"DRIFT-RECEIPT-DESIRED"}


def test_a_different_rule_set_shows_up_between_live_and_receipt():
    live = passing()
    fewer = dataclasses.replace(live, rules=())
    report = compare(tree=TREE, live=fewer, receipt=accepted_receipt())
    locations = {finding.location for finding in report.live_vs_receipt}
    assert "live.rules_semantic_digest" in locations


def test_a_read_back_that_listed_no_files_is_not_a_match():
    report = compare(
        tree=TREE, live=dataclasses.replace(passing(), tree=()), receipt=accepted_receipt()
    )
    assert "DRIFT-LIVE-TREE-NOT-READ" in codes(report.findings)


def test_a_stale_file_on_the_host_is_desired_versus_live():
    live = passing()
    extra = (*live.tree, TreeEntry(path="prometheus/leftover.yml", sha256="d" * 64))
    report = compare(
        tree=TREE, live=dataclasses.replace(live, tree=extra), receipt=accepted_receipt()
    )
    assert any(finding.location == "prometheus/leftover.yml" for finding in report.desired_vs_live)
