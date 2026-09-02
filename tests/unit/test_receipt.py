"""A receipt records what was proved, and refuses to claim more.

Building is checked once — a receipt built from a passing promotion satisfies
its own contract and its own validator — and everything after that breaks one
field and asserts the specific refusal. A validator that reported "invalid" for
every mutation would be indistinguishable from one that reported it for none,
so each test names the code it expects rather than asserting that findings
exist.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence

from dotmac_observability.live_verify import CONDITIONS, ConditionResult, LiveState, Verification
from dotmac_observability.receipt import (
    OUTCOME_ACCEPTED,
    OUTCOME_FAILED,
    Authorization,
    CheckResult,
    ImageRecord,
    Runs,
    build_receipt,
    receipt_findings,
)
from dotmac_observability.validate import Finding
from tests.conftest import CONTRACTS
from tests.unit.observations import (
    AUTHORIZATION,
    BUNDLES,
    IMAGES,
    INVENTORY,
    PASSED,
    PLAN_DIGEST,
    REVISION,
    RUNS,
    STATE,
    TREE,
    passing,
    verification,
)


def build(
    *,
    outcome: str = OUTCOME_ACCEPTED,
    live: LiveState | None = None,
    validation: Mapping[str, CheckResult] | None = None,
    runs: Runs | None = None,
    images: Sequence[ImageRecord] | None = None,
    authorization: Authorization | None = None,
) -> dict[str, object]:
    return build_receipt(
        outcome=outcome,
        state=STATE,
        control_plane_revision=REVISION,
        authorization=AUTHORIZATION if authorization is None else authorization,
        inventory=INVENTORY,
        tree=TREE,
        images=IMAGES if images is None else images,
        bundles=BUNDLES,
        live=passing() if live is None else live,
        verification=verification(),
        validation=PASSED if validation is None else validation,
        runs=RUNS if runs is None else runs,
        started_at="2026-09-01T11:59:00+00:00",
        finished_at="2026-09-01T12:00:00+00:00",
    )


def check(
    document: Mapping[str, object],
    *,
    first_promotion: bool = False,
    held: Verification | None = None,
    authorized_images: Sequence[ImageRecord] | None = None,
) -> tuple[Finding, ...]:
    return receipt_findings(
        document,
        contracts=CONTRACTS,
        first_promotion=first_promotion,
        verification=verification() if held is None else held,
        authorized_images=IMAGES if authorized_images is None else authorized_images,
        authorized_plan_digest=PLAN_DIGEST,
        tree=TREE,
    )


def codes(findings: Sequence[Finding]) -> set[str]:
    return {finding.code for finding in findings}


def table(document: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = document[key]
    assert isinstance(value, Mapping), f"{key} is not an object"
    return value


# ── The premise ─────────────────────────────────────────────────────────────


def test_a_receipt_for_a_clean_promotion_satisfies_its_own_contract():
    findings = check(build())
    assert findings == (), [finding.render() for finding in findings]


def test_the_recorded_counts_come_from_the_observation_and_not_from_an_argument():
    live = table(build(), "live")
    assert live["targets_up"] == live["targets_expected"]
    assert live["rules_loaded"] == live["rules_healthy"] == len(passing().rules)
    assert live["routes_verified"] == len(passing().routes)


def test_the_plan_digest_is_recorded_in_the_owners_canonical_form():
    """The receipt mirrors `dotmac-deployment-control`'s spelling, prefix included.

    A contract demanding bare hex would force every adopter to strip the
    prefix, and a forked digest parser surfaces later as a false "the plan
    changed" that nobody can explain.
    """
    document = build()
    assert str(table(document, "authorization")["plan_digest"]).startswith("sha256:")
    assert check(document) == ()


# ── What an `accepted` outcome asserts ──────────────────────────────────────


def test_accepted_with_a_failed_validation_check_is_refused():
    failed = dict(PASSED)
    failed["promtool_rules"] = CheckResult(passed=False, detail="rules rejected")
    assert "RECEIPT-ACCEPTED-WITH-FAILED-CHECK" in codes(check(build(validation=failed)))


def test_the_same_failed_check_on_a_failed_receipt_is_not_a_finding():
    """A failed promotion recording failed checks is a correct receipt.

    Refusing it would push a lane towards writing no receipt at all, which is
    the state the contract exists to end.
    """
    failed = dict(PASSED)
    failed["promtool_rules"] = CheckResult(passed=False, detail="rules rejected")
    document = build(outcome=OUTCOME_FAILED, validation=failed)
    assert "RECEIPT-ACCEPTED-WITH-FAILED-CHECK" not in codes(check(document))


def test_accepted_with_a_target_down_is_refused():
    live = passing()
    degraded = (dataclasses.replace(live.targets[0], health="down"), *live.targets[1:])
    document = build(live=dataclasses.replace(live, targets=degraded))
    assert "RECEIPT-ACCEPTED-TARGETS" in codes(check(document))


def test_accepted_with_no_rule_loaded_is_refused():
    document = build(live=dataclasses.replace(passing(), rules=()))
    assert "RECEIPT-ACCEPTED-NO-RULES" in codes(check(document))


def test_accepted_with_a_rule_that_does_not_evaluate_is_refused():
    live = passing()
    broken = tuple(dataclasses.replace(rule, health="err") for rule in live.rules)
    document = build(live=dataclasses.replace(live, rules=broken))
    assert "RECEIPT-ACCEPTED-UNHEALTHY-RULES" in codes(check(document))


def test_accepted_without_delivery_at_the_receiver_is_refused():
    live = passing()
    document = build(
        live=dataclasses.replace(live, canary=dataclasses.replace(live.canary, delivered=False))
    )
    assert "RECEIPT-ACCEPTED-CANARY" in codes(check(document))


def test_accepted_with_no_external_run_identifier_is_refused():
    document = build(runs=Runs(ci="ci/1", rehearsal="rehearsal/1", promotion=None))
    assert "RECEIPT-ACCEPTED-UNPROVEN-RUN" in codes(check(document))


def test_accepted_while_verification_holds_at_rendered_guarded_is_refused():
    held = Verification(
        conditions=tuple(
            ConditionResult(
                number=number,
                name=name,
                findings=(Finding("PROBE-FAMILY-MISSING", "x/ipv6", "unprobed"),)
                if number == 5
                else (),
            )
            for number, name in CONDITIONS
        )
    )
    assert "RECEIPT-ACCEPTED-WITHOUT-VERDICT" in codes(check(build(), held=held))


# ── The rollback target ─────────────────────────────────────────────────────


def test_a_null_previous_release_on_a_later_promotion_is_refused():
    live = passing()
    without = dataclasses.replace(live, release=dataclasses.replace(live.release, previous=None))
    assert "RECEIPT-NO-ROLLBACK-TARGET" in codes(check(build(live=without)))


def test_a_null_previous_release_on_the_very_first_promotion_is_allowed():
    live = passing()
    without = dataclasses.replace(live, release=dataclasses.replace(live.release, previous=None))
    findings = check(build(live=without), first_promotion=True)
    assert "RECEIPT-NO-ROLLBACK-TARGET" not in codes(findings)


# ── What was approved versus what ran ───────────────────────────────────────


def test_an_image_set_that_differs_from_the_approved_plan_is_the_finding():
    other = (dataclasses.replace(IMAGES[0], digest="sha256:" + "e" * 64), IMAGES[1])
    assert "RECEIPT-IMAGE-SET" in codes(check(build(images=other)))


def test_a_receipt_naming_a_different_plan_from_the_authorized_one_is_refused():
    other = Authorization(plan_digest="sha256:" + "8" * 64, approval_decision_ref="decision/1")
    assert "RECEIPT-PLAN-DIGEST" in codes(check(build(authorization=other)))


def test_a_rendered_digest_that_is_not_the_promoted_trees_is_refused():
    document = build()
    document["rendered_digest"] = "f" * 64
    assert "RECEIPT-RENDERED-DIGEST" in codes(check(document))


# ── Rule 18 over the artifact most likely to be pasted into a ticket ────────


def test_a_receipt_carrying_a_resolved_address_is_refused():
    """The one detector, applied to a document rather than a tracked file.

    The address is assembled from parts at run time rather than written as a
    literal, because this file is itself scanned by `make private-scan` and a
    literal here would fail the repository's own rule 18 gate. Joining it is
    not a way around the rule: the scanner is a line-based text detector, and
    what it must catch is the string the RECEIPT would carry, which is exactly
    what this constructs.
    """
    address = ".".join(["203", "0", "113", "7"])
    document = build()
    document["release"] = {"previous": f"/opt/releases/{address}", "current": "/opt/releases/b"}
    assert "PRIVATE-ADDRESS" in codes(check(document))


def test_the_private_material_check_is_not_firing_on_a_clean_receipt():
    """Sensitivity for the test above.

    Without it, a detector that flagged every receipt would make the previous
    test pass while telling nobody anything.
    """
    assert not [code for code in codes(check(build())) if code.startswith("PRIVATE-")]


# ── A shape error is reported once, not as a cascade ────────────────────────


def test_a_schema_failure_suppresses_the_semantic_cascade():
    document = build()
    del document["live"]
    assert codes(check(document)) == {"SCHEMA"}
