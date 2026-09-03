"""The ingestion boundary: what is accepted, what is refused, what is unmeasured.

Every test here names the state it keeps apart from another state that looks
like it, because looking alike is the whole defect this contract exists to
repair. A drop counter at zero and a drop counter that was never written. A
rejection rule that bit and one the vocabulary check bit for it. A rebuild that
agreed and a rebuild that never ran. In each pair the wrong reading is the
reassuring one.
"""

from __future__ import annotations

from pathlib import Path

from dotmac_observability.ingestion import (
    ACCEPTED,
    PLANTED_SHAPES,
    REJECTED,
    UNMEASURED,
    classify,
    compare_rebuild,
    duration_seconds,
    integrity_state,
)
from dotmac_observability.render import INGESTION_RULES, LOKI_CONFIG, render_control_plane
from dotmac_observability.validate import load, semantic_findings
from tests.conftest import CONTRACTS, REFERENCE, resolved


def _policy(root: Path = REFERENCE):
    return load(root, contracts=CONTRACTS).ingestion


def _tree(root: Path = REFERENCE) -> dict[str, str]:
    return dict(render_control_plane(load(root, contracts=CONTRACTS), resolved(root)))


# ── the reference document is clean, so every mutation elsewhere means something ──


def test_the_reference_ingestion_document_raises_no_findings():
    assert semantic_findings(load(REFERENCE, contracts=CONTRACTS)) == ()


def test_the_production_ingestion_document_raises_no_findings():
    """The gates PASS on the tree a promotion will actually render.

    The fixture proves the gates work. This proves they do not merely work on a
    document written to satisfy them.
    """
    root = Path(__file__).resolve().parents[2]
    assert semantic_findings(load(root, contracts=CONTRACTS)) == ()


# ── rejection is proved by rule, not by outcome ─────────────────────────────


def test_every_planted_probe_is_refused_by_its_own_rule():
    """The gate the loader runs, asserted here as a property of the document.

    A probe usually carries a field this contract does not accept anyway, so a
    classifier that checked the vocabulary first would refuse every probe for
    the wrong reason while every rejection rule sat inert. The rule NAME is
    what is compared.
    """
    policy = _policy()
    assert policy.rejected, "the document declares no rejection rules"
    for rule in policy.rejected:
        assert rule.planted, f"{rule.name} carries no planted material"
        for probe in rule.planted:
            verdict = classify(
                policy, "logs", ((probe.attribute, PLANTED_SHAPES[probe.value_shape]),)
            )
            assert verdict.outcome == REJECTED, (rule.name, probe.attribute, verdict)
            assert verdict.rule == rule.name, (
                f"planted {probe.value_shape!r} on {probe.attribute!r} was refused by "
                f"{verdict.rule!r}, not by {rule.name!r}"
            )


def test_the_positive_controls_are_accepted():
    """The half a negative suite cannot supply itself.

    A classifier that refuses everything satisfies every probe above, and
    nothing about its refusals says so.
    """
    policy = _policy()
    assert policy.accepted_control, "the document declares no positive control"
    for control in policy.accepted_control:
        attributes = tuple(
            (entry.name, PLANTED_SHAPES[entry.value_shape]) for entry in control.attributes
        )
        verdict = classify(policy, control.signal, attributes)
        assert verdict.outcome == ACCEPTED, (control.name, verdict.rule, verdict.reason)


def test_a_uuid_on_a_shape_validated_attribute_survives_the_opaque_token_rule():
    """The false positive the positive control found.

    A UUID is thirty-six characters of hex and dashes and matches an
    opaque-token heuristic exactly. Without the structural exemption, an
    ordinary request log line was refused — and every negative test still
    passed, because refusing more is what a negative test rewards.
    """
    policy = _policy()
    identifier = PLANTED_SHAPES["uuid"]
    assert classify(policy, "logs", (("request.id", identifier),)).outcome == ACCEPTED
    # The SAME value under a name the contract does not accept is still refused,
    # so the exemption is about the declared shape rather than about the value.
    stray = classify(policy, "logs", (("session.token", identifier),))
    assert stray.outcome == REJECTED


def test_a_name_rule_is_not_exempted_by_a_well_formed_value():
    """A forbidden field is forbidden however tidy its contents are.

    The structural exemption applies only to value-shape heuristics. A name or
    prefix rule says the field must not arrive at all, and a body containing
    perfectly valid JSON is exactly the case where relaxing that would feel
    reasonable.
    """
    policy = _policy()
    verdict = classify(policy, "logs", (("http.request.body", PLANTED_SHAPES["clean_short_text"]),))
    assert verdict.outcome == REJECTED
    assert verdict.rule == "request-body"


def test_an_unlisted_attribute_is_refused():
    policy = _policy()
    verdict = classify(policy, "logs", (("some.new.field", "anything"),))
    assert verdict.outcome == REJECTED
    assert verdict.rule == "attribute-not-accepted"


def test_an_accepted_attribute_with_a_bad_value_is_refused():
    """Acceptance is not a rubber stamp.

    `client.address` is accepted and shape-validated; a value that is not an
    address is refused under the attribute's own validation rather than waved
    through because the name was on the list.
    """
    policy = _policy()
    verdict = classify(policy, "logs", (("client.address", "not-an-address"),))
    assert verdict.outcome == REJECTED
    assert verdict.rule == "attribute-value-invalid"


def test_an_attribute_accepted_for_one_signal_is_not_accepted_for_another():
    policy = _policy()
    verdict = classify(policy, "metrics", (("client.address", PLANTED_SHAPES["loopback_address"]),))
    assert verdict.outcome == REJECTED


def test_the_attribution_vocabulary_is_refused_structurally_rather_than_gated():
    """No mutation test for this, because no document can express the mistake.

    `values` is a three-member enum with `minItems: 3` and `uniqueItems`, and
    `unresolved` is a `const`. The only set that validates is the complete one,
    so a document that drops `unknown` — or that answers `direct` when the peer
    could not be established — is a shape this contract cannot hold. The gate
    in the loader is belt to that brace and says so where it sits.
    """
    import json

    import jsonschema

    schema = json.loads((CONTRACTS / "telemetry-ingestion.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema["$defs"]["attribution"])
    good = {
        "values": ["direct", "trusted_forwarded", "unknown"],
        "unresolved": "unknown",
        "rationale": "x" * 40,
    }
    assert validator.is_valid(good), "the positive control does not validate"
    assert not validator.is_valid({**good, "values": ["direct", "trusted_forwarded"]})
    assert not validator.is_valid({**good, "unresolved": "direct"})


# ── unmeasured is a verdict, not a missing value ────────────────────────────


def test_a_counter_that_was_never_observed_is_unmeasured_not_clean():
    assert integrity_state("c", None, 0) == UNMEASURED
    assert integrity_state("c", 0, None) == UNMEASURED


def test_a_counter_that_went_backwards_is_unmeasured_not_stable():
    """A reset makes the interval unobserved, which is not the same as clean.

    Reporting STABLE here would claim the window between the reset and now was
    free of drops, and nothing observed that window at all.
    """
    assert integrity_state("c", 5, 100) == UNMEASURED


def test_a_counter_standing_still_is_stable_and_a_growing_one_is_growing():
    assert integrity_state("c", 100, 100) == "STABLE"
    assert integrity_state("c", 101, 100) == "GROWING"


# ── the rebuild-and-compare path ────────────────────────────────────────────


def test_a_rebuild_that_read_nothing_is_unmeasured():
    """Two empty sides agree perfectly, against nothing.

    The same refusal the live-observation contract makes about an empty tree
    read-back: a comparison that cannot fail is not a comparison, and reporting
    MATCHED here would turn a broken reader into evidence of correctness.
    """
    assert compare_rebuild({}, {}).verdict == UNMEASURED
    assert compare_rebuild(None, {"a": "d"}).verdict == UNMEASURED
    assert compare_rebuild({"a": "d"}, None).verdict == UNMEASURED


def test_a_rebuild_that_agrees_row_by_row_matches():
    rows = {"a": "d1", "b": "d2"}
    assert compare_rebuild(rows, dict(rows)).verdict == "MATCHED"


def test_a_rebuild_reports_which_rows_disagree_and_how():
    source = {"a": "d1", "b": "d2", "c": "d3"}
    projection = {"a": "d1", "b": "CHANGED", "d": "d4"}
    result = compare_rebuild(source, projection)
    assert result.verdict == "DIVERGED"
    assert result.missing == ("c",)
    assert result.extra == ("d",)
    assert result.differing == ("b",)


def test_the_same_row_count_is_not_the_same_rows():
    """Why the declared comparison is `row_digest` and not `count_only`.

    Two sets of equal size agree on every count anybody would think to check.
    """
    source = {"a": "d1", "b": "d2"}
    projection = {"a": "d1", "c": "d2"}
    assert len(source) == len(projection)
    assert compare_rebuild(source, projection).verdict == "DIVERGED"


def test_the_projection_declares_itself_unmeasured_because_it_has_never_been_rebuilt():
    """`rebuildable` is a property nobody here has yet, and it says so.

    The contract refuses any verdict but UNMEASURED while no rebuild is
    recorded, so this assertion cannot be satisfied by an optimistic edit.
    """
    projection = _policy().projection
    assert projection.authoritative is False
    assert projection.rebuild.last_rebuilt is None
    assert projection.rebuild.verdict == UNMEASURED


# ── what is rendered, and what is deliberately not ──────────────────────────


def test_silence_is_detected_by_absence_and_never_by_a_rate_threshold():
    """The query shape that survives the series going away.

    `rate(arrivals[5m]) == 0` reads like the same question. It is not: when a
    shipper stops, its series stops existing, and a comparison against a series
    that does not exist matches no rows and produces no alert at all.
    """
    rules = _tree()[INGESTION_RULES]
    assert "absent_over_time(loki_distributor_lines_received_total[15m])" in rules
    assert "rate(loki_distributor_lines_received_total" not in rules


def test_the_unmeasured_state_has_its_own_alert():
    rules = _tree()[INGESTION_RULES]
    assert "alert: LogsIntegrityUnmeasured" in rules
    assert "absent(loki_discarded_samples_total)" in rules


def test_the_drop_alert_is_delta_shaped():
    rules = _tree()[INGESTION_RULES]
    assert "increase(loki_discarded_samples_total[15m]) > 0" in rules
    assert "loki_discarded_samples_total == 0" not in rules


def test_a_stream_whose_lag_nothing_measures_renders_no_lag_alert():
    """Better an admitted gap than a rule that can never fire.

    An expression over a metric nothing emits renders an alert that reads on
    every dashboard exactly like one that is quietly passing.
    """
    policy = _policy()
    logs = next(stream for stream in policy.streams if stream.signal == "logs")
    assert logs.lag_expr is None
    assert logs.lag_unmeasured is not None
    assert "alert: LogsIngestionLag" not in _tree()[INGESTION_RULES]


def test_the_measured_lag_alert_compares_against_its_own_declared_budget():
    """The threshold and the hold are rendered from one string.

    Two spellings of the budget is an alert that fires on one number and holds
    for another, and nothing in the rendered file would look wrong.
    """
    policy = _policy()
    metrics = next(stream for stream in policy.streams if stream.signal == "metrics")
    assert metrics.lag_budget is not None
    rules = _tree()[INGESTION_RULES]
    assert f"> {int(duration_seconds(metrics.lag_budget))}" in rules
    assert f'for: "{metrics.lag_budget}"' in rules


def test_a_planned_projection_renders_no_lag_alert_and_still_carries_its_decisions():
    policy = _policy()
    assert policy.projection.status == "planned"
    assert "alert: FleetAuditSearchLag" not in _tree()[INGESTION_RULES]
    # The decisions that are expensive to take later are declared regardless.
    assert policy.projection.non_authority_notice
    assert policy.projection.source_retention


def test_an_unproved_deadman_says_so_in_the_alert_a_responder_reads():
    """The annotation an operator sees at three in the morning.

    A deadman that has never fired is indistinguishable from one whose
    expression matches no series at all, and the moment that matters is the
    moment somebody is relying on it.
    """
    rules = _tree()[INGESTION_RULES]
    assert "UNPROVED — this deadman has never been observed to fire" in rules


def test_the_projection_lag_alert_text_would_say_it_is_not_authoritative():
    """Checked on the document, because the alert is not rendered while planned.

    The notice is gated whether or not it is rendered, which is the point: the
    wording is settled before anybody is reading it under pressure.
    """
    projection = _policy().projection
    assert "not authoritative" in projection.non_authority_notice.lower()
    assert projection.derived_from in projection.non_authority_notice


def test_the_label_budget_reaches_the_store_that_enforces_it():
    """One number, not two.

    A budget declared in a document and a limit configured in the store are two
    answers to one question, and the store enforces whichever was rendered.
    """
    policy = _policy()
    assert f"max_label_names_per_series: {policy.labels.max_stream_labels}" in _tree()[LOKI_CONFIG]


def test_log_retention_is_one_decision_across_two_documents():
    state = load(REFERENCE, contracts=CONTRACTS)
    logs = next(stream for stream in state.ingestion.streams if stream.signal == "logs")
    declared = next(
        entry for entry in state.ingestion.retention if entry.name == logs.retention_class
    )
    assert declared.duration == state.bundle.loki.retention


def test_every_retention_class_states_who_may_read_it():
    for entry in _policy().retention:
        assert entry.access, f"{entry.name} names no reader"
        assert entry.last_copy is False


def test_duration_seconds_compares_units_rather_than_strings():
    assert duration_seconds("720h") > duration_seconds("30m")
    assert duration_seconds("90d") == duration_seconds("2160h")
