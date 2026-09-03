"""Sensitivity proofs for the ingestion boundary (AGENTS.md rule 15).

`test_the_reference_ingestion_document_raises_no_findings` passes on a clean
document. It would also pass if `_ingestion_findings` returned an empty list,
if a mutation's anchor had drifted so nothing was edited, or if a gate had been
written inverted. Each case below plants one break and requires the named code.

The second half of the file is the one that matters more, and it follows the
shape `test_live_verify_bites.py` established: it writes the OBVIOUS version of
each check and shows it reporting the fault as healthy. Every one of these was
a real alternative — the shorter, more natural thing to write — and every one
of them agrees with the correct check on all the good inputs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dotmac_observability.ingestion import (
    ACCEPTED,
    PLANTED_SHAPES,
    REJECTED,
    UNMEASURED,
    Verdict,
    classify,
    compare_rebuild,
    integrity_state,
)
from dotmac_observability.render import INGESTION_RULES, render_control_plane
from dotmac_observability.validate import load, semantic_findings
from tests.conftest import CONTRACTS, REFERENCE, edit, resolved

INGESTION = ("inventory", "ingestion.toml")

BREAKS: tuple[tuple[str, str, str, str], ...] = (
    (
        "RESOURCE-IDENTITY-INCOMPLETE",
        "a record that cannot say which service produced it",
        'field = "service.name"\nrequired = true',
        'field = "service.name"\nrequired = false',
    ),
    (
        "IDENTIFIER-COLLAPSED",
        "two identifiers meaning the same thing",
        'name = "correlation-id"\nmeans = "one_business_flow"',
        'name = "correlation-id"\nmeans = "one_request"',
    ),
    (
        "IDENTIFIER-MISSING",
        "a meaning nothing carries any more",
        'name = "audit-event-id"\nmeans = "one_durable_audit_event"',
        'name = "audit-event-id"\nmeans = "one_request"',
    ),
    (
        "IDENTIFIER-NOT-NATIVE",
        "a trace id copied into an attribute beside the field that already holds it",
        'name = "trace-id"\nmeans = "one_telemetry_trace"\ntransport = "native"',
        'name = "trace-id"\nmeans = "one_telemetry_trace"\ntransport = "attribute"',
    ),
    (
        "ATTRIBUTE-UNBOUNDED-LABEL",
        "an unbounded attribute promoted to an index dimension",
        'name = "client.address"\nsignals = ["logs"]\ndisposition = "structured"',
        'name = "client.address"\nsignals = ["logs"]\ndisposition = "label"',
    ),
    (
        "LABEL-BUDGET-EXCEEDED",
        "more labels declared than the store will be told to accept",
        "max_stream_labels = 12",
        "max_stream_labels = 3",
    ),
    (
        "VALIDATION-OPAQUE-UNEXPLAINED",
        "a field accepted without being looked at, and nothing said about why",
        '  [attributes.validation]\n  kind = "shape"\n  shape = "ip_address"',
        '  [attributes.validation]\n  kind = "opaque"',
    ),
    (
        "VALIDATION-SHAPE-UNNAMED",
        "a shape validation that names no shape and therefore checks nothing",
        '  [attributes.validation]\n  kind = "shape"\n  shape = "http_status"',
        '  [attributes.validation]\n  kind = "shape"',
    ),
    (
        "VALIDATION-ENUM-EMPTY",
        "an enum with no members, which accepts nothing or everything by taste",
        '  kind = "enum"\n  values = ["debug", "info", "warn", "error", "fatal"]',
        '  kind = "enum"',
    ),
    (
        "REJECTION-UNPROVEN",
        "a rejection rule that has stopped matching its own planted material",
        'match = "http.request.header."',
        'match = "http.request.headers."',
    ),
    (
        "REJECTION-UNKNOWN-SHAPE",
        "a value-shape rule naming a shape the classifier cannot apply",
        'match = "pem_private_key"',
        'match = "pem_privatekey"',
    ),
    (
        "CONTROL-REFUSED",
        "a rule widened until ordinary traffic is refused",
        'kind = "attribute_name"\nmatch = "url.query"',
        'kind = "attribute_name"\nmatch = "client.address"',
    ),
    (
        "STREAM-COUNTERS-CONFLATED",
        "silence and cleanliness read off one counter",
        'integrity_counter = "loki_discarded_samples_total"',
        'integrity_counter = "loki_distributor_lines_received_total"',
    ),
    (
        "STREAM-LAG-UNDECLARED",
        "a stream that measures no lag and does not say why",
        "lag_expr = ",
        "# lag_expr removed by a mutation: ",
    ),
    (
        "STREAM-LAG-UNBUDGETED",
        "a lag expression with no budget, so the number is one nobody compares",
        'lag_budget = "5m"',
        "# lag_budget removed by a mutation",
    ),
    (
        "STREAM-LAG-DOUBLE-DECLARED",
        "a stream that both measures its lag and says its lag is unmeasured",
        "# \u2500\u2500 Deadman signals",
        "  [streams.lag_unmeasured]\n"
        '  rationale = "A second, contradictory declaration planted by a mutation test."\n'
        '  monitored_by = "nobody"\n\n'
        "# \u2500\u2500 Deadman signals",
    ),
    (
        "RETENTION-DISAGREES-WITH-STORE",
        "two documents describing one store's retention",
        'name = "telemetry-logs"\nkind = "telemetry"\nduration = "720h"',
        'name = "telemetry-logs"\nkind = "telemetry"\nduration = "168h"',
    ),
    (
        "PROJECTION-OUTLIVES-SOURCE",
        "a projection kept longer than the rows it derives from",
        'name = "audit-projection"\nkind = "audit_projection"\nduration = "2160h"',
        'name = "audit-projection"\nkind = "audit_projection"\nduration = "17520h"',
    ),
    (
        "PROJECTION-DECLARED-LAST-COPY",
        "a projection allowed to be the last surviving copy of an audit row",
        'duration = "2160h"\naccess = ["platform-operations"]\nlast_copy = false',
        'duration = "2160h"\naccess = ["platform-operations"]\nlast_copy = true',
    ),
    (
        "REBUILD-OVERCLAIMED",
        "a comparison that never ran, recorded as agreement",
        'last_rebuilt = "never"\n  verdict = "UNMEASURED"',
        'last_rebuilt = "never"\n  verdict = "MATCHED"',
    ),
    (
        "REBUILD-UNDERCLAIMED",
        "a completed proof left looking like an outstanding one",
        'last_rebuilt = "never"\n  verdict = "UNMEASURED"',
        'last_rebuilt = "2026-09-03"\n  verdict = "UNMEASURED"',
    ),
    (
        "PROJECTION-NOTICE-NO-SOURCE",
        "an alert that says what is not authoritative and not what is",
        "(application-audit-rows)",
        "(the application)",
    ),
    (
        "DEADMAN-UNPROVED-COUNT",
        "a deadman proved without the ratchet being lowered",
        'procedure_ref = "docs/runbooks/README.md"\n    last_proved = "never"',
        'procedure_ref = "docs/runbooks/README.md"\n    last_proved = "2026-09-03"',
    ),
    (
        "DEADMAN-NOT-META",
        "a product's alert expression wearing a deadman's name",
        'expr = "absent_over_time(up[10m])"',
        'expr = "erp_orders_pending > 100"',
    ),
    (
        "STREAM-RETENTION-UNDECLARED",
        "a stream aged out under a policy nobody declared",
        'retention_class = "telemetry-metrics"',
        'retention_class = "telemetry-forever"',
    ),
)


@pytest.mark.parametrize(
    ("code", "why", "old", "new"), BREAKS, ids=[case[0].lower() for case in BREAKS]
)
def test_the_ingestion_gate_bites(reference_copy: Path, code: str, why: str, old: str, new: str):
    edit(reference_copy.joinpath(*INGESTION), old, new)
    found = {
        finding.code for finding in semantic_findings(load(reference_copy, contracts=CONTRACTS))
    }
    assert code in found, f"the gate for {why} did not fire"


def test_a_clean_document_produces_none_of_those_codes():
    """The other half of a sensitivity proof.

    Without it, a gate that fired on EVERYTHING would satisfy every case above
    and the suite would report a detector that cannot discriminate as working.
    """
    found = {finding.code for finding in semantic_findings(load(REFERENCE, contracts=CONTRACTS))}
    assert found.isdisjoint({case[0] for case in BREAKS})


# ── the obvious version of each check, reporting the fault as healthy ───────


def test_the_obvious_drop_reading_calls_a_dead_pipeline_clean():
    """`value or 0` is the shorter thing to write, and it is the whole defect.

    A counter that has never been written and a counter standing at zero are
    the same number and opposite news. The obvious reading collapses them into
    the reassuring one, and it agrees with the correct reading on every input
    where anything is actually being measured — which is why nobody notices.
    """

    def obvious(value: int | None, baseline: int | None) -> str:
        return "GROWING" if (value or 0) > (baseline or 0) else "STABLE"

    assert obvious(None, None) == "STABLE"
    assert integrity_state("c", None, None) == UNMEASURED
    # And they agree everywhere else, which is the trap.
    assert obvious(101, 100) == integrity_state("c", 101, 100) == "GROWING"
    assert obvious(100, 100) == integrity_state("c", 100, 100) == "STABLE"


def test_the_obvious_rejection_check_passes_an_inert_rule():
    """Comparing the OUTCOME instead of the rule name.

    Every planted probe carries a field the contract does not accept, so the
    vocabulary check refuses it whatever the rejection rules do. An
    outcome-only assertion therefore passes with every rejection rule deleted.
    """
    policy = _policy_without_rejection_rules()
    refused_anyway = 0
    for rule in REFERENCE_POLICY.rejected:
        for probe in rule.planted:
            verdict = classify(
                policy, "logs", ((probe.attribute, PLANTED_SHAPES[probe.value_shape]),)
            )
            assert verdict.outcome == REJECTED  # the obvious check: still "passing"
            assert verdict.rule != rule.name  # the real check: nothing bit
            refused_anyway += 1
    assert refused_anyway >= 10, "the probe corpus is too small to prove anything"


def test_a_classifier_that_refuses_everything_satisfies_every_probe():
    """Why the negative suite carries positive controls in the same document.

    This is the failure that hides best: a boundary that has stopped accepting
    anything looks, from every rejection test ever written, like a boundary
    working perfectly. Only the control records can tell the two apart, and
    they fail loudly the moment the fleet stops shipping.
    """

    def refuse_everything(*_args: object, **_kwargs: object) -> Verdict:
        return Verdict(REJECTED, rule="everything", attribute=None, reason="no")

    for rule in REFERENCE_POLICY.rejected:
        for _probe in rule.planted:
            assert refuse_everything().outcome == REJECTED

    # The control is what notices.
    for control in REFERENCE_POLICY.accepted_control:
        attributes = tuple(
            (entry.name, PLANTED_SHAPES[entry.value_shape]) for entry in control.attributes
        )
        assert refuse_everything().outcome != ACCEPTED
        assert classify(REFERENCE_POLICY, control.signal, attributes).outcome == ACCEPTED


def test_the_obvious_rebuild_comparison_calls_two_failed_reads_agreement():
    """`source == projection` on two empty dictionaries is True.

    A rebuild whose reader could not connect produces an exact match against
    nothing, in a function whose entire purpose is to be able to disagree —
    and it produces the one verdict that would let somebody write
    `last_rebuilt` into the contract.
    """
    assert ({} == {}) is True
    assert compare_rebuild({}, {}).verdict == UNMEASURED


def test_the_obvious_rebuild_comparison_calls_two_different_sets_of_the_same_size_equal():
    """A count comparison is the other shorter thing to write."""
    source = {"a": "d1", "b": "d2"}
    projection = {"a": "d1", "c": "d2"}
    assert len(source) == len(projection)  # the obvious check: "matched"
    assert compare_rebuild(source, projection).verdict == "DIVERGED"


def test_a_rate_threshold_would_be_written_over_a_series_that_stops_existing():
    """The silence detector's shape, asserted on the rendered bytes.

    No Python test can run PromQL, so what is checked is that the renderer
    emits an ABSENCE and does not emit the rate comparison that reads like the
    same question. `rate(x[5m]) == 0` over a series that has ceased to exist
    matches no rows, and a rule matching no rows fires nothing at all.
    """
    rules = dict(render_control_plane(load(REFERENCE, contracts=CONTRACTS), resolved(REFERENCE)))[
        INGESTION_RULES
    ]
    assert "absent_over_time(" in rules
    for stream in REFERENCE_POLICY.streams:
        assert f"rate({stream.arrival_counter}" not in rules
        assert f"{stream.arrival_counter} == 0" not in rules


REFERENCE_POLICY = load(REFERENCE, contracts=CONTRACTS).ingestion


def _policy_without_rejection_rules():
    """The reference policy with every rejection rule removed.

    Built by replacing the tuple rather than by editing a document, so the
    mutation is exactly "the rules do nothing" and not "the document is also
    differently shaped".
    """
    import dataclasses

    return dataclasses.replace(REFERENCE_POLICY, rejected=())
