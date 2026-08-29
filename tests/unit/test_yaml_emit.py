"""The emitter is the bottom of the determinism guarantee.

Every test here is about a property AGENTS.md rule 13 depends on, not about
YAML in general: if any of these change, every committed rendered byte changes
with them, so they are worth pinning explicitly rather than inferring from a
golden file.
"""

from __future__ import annotations

from dotmac_observability.yaml_emit import emit


def test_a_bool_is_not_emitted_as_a_number():
    # `isinstance(True, int)` is true in Python. An emitter that checks int
    # before bool writes `honor_labels: 1`, which Prometheus reads as a number
    # and rejects — at config load, on the live host, after promotion.
    assert emit({"flag": True, "count": 1}) == "flag: true\ncount: 1\n"


def test_ambiguous_scalars_are_quoted():
    rendered = emit(
        {
            "duration": "15s",
            "listen": "127.0.0.1:9090",
            "path": "/metrics",
            "yes_like": "yes",
            "numeric": "0.10",
            "plain": "dotmac-erp",
        }
    )
    assert '"15s"' in rendered
    assert '"127.0.0.1:9090"' in rendered
    assert '"/metrics"' in rendered
    assert '"yes"' in rendered  # unquoted, YAML 1.1 readers make this a bool
    assert '"0.10"' in rendered  # unquoted, this becomes the float 0.1
    assert "plain: dotmac-erp\n" in rendered


def test_quotes_and_backslashes_survive_a_round_trip_shape():
    rendered = emit({"matcher": 'severity="critical"', "escaped": "a\\b"})
    assert 'matcher: "severity=\\"critical\\""' in rendered
    assert 'escaped: "a\\\\b"' in rendered


def test_key_order_is_the_caller_s_order_and_is_never_sorted():
    assert emit({"z": 1, "a": 2, "m": 3}) == "z: 1\na: 2\nm: 3\n"


def test_empty_collections_use_the_only_spelling_that_exists():
    assert emit({"m": {}, "s": []}) == "m: {}\ns: []\n"


def test_a_mapping_inside_a_sequence_rides_the_dash():
    rendered = emit({"items": [{"first": 1, "second": 2}]})
    assert rendered == "items:\n  - first: 1\n    second: 2\n"


def test_output_ends_in_exactly_one_newline():
    rendered = emit({"a": 1})
    assert rendered.endswith("\n")
    assert not rendered.endswith("\n\n")


def test_the_header_is_emitted_as_comments():
    assert emit({"a": 1}, header=["generated", ""]).startswith("# generated\n#\na: 1")
