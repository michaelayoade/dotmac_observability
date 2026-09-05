"""One envelope version, two observation versions, and one binding between them.

The envelope carries `observation_digest`. That digest binds the COMPLETE
observation, including both artifact digests, so nothing beneath it needs
copying up -- and copying anything up would create a second place the same
truth lives, which is the copy that goes stale.

An envelope v2 briefly existed here carrying `source_artifact_digest`, on the
reasoning that a gate reads the envelope and should not have to fetch a private
document. The correction is that such a reader must resolve the retained
observation or answer UNKNOWN, which is the identical discipline
`derive_verdict` already enforces one level down: "we could not look" is never
spelled the same way as "there is nothing there". It was removed rather than
superseded because no instance was ever produced, signed or accepted -- the
tests below pin that removal so the copy cannot come back by convenience.

The observation is versioned and v1 is retained. v1 stays readable historical
evidence. It cannot discharge the rotation interlock -- not because it is old,
but because it has no field in which the `HostSource` implementation could be
named, and that implementation decides which failures are reported as
`missing`, which is the single code separating a clean host from an unreadable
one.
"""

from __future__ import annotations

import json

import pytest

from dotmac_observability.attribution import (
    ATTRIBUTION_SCHEMA_VERSION,
    CLASSIFIED_FIELDS,
    ENVELOPE_FIELDS,
    InterlockVerdict,
    RedactionVault,
    UnclassifiedField,
    discharges_rotation_interlock,
    project_envelope,
)
from dotmac_observability.validate import canonical_digest
from tests.attribution_fixtures import clean_scans, observation
from tests.conftest import CONTRACTS

V1_ENVELOPE = CONTRACTS / "postgres-consumer-attribution-envelope.schema.json"
V1_OBSERVATION = CONTRACTS / "postgres-consumer-attribution-observation.schema.json"
V2_OBSERVATION = CONTRACTS / "postgres-consumer-attribution-observation-v2.schema.json"

_COLLECTOR_DIGEST = "sha256:" + "cd" * 32
_SOURCE_DIGEST = "sha256:" + "ef" * 32


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _observation_document(**overrides: object) -> dict[str, object]:
    """A minimal v2 observation. Only the fields the interlock reads matter here."""
    document: dict[str, object] = {
        "schema_version": "observability-consumer-attribution-observation.v2",
        "target_id": "erp-production",
        "observed_at": "2026-09-05T09:00:00Z",
        "host_identity_digest": "sha256:" + "ab" * 32,
        "collector_artifact_digest": _COLLECTOR_DIGEST,
        "source_artifact_digest": _SOURCE_DIGEST,
        "consumers": [],
        "families": [],
    }
    document.update(overrides)
    return document


def _envelope_for(document) -> dict[str, object]:
    return project_envelope(
        observation(observation_digest=f"sha256:{canonical_digest(document)}"),
        clean_scans(),
        vault=RedactionVault(),
    )


def test_the_three_contracts_exist_and_the_fourth_does_not():
    """Sensitivity in both directions.

    Without the positive half, every comparison below would pass over a missing
    file. Without the negative half, the removal this change exists for could
    be silently undone by re-adding the schema.
    """
    for path in (V1_ENVELOPE, V1_OBSERVATION, V2_OBSERVATION):
        assert path.is_file(), path.name
    assert not (CONTRACTS / "postgres-consumer-attribution-envelope-v2.schema.json").is_file(), (
        "an envelope v2 is back. The envelope carries `observation_digest`, which binds the "
        "complete observation; a copied artifact digest is a second place the truth lives"
    )


def test_there_is_exactly_one_envelope_version():
    envelopes = sorted(CONTRACTS.glob("postgres-consumer-attribution-envelope*.schema.json"))
    assert [path.name for path in envelopes] == [
        "postgres-consumer-attribution-envelope.schema.json"
    ]
    assert _load(V1_ENVELOPE)["properties"]["schema_version"]["const"] == (
        ATTRIBUTION_SCHEMA_VERSION
    )


def test_the_envelope_carries_no_artifact_digest_it_did_not_already_carry():
    """`source_artifact_digest` is absent from the envelope, at every level.

    Checked over every nested `properties` block rather than the top level
    only, because a copied field would most naturally be added to a per-family
    result rather than to the root.
    """
    names: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    names.update(value)
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(_load(V1_ENVELOPE))
    assert "source_artifact_digest" not in names
    assert "observation_digest" in names, "the one binding is gone; nothing binds the evidence"


# ── The projection refuses the copy ─────────────────────────────────────────


def test_the_projection_refuses_the_source_digest_rather_than_dropping_it():
    """Raise, not drop. A dropped field produces an envelope that looks correct.

    `source_artifact_digest` is simply not classified, so default-deny does the
    work -- there is no special case naming it, which is why the next field
    nobody has thought about behaves the same way.
    """
    with pytest.raises(UnclassifiedField, match="source_artifact_digest"):
        project_envelope(
            observation(source_artifact_digest=_SOURCE_DIGEST),
            clean_scans(),
            vault=RedactionVault(),
        )
    assert "source_artifact_digest" not in CLASSIFIED_FIELDS


def test_a_normal_projection_still_succeeds():
    """Positive control: refusing everything would satisfy the test above."""
    envelope = project_envelope(observation(), clean_scans(), vault=RedactionVault())
    assert set(envelope) == set(ENVELOPE_FIELDS)
    assert envelope["schema_version"] == ATTRIBUTION_SCHEMA_VERSION


def test_the_projection_takes_no_version_argument():
    """The version machinery is gone, not merely unused.

    A dormant `version=` parameter is an invitation to add the second envelope
    back, and it would read as supported.
    """
    import inspect

    assert "version" not in inspect.signature(project_envelope).parameters


# ── v1 observation untouched, v2 requires both digests ──────────────────────


def test_the_v1_observation_gained_nothing():
    document = _load(V1_OBSERVATION)
    assert "source_artifact_digest" not in document["properties"]
    assert "collector_artifact_digest" not in document["properties"]
    assert set(document["$defs"]["family_scan"]["properties"]["errors"]["items"]["enum"]) == {
        "denied",
        "parse",
        "syntax",
        "ambiguous",
        "dynamic",
        "timeout",
        "unsupported",
    }


def test_the_v2_observation_requires_both_artifact_digests():
    document = _load(V2_OBSERVATION)
    assert {"collector_artifact_digest", "source_artifact_digest"} <= set(document["required"])
    assert document["additionalProperties"] is False


# ── The interlock resolves the observation, or answers UNKNOWN ──────────────


def test_an_envelope_alone_cannot_answer_and_says_so():
    """The ruling, as the assertion it becomes.

    Not `False`. A reader holding only the envelope has not established that
    the binding fails -- it has established nothing, and `REFUSED` would be a
    claim it is not entitled to make.
    """
    document = _observation_document()
    assert discharges_rotation_interlock(_envelope_for(document)) is InterlockVerdict.UNKNOWN


def test_resolving_the_named_observation_discharges_it():
    """Positive control. A predicate that always answered UNKNOWN would pass above."""
    document = _observation_document()
    verdict = discharges_rotation_interlock(_envelope_for(document), document)
    assert verdict is InterlockVerdict.DISCHARGED


def test_a_resolved_v1_observation_is_refused_rather_than_unknown():
    """Determinate: we looked at the right document and it names no source.

    `REFUSED` and `UNKNOWN` both block rotation, so collapsing them would be
    safe and still wrong -- they call for different repairs. One is fixed by
    fetching the observation; the other by re-running the census with a source
    that identifies itself.
    """
    legacy = _observation_document(
        schema_version="observability-consumer-attribution-observation.v1"
    )
    del legacy["collector_artifact_digest"]
    del legacy["source_artifact_digest"]
    verdict = discharges_rotation_interlock(_envelope_for(legacy), legacy)
    assert verdict is InterlockVerdict.REFUSED


@pytest.mark.parametrize("missing", ["collector_artifact_digest", "source_artifact_digest"])
def test_a_v2_observation_missing_either_digest_is_refused(missing):
    """One digest identifies half of what ran, which is not an identification."""
    document = _observation_document()
    del document[missing]
    assert discharges_rotation_interlock(_envelope_for(document), document) is (
        InterlockVerdict.REFUSED
    )


def test_the_wrong_observation_is_unknown_and_never_discharges():
    """Being handed the wrong document says nothing about the right one.

    The dangerous alternative is not `REFUSED` -- it is accepting any document
    that happens to carry two digests, which would let an unrelated
    observation discharge an envelope it has nothing to do with.
    """
    named = _observation_document()
    other = _observation_document(target_id="academy-production")
    envelope = _envelope_for(named)
    assert discharges_rotation_interlock(envelope, other) is InterlockVerdict.UNKNOWN


def test_an_envelope_with_no_binding_is_unknown():
    envelope = dict(project_envelope(observation(), clean_scans(), vault=RedactionVault()))
    del envelope["observation_digest"]
    assert discharges_rotation_interlock(envelope, _observation_document()) is (
        InterlockVerdict.UNKNOWN
    )


def test_the_interlock_is_three_valued_and_all_three_are_reachable():
    """A two-valued predicate cannot express "we could not look".

    Asserted as reachability rather than as an enum listing, because an enum
    with an unreachable member is the same defect as not having it.
    """
    named = _observation_document()
    envelope = _envelope_for(named)
    legacy = _observation_document()
    del legacy["source_artifact_digest"]
    reached = {
        discharges_rotation_interlock(envelope),
        discharges_rotation_interlock(envelope, named),
        discharges_rotation_interlock(_envelope_for(legacy), legacy),
    }
    assert reached == set(InterlockVerdict)
