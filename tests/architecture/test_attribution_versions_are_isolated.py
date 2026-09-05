"""Adding v2 must not widen v1. That is the whole of ruling 2's second clause.

The mistake it forbids is small and almost invisible. One shared
`CLASSIFIED_FIELDS` table, one new entry for `source_artifact_digest`, and from
that moment `project_envelope` accepts the field for a v1 projection too. It
does not raise; it does not appear in the output; the field is simply dropped.
A v1 envelope then exists that a v1 reader believes was produced under v1
rules, and nothing anywhere says otherwise.

So the allowlists are version-SPECIFIC and the isolation is asserted in both
directions: v2's field must be refused by v1, and v1 must still accept
everything it always did.

v1 is retained, not deprecated. It stays readable historical evidence. What it
cannot do is discharge the rotation interlock, because it has no field naming
the `HostSource` implementation that decided which failures were `missing` --
and that decision is what separates a clean host from an unreadable one.
"""

from __future__ import annotations

import json

import pytest

from dotmac_observability.attribution import (
    ATTRIBUTION_SCHEMA_VERSION,
    ATTRIBUTION_SCHEMA_VERSION_V2,
    CLASSIFIED_FIELDS,
    CLASSIFIED_FIELDS_BY_VERSION,
    ENVELOPE_FIELDS,
    ENVELOPE_FIELDS_BY_VERSION,
    ENVELOPE_FIELDS_V2,
    ENVELOPE_VERSIONS,
    RedactionVault,
    UnclassifiedField,
    discharges_rotation_interlock,
    project_envelope,
)
from tests.attribution_fixtures import clean_scans, observation
from tests.conftest import CONTRACTS

V1_ENVELOPE = CONTRACTS / "postgres-consumer-attribution-envelope.schema.json"
V2_ENVELOPE = CONTRACTS / "postgres-consumer-attribution-envelope-v2.schema.json"
V1_OBSERVATION = CONTRACTS / "postgres-consumer-attribution-observation.schema.json"
V2_OBSERVATION = CONTRACTS / "postgres-consumer-attribution-observation-v2.schema.json"

_SOURCE_DIGEST = "sha256:" + "ef" * 32


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_all_four_contracts_exist():
    """Sensitivity: every comparison below would pass over a missing file."""
    for path in (V1_ENVELOPE, V2_ENVELOPE, V1_OBSERVATION, V2_OBSERVATION):
        assert path.is_file(), path.name


# ── v1 was not touched ──────────────────────────────────────────────────────


def test_v1_gained_no_field_and_no_new_requirement():
    """A published closed contract's shape and digest meaning are frozen.

    An optional field would make one version name two shapes; a required one
    would change what an already-stored document's digest means. Neither is
    available, which is why v2 exists at all.
    """
    envelope = _load(V1_ENVELOPE)
    assert set(envelope["properties"]) == set(ENVELOPE_FIELDS)
    assert "source_artifact_digest" not in envelope["properties"]
    assert envelope["properties"]["schema_version"]["const"] == ATTRIBUTION_SCHEMA_VERSION

    observation_v1 = _load(V1_OBSERVATION)
    assert "source_artifact_digest" not in observation_v1["properties"]
    assert "collector_artifact_digest" not in observation_v1["properties"]
    assert set(observation_v1["$defs"]["family_scan"]["properties"]["errors"]["items"]["enum"]) == {
        "denied",
        "parse",
        "syntax",
        "ambiguous",
        "dynamic",
        "timeout",
        "unsupported",
    }


def test_v2_requires_both_artifact_digests():
    """Both, and required. One of them alone identifies half of what ran."""
    observation_v2 = _load(V2_OBSERVATION)
    assert {"collector_artifact_digest", "source_artifact_digest"} <= set(
        observation_v2["required"]
    )
    assert observation_v2["properties"]["schema_version"]["const"].endswith("observation.v2")

    envelope_v2 = _load(V2_ENVELOPE)
    assert "source_artifact_digest" in envelope_v2["required"]
    assert "collector_artifact_digest" in envelope_v2["required"]


@pytest.mark.parametrize("path", [V2_ENVELOPE, V2_OBSERVATION], ids=lambda p: p.name)
def test_v2_closes_every_object_exactly_as_v1_does(path):
    """The new version must not be the loosening the old one refused to be."""
    open_objects: list[str] = []

    def walk(node, where: str) -> None:
        if isinstance(node, dict):
            if (
                node.get("type") == "object"
                and "properties" in node
                and node.get("additionalProperties") is not False
            ):
                open_objects.append(where)
            for key, value in node.items():
                walk(value, f"{where}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}/{index}")

    walk(_load(path), "")
    assert open_objects == [], f"{path.name} has open objects at {open_objects}"


def test_the_v2_envelope_still_has_no_private_field():
    forbidden = {
        "db_host",
        "db_port",
        "db_user",
        "db_name",
        "launch_path",
        "secret_pointers",
        "env_var_names",
        "dsn",
        "password",
    }
    assert not (set(_load(V2_ENVELOPE)["properties"]) & forbidden)


# ── The allowlists do not leak into one another ─────────────────────────────


def test_the_v2_field_is_refused_by_a_v1_projection():
    """The exact defect a shared table would introduce, planted.

    Not "it is dropped" -- it must RAISE. A silently dropped field produces a
    v1 envelope that looks correct and was built from an input v1 does not
    know about.
    """
    with pytest.raises(UnclassifiedField, match="source_artifact_digest"):
        project_envelope(
            observation(source_artifact_digest=_SOURCE_DIGEST),
            clean_scans(),
            vault=RedactionVault(),
            version=ATTRIBUTION_SCHEMA_VERSION,
        )


def test_the_default_version_is_v1_so_an_unversioned_caller_cannot_widen():
    """A caller that names no version gets the NARROWER allowlist.

    Defaulting to the newest would mean every existing call site silently
    started accepting v2's field the moment v2 landed, which is the same
    widening by a different route.
    """
    with pytest.raises(UnclassifiedField):
        project_envelope(
            observation(source_artifact_digest=_SOURCE_DIGEST),
            clean_scans(),
            vault=RedactionVault(),
        )


def test_a_v2_projection_accepts_and_emits_the_field():
    """Positive control. Without it, refusing everything would pass the above."""
    envelope = project_envelope(
        observation(source_artifact_digest=_SOURCE_DIGEST),
        clean_scans(),
        vault=RedactionVault(),
        version=ATTRIBUTION_SCHEMA_VERSION_V2,
    )
    assert envelope["source_artifact_digest"] == _SOURCE_DIGEST
    assert envelope["schema_version"] == ATTRIBUTION_SCHEMA_VERSION_V2
    assert set(envelope) == set(ENVELOPE_FIELDS_V2)


def test_a_v2_projection_without_the_field_is_refused():
    """v2 requires it. An absent required field must not produce a short envelope."""
    with pytest.raises(KeyError):
        project_envelope(
            observation(),
            clean_scans(),
            vault=RedactionVault(),
            version=ATTRIBUTION_SCHEMA_VERSION_V2,
        )


def test_an_unknown_version_is_refused_rather_than_guessed():
    with pytest.raises(ValueError, match="v3"):
        project_envelope(
            observation(),
            clean_scans(),
            vault=RedactionVault(),
            version="observability-consumer-attribution-envelope.v3",
        )


def test_the_allowlists_differ_by_exactly_the_new_field():
    """Asserted as a difference, not as two lists, so drift names itself."""
    v1 = set(CLASSIFIED_FIELDS_BY_VERSION[ATTRIBUTION_SCHEMA_VERSION])
    v2 = set(CLASSIFIED_FIELDS_BY_VERSION[ATTRIBUTION_SCHEMA_VERSION_V2])
    assert v2 - v1 == {"source_artifact_digest"}
    assert v1 - v2 == set()
    assert v1 == set(CLASSIFIED_FIELDS), "the v1 table is no longer the merged one"


def test_every_declared_version_has_both_a_field_list_and_an_allowlist():
    for version in ENVELOPE_VERSIONS:
        assert version in ENVELOPE_FIELDS_BY_VERSION
        assert version in CLASSIFIED_FIELDS_BY_VERSION
    assert set(ENVELOPE_FIELDS_BY_VERSION) == set(ENVELOPE_VERSIONS)
    assert set(CLASSIFIED_FIELDS_BY_VERSION) == set(ENVELOPE_VERSIONS)


@pytest.mark.parametrize(
    ("version", "path"),
    [
        (ATTRIBUTION_SCHEMA_VERSION, V1_ENVELOPE),
        (ATTRIBUTION_SCHEMA_VERSION_V2, V2_ENVELOPE),
    ],
)
def test_each_contract_agrees_with_the_library_that_projects_into_it(version, path):
    """Two spellings of one shape drift, and the published one is the stale one."""
    schema = _load(path)
    assert set(schema["properties"]) == set(ENVELOPE_FIELDS_BY_VERSION[version])
    assert set(schema["required"]) == set(ENVELOPE_FIELDS_BY_VERSION[version])
    assert schema["properties"]["schema_version"]["const"] == version


# ── The interlock ───────────────────────────────────────────────────────────


def test_a_v1_envelope_does_not_discharge_the_rotation_interlock():
    """v1 is readable evidence and cannot release what rotation waits on.

    Not because it is old, but because it names no `HostSource` artifact -- and
    that artifact decides which failures are reported as `missing`, which is
    the single code separating a clean host from an unreadable one.
    """
    envelope = project_envelope(observation(), clean_scans(), vault=RedactionVault())
    assert discharges_rotation_interlock(envelope) is False


def test_a_v2_envelope_with_both_bindings_does_discharge_it():
    """Positive control: a predicate that always refused would pass the above."""
    envelope = project_envelope(
        observation(source_artifact_digest=_SOURCE_DIGEST),
        clean_scans(),
        vault=RedactionVault(),
        version=ATTRIBUTION_SCHEMA_VERSION_V2,
    )
    assert discharges_rotation_interlock(envelope) is True


@pytest.mark.parametrize("missing", ["collector_artifact_digest", "source_artifact_digest"])
def test_a_v2_envelope_missing_either_binding_does_not_discharge_it(missing):
    """One digest identifies half of what ran, which is not an identification."""
    envelope = project_envelope(
        observation(source_artifact_digest=_SOURCE_DIGEST),
        clean_scans(),
        vault=RedactionVault(),
        version=ATTRIBUTION_SCHEMA_VERSION_V2,
    )
    del envelope[missing]
    assert discharges_rotation_interlock(envelope) is False


def test_the_interlock_predicate_reads_the_version_and_not_merely_the_fields():
    """A v1 envelope carrying a stray v2-shaped key still does not discharge.

    Checking only for the presence of two digests would let a hand-assembled
    document claim a binding under a version whose contract has no such field.
    """
    forged = dict(project_envelope(observation(), clean_scans(), vault=RedactionVault()))
    forged["source_artifact_digest"] = _SOURCE_DIGEST
    assert discharges_rotation_interlock(forged) is False
