"""AGENTS.md rules 18 and 20, asserted against the attribution contracts.

The structural half of rule 18 is the half that cannot be forgotten in a hurry:
if the public envelope has no `db_host` property and closes every object, then
there is no field a resolved endpoint can be typed into and no unread extra key
it can arrive through. A redactor has to be right every time; an absent field
has to be added on purpose, in a diff, by somebody.

Rule 20 is asserted here too, in the one direction this contract is exposed to.
The upstream documents -- `ConsumerAttributionAuthorizationV1` (owned by
`dotmac-deployment-control`) and `AttributionChallengeV1` (owned by the
observation authority) -- must be REFERENCED and never DESCRIBED. A local
`$defs` for either, even a convenience stub, is a second definition that drifts
from the first, and then two systems disagree about what was permitted.
"""

from __future__ import annotations

import json

import pytest

from dotmac_observability.attribution import (
    ATTRIBUTION_SCHEMA_VERSION,
    DECLARED_FAMILIES,
    ENVELOPE_FIELDS,
)
from tests.conftest import CONTRACTS

ENVELOPE = CONTRACTS / "postgres-consumer-attribution-envelope.schema.json"
OBSERVATION = CONTRACTS / "postgres-consumer-attribution-observation.schema.json"

# Names for resolved material. None of these may exist as a property ANYWHERE in
# the public envelope -- not optional, not nullable, not deprecated.
_FORBIDDEN_IN_PUBLIC = frozenset(
    {
        "db_host",
        "db_port",
        "db_user",
        "db_name",
        "dsn",
        "url",
        "endpoint",
        "endpoints",
        "address",
        "host",
        "port",
        "password",
        "launch_path",
        "secret_pointer",
        "secret_pointers",
        "env_var_names",
        "environment_file",
        "container_id",
        "unit_path",
        "owner_unit",
        "owner_principal",
        "error_message",
        "last_error",
    }
)


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _property_names(schema) -> set[str]:
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

    walk(schema)
    return names


def test_both_contracts_exist_and_are_read():
    # Without this the scans below pass over a file that is not there.
    assert ENVELOPE.is_file()
    assert OBSERVATION.is_file()


def test_the_public_envelope_has_no_field_private_material_could_fill():
    found = sorted(_property_names(_load(ENVELOPE)) & _FORBIDDEN_IN_PUBLIC)
    assert not found, (
        f"the public envelope declares {found}. Public Git carries the LOGICAL description; "
        "the resolved material belongs in the private observation, whose DIGEST this "
        "envelope carries and whose values it never does (AGENTS.md rule 18, ADR-0004)"
    )


def test_the_detector_would_notice_a_private_field_being_added():
    """Sensitivity proof. A scan over a clean contract proves nothing on its own.

    `db_host` is planted into the exact block a future collector would add it
    to, and the same walk that reports nothing above must report it here.
    """
    planted = _load(ENVELOPE)
    assert "db_host" not in planted["properties"], "the real contract regressed"
    planted["properties"]["db_host"] = {"type": "string"}
    assert "db_host" in _property_names(planted) & _FORBIDDEN_IN_PUBLIC


def test_a_nested_private_field_is_caught_as_well_as_a_top_level_one():
    """The near-miss the obvious implementation misses.

    Checking only `schema["properties"]` passes a `db_host` added inside a
    `$defs` entry, which is where it would actually land -- nobody adds a host
    to the top level of an envelope; they add it to the per-family result.
    """
    planted = _load(ENVELOPE)
    planted["$defs"]["family_result"]["properties"]["launch_path"] = {"type": "string"}
    assert "launch_path" in _property_names(planted) & _FORBIDDEN_IN_PUBLIC


@pytest.mark.parametrize("path", [ENVELOPE, OBSERVATION], ids=lambda p: p.name)
def test_every_object_is_closed(path):
    """A typo that validates is how a control plane silently loses a setting.

    Asserted here as well as in `test_repository_contract.py` because for THESE
    two documents an open object is not a lost setting: it is a place a
    collector's `db_host` arrives as an unread extra key and is published.
    """
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


def test_the_envelope_agrees_with_the_library_that_projects_into_it():
    """Two spellings of one field list drift, and the published one is the stale one."""
    schema = _load(ENVELOPE)
    assert set(schema["properties"]) == set(ENVELOPE_FIELDS)
    assert set(schema["required"]) == set(ENVELOPE_FIELDS)
    assert schema["properties"]["schema_version"]["const"] == ATTRIBUTION_SCHEMA_VERSION


@pytest.mark.parametrize("path", [ENVELOPE, OBSERVATION], ids=lambda p: p.name)
def test_the_family_vocabulary_is_one_list_in_three_places(path):
    schema = _load(path)

    def walk(node) -> list[list[str]]:
        found: list[list[str]] = []
        if isinstance(node, dict):
            if isinstance(node.get("enum"), list) and "cron" in node["enum"]:
                found.append(node["enum"])
            for value in node.values():
                found.extend(walk(value))
        elif isinstance(node, list):
            for value in node:
                found.extend(walk(value))
        return found

    enums = walk(schema)
    assert enums, f"{path.name} declares no family vocabulary"
    for enum in enums:
        assert enum == list(DECLARED_FAMILIES), (
            "the contract's family list has drifted from `DECLARED_FAMILIES`; a family "
            "declared in one place and not the other is scanned and never reported, or "
            "reported and never scanned"
        )


def test_the_envelope_requires_a_result_for_every_declared_family():
    """Not `minItems: 1`. Exactly one per family, all of them, every time.

    A family omitted because it was never attempted reads to every consumer as
    a family with nothing in it, and the whole point of this contract is that
    "we did not look" is never spelled the same way as "there is nothing there".
    """
    coverage = _load(ENVELOPE)["properties"]["coverage"]
    assert coverage["minItems"] == len(DECLARED_FAMILIES)
    assert coverage["maxItems"] == len(DECLARED_FAMILIES)
    assert coverage["uniqueItems"] is True


def test_absent_is_not_a_verdict_the_schema_lets_a_producer_choose_freely():
    """The schema admits three verdicts; the LIBRARY decides which one applies.

    A schema cannot express "derived", so it must not be read as permission to
    assign. This asserts the enum is exactly the derived vocabulary -- no
    fourth, more reassuring value such as `CLEAN` or `NOT_FOUND` -- and the
    unit battery holds the derivation to one path.
    """
    verdict = _load(ENVELOPE)["$defs"]["family_result"]["properties"]["verdict"]
    assert set(verdict["enum"]) == {"SCANNED", "ABSENT", "UNKNOWN"}


def test_custody_admits_no_third_reading():
    custody = _load(OBSERVATION)["$defs"]["consumer"]["properties"]["custody"]
    assert set(custody["enum"]) == {"ATTRIBUTED", "UNATTRIBUTED"}


# ── Rule 20: referenced, never defined ──────────────────────────────────────


@pytest.mark.parametrize("path", [ENVELOPE, OBSERVATION], ids=lambda p: p.name)
def test_neither_upstream_document_is_defined_here(path):
    """Not even a stub `$defs`. A local shape becomes a second definition.

    `dotmac-deployment-control` owns `ConsumerAttributionAuthorizationV1`; the
    observation authority owns `AttributionChallengeV1`. This repository records
    a digest of each and owns neither, exactly as promotion records a
    `plan_digest` it never re-derives.
    """
    schema = _load(path)
    defined = {name.lower() for name in schema.get("$defs", {})}
    forbidden = {"authorization", "approval", "signature", "attestation", "challenge", "request"}
    overlap = defined & forbidden
    assert not overlap, (
        f"{path.name} defines {sorted(overlap)}. Permission and challenge are issued by two "
        "DIFFERENT authorities and neither is owned here (AGENTS.md rule 20)"
    )


def test_the_two_references_are_separate_fields_naming_separate_authorities():
    """One field for both would let the permission issuer define the proof.

    That is the whole reason for the split: a single request object makes
    "you may look at this host" and "here is a nonce, sign the answer" the same
    document, and then whoever granted access also decides what counts as
    evidence of what happened.
    """
    properties = _load(ENVELOPE)["properties"]
    assert "authorization_digest" in properties
    assert "challenge_digest" in properties
    assert properties["authorization_digest"] != properties["challenge_digest"], (
        "the two references are described identically; a reader cannot tell which "
        "authority issued which, which is the confusion the split exists to prevent"
    )
    for name in ("authorization_digest", "challenge_digest"):
        assert "dotmac-deployment-control" in properties[name]["description"] or (
            "observation authority" in properties[name]["description"]
        ), f"{name} does not say who issues it"


def test_no_approver_name_appears_in_either_contract():
    """A name typed into a tracked file is verified by nothing and notifies nobody."""
    self_attested = {"approved_by", "approver", "authorized_by", "signed_by", "reviewed_by"}
    for path in (ENVELOPE, OBSERVATION):
        assert not (_property_names(_load(path)) & self_attested), path.name
