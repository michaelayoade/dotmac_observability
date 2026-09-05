"""`attribution-project` publishes an envelope, or it publishes nothing at all.

The command is the last place private material could escape, and it is the
place most likely to be run by hand with the output pasted into a ticket. So
the properties asserted here are about what reaches stdout: the envelope and
only the envelope on success, and NOTHING on refusal -- a half-written document
on stdout is the artifact that gets forwarded.

Coverage verdicts are re-derived from the observation's recorded evidence, not
read off the document. That is what stops a hand-edited observation claiming
`ABSENT` for a family it recorded as denied.
"""

from __future__ import annotations

import json

import pytest

from dotmac_observability.attribution import (
    ATTRIBUTION_SCHEMA_VERSION,
    ATTRIBUTION_SCHEMA_VERSION_V2,
    DECLARED_FAMILIES,
    ENVELOPE_FIELDS,
    ENVELOPE_FIELDS_V2,
    RedactionVault,
    discharges_rotation_interlock,
)
from dotmac_observability.attribution_enumerators import build_observation, enumerate_all
from dotmac_observability.cli import main
from tests.attribution_fixtures import DIGEST_C, DIGEST_D
from tests.attribution_hosts import populated_host
from tests.conftest import CONTRACTS

_REFERENCES = [
    "--authorization-digest",
    DIGEST_C,
    "--challenge-digest",
    DIGEST_D,
    "--authority-ref",
    "control:decision/7f2c",
]


def _observation(tmp_path, **overrides: object):
    document = build_observation(
        enumerate_all(populated_host(present=()), vault=RedactionVault()),
        target_id="erp-production",
        observed_at="2026-09-05T09:00:00Z",
        host_identity_digest="sha256:" + "ab" * 32,
        collector_artifact_digest="sha256:" + "cd" * 32,
        source_artifact_digest="sha256:" + "ef" * 32,
    )
    document.update(overrides)
    path = tmp_path / "observation.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path, document


def _v1_observation(tmp_path):
    """A v1 document, built by hand because `build_observation` only writes v2.

    Hand-built deliberately: the point is to exercise a document produced by an
    older collector, and generating it from today's builder would prove only
    that today's builder can be downgraded.
    """
    _, document = _observation(tmp_path)
    legacy = {
        "schema_version": "observability-consumer-attribution-observation.v1",
        "target_id": document["target_id"],
        "observed_at": document["observed_at"],
        "host_identity_digest": document["host_identity_digest"],
        "consumers": document["consumers"],
        # v1's `errors` enum has neither `missing` nor `unknown`, so a v1
        # document cannot carry them. Emptied rather than translated: inventing
        # a v1 spelling for a v2 code is exactly the flattening v2 exists to
        # undo.
        "families": [{**entry, "errors": []} for entry in document["families"]],
    }
    path = tmp_path / "observation-v1.json"
    path.write_text(json.dumps(legacy, indent=2), encoding="utf-8")
    return path


def _run(path, capsys, *extra: str):
    code = main(
        [
            "--contracts",
            str(CONTRACTS),
            "attribution-project",
            "--observation",
            str(path),
            *_REFERENCES,
            *extra,
        ]
    )
    return code, capsys.readouterr()


def test_a_valid_observation_projects_to_a_publishable_envelope(tmp_path, capsys):
    path, _ = _observation(tmp_path)
    code, captured = _run(path, capsys)
    assert code == 0
    envelope = json.loads(captured.out)
    assert set(envelope) == set(ENVELOPE_FIELDS_V2)
    assert envelope["schema_version"] == ATTRIBUTION_SCHEMA_VERSION_V2
    assert envelope["target_id"] == "erp-production"
    assert len(envelope["coverage"]) == len(DECLARED_FAMILIES)


def test_the_envelope_on_stdout_carries_no_resolved_material(tmp_path, capsys):
    """The end-to-end containment assertion, over the real command's real output.

    Every unit-level guard could hold and this still fail, because this is the
    only place the two halves meet: a private document full of hosts, users and
    databases goes in, and a public document comes out on a stream.
    """
    path, document = _observation(tmp_path)
    code, captured = _run(path, capsys)
    assert code == 0
    private = {
        value
        for consumer in document["consumers"]
        for value in consumer.values()
        if isinstance(value, str) and value not in ("ATTRIBUTED", "UNATTRIBUTED")
    }
    assert private, "the observation carried no private values; this check would be vacuous"
    for value in private:
        if value in DECLARED_FAMILIES:
            continue
        assert value not in captured.out, f"{value!r} reached stdout"


def test_verdicts_are_re_derived_rather_than_trusted(tmp_path, capsys):
    """A hand-edited observation cannot talk its way into ABSENT.

    The document records evidence -- attempted, completed, errors, found -- and
    carries no verdict field at all. This asserts the consequence: a family
    recorded as denied projects to UNKNOWN no matter what a reader of the
    document might have assumed.
    """
    path, document = _observation(tmp_path)
    for entry in document["families"]:
        if entry["family"] == "compose":
            entry["errors"] = ["denied"]
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    code, captured = _run(path, capsys)
    assert code == 0
    envelope = json.loads(captured.out)
    entry = next(e for e in envelope["coverage"] if e["family"] == "compose")
    assert entry["verdict"] == "UNKNOWN"
    assert entry["error_count"] == 1


def test_an_observation_that_does_not_match_its_contract_is_refused(tmp_path, capsys):
    path, document = _observation(tmp_path)
    document["families"] = document["families"][:3]
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    code, captured = _run(path, capsys)
    assert code == 1
    assert captured.out == "", "a refused projection still wrote to stdout"


def test_an_unreadable_observation_reports_a_type_name_and_not_a_path_contents(tmp_path, capsys):
    missing = tmp_path / "absent.json"
    code, captured = _run(missing, capsys)
    assert code == 1
    assert captured.out == ""
    assert "FileNotFoundError" in captured.err


def test_a_missing_reference_is_refused_because_each_names_a_different_authority(tmp_path, capsys):
    """Permission and challenge are issued by two different owners.

    Neither can stand in for the other, so `argparse` requires all three rather
    than defaulting any of them -- a default here would be this repository
    inventing an authorization value, which is precisely rule 20's line.
    """
    path, _ = _observation(tmp_path)
    with pytest.raises(SystemExit):
        main(
            [
                "--contracts",
                str(CONTRACTS),
                "attribution-project",
                "--observation",
                str(path),
                "--authorization-digest",
                DIGEST_C,
            ]
        )


def test_both_artifact_digests_are_read_from_the_document_never_recomputed(tmp_path, capsys):
    """The artifacts that ran are not this checkout, and must not be assumed to be.

    A collector released last month produced the observation; the `HostSource`
    implementation is built in another repository entirely. Recomputing either
    here would answer "what is installed now" while claiming to answer "what
    produced this" -- a binding that can never disagree with itself, and
    therefore proves nothing. It would also be silently WRONG the first time an
    operator ran a published collector against a newer checkout.

    The previous version of this test asserted the local recomputation, and it
    passed for exactly that reason.
    """
    path, document = _observation(tmp_path)
    code, captured = _run(path, capsys)
    assert code == 0
    envelope = json.loads(captured.out)
    assert envelope["collector_artifact_digest"] == document["collector_artifact_digest"]
    assert envelope["source_artifact_digest"] == document["source_artifact_digest"]
    assert envelope["collector_artifact_digest"] != envelope["source_artifact_digest"], (
        "the two artifacts are reported as one; reaching for the near-miss binding is how "
        "a pair that could never be equal for any input ships reading as correct"
    )


def test_a_v2_envelope_discharges_the_interlock_and_a_v1_one_does_not(tmp_path, capsys):
    """Both halves in one test, so neither can be satisfied by a constant."""
    path, _ = _observation(tmp_path)
    code, captured = _run(path, capsys)
    assert code == 0
    assert discharges_rotation_interlock(json.loads(captured.out)) is True

    legacy = _v1_observation(tmp_path)
    code, captured = _run(legacy, capsys)
    assert code == 0
    envelope = json.loads(captured.out)
    assert envelope["schema_version"] == ATTRIBUTION_SCHEMA_VERSION
    assert set(envelope) == set(ENVELOPE_FIELDS)
    assert discharges_rotation_interlock(envelope) is False


def test_a_v1_observation_is_still_readable_rather_than_refused(tmp_path, capsys):
    """v1 is historical evidence. Refusing it would destroy the record.

    It is not deprecated and not deleted -- it simply cannot discharge what
    rotation waits on, because it has no field in which the `HostSource`
    implementation could be named.
    """
    legacy = _v1_observation(tmp_path)
    code, captured = _run(legacy, capsys)
    assert code == 0
    envelope = json.loads(captured.out)
    assert "source_artifact_digest" not in envelope
    assert len(envelope["coverage"]) == len(DECLARED_FAMILIES)


def test_an_unknown_observation_version_is_refused_rather_than_guessed(tmp_path, capsys):
    path, document = _observation(tmp_path)
    document["schema_version"] = "observability-consumer-attribution-observation.v9"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    code, captured = _run(path, capsys)
    assert code == 1
    assert captured.out == ""
    assert "v9" in captured.err


def test_a_short_private_value_can_abort_a_correct_run(tmp_path, capsys):
    """A real characteristic of the merged containment design, pinned deliberately.

    `assert_clean` matches SUBSTRINGS with no minimum length, because a minimum
    length is a silent allowlist and a two-character password is still a
    password. The cost is that a very short private value collides with
    unrelated public text -- a database user `cont` is a substring of an
    `authority_ref` reading `control:decision/...`, and the projection refuses.

    This is pinned rather than engineered away for three reasons. It fails
    CLOSED: refusal, exit 2, nothing on stdout, which is the safe direction.
    Weakening it would mean either a length floor (the allowlist the merged
    design rejected) or unpoisoning values that collide (removing protection
    from exactly the shortest secrets). And an operator who meets it needs to
    recognise a collision rather than conclude there was a leak -- which they
    cannot do if no test says it happens.
    """
    path, document = _observation(tmp_path)
    document["consumers"][0]["db_user"] = "cont"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    code, captured = _run(path, capsys)
    assert code == 2, "the collision no longer refuses; containment has been weakened"
    assert captured.out == "", "a refused projection wrote to stdout"
    assert "cont" not in captured.err, "the refusal named the value it found"


def test_a_planted_launch_path_in_a_copied_field_is_refused(tmp_path, capsys):
    """The guard is live, not merely present.

    `target_id` is copied from the private document straight into the public
    envelope, so it is the field a leak would actually travel through. A
    launch path planted there must abort.
    """
    path, document = _observation(tmp_path)
    document["target_id"] = "erp-production"
    document["consumers"][0]["launch_path"] = "erp-production"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    code, captured = _run(path, capsys)
    assert code == 2
    assert captured.out == ""


def test_a_clean_observation_is_not_refused(tmp_path, capsys):
    """The other half of sensitivity: the guard stays quiet on correct input.

    Without this the two refusals above would be satisfied by a command that
    refused everything, which leaks nothing and is useless.
    """
    path, _ = _observation(tmp_path)
    code, captured = _run(path, capsys)
    assert code == 0
    assert json.loads(captured.out)["target_id"] == "erp-production"
