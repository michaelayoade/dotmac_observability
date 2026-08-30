"""Reading the pre-contract capture format, and migrating out of it.

The production private inventory is stored in the shape the 2026-08-29 census
produced, three PRs before the contract existed. Both mutation tools load the
previous version through the ACCEPTED contract first, so the supersession
workflow fails at its FIRST tool step — after passing its own precondition
guard — with 68 schema errors on a document that is not corrupt at all.

Every test below is about making that legible and then fixing it without a
human editing OpenBao by hand.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from dotmac_observability.cli import main
from dotmac_observability.validate import (
    ACCEPTED_SCHEMA_VERSION,
    CAPTURE_SCHEMA_VERSION,
    InventoryError,
    canonical_bytes,
    canonical_digest,
    classify_stored_inventory,
    load,
    load_capture_inventory,
    load_private_inventory,
    load_supersession_request,
    migrate_capture,
    migration_findings,
)
from tests.conftest import CONTRACTS, REFERENCE

CAPTURE = {
    "schema_version": CAPTURE_SCHEMA_VERSION,
    "version": 1,
    "environment": "reference",
    "captured_at": "2026-08-29T00:00:00Z",
    "captured_from": "a synthetic census",
    "note": "fixture",
    "targets": [
        {
            "target_id": "erp-production",
            "resolved_endpoints": ["erp.invalid:443"],
            "credential": {
                "openbao_path": "secret/fixture/erp-scrape",
                "file_name": "erp-scrape.token",
            },
            "scheme": "https",
            "metrics_path": "/metrics",
            "params": {"format": ["prometheus"]},
            "static_labels": {"instance": "erp"},
        },
        {
            "target_id": "erp-workers",
            "resolved_endpoints": ["erp-worker-1.invalid:443", "erp-worker-2.invalid:443"],
        },
        # Federations are FOLDED INTO `targets` by the capture format. Splitting
        # them back out is the single largest structural difference.
        {
            "target_id": "sub-federation",
            "resolved_endpoints": ["sub.invalid:443"],
            "credential": {
                "openbao_path": "secret/fixture/sub-federation",
                "file_name": "sub-federation.token",
            },
        },
    ],
    "receiver_bindings": [
        {
            "receiver": "telegram-oncall",
            "kind": "telegram",
            "destination": "-1000000000001",
            "credential_file": {
                "openbao_path": "secret/fixture/telegram-oncall",
                "file_name": "telegram-oncall.token",
            },
        },
        {
            "receiver": "platform-smtp",
            "kind": "email",
            "destination": "platform@dotmac.invalid",
            "credential_file": {
                "openbao_path": "secret/fixture/smtp",
                "file_name": "smtp.password",
            },
        },
    ],
}

HOST_BINDING = {
    "target_id": "reference-evaluator",
    "identity": "reference-evaluator",
    "ssh_alias": "reference",
}

REQUEST = """schema_version = "observability-supersession-request.v1"
kind = "migrate-capture"
document = "reference-private-inventory"
rationale = "The stored version predates the accepted contract; this brings it to the contract."

[previous]
version = 1
sha256 = "{digest}"
format = "observability-private-inventory.v1 (PROPOSED)"

[storage]
shape = "data-object"

[migrate]
document = "reference-private-inventory"
host_target_id = "reference-evaluator"
federations = ["sub-federation"]
"""


def _write(path: Path, document: dict[str, object]) -> Path:
    path.write_bytes(canonical_bytes(document))
    return path


def _request(tmp_path: Path, digest: str, body: str | None = None) -> Path:
    path = tmp_path / "request.toml"
    path.write_text(body if body is not None else REQUEST.format(digest=digest))
    return path


@pytest.fixture
def capture_file(tmp_path: Path) -> Path:
    return _write(tmp_path / "stored.json", dict(CAPTURE))


# ── classification: the step the workflow did not have ──────────────────────


def test_the_capture_format_is_recognised_as_itself_rather_than_as_corruption():
    assert classify_stored_inventory(CAPTURE) == CAPTURE_SCHEMA_VERSION


def test_a_third_shape_is_unrecognised_rather_than_sorted_into_the_nearest_known_one():
    """Being wrong about which format holds a production estate is the risk.

    The two known formats are migrated by different code, so a document that
    has drifted into a third shape must present as unrecognised rather than be
    guessed at from its key set.
    """
    drifted = dict(CAPTURE, schema_version="observability-private-inventory.v2")
    assert classify_stored_inventory(drifted) == "unrecognised"


def test_classify_prints_the_format_and_no_other_fact(capture_file: Path, capsys):
    code = main(["inventory-classify", str(capture_file)])
    captured = capsys.readouterr()
    assert code == 2, "the capture format has its own exit code, so a workflow can branch"
    assert captured.out.strip() == f"format {CAPTURE_SCHEMA_VERSION}"
    # No key name, no length, no value: a classifier that described the
    # document would be the leak the whole workflow exists to avoid.
    for leak in ("erp.invalid", "secret/fixture", "telegram", "-1000000000001", "erp-scrape"):
        assert leak not in captured.out + captured.err


def test_an_accepted_contract_document_classifies_clean(tmp_path: Path, capsys):
    stored = tmp_path / "v1.json"
    stored.write_text((REFERENCE / "private" / "inventory.json").read_text())
    assert main(["inventory-classify", str(stored)]) == 0
    assert capsys.readouterr().out.strip() == f"format {ACCEPTED_SCHEMA_VERSION}"


# ── the migration itself ────────────────────────────────────────────────────


def _migrated(tmp_path: Path, capture_file: Path):
    capture = load_capture_inventory(capture_file, contracts=CONTRACTS)
    request = load_supersession_request(_request(tmp_path, capture.digest), contracts=CONTRACTS)
    state = load(REFERENCE, contracts=CONTRACTS)
    return capture, migrate_capture(
        capture, request, HOST_BINDING, [f.target_id for f in state.federations]
    )


def test_a_migration_produces_a_document_the_accepted_contract_loads(
    tmp_path: Path, capture_file: Path
):
    capture, (produced, findings) = _migrated(tmp_path, capture_file)
    assert findings == ()
    output = _write(tmp_path / "v2.json", produced)
    after = load_private_inventory(output, contracts=CONTRACTS)
    assert after.version == capture.version + 1
    assert after.document == "reference-private-inventory"
    assert after.host.ssh_alias == "reference"
    # The federation was folded into `targets` by the capture and is split back
    # out here — by DECLARATION cross-checked against public inventory, never by
    # pattern-matching a name.
    assert [binding.target_id for binding in after.federations] == ["sub-federation"]
    assert sorted(binding.target_id for binding in after.targets) == [
        "erp-production",
        "erp-workers",
    ]
    assert migration_findings(capture, after, expect_previous_digest=capture.digest) == ()


def test_the_migration_carries_no_value_the_capture_did_not_hold(
    tmp_path: Path, capture_file: Path
):
    """Provisioning without disclosure, asserted rather than asserted-by-comment."""
    _, (produced, findings) = _migrated(tmp_path, capture_file)
    assert findings == ()
    captured: list[dict[str, object]] = CAPTURE["targets"]  # type: ignore[assignment]
    stored_endpoints = {
        endpoint for row in captured for endpoint in cast(list[str], row["resolved_endpoints"])
    }
    produced_endpoints = {
        endpoint for row in produced["targets"] for endpoint in row["endpoints"]
    } | {row["endpoint"] for row in produced["federations"]}
    assert produced_endpoints <= stored_endpoints


def test_the_two_public_fields_move_out_of_the_private_document(tmp_path: Path, capture_file: Path):
    """`params` and `static_labels` are scrape protocol and logical labelling.

    Both are public under the same reasoning that settled `metrics_path`, and
    both now have a home in `observability-target.v2`. The migration therefore
    drops them from the private half rather than carrying them across.
    """
    _, (produced, findings) = _migrated(tmp_path, capture_file)
    assert findings == ()
    for row in produced["targets"]:
        assert "params" not in row
        assert "static_labels" not in row


# ── the compare-and-set problem the migration creates ───────────────────────


def test_a_request_naming_the_pre_migration_digest_is_refused_after_the_migration(
    tmp_path: Path, capture_file: Path
):
    """The consequence that looks correct beforehand and fails afterwards.

    The migration rewrites the document, which changes its digest, and the
    digest is the compare-and-set precondition. A request written against the
    pre-migration digest is therefore refused once the migration has run —
    correctly, but only after looking as though the work had been done.

    The refusal is the behaviour under test, and so is the message: it names
    `inventory-classify` as the way to tell "already migrated" from "somebody
    else moved the store", which are the same digest mismatch and different
    problems.
    """
    capture, (produced, findings) = _migrated(tmp_path, capture_file)
    assert findings == ()
    stale = load_supersession_request(_request(tmp_path, capture.digest), contracts=CONTRACTS)

    # Re-running against the MIGRATED store: it is no longer a capture at all.
    migrated = _write(tmp_path / "v2.json", produced)
    with pytest.raises(InventoryError) as error:
        load_capture_inventory(migrated, contracts=CONTRACTS)
    assert any(finding.code == "SCHEMA" for finding in error.value.findings)

    # And against a capture the store has since moved on from: the digest half.
    moved = _write(tmp_path / "moved.json", dict(CAPTURE, note="somebody else wrote"))
    _, refusal = migrate_capture(
        load_capture_inventory(moved, contracts=CONTRACTS),
        stale,
        HOST_BINDING,
        ["sub-federation"],
    )
    codes = {finding.code for finding in refusal}
    assert "REQUEST-PREVIOUS-DIGEST" in codes
    assert any("inventory-classify" in finding.message for finding in refusal)


def test_the_digest_a_request_must_name_is_the_one_the_tool_prints(capture_file: Path):
    assert (
        canonical_digest(CAPTURE)
        == load_capture_inventory(capture_file, contracts=CONTRACTS).digest
    )


# ── the refusals that stop a guess reaching the store ───────────────────────


def test_a_credential_the_migration_cannot_map_is_refused_rather_than_guessed(tmp_path: Path):
    broken = json.loads(json.dumps(CAPTURE))
    broken["targets"][0]["credential"] = "erp-scrape.token"
    stored = _write(tmp_path / "stored.json", broken)
    capture = load_capture_inventory(stored, contracts=CONTRACTS)
    _, findings = migrate_capture(
        capture,
        load_supersession_request(_request(tmp_path, capture.digest), contracts=CONTRACTS),
        HOST_BINDING,
        ["sub-federation"],
    )
    assert "MIGRATE-CREDENTIAL-SHAPE" in {finding.code for finding in findings}


def test_a_tls_config_is_refused_rather_than_dropped(tmp_path: Path):
    """Dropping it silently would change how a live target is verified."""
    broken = json.loads(json.dumps(CAPTURE))
    broken["targets"][0]["tls_config"] = {"server_name": "erp.invalid"}
    stored = _write(tmp_path / "stored.json", broken)
    capture = load_capture_inventory(stored, contracts=CONTRACTS)
    _, findings = migrate_capture(
        capture,
        load_supersession_request(_request(tmp_path, capture.digest), contracts=CONTRACTS),
        HOST_BINDING,
        ["sub-federation"],
    )
    assert "MIGRATE-TLS-CONFIG" in {finding.code for finding in findings}


def test_a_federation_split_the_public_inventory_disagrees_with_is_refused(
    tmp_path: Path, capture_file: Path
):
    capture = load_capture_inventory(capture_file, contracts=CONTRACTS)
    request = load_supersession_request(_request(tmp_path, capture.digest), contracts=CONTRACTS)
    _, findings = migrate_capture(capture, request, HOST_BINDING, ["something-else"])
    assert "MIGRATE-FEDERATION-SPLIT" in {finding.code for finding in findings}


def test_an_incomplete_host_binding_is_refused(tmp_path: Path, capture_file: Path):
    capture = load_capture_inventory(capture_file, contracts=CONTRACTS)
    request = load_supersession_request(_request(tmp_path, capture.digest), contracts=CONTRACTS)
    _, findings = migrate_capture(
        capture, request, {"target_id": "reference-evaluator", "identity": ""}, ["sub-federation"]
    )
    assert "MIGRATE-HOST-INCOMPLETE" in {finding.code for finding in findings}


def test_a_retirement_request_cannot_be_applied_as_a_migration(tmp_path: Path, capture_file: Path):
    body = REQUEST.format(digest="0" * 64).replace('kind = "migrate-capture"', 'kind = "retire"')
    body = body.replace(
        '[migrate]\ndocument = "reference-private-inventory"\n'
        'host_target_id = "reference-evaluator"\nfederations = ["sub-federation"]\n',
        '[retire]\ntargets = ["erp-workers"]\n',
    )
    body = body.replace(
        'format = "observability-private-inventory.v1 (PROPOSED)"',
        'format = "observability-private-inventory.v1"',
    )
    request = load_supersession_request(_request(tmp_path, "", body), contracts=CONTRACTS)
    assert request.kind == "retire"
    assert request.migrate is None


def test_a_migration_request_cannot_be_applied_as_a_retirement(tmp_path: Path, capture_file: Path):
    from dotmac_observability.validate import apply_supersession

    capture = load_capture_inventory(capture_file, contracts=CONTRACTS)
    request = load_supersession_request(_request(tmp_path, capture.digest), contracts=CONTRACTS)
    stored = json.loads((REFERENCE / "private" / "inventory.json").read_text())
    previous = load_private_inventory(REFERENCE / "private" / "inventory.json", contracts=CONTRACTS)
    _, findings = apply_supersession(request, previous, stored)
    assert "REQUEST-KIND" in {finding.code for finding in findings}
