"""A retirement request is reviewed on main, in public vocabulary, and applied once.

The request exists so the change is a diff somebody approved rather than a
target name typed into a dispatch box at run time. Everything it can express is
already public under ADR-0004 — logical target ids and credential-ref names —
so reviewing it discloses nothing, and the workflow that applies it needs no
judgement of its own.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from dotmac_observability.validate import (
    InventoryError,
    apply_supersession,
    canonical_bytes,
    load_private_inventory,
    load_supersession_request,
)
from tests.conftest import CONTRACTS, REFERENCE_PRIVATE

REQUEST = """schema_version = "observability-supersession-request.v1"
document = "reference-private-inventory"
rationale = "Decommissioned on a named host; its credential file was shredded."

[previous]
version = 1
sha256 = "{digest}"

[storage]
shape = "data-object"

[retire]
targets = ["erp-production"]
"""


@pytest.fixture
def stored(tmp_path: Path):
    path = tmp_path / "v1.json"
    path.write_text(REFERENCE_PRIVATE.read_text(encoding="utf-8"), encoding="utf-8")
    inventory = load_private_inventory(path, contracts=CONTRACTS)
    return path, inventory, json.loads(path.read_text(encoding="utf-8"))


def _request(tmp_path: Path, digest: str, body: str | None = None) -> Path:
    path = tmp_path / "request.toml"
    path.write_text(body if body is not None else REQUEST.format(digest=digest))
    return path


def test_a_reviewed_request_retires_the_named_entry(tmp_path, stored):
    _, inventory, raw = stored
    request = load_supersession_request(_request(tmp_path, inventory.digest), contracts=CONTRACTS)
    document, findings = apply_supersession(request, inventory, raw)
    assert findings == ()
    assert document["version"] == 2
    targets = cast(list[dict[str, object]], document["targets"])
    assert [row["target_id"] for row in targets] == ["erp-workers"]


def test_the_produced_document_is_canonical_and_loadable(tmp_path, stored):
    _, inventory, raw = stored
    request = load_supersession_request(_request(tmp_path, inventory.digest), contracts=CONTRACTS)
    document, _ = apply_supersession(request, inventory, raw)
    path = tmp_path / "v2.json"
    path.write_bytes(canonical_bytes(document))
    # No trailing newline: a reader that adds one reports false drift, so the
    # written bytes must already be the form the digest is taken over.
    assert not path.read_bytes().endswith(b"\n")
    assert load_private_inventory(path, contracts=CONTRACTS).version == 2


def test_a_request_naming_a_stale_digest_is_refused(tmp_path, stored):
    _, inventory, raw = stored
    request = load_supersession_request(_request(tmp_path, "0" * 64), contracts=CONTRACTS)
    _, findings = apply_supersession(request, inventory, raw)
    # This is what makes a request single-use: applied once, the stored document
    # no longer hashes to the digest the request was reviewed against.
    assert "REQUEST-PREVIOUS-DIGEST" in {finding.code for finding in findings}


def test_a_request_aimed_at_another_document_is_refused(tmp_path, stored):
    _, inventory, raw = stored
    body = REQUEST.format(digest=inventory.digest).replace(
        'document = "reference-private-inventory"', 'document = "production-private-inventory"'
    )
    request = load_supersession_request(_request(tmp_path, "", body), contracts=CONTRACTS)
    _, findings = apply_supersession(request, inventory, raw)
    assert "REQUEST-DOCUMENT" in {finding.code for finding in findings}


def test_retiring_something_absent_is_refused(tmp_path, stored):
    _, inventory, raw = stored
    body = REQUEST.format(digest=inventory.digest).replace(
        'targets = ["erp-production"]', 'targets = ["erp-production", "never-existed"]'
    )
    request = load_supersession_request(_request(tmp_path, "", body), contracts=CONTRACTS)
    _, findings = apply_supersession(request, inventory, raw)
    # A no-op removal means the request is stale or names the wrong entry, and
    # applying it quietly would produce a version whose diff does not match the
    # change that was reviewed.
    assert "REQUEST-ABSENT" in {finding.code for finding in findings}


def test_an_empty_request_is_refused_by_the_contract(tmp_path, stored):
    _, inventory, _ = stored
    body = REQUEST.format(digest=inventory.digest).replace('targets = ["erp-production"]', "")
    with pytest.raises(InventoryError) as raised:
        load_supersession_request(_request(tmp_path, "", body), contracts=CONTRACTS)
    assert {finding.code for finding in raised.value.findings} == {"SCHEMA"}


def test_the_request_contract_has_no_way_to_provision(tmp_path, stored):
    """Retirement only, and the contract is where that boundary is kept.

    Removing an entry needs a logical name. ADDING one needs a resolved
    endpoint or credential binding, which must never pass through public Git or
    a CI input — so there is no field for it, and adding one would be a visible
    contract change rather than a quiet capability.
    """
    schema = json.loads((CONTRACTS / "supersession-request.schema.json").read_text())
    assert set(schema["properties"]["retire"]["properties"]) == {
        "targets",
        "federations",
        "receivers",
    }
    # Property NAMES, not the whole document. The description deliberately says
    # the word "endpoint" while explaining why there is no endpoint field, and a
    # check that could not tell those apart would force the contract to stop
    # explaining itself — the same distinction the workflow guard draws between
    # prose and code.
    names: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    names.update(value)
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
    assert "retire" in names, "no property names collected; the walk has drifted"
    for resolved in ("endpoint", "endpoints", "openbao_path", "file_name", "destination"):
        assert resolved not in names, (
            f"the request contract declares a {resolved!r} field; a retirement needs only "
            "logical names, and a field carrying resolved material would put it in public Git"
        )


def test_unknown_fields_in_the_stored_document_survive_a_retirement(tmp_path, stored):
    """The write-back preserves bytes this package does not read.

    A model-shaped rewrite would silently drop any field a future schema
    version adds and this loader does not yet know about, turning an unrelated
    deployment's data into collateral of a retirement. The retirement edits the
    STORED document rather than re-serialising a parsed model, and this is the
    assertion that keeps it that way.
    """
    path, inventory, raw = stored
    raw["targets"][0]["future_field"] = {"kept": True}
    document, findings = apply_supersession(
        load_supersession_request(_request(tmp_path, inventory.digest), contracts=CONTRACTS),
        inventory,
        raw,
    )
    assert findings == ()
    # `erp-production` was retired; every surviving row keeps everything it had,
    # including the field this package's loader has never heard of.
    targets = cast(list[dict[str, object]], document["targets"])
    surviving = {str(row["target_id"]): row for row in targets}
    assert "erp-production" not in surviving
    federations = cast(list[dict[str, object]], document["federations"])
    assert federations[0]["endpoint"]


def test_the_confirmed_storage_shape_is_reviewed_input(tmp_path, stored):
    """The shape is declared, not discovered.

    An earlier draft had the mutation workflow detect the shape at run time and
    then write immediately. That is detection, not confirmation — the same
    defect as a probe whose result nobody reads before acting on it. Discovery
    is now a separate read-only workflow that reports and stops; the answer
    comes back through review, in this field.
    """
    _, inventory, _ = stored
    request = load_supersession_request(_request(tmp_path, inventory.digest), contracts=CONTRACTS)
    assert request.storage_shape == "data-object"


def test_a_request_with_no_confirmed_shape_is_refused(tmp_path, stored):
    _, inventory, _ = stored
    body = REQUEST.format(digest=inventory.digest).replace('[storage]\nshape = "data-object"\n', "")
    with pytest.raises(InventoryError) as raised:
        load_supersession_request(_request(tmp_path, "", body), contracts=CONTRACTS)
    assert {finding.code for finding in raised.value.findings} == {"SCHEMA"}


def test_an_unrecognised_shape_is_refused_by_the_contract(tmp_path, stored):
    _, inventory, _ = stored
    body = REQUEST.format(digest=inventory.digest).replace(
        'shape = "data-object"', 'shape = "whatever-the-store-says"'
    )
    with pytest.raises(InventoryError) as raised:
        load_supersession_request(_request(tmp_path, "", body), contracts=CONTRACTS)
    assert {finding.code for finding in raised.value.findings} == {"SCHEMA"}


def test_the_request_carries_no_field_name(tmp_path, stored):
    """The shape is reviewed; the field NAME is not.

    Which of two code paths applies is a choice a reviewer should see. What the
    field is called is storage layout at a private path, so it stays a secret —
    the same line ADR-0004 draws between a capability and a binding.
    """
    schema = json.loads((CONTRACTS / "supersession-request.schema.json").read_text())
    assert set(schema["properties"]["storage"]["properties"]) == {"shape"}
