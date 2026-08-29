"""ADR-0004's resolution layer: the join, and every way it can be wrong.

The split is only worth having if the two halves are checked against each
other. A public document that names a target nothing resolves, a private
binding nothing reaches, or a capability the binding contradicts would each
render perfectly and deploy something nobody described — and each is invisible
from either half alone, which is precisely why the gates live here.

Every test below mutates a copy and asserts one code. The clean-inventory
assertion at the top is meaningless without them: a resolver that returned
``()`` unconditionally would pass it.
"""

from __future__ import annotations

import json

import pytest

from dotmac_observability.validate import (
    InventoryError,
    canonical_bytes,
    canonical_digest,
    load,
    load_private_inventory,
    resolution_findings,
)
from tests.conftest import CONTRACTS, REFERENCE, edit, private_path, resolved


def _codes(root) -> set[str]:
    inventory = load_private_inventory(private_path(root), contracts=CONTRACTS)
    return {
        finding.code for finding in resolution_findings(load(root, contracts=CONTRACTS), inventory)
    }


# ── The canonical form ──────────────────────────────────────────────────────


def test_the_canonical_form_is_the_one_the_contract_states():
    document = {"b": 2, "a": {"d": 4, "c": 3}}
    rendered = canonical_bytes(document).decode("utf-8")
    assert rendered == '{\n  "a": {\n    "c": 3,\n    "d": 4\n  },\n  "b": 2\n}'
    # No trailing newline. Stated because the failure it prevents is the least
    # debuggable one a promotion can produce: a reader that appends "\n" before
    # hashing reports drift on an inventory that has not changed.
    assert not rendered.endswith("\n")


def test_key_order_and_whitespace_do_not_change_the_digest():
    a = {"schema_version": "x", "version": 1}
    b = {"version": 1, "schema_version": "x"}
    assert canonical_digest(a) == canonical_digest(b)


def test_a_changed_value_does_change_the_digest():
    # Sensitivity for the pair above. A digest function that ignored everything
    # would satisfy the previous test perfectly.
    assert canonical_digest({"version": 1}) != canonical_digest({"version": 2})


def test_the_digest_is_taken_over_the_parsed_document_not_the_file_bytes(reference_copy):
    """A reformat is not drift; a value change is.

    Hashing raw bytes would make an indentation change report as a different
    environment, which trains a reader to re-record the digest without looking
    at what moved — the exact habit a digest exists to prevent.
    """
    path = private_path(reference_copy)
    before = load_private_inventory(path, contracts=CONTRACTS).digest
    document = json.loads(path.read_text())
    path.write_text(json.dumps(document, indent=8) + "\n\n")
    assert load_private_inventory(path, contracts=CONTRACTS).digest == before


# ── The join ────────────────────────────────────────────────────────────────


def test_the_reference_inventory_resolves_cleanly():
    assert _codes(REFERENCE) == set()
    resolution = resolved(REFERENCE)
    assert resolution.inventory.document == "reference-private-inventory"
    assert resolution.jobs["dotmac-erp-app"].credential is not None
    assert resolution.jobs["dotmac-erp-worker"].credential is None


def test_a_resolution_is_read_only():
    # The renderer holds this object while producing three files. If it could
    # be mutated, "the resolution" would depend on the order the emitters ran.
    with pytest.raises(TypeError):
        resolved(REFERENCE).jobs["dotmac-erp-app"] = None  # type: ignore[index]


def test_a_target_with_no_binding_is_refused(reference_copy):
    edit(
        private_path(reference_copy),
        '"target_id": "erp-production"',
        '"target_id": "erp-production-old"',
    )
    codes = _codes(reference_copy)
    # BOTH directions, in one edit: the job now resolves to nothing, and the
    # renamed binding is reached by nothing. Reporting only the first would
    # leave a stale resolved endpoint in the inventory with no gate on it.
    assert "RESOLUTION-MISSING" in codes
    assert "RESOLUTION-UNUSED" in codes


def test_an_unused_binding_is_refused_on_its_own(reference_copy):
    document = json.loads(private_path(reference_copy).read_text())
    document["targets"].append(
        {"target_id": "decommissioned-product", "endpoints": ["gone.invalid:443"]}
    )
    private_path(reference_copy).write_text(json.dumps(document, indent=2))
    # The shape of the CRM scrape job that outlived its product: a resolved
    # endpoint nothing points at, which no other gate would ever mention.
    assert _codes(reference_copy) == {"RESOLUTION-UNUSED"}


def test_an_authentication_claim_the_binding_contradicts_is_refused(reference_copy):
    edit(
        reference_copy / "inventory" / "targets" / "erp.toml",
        'target_id = "erp-workers"\nscheme = "https"\nmetrics_path = "/metrics"\n'
        "authenticated = false",
        'target_id = "erp-workers"\nscheme = "https"\nmetrics_path = "/metrics"\n'
        "authenticated = true",
    )
    # The public half claims a capability; the private half is the only thing
    # that can falsify it. Without this gate `authenticated` would be a comment.
    assert "AUTHENTICATION-MISMATCH" in _codes(reference_copy)


def test_a_credential_no_job_admits_to_using_is_refused(reference_copy):
    document = json.loads(private_path(reference_copy).read_text())
    for binding in document["targets"]:
        if binding["target_id"] == "erp-workers":
            binding["credential"] = {
                "openbao_path": "secret/fixture/worker-scrape",
                "file_name": "worker-scrape.token",
            }
    private_path(reference_copy).write_text(json.dumps(document, indent=2))
    # The other direction, and the one that matters operationally: a credential
    # nobody declares is a credential nobody will think to revoke.
    assert "AUTHENTICATION-MISMATCH" in _codes(reference_copy)


def test_an_inventory_for_another_environment_is_refused(reference_copy):
    edit(private_path(reference_copy), '"environment": "reference"', '"environment": "production"')
    # Renders perfectly and points a reference evaluator at production.
    assert "RESOLUTION-ENVIRONMENT" in _codes(reference_copy)


def test_an_inventory_binding_another_host_is_refused(reference_copy):
    edit(
        private_path(reference_copy),
        '"target_id": "reference-evaluator"',
        '"target_id": "some-other-host"',
    )
    assert "RESOLUTION-HOST" in _codes(reference_copy)


def test_an_unresolvable_credential_ref_is_refused(reference_copy):
    edit(
        reference_copy / "routing" / "receivers.toml",
        'credential_ref = "telegram-oncall"',
        'credential_ref = "telegram-oncall-rotated"',
    )
    codes = _codes(reference_copy)
    assert "RESOLUTION-MISSING" in codes
    assert "RESOLUTION-UNUSED" in codes


def test_a_publication_shadowing_a_binding_is_refused(reference_copy):
    document = json.loads(private_path(reference_copy).read_text())
    document["targets"].append(
        {"target_id": "status-page", "endpoints": ["status-internal.invalid:443"]}
    )
    private_path(reference_copy).write_text(json.dumps(document, indent=2))
    # Two answers to one question. The publication wins, so the binding is a
    # value nobody reads that everybody assumes is in effect — and the two can
    # drift apart with nothing comparing them.
    assert "PUBLICATION-SHADOWED" in _codes(reference_copy)


def test_a_published_endpoint_resolves_without_any_private_material(reference_copy):
    document = json.loads(private_path(reference_copy).read_text())
    document["targets"] = [t for t in document["targets"] if t["target_id"] != "erp-production"]
    document["federations"] = []
    document["receivers"] = []
    private_path(reference_copy).write_text(json.dumps(document, indent=2))
    findings = _codes(reference_copy)
    # `status-page` carries a reviewed publication, so it is the ONE target
    # that still resolves when the private half is gutted. That is the property
    # the exception exists to provide, and it is worth proving rather than
    # assuming: an exception that still needed the binding would buy nothing.
    assert "RESOLUTION-MISSING" in findings
    resolution_targets = {
        f.location
        for f in resolution_findings(
            load(reference_copy, contracts=CONTRACTS),
            load_private_inventory(private_path(reference_copy), contracts=CONTRACTS),
        )
        if f.code == "RESOLUTION-MISSING"
    }
    assert not any("dotmac-status-page" in location for location in resolution_targets)


def test_resolve_refuses_to_build_a_half_joined_object(reference_copy):
    edit(private_path(reference_copy), '"target_id": "erp-production"', '"target_id": "renamed"')
    with pytest.raises(InventoryError):
        resolved(reference_copy)
    # The renderer indexes without guarding, so a Resolution that exists must be
    # one whose every lookup succeeds. Returning a partial object here would
    # move the failure into the middle of emitting a file.
