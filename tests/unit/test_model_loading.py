"""Loading turns validated documents into the frozen desired state."""

from __future__ import annotations

import pytest

from dotmac_observability.model import DesiredState
from dotmac_observability.validate import (
    DEFAULT_SCRAPE_INTERVAL,
    InventoryError,
    load,
)
from tests.conftest import CONTRACTS, REFERENCE


def _state() -> DesiredState:
    return load(REFERENCE, contracts=CONTRACTS)


def test_the_reference_inventory_loads():
    state = _state()
    assert state.control_plane.environment == "reference"
    assert [target.product for target in state.targets] == ["dotmac-erp"]
    assert [federation.name for federation in state.federations] == ["dotmac-sub-federation"]


def test_declaration_order_is_preserved_rather_than_sorted():
    # A reviewer who moves a job sees exactly that move in the rendered diff.
    # Sorting here would make an unrelated rename reorder the whole file.
    jobs = [job.job for job in _state().targets[0].jobs]
    assert jobs == ["dotmac-erp-app", "dotmac-erp-worker"]
    labels = [label.name for label in _state().control_plane.external_labels]
    assert labels == ["environment", "control_plane"]


def test_the_state_is_immutable():
    state = _state()
    with pytest.raises(AttributeError):
        state.control_plane.environment = "production"  # type: ignore[misc]


def test_an_omitted_knob_takes_its_documented_default(reference_copy):
    text = (reference_copy / "inventory" / "control-plane.toml").read_text()
    (reference_copy / "inventory" / "control-plane.toml").write_text(
        text.replace('scrape_interval = "30s"\n', "", 1)
    )
    assert load(reference_copy, contracts=CONTRACTS).control_plane.scrape_interval == (
        DEFAULT_SCRAPE_INTERVAL
    )


def test_a_malformed_document_reports_every_problem_at_once(reference_copy):
    (reference_copy / "inventory" / "targets" / "erp.toml").write_text(
        'schema_version = "observability-target.v1"\nkind = "targets"\n'
    )
    with pytest.raises(InventoryError) as raised:
        load(reference_copy, contracts=CONTRACTS)
    # product, owner and jobs are all absent. Reporting only the first would
    # make an operator re-run the gate once per missing key.
    codes = {finding.code for finding in raised.value.findings}
    assert codes == {"SCHEMA"}
    assert len(raised.value.findings) >= 2


def test_a_missing_required_document_is_named(reference_copy):
    (reference_copy / "routing" / "receivers.toml").unlink()
    with pytest.raises(InventoryError) as raised:
        load(reference_copy, contracts=CONTRACTS)
    assert [f.code for f in raised.value.findings] == ["MISSING"]
    assert "receivers.toml" in raised.value.findings[0].location


def test_a_federation_filed_under_targets_is_refused(reference_copy):
    source = reference_copy / "inventory" / "federations" / "sub.toml"
    (reference_copy / "inventory" / "targets" / "sub.toml").write_text(source.read_text())
    source.unlink()
    with pytest.raises(InventoryError) as raised:
        load(reference_copy, contracts=CONTRACTS)
    # The discriminator is checked, not inferred from the directory: a
    # federation rendered as a plain scrape job would import `up` unrenamed.
    assert any(finding.code == "KIND" for finding in raised.value.findings)
