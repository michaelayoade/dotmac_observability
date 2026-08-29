"""AGENTS.md rule 9 — imported health series never join local health series.

An upstream's `up` describes the upstream's opinion of ITS targets. Imported
under that name it becomes indistinguishable from this plane's own `up`, and a
central `up == 0` rule then pages on a target this plane neither owns nor can
repair. That has happened on this fleet; the repair was renaming, not tuning
the rule out.
"""

from __future__ import annotations

import pytest

from dotmac_observability.render import PROMETHEUS_CONFIG, render_control_plane
from dotmac_observability.validate import InventoryError, load, semantic_findings
from tests.conftest import CONTRACTS, REFERENCE, edit


def _prometheus(root) -> str:
    return dict(render_control_plane(load(root, contracts=CONTRACTS)))[PROMETHEUS_CONFIG]


def test_the_rename_is_actually_emitted():
    rendered = _prometheus(REFERENCE)
    assert "metric_relabel_configs" in rendered
    assert 'regex: "(up|scrape_.+)"' in rendered
    assert 'replacement: "federated_${1}"' in rendered
    assert "target_label: __name__" in rendered


def test_a_federation_without_a_rename_prefix_cannot_be_loaded(reference_copy):
    edit(
        reference_copy / "inventory" / "federations" / "sub.toml",
        'rename_prefix = "federated_"\n',
        "",
    )
    # Required by the contract, not defaulted. There is no correct federation
    # without one, so an omission must fail rather than pick something.
    with pytest.raises(InventoryError):
        load(reference_copy, contracts=CONTRACTS)


def test_two_upstreams_may_not_rename_into_the_same_namespace(reference_copy):
    source = (reference_copy / "inventory" / "federations" / "sub.toml").read_text()
    (reference_copy / "inventory" / "federations" / "vcp.toml").write_text(
        source.replace('name = "dotmac-sub-federation"', 'name = "dotmac-vcp-federation"').replace(
            'endpoint = "sub.invalid:443"', 'endpoint = "vcp.invalid:443"'
        )
    )
    codes = {f.code for f in semantic_findings(load(reference_copy, contracts=CONTRACTS))}
    # Renaming two upstreams into one prefix reintroduces exactly the confusion
    # the rename exists to remove.
    assert "FEDERATION-PREFIX-COLLISION" in codes


def test_a_federation_may_not_take_a_scrape_job_s_name(reference_copy):
    edit(
        reference_copy / "inventory" / "federations" / "sub.toml",
        'name = "dotmac-sub-federation"',
        'name = "dotmac-erp-app"',
    )
    codes = {f.code for f in semantic_findings(load(reference_copy, contracts=CONTRACTS))}
    assert "JOB-DUPLICATE" in codes


def test_an_expectation_no_endpoint_can_satisfy_is_refused(reference_copy):
    edit(reference_copy / "inventory" / "targets" / "erp.toml", "expected = 1", "expected = 3")
    codes = {f.code for f in semantic_findings(load(reference_copy, contracts=CONTRACTS))}
    # `expected` is what stops "zero targets scraped" reading as health later.
    # An expectation larger than the endpoint list can never be met, so the
    # check it feeds would fail forever and be silenced.
    assert "TARGET-UNREACHABLE-EXPECTATION" in codes
