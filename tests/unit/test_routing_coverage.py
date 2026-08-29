"""AGENTS.md rule 7 — a warning or critical alert must reach a real receiver.

Each test mutates a copy of the reference inventory and asserts the specific
finding. That in-place sensitivity proof is what makes the clean-inventory
assertion meaningful: a validator that returns `()` unconditionally would pass
the first test here and fail every other one.
"""

from __future__ import annotations

from dotmac_observability.validate import load, semantic_findings
from tests.conftest import CONTRACTS, REFERENCE, edit


def _codes(root) -> set[str]:
    return {finding.code for finding in semantic_findings(load(root, contracts=CONTRACTS))}


def test_the_reference_routing_is_clean():
    assert _codes(REFERENCE) == set()


def test_an_unrouted_severity_is_refused(reference_copy):
    edit(
        reference_copy / "routing" / "policies.toml",
        '[[routes]]\nid = "critical-to-oncall"\nmatchers = [\'severity="critical"\']\n'
        'receiver = "oncall"\ngroup_wait = "10s"\nrepeat_interval = "1h"\n',
        "",
    )
    # Without a matching route, criticals silently inherit the default
    # receiver. That is not obviously wrong from the config — which is why it
    # has to be stated rather than inferred.
    assert "SEVERITY-UNROUTED" in _codes(reference_copy)


def test_routing_a_severity_at_a_null_receiver_is_refused(reference_copy):
    edit(
        reference_copy / "routing" / "policies.toml",
        'id = "critical-to-oncall"\nmatchers = [\'severity="critical"\']\nreceiver = "oncall"',
        'id = "critical-to-oncall"\nmatchers = [\'severity="critical"\']\n'
        'receiver = "recorded-only"',
    )
    assert "SEVERITY-UNDELIVERED" in _codes(reference_copy)


def test_a_receiver_that_delivers_nowhere_needs_a_written_policy(reference_copy):
    path = reference_copy / "routing" / "receivers.toml"
    text = path.read_text()
    start = text.index('null_policy = """')
    path.write_text(text[:start].rstrip() + "\n")
    assert "RECEIVER-SILENT" in _codes(reference_copy)


def test_a_route_to_an_undeclared_receiver_is_refused(reference_copy):
    edit(
        reference_copy / "routing" / "policies.toml",
        'receiver = "oncall"\ngroup_wait',
        'receiver = "pager"\ngroup_wait',
    )
    assert "ROUTE-UNDECLARED" in _codes(reference_copy)


def test_a_receiver_nothing_routes_to_is_refused(reference_copy):
    edit(
        reference_copy / "routing" / "policies.toml",
        '[[routes]]\nid = "informational-recorded"\nmatchers = [\'severity="info"\']\n'
        'receiver = "recorded-only"\n',
        "",
    )
    # Configuration nobody exercises is configuration nobody notices is broken.
    assert "RECEIVER-UNUSED" in _codes(reference_copy)


def test_a_duplicate_route_id_is_refused(reference_copy):
    edit(
        reference_copy / "routing" / "policies.toml",
        'id = "warning-to-oncall"',
        'id = "critical-to-oncall"',
    )
    assert "ROUTE-DUPLICATE" in _codes(reference_copy)


def test_a_non_numeric_telegram_chat_id_is_refused(reference_copy):
    edit(
        reference_copy / "routing" / "receivers.toml",
        'destination = "-1000000000001"',
        'destination = "@dotmac-oncall"',
    )
    # Alertmanager wants a number here. A string is rejected at config load and
    # the visible symptom is a receiver that simply never delivers.
    assert "RECEIVER-CHAT-ID" in _codes(reference_copy)


def test_an_email_receiver_without_global_smtp_is_refused(reference_copy):
    path = reference_copy / "inventory" / "control-plane.toml"
    text = path.read_text()
    path.write_text(text[: text.index("[smtp]")].rstrip() + "\n")
    assert "SMTP-UNCONFIGURED" in _codes(reference_copy)
