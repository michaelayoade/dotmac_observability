"""AGENTS.md rule 7 — a warning or critical alert must reach a real receiver.

Each test mutates a copy of the reference inventory and asserts the specific
finding. That in-place sensitivity proof is what makes the clean-inventory
assertion meaningful: a validator that returns `()` unconditionally would pass
the first test here and fail every other one.
"""

from __future__ import annotations

from typing import cast

from dotmac_observability.render import _alertmanager, _route_config
from dotmac_observability.validate import (
    load,
    load_private_inventory,
    resolution_findings,
    semantic_findings,
)
from dotmac_observability.yaml_emit import YamlValue
from tests.conftest import CONTRACTS, REFERENCE, REPO_ROOT, edit, private_path, resolved


def _codes(root) -> set[str]:
    return {finding.code for finding in semantic_findings(load(root, contracts=CONTRACTS))}


def _resolution_codes(root) -> set[str]:
    inventory = load_private_inventory(private_path(root), contracts=CONTRACTS)
    return {
        finding.code for finding in resolution_findings(load(root, contracts=CONTRACTS), inventory)
    }


def test_the_reference_routing_is_clean():
    assert _codes(REFERENCE) == set()
    assert _resolution_codes(REFERENCE) == set()


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
        private_path(reference_copy),
        '"destination": "-1000000000001"',
        '"destination": "@dotmac-oncall"',
    )
    # Alertmanager wants a number here. A string is rejected at config load and
    # the visible symptom is a receiver that simply never delivers.
    #
    # The check moved to the resolution layer with the value it reads:
    # ADR-0004 makes a destination private, so a public reader can no longer
    # run this gate. What a public reader loses is the CHECK, not the
    # guarantee — a promotion supplies the inventory and cannot skip it.
    assert "RECEIVER-CHAT-ID" in _resolution_codes(reference_copy)


def test_an_email_receiver_without_global_smtp_is_refused(reference_copy):
    path = reference_copy / "inventory" / "control-plane.toml"
    text = path.read_text()
    path.write_text(text[: text.index("[smtp]")].rstrip() + "\n")
    assert "SMTP-UNCONFIGURED" in _codes(reference_copy)


def test_warning_repeats_less_often_than_critical_and_the_dead_inhibition_is_gone():
    """The 2026-09-13 emergency fix, codified: warning pages less often than
    critical, and the inhibition rule that could never fire is gone.

    Loads the ACTUAL repo root `routing/` config (not the synthetic reference
    fixture under `tests/fixtures/reference/`) — the desired-state routing a
    future promotion will render, not a claim about what the live host is
    already running.
    """
    state = load(REPO_ROOT, contracts=CONTRACTS)

    # The root fallback cadence is untouched.
    assert state.defaults.repeat_interval == "1h"

    rendered_root = _route_config(state)
    assert rendered_root["repeat_interval"] == "1h"
    rendered_children = cast("list[dict[str, YamlValue]]", rendered_root["routes"])

    # Alertmanager is first-match-wins (absent `continue: true`), so checking
    # only that SOME route matches each severity is not enough: an earlier,
    # differently-configured shadowing route (a broader matcher, or an extra
    # label pinned ahead of these two) would still let a "some route matches"
    # check pass while live routing actually used the earlier route instead.
    # Pinning the exact ordered two-route shape — and that neither carries
    # `continue: true` — makes an inserted, reordered, or now-non-terminal
    # route fail this test loudly instead of passing on a stale assumption.
    assert len(rendered_children) == 2

    critical_route, warning_route = rendered_children
    assert critical_route["matchers"] == ['severity="critical"']
    assert critical_route["repeat_interval"] == "1h"
    assert "continue" not in critical_route

    assert warning_route["matchers"] == ['severity="warning"']
    assert warning_route["repeat_interval"] == "12h"
    assert "continue" not in warning_route

    # No desired-state inhibition rule remains.
    assert state.inhibitions == ()

    # The rendered Alertmanager config omits `inhibit_rules:` entirely rather
    # than emitting an empty list — confirmed by reading `_alertmanager` in
    # render.py, which only sets the key `if state.inhibitions:`.
    rendered = _alertmanager(state, resolved(REFERENCE))
    assert "inhibit_rules:" not in rendered
