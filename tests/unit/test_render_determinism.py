"""AGENTS.md rule 13 — same inputs, same bytes, and a committed expectation.

A determinism test that only re-renders proves the renderer agrees with
itself, which it would do even if it emitted the wrong thing. The committed
fixture under `tests/fixtures/reference/rendered/` is the other half: it makes
an unintended change to the output visible as a diff a human must accept.
"""

from __future__ import annotations

from pathlib import Path

from dotmac_observability.render import (
    ALERTMANAGER_CONFIG,
    COMPOSE_FILE,
    EXPOSURE_IPV4,
    EXPOSURE_IPV6,
    GRAFANA_ALERTING,
    GRAFANA_DASHBOARDS,
    GRAFANA_DATASOURCES,
    GRAFANA_PLUGINS,
    INGESTION_RULES,
    LOGROTATE_CONFIG,
    LOKI_CONFIG,
    META_RULES,
    PROMETHEUS_CONFIG,
    PROMTAIL_CONFIG,
    RSYSLOG_CONFIG,
    TIMEZONE_FILE,
    TMPFILES_CONFIG,
    differences,
    render_control_plane,
    tree_digest,
    write_tree,
)
from dotmac_observability.validate import load
from tests.conftest import CONTRACTS, REFERENCE, REFERENCE_RENDERED, resolved


def _tree():
    return render_control_plane(load(REFERENCE, contracts=CONTRACTS), resolved(REFERENCE))


def test_rendering_twice_produces_identical_bytes():
    assert _tree() == _tree()


def test_the_committed_fixture_matches_a_fresh_render():
    assert differences(_tree(), REFERENCE_RENDERED) == ()


def test_every_declared_file_is_produced_exactly_once():
    paths = [path for path, _ in _tree()]
    # ORDER is asserted, not just membership. The tuple's order is the order a
    # reviewer reads a render diff in, and a renderer that emits its files in a
    # different order on a different machine fails the byte gate for a reason
    # that has nothing to do with the configuration.
    assert paths == [
        PROMETHEUS_CONFIG,
        META_RULES,
        INGESTION_RULES,
        ALERTMANAGER_CONFIG,
        LOKI_CONFIG,
        PROMTAIL_CONFIG,
        GRAFANA_DATASOURCES,
        GRAFANA_DASHBOARDS,
        GRAFANA_PLUGINS,
        GRAFANA_ALERTING,
        RSYSLOG_CONFIG,
        LOGROTATE_CONFIG,
        TMPFILES_CONFIG,
        TIMEZONE_FILE,
        EXPOSURE_IPV4,
        EXPOSURE_IPV6,
        COMPOSE_FILE,
    ]
    assert len(paths) == len(set(paths))


def test_the_digest_covers_paths_as_well_as_contents():
    tree = _tree()
    moved = ((f"moved/{tree[0][0]}", tree[0][1]),) + tree[1:]
    # A file relocated without changing a byte inside it is still a different
    # deployment: the mount that picks it up is chosen by path.
    assert tree_digest(tree) != tree_digest(moved)


def test_check_reports_a_missing_file(tmp_path: Path):
    tree = _tree()
    write_tree(tree, tmp_path)
    (tmp_path / PROMETHEUS_CONFIG).unlink()
    assert differences(tree, tmp_path) == (f"{PROMETHEUS_CONFIG} (missing)",)


def test_check_reports_a_hand_edited_file(tmp_path: Path):
    tree = _tree()
    write_tree(tree, tmp_path)
    target = tmp_path / ALERTMANAGER_CONFIG
    target.write_text(target.read_text() + "# edited on the host\n")
    assert differences(tree, tmp_path) == (f"{ALERTMANAGER_CONFIG} (differs)",)


def test_check_reports_a_stale_file_the_renderer_no_longer_produces(tmp_path: Path):
    tree = _tree()
    write_tree(tree, tmp_path)
    (tmp_path / "prometheus" / "leftover.yml").write_text("groups: []\n")
    # A file nobody renders still gets mounted into the evaluator, and a
    # `rule_files` glob will happily load it.
    assert differences(tree, tmp_path) == ("prometheus/leftover.yml (unexpected)",)


def test_a_reordered_inventory_changes_the_bytes(reference_copy):
    path = reference_copy / "inventory" / "control-plane.toml"
    text = path.read_text()
    first = '[[external_labels]]\nname = "environment"\nvalue = "reference"\n\n'
    second = '[[external_labels]]\nname = "control_plane"\nvalue = "dotmac-observability"\n'
    assert first in text and second in text
    path.write_text(text.replace(first + second, second + "\n" + first.rstrip("\n") + "\n"))
    reordered = render_control_plane(
        load(reference_copy, contracts=CONTRACTS), resolved(reference_copy)
    )
    # Order is the author's, not the renderer's. If this ever passes, some
    # sort() has crept in and the committed diff stopped reflecting the edit.
    assert reordered != _tree()
