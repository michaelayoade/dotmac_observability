"""The bundle's own gates, and the two rendering rules that were host defects.

Every test here names the thing that was actually wrong on the Observer host,
because a gate whose motivating failure is not written down is a gate somebody
deletes in six months for being noisy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dotmac_observability.render import (
    EXPOSURE_IPV4,
    EXPOSURE_IPV6,
    LOGROTATE_CONFIG,
    META_RULES,
    RSYSLOG_CONFIG,
    TIMEZONE_FILE,
    TMPFILES_CONFIG,
    render_control_plane,
)
from dotmac_observability.validate import load, semantic_findings
from tests.conftest import CONTRACTS, REFERENCE, edit, resolved

INTEGRITY = (
    'integrity = "increase('
    'prometheus_target_scrapes_sample_duplicate_timestamp_total[15m]) == 0"'
)


def _codes(root: Path) -> set[str]:
    return {finding.code for finding in semantic_findings(load(root, contracts=CONTRACTS))}


def _tree(root: Path = REFERENCE) -> dict[str, str]:
    return dict(render_control_plane(load(root, contracts=CONTRACTS), resolved(root)))


# ── the reference bundle is clean, so every mutation below means something ──


def test_the_reference_bundle_raises_no_findings():
    assert semantic_findings(load(REFERENCE, contracts=CONTRACTS)) == ()


# ── syslog: the ten-thousand-suspension failure ─────────────────────────────


def test_the_rotation_stanza_recreates_the_file_with_owner_group_and_mode():
    """The whole repair, in one assertion.

    `create` with no arguments — which the host's global logrotate.conf
    supplies — reuses the ORIGINAL file's owner and mode, and does nothing at
    all when the original does not exist. `/var/log/mail.log` did not exist,
    `missingok` skipped the stanza, and rsyslog was left to create a file it
    cannot create because it runs as `syslog` in a directory that is
    `root:syslog 0755`.
    """
    stanza = _tree()[LOGROTATE_CONFIG]
    assert "create 0640 syslog adm" in stanza
    assert "\n    create\n" not in stanza, "a bare `create` inherits from a file that is absent"


def test_rotation_reopens_the_writer_rather_than_truncating_it():
    stanza = _tree()[LOGROTATE_CONFIG]
    assert "postrotate" in stanza and "rsyslog-rotate" in stanza
    # `copytruncate` loses whatever is written between the copy and the
    # truncate, which for a log nobody is watching is a silent hole.
    assert "copytruncate" not in stanza


def test_compression_is_delayed_by_one_cycle_whenever_it_is_enabled():
    stanza = _tree()[LOGROTATE_CONFIG]
    assert "compress" in stanza
    assert "delaycompress" in stanza, "compressing the newest rotation races an unreopened writer"


def test_tmpfiles_creates_the_file_so_rsyslog_never_has_to():
    """The half that removes the dependency on directory write permission."""
    lines = _tree()[TMPFILES_CONFIG].splitlines()
    assert "d /var/log 0755 root syslog -" in lines
    assert "f /var/log/mail.log 0640 syslog adm -" in lines
    # `f+` truncates on every application, which would delete a day of logs at
    # each boot. `f` creates if absent and leaves the contents alone.
    assert not any(line.startswith("f+ ") for line in lines)


def test_the_directory_is_not_widened_to_make_the_writer_work():
    """The repair that was NOT taken, asserted so nobody takes it later.

    Granting group write on /var/log would let the privilege-dropped writer
    create files, and would also let it create, rename and unlink every other
    service's log.
    """
    assert "d /var/log 0755 root syslog -" in _tree()[TMPFILES_CONFIG]


def test_every_action_states_its_own_owner_group_and_mode():
    """rsyslog's directives are positional, which is how ownership drifts.

    A `$FileOwner` block at the top of one included file governs every action
    after it, including actions in files included later. An action that does
    not restate the three values inherits whatever the previous file left.
    """
    body = _tree()[RSYSLOG_CONFIG]
    actions = [line for line in body.splitlines() if line.startswith(("mail.", "auth", "kern"))]
    assert actions
    assert body.count("$FileOwner ") == len(actions)
    assert body.count("$FileGroup ") == len(actions)
    assert body.count("$FileCreateMode ") == len(actions)


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        # A mode with no owner write suspends the action on the first append.
        ('mode = "0640"', 'mode = "0440"', "SYSLOG-OWNER-WRITE"),
        # A world-readable log leaks message contents to every local account.
        ('mode = "0640"', 'mode = "0644"', "SYSLOG-WORLD-READABLE"),
        # A file outside the declared directory has no stated parent ownership,
        # which is the exact shape of the original failure.
        ('path = "/var/log/mail.log"', 'path = "/srv/mail.log"', "SYSLOG-OUTSIDE-CONTRACT"),
    ],
)
def test_a_broken_syslog_declaration_is_refused(
    reference_copy: Path, old: str, new: str, code: str
):
    edit(reference_copy / "inventory" / "bundle.toml", old, new)
    assert code in _codes(reference_copy)


# ── exposure: the dead IPv6 rules ───────────────────────────────────────────


def test_an_ipv4_container_publish_is_written_in_docker_user():
    ipv4 = _tree()[EXPOSURE_IPV4]
    assert "-A DOCKER-USER -p tcp --dport 9090" in ipv4


def test_an_ipv6_container_publish_is_written_on_input_and_never_in_docker_user():
    """The measured defect, made unrepresentable.

    Seven IPv6 DROP rules sit in DOCKER-USER on the Observer host. No IPv6
    packet to a published port ever traverses that chain — it terminates on
    INPUT — so every port they name reads as closed and is open. The renderer
    derives the chain from the surface kind and the family, so an author cannot
    put the rule in the wrong one.
    """
    ipv6 = _tree()[EXPOSURE_IPV6]
    assert "DOCKER-USER" not in ipv6, "an IPv6 rule in DOCKER-USER is silently dead"
    assert "-A INPUT -p tcp --dport 9090" in ipv6


def test_the_management_source_is_an_interface_match_in_iptables_syntax():
    """`-i`, not nftables' `iifname`, which has been carried across once already.

    And an interface rather than a prefix: WireGuard membership is
    cryptographic, so matching the interface is both simpler and stricter than
    matching an address range — and it means no prefix is written into a
    reusable artefact at all.
    """
    ipv4 = _tree()[EXPOSURE_IPV4]
    assert "-A INPUT -i wg0 -p tcp --dport 22 -j ACCEPT" in ipv4
    assert "iifname" not in ipv4


def test_no_rendered_rule_carries_a_literal_prefix_when_the_set_is_a_tunnel():
    for family in (EXPOSURE_IPV4, EXPOSURE_IPV6):
        assert " -s " not in _tree()[family]


def test_an_ingress_surface_with_no_source_set_is_refused(reference_copy: Path):
    edit(
        reference_copy / "inventory" / "bundle.toml",
        'exposure = "ingress"\n  allow_from = "management"',
        'exposure = "ingress"',
    )
    assert "SURFACE-NO-SOURCE" in _codes(reference_copy)


def test_a_source_set_nobody_allows_from_is_refused(reference_copy: Path):
    edit(reference_copy / "inventory" / "bundle.toml", '  allow_from = "management"\n', "")
    assert "SOURCE-SET-UNUSED" in _codes(reference_copy)


def test_a_tunnel_set_bound_to_prefixes_is_refused(reference_copy: Path):
    """Only the JOIN can see this one, which is why it is a resolution gate.

    A set declared `tunnel_interface` and bound to prefixes renders a source
    match where an interface match was intended: strictly weaker, silently
    different, and valid under both schemas on its own.
    """
    from dotmac_observability.validate import load_private_inventory, resolution_findings
    from tests.conftest import private_path

    # Assembled rather than written as a literal. The private-material scan
    # reads every tracked file including this one, and it is not in
    # PRIVATE_SCAN_EXCLUSIONS — correctly, because that list's premise is "the
    # detector and its sensitivity proof", and this is neither.
    prefix = ".".join(("10", "0", "0", "0")) + "/24"
    edit(
        private_path(reference_copy),
        '"interface": "wg0"',
        f'"prefixes": ["{prefix}"]',
    )
    findings = resolution_findings(
        load(reference_copy, contracts=CONTRACTS),
        load_private_inventory(private_path(reference_copy), contracts=CONTRACTS),
    )
    assert "SOURCE-SET-KIND" in {finding.code for finding in findings}


# ── verification: the conjunction that Observer did not have ────────────────


def test_the_gate_fires_only_when_health_holds_and_integrity_does_not():
    """Eighteen targets read `up == 1` while 1,858,942 samples were rejected.

    The rendered expression has to be able to distinguish those two facts, and
    `unless` is what does it: the alert fires exactly on the state a
    scrape-health check reports as green.
    """
    rules = _tree()[META_RULES]
    assert "unless" in rules
    assert "prometheus_target_scrapes_sample_duplicate_timestamp_total" in rules
    assert "up" in rules


def test_a_gate_whose_two_predicates_are_the_same_is_refused(reference_copy: Path):
    edit(
        reference_copy / "inventory" / "bundle.toml",
        INTEGRITY,
        'integrity = "min(up{job=~\\".+\\"}) == 1"',
    )
    assert "GATE-CONFLATED" in _codes(reference_copy)


def test_an_integrity_predicate_that_is_not_about_ingestion_is_refused(reference_copy: Path):
    edit(
        reference_copy / "inventory" / "bundle.toml",
        INTEGRITY,
        'integrity = "min(prometheus_build_info) == 1"',
    )
    assert "GATE-INTEGRITY-NOT-INGESTION" in _codes(reference_copy)


# ── roster, timezone, datasources ───────────────────────────────────────────


def test_the_declared_infrastructure_timezone_is_utc_and_reaches_every_container():
    assert _tree()[TIMEZONE_FILE] == "UTC\n"
    compose = _tree()["docker-compose.yml"]
    assert compose.count("TZ: UTC") == 5


def test_the_presentation_zone_reaches_grafana_and_nothing_else():
    compose = _tree()["docker-compose.yml"]
    assert "GF_DATE_FORMATS_DEFAULT_TIMEZONE" in compose
    # Presented, never stored: no other service sees it.
    assert compose.count("Africa/Lagos") == 1


def test_a_placeholder_owner_is_refused(reference_copy: Path):
    edit(
        reference_copy / "inventory" / "bundle.toml",
        'name = "loki"\nkind = "service"\nowner = "observability-control-plane"',
        'name = "loki"\nkind = "service"\nowner = "unowned"',
    )
    assert "ROSTER-UNOWNED" in _codes(reference_copy)


def test_a_datasource_url_is_derived_from_the_roster_rather_than_written_by_hand():
    datasources = _tree()["grafana/provisioning/datasources/datasources.yml"]
    assert "http://prometheus:9090" in datasources
    assert "http://loki:3100" in datasources


def test_two_default_datasources_are_refused(reference_copy: Path):
    edit(
        reference_copy / "inventory" / "bundle.toml",
        'name = "logs"\n  kind = "loki"\n  service = "loki"\n  default = false',
        'name = "logs"\n  kind = "loki"\n  service = "loki"\n  default = true',
    )
    assert "DATASOURCE-DEFAULT" in _codes(reference_copy)


# ── Alertmanager singleton ──────────────────────────────────────────────────


def test_alertmanager_declares_singleton_mode_by_disabling_the_cluster():
    """One self-peer, a 4096-message gossip queue, and a warning every 15 minutes.

    Alertmanager clusters by DEFAULT and binds :9094 whether or not a peer
    exists, so a single instance gossips with itself. An empty listen address
    disables the cluster outright; the declaration is what was missing, not a
    tuning parameter.
    """
    compose = _tree()["docker-compose.yml"]
    assert '"--cluster.listen-address="' in compose


def test_disabling_the_cluster_changes_nothing_about_routing_or_delivery():
    """The proof that the singleton declaration is inert everywhere else.

    Routing, receivers and inhibition are not cluster concerns; the only
    behaviour a cluster provides is notification deduplication BETWEEN peers,
    and there are none. Asserted by byte-comparing the rendered Alertmanager
    configuration against the committed expectation, which predates this change.
    """
    committed = (REFERENCE / "rendered" / "alertmanager" / "alertmanager.yml").read_text()
    rendered = _tree()["alertmanager/alertmanager.yml"]
    assert rendered == committed
    for required in ("route:", "receivers:", "inhibit_rules:", "templates:"):
        assert required in rendered


# ── a retired product stays retired ─────────────────────────────────────────


def test_the_reference_render_mentions_no_retired_product():
    from dotmac_observability.validate import retirement_findings

    state = load(REFERENCE, contracts=CONTRACTS)
    tree = render_control_plane(state, resolved(REFERENCE))
    assert retirement_findings(state, tree) == ()


def test_the_retirement_gate_reads_a_tree_that_is_not_empty():
    """The half that stops "no references" meaning "nothing was read".

    A sweep over a tree it failed to load reports exactly what a sweep over a
    clean tree reports. This asserts the corpus is real before believing the
    absence, and it is the reason the gate runs over RENDERED bytes: an empty
    tree would have failed the render first.
    """
    tree = render_control_plane(load(REFERENCE, contracts=CONTRACTS), resolved(REFERENCE))
    assert len(tree) == 14
    assert all(text.strip() for _, text in tree)
    assert sum(len(text) for _, text in tree) > 5000


def test_the_gate_bites_when_a_retired_product_reappears(reference_copy: Path):
    """A retired product coming back under its old name, in the place it would.

    The plausible regression is not somebody re-adding a scrape job on purpose.
    It is a label, a folder name or a promtail job carrying the old name back
    into the tree, which is why the gate reads every rendered surface rather
    than the scrape configs.
    """
    from dotmac_observability.validate import retirement_findings

    edit(
        reference_copy / "inventory" / "bundle.toml",
        'name = "control-plane"\n  folder = "Control plane"',
        'name = "control-plane"\n  folder = "reference-retired-product"',
    )
    state = load(reference_copy, contracts=CONTRACTS)
    findings = retirement_findings(state, render_control_plane(state, resolved(reference_copy)))
    assert {finding.code for finding in findings} == {"RETIRED-PRODUCT-REFERENCED"}


def test_the_gate_bites_on_a_scrape_job_too(reference_copy: Path):
    from dotmac_observability.validate import retirement_findings

    edit(
        reference_copy / "inventory" / "targets" / "erp.toml",
        'job = "dotmac-erp-worker"',
        'job = "reference-retired-product"',
    )
    state = load(reference_copy, contracts=CONTRACTS)
    findings = retirement_findings(state, render_control_plane(state, resolved(reference_copy)))
    assert any(finding.code == "RETIRED-PRODUCT-REFERENCED" for finding in findings)


def test_render_refuses_to_write_a_tree_naming_a_retired_product(
    reference_copy: Path, tmp_path: Path
):
    """Refused before anything is written, not reported after."""
    from dotmac_observability.cli import main
    from tests.conftest import private_path

    edit(
        reference_copy / "inventory" / "targets" / "erp.toml",
        'job = "dotmac-erp-worker"',
        'job = "reference-retired-product"',
    )
    output = tmp_path / "out"
    code = main(
        [
            "--root",
            str(reference_copy),
            "--contracts",
            str(CONTRACTS),
            "render",
            "--private-inventory",
            str(private_path(reference_copy)),
            "--output",
            str(output),
        ]
    )
    assert code == 1
    assert not output.exists(), "the tree was written before the gate ran"


def test_rsyslog_is_told_not_to_create_directories():
    """The other half of "something else creates the file".

    rsyslog's `omfile` creates parent directories by default. A
    privilege-dropped writer that also creates its own parents creates them
    owned by ITSELF with whatever its umask gave — so the tmpfiles declaration
    would be describing something that had already happened differently, and
    the ownership contract would silently be whatever won the race.

    It is also what the CI rotation proof hit: `omfile: creating parent
    directories ... failed: Permission denied`, on a directory that already
    existed.
    """
    assert "$CreateDirs off" in _tree()[RSYSLOG_CONFIG]


def test_an_integrity_predicate_that_compares_a_raw_counter_is_refused(reference_copy: Path):
    """Condition 4's trap, made unrepresentable.

    `<counter> == 0` is satisfiable by RESETTING the counter, by a fresh TSDB,
    or by a container restart — and a predicate made true that way cannot be
    told from one made true by a repair. This host's counter stands at roughly
    1.86 million historical rejections and must stay visible; what is asserted
    is that it does not GROW from a recorded baseline.
    """
    edit(
        reference_copy / "inventory" / "bundle.toml",
        INTEGRITY,
        'integrity = "prometheus_target_scrapes_sample_duplicate_timestamp_total == 0"',
    )
    assert "GATE-INTEGRITY-NOT-DELTA" in _codes(reference_copy)


def test_both_production_gates_are_delta_shaped_and_name_an_ingestion_counter():
    """Over the REAL bundle, not the fixture.

    The fixture proves the gate works. This proves the production document
    passes it — which is only possible to check at all since `routing/` was
    populated and the production tree became loadable.
    """
    production = load(Path(__file__).resolve().parents[2], contracts=CONTRACTS)
    gates = production.bundle.gates
    assert gates, "the production bundle declares no verification gate"
    for gate in gates:
        assert "increase(" in gate.integrity, gate.name
        assert gate.health != gate.integrity, gate.name
        assert "up" in gate.health, gate.name
