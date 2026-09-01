"""Fleet-agent exposure, authentication and completeness invariants."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "fleet" / "alloy" / "config.alloy"
HOST_CONFIG = ROOT / "fleet" / "alloy" / "config-host.alloy"
CONFIGS = (CONFIG, HOST_CONFIG)
DROP_IN = ROOT / "fleet" / "alloy" / "systemd" / "alloy.service.d" / "10-dotmac.conf"
VERSION = ROOT / "fleet" / "alloy" / "VERSION"


def test_alloy_collects_every_required_signal() -> None:
    text = CONFIG.read_text()
    required = (
        'prometheus.exporter.unix "host"',
        'prometheus.exporter.cadvisor "containers"',
        'loki.source.journal "host"',
        'loki.source.docker "containers"',
        'otelcol.receiver.otlp "local"',
        'otelcol.processor.resourcedetection "host"',
        'otelcol.exporter.prometheus "central"',
        'otelcol.exporter.loki "central"',
        'otelcol.exporter.otlp "central"',
        'prometheus.scrape "agent"',
    )
    assert all(component in text for component in required)


def test_host_profile_has_no_container_runtime_dependency() -> None:
    text = HOST_CONFIG.read_text()
    assert 'prometheus.exporter.unix "host"' in text
    assert 'loki.source.journal "host"' in text
    assert 'otelcol.receiver.otlp "local"' in text
    assert "cadvisor" not in text
    assert "discovery.docker" not in text
    assert "loki.source.docker" not in text


def test_every_remote_signal_uses_mutual_tls() -> None:
    for config in CONFIGS:
        text = config.read_text()
        assert text.count("ca_file") == 3
        assert text.count("cert_file") == 3
        assert text.count("key_file") == 3
        assert text.count("server_name") == 3
        assert "insecure_skip_verify" not in text
        assert "insecure = true" not in text
        assert 'min_version     = "1.3"' in text


def test_receivers_and_agent_ui_are_loopback_only() -> None:
    for config in CONFIGS:
        text = config.read_text()
        assert 'endpoint = "127.0.0.1:4317"' in text
        assert 'endpoint = "127.0.0.1:4318"' in text
        assert '"__address__" = "127.0.0.1:12345"' in text
        assert "0.0.0.0" not in text


def test_every_pipeline_carries_fleet_host_identity() -> None:
    for config, minimum in ((CONFIG, 5), (HOST_CONFIG, 3)):
        text = config.read_text()
        for name in ("DOTMAC_FLEET", "DOTMAC_ENVIRONMENT", "DOTMAC_HOST_ID"):
            assert text.count(name) >= minimum
    environment = (ROOT / "fleet" / "alloy" / "alloy.env.example").read_text()
    assert "OTEL_RESOURCE_ATTRIBUTES=" in environment


def test_service_is_hardened_and_has_no_remote_configuration() -> None:
    config = CONFIG.read_text()
    drop_in = DROP_IN.read_text()
    assert "remote." not in config
    assert "NoNewPrivileges=yes" in drop_in
    assert "ProtectSystem=strict" in drop_in
    assert "ProtectHome=yes" in drop_in
    assert "EnvironmentFile=/etc/default/dotmac-alloy" in drop_in
    assert "--server.http.listen-addr=127.0.0.1:12345" in drop_in
    assert "--disable-reporting" in drop_in


def test_alloy_release_inputs_are_exact() -> None:
    version = VERSION.read_text().splitlines()
    assert version[0].startswith("ALLOY_PACKAGE_VERSION=")
    assert version[0].count(".") == 2
    assert version[1].startswith("ALLOY_IMAGE=grafana/alloy@sha256:")
    assert len(version[1].split("sha256:", 1)[1]) == 64


def test_promtail_is_not_part_of_the_fleet_agent() -> None:
    fleet = (ROOT / "fleet").read_text() if (ROOT / "fleet").is_file() else ""
    files = tuple((ROOT / "fleet").rglob("*"))
    tracked_text = fleet + "\n".join(
        path.read_text() for path in files if path.is_file() and path.suffix != ".pyc"
    )
    assert "grafana/promtail" not in tracked_text
