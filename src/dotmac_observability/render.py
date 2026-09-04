"""Deterministic rendering of the desired state into evaluator configuration.

The single authority for what the control plane's configuration BYTES are
(``.dotmac/standards-profile.json`` names this module's
:func:`render_control_plane` as the decision interface). Everything else —
the CLI, the promotion lane, the rehearsal — is an adapter that calls it and
writes or compares the result.

Two properties matter more than elegance here:

* **Determinism.** Same desired state, same bytes, every time, on every
  machine. No timestamps, no hostname, no iteration over a set, no locale-
  dependent sort. ``make render-check`` is a byte comparison, so a renderer
  that is merely *usually* stable turns the gate into noise.
* **Wholeness.** One call produces the entire file tree. A renderer that emits
  one file per call invites a caller to update two of three files and stage a
  configuration nobody has ever seen.

Since ADR-0004 the renderer takes TWO inputs: the public desired state and a
:class:`~.model.Resolution` joining it to one private inventory. It performs no
lookup that could fail — every endpoint and every credential it reads was
proved present by :func:`~.validate.resolve` before the ``Resolution`` existed.
That is the whole reason resolution is a separate value rather than something
the renderer does as it goes: a renderer that resolved inline would discover a
missing binding half-way through emitting a file, and would report the first
failure rather than all of them.

The consequence ADR-0004 accepted is visible here: nobody can reproduce a
production render from public inputs alone. The determinism gate is unharmed,
because determinism is a property of the renderer and its inputs rather than of
whether those inputs are real.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import TypeAlias, cast

from .ingestion import duration_seconds
from .model import (
    DesiredState,
    Federation,
    Label,
    Receiver,
    Resolution,
    ResolvedEndpoint,
    Runtime,
    ScrapeJob,
    SecretFile,
    Surface,
)
from .yaml_emit import YamlValue, emit

__all__ = [
    "ALERTMANAGER_CONFIG",
    "COMPOSE_FILE",
    "EXPOSURE_IPV4",
    "EXPOSURE_IPV6",
    "GRAFANA_ALERTING",
    "GRAFANA_DASHBOARDS",
    "GRAFANA_DATASOURCES",
    "GRAFANA_PLUGINS",
    "INGESTION_RULES",
    "LOGROTATE_CONFIG",
    "LOKI_CONFIG",
    "META_RULES",
    "PROMETHEUS_CONFIG",
    "PROMTAIL_CONFIG",
    "RSYSLOG_CONFIG",
    "TIMEZONE_FILE",
    "TMPFILES_CONFIG",
    "RenderedTree",
    "differences",
    "file_digest",
    "render_control_plane",
    "tree_digest",
    "write_tree",
]

RenderedTree: TypeAlias = tuple[tuple[str, str], ...]

PROMETHEUS_CONFIG = "prometheus/prometheus.yml"
# Control-plane META rules, which this repository legitimately owns: a deadman,
# evaluator health, and the ingestion-integrity gate. Rule 5 forbids authoring a
# PRODUCT's alert expression; it does not forbid the alerts no product can
# observe, and the ingestion gate is exactly one of those — a product cannot see
# that the samples it emitted were refused at this evaluator's append path.
META_RULES = "prometheus/rules/00-control-plane-meta.yml"
# The ingestion boundary's own alerts (ADR-0011). A SECOND rules file rather
# than more entries in the first, because the two answer different questions
# and are read at different moments: `00-` is what a promotion is accepted
# against, `01-` is what tells an operator months later that a shipper stopped.
# They also fail differently — a gate that never fires means a promotion is
# clean, and a deadman that never fires means nobody knows whether it works.
INGESTION_RULES = "prometheus/rules/01-ingestion-meta.yml"
ALERTMANAGER_CONFIG = "alertmanager/alertmanager.yml"
LOKI_CONFIG = "loki/loki.yml"
PROMTAIL_CONFIG = "promtail/promtail.yml"
GRAFANA_DATASOURCES = "grafana/provisioning/datasources/datasources.yml"
GRAFANA_DASHBOARDS = "grafana/provisioning/dashboards/dashboards.yml"
GRAFANA_PLUGINS = "grafana/provisioning/plugins/plugins.yml"
GRAFANA_ALERTING = "grafana/provisioning/alerting/alerting.yml"
# Host-level artefacts. Under `host/` rather than at the root so that the
# release directory's shape says which files are mounted into a container and
# which are installed onto the machine — a distinction the operator has to get
# right and the previous hand-maintained tree did not record anywhere.
RSYSLOG_CONFIG = "host/rsyslog.d/40-observability.conf"
LOGROTATE_CONFIG = "host/logrotate.d/observability"
TMPFILES_CONFIG = "host/tmpfiles.d/observability.conf"
TIMEZONE_FILE = "host/timezone"
EXPOSURE_IPV4 = "host/exposure/ipv4.rules"
EXPOSURE_IPV6 = "host/exposure/ipv6.rules"
COMPOSE_FILE = "docker-compose.yml"

# Paths INSIDE the containers. Fixed rather than configurable: they are an
# implementation detail of the rendered compose file, which mounts the release
# directory at these locations. Making them knobs would let the config and the
# mount disagree, which is unobservable until an evaluator starts with no rules.
_PROMETHEUS_ETC = "/etc/prometheus"
_ALERTMANAGER_ETC = "/etc/alertmanager"
_RULES_GLOB = f"{_PROMETHEUS_ETC}/rules/*.yml"
_TEMPLATES_GLOB = f"{_ALERTMANAGER_ETC}/templates/*.tmpl"
# One host directory of secret files is mounted into BOTH containers, at a
# different path in each. Deriving the reference from the same constant the
# mount uses is what stops a credential path pointing into the other
# service's tree — a mistake that renders and validates cleanly and then
# silently delivers nothing.
# `:?` rather than `:-`: there is no sensible default release directory, and
# a bare ${VAR} would resolve to the empty string, which for a mount source
# means the container starts with nothing mounted and no error.
_RELEASE = "${OBSERVABILITY_RELEASE:?release directory is required}"
_PROMETHEUS_SECRETS = f"{_PROMETHEUS_ETC}/secrets"
_ALERTMANAGER_SECRETS = f"{_ALERTMANAGER_ETC}/secrets"
_LOKI_ETC = "/etc/loki"
_PROMTAIL_ETC = "/etc/promtail"
_GRAFANA_PROVISIONING = "/etc/grafana/provisioning"

_HEADER = (
    "GENERATED by `dotmac-observability render` — do not edit.",
    "Source of truth: inventory/, bundles/ and routing/ in dotmac_observability.",
    "`make render-check` compares these bytes against a fresh render and fails on drift.",
)


def _port(listen: str) -> str:
    return listen.rsplit(":", 1)[1]


def _host(listen: str) -> str:
    return listen.rsplit(":", 1)[0]


def _labels_mapping(labels: tuple[Label, ...]) -> dict[str, YamlValue]:
    return {label.name: label.value for label in labels}


def _secret_path(directory: str, secret: SecretFile) -> str:
    return f"{directory}/{secret.file_name}"


def _scrape_config(job: ScrapeJob, resolved: ResolvedEndpoint) -> dict[str, YamlValue]:
    config: dict[str, YamlValue] = {
        "job_name": job.job,
        "scheme": job.scheme,
        "metrics_path": job.metrics_path,
    }
    if job.params:
        # ADR-0008. Omitted when empty rather than rendered as `params: {}`,
        # so adding the field changes no existing job's bytes — a determinism
        # gate that fired on every job the day an optional field landed would
        # have taught everyone to re-run `make render` without reading the diff.
        config["params"] = {name: list(values) for name, values in job.params}
    if job.scrape_interval is not None:
        config["scrape_interval"] = job.scrape_interval
    if job.scrape_timeout is not None:
        config["scrape_timeout"] = job.scrape_timeout
    if resolved.credential is not None:
        # A FILE reference. The token itself is placed on the host from
        # OpenBao by the deployment and never appears in this repository. Since
        # ADR-0004 the BASENAME does not either: it arrives from the private
        # inventory and reaches only the rendered artefact.
        config["bearer_token_file"] = _secret_path(_PROMETHEUS_SECRETS, resolved.credential)
    static: dict[str, YamlValue] = {"targets": list(resolved.endpoints)}
    # `labels` describe the product, `static_labels` identify the target. They
    # render onto the SAME mapping, in that order, so a job carrying both
    # produces one block; a target label deliberately wins a collision, because
    # it is the more specific claim about the thing being scraped.
    combined = _labels_mapping(job.labels)
    combined.update(_labels_mapping(job.static_labels))
    if combined:
        static["labels"] = combined
    config["static_configs"] = [static]
    return config


def _federation_config(federation: Federation, resolved: ResolvedEndpoint) -> dict[str, YamlValue]:
    config: dict[str, YamlValue] = {
        "job_name": federation.name,
        # The upstream's labels win: this plane is importing the upstream's
        # view, not relabelling it into its own.
        "honor_labels": True,
        "scheme": federation.source.scheme,
        "metrics_path": federation.source.path,
        "params": {"match[]": list(federation.match)},
    }
    if federation.scrape_interval is not None:
        config["scrape_interval"] = federation.scrape_interval
    if resolved.credential is not None:
        config["bearer_token_file"] = _secret_path(_PROMETHEUS_SECRETS, resolved.credential)
    static: dict[str, YamlValue] = {"targets": list(resolved.endpoints)}
    if federation.labels:
        static["labels"] = _labels_mapping(federation.labels)
    config["static_configs"] = [static]
    # AGENTS.md rule 9. `up` and `scrape_*` describe the UPSTREAM's opinion of
    # its own targets. Imported under their own names they join this plane's
    # health series, and a central `up == 0` then pages on something this plane
    # neither owns nor can repair. Renaming makes the two populations
    # impossible to conflate in a query.
    config["metric_relabel_configs"] = [
        {
            "source_labels": ["__name__"],
            "regex": "(up|scrape_.+)",
            "target_label": "__name__",
            "replacement": f"{federation.rename_prefix}${{1}}",
        }
    ]
    return config


def _prometheus(state: DesiredState, resolution: Resolution) -> str:
    plane = state.control_plane
    scrape_configs: list[YamlValue] = []
    for target_set in state.targets:
        for job in target_set.jobs:
            scrape_configs.append(_scrape_config(job, resolution.jobs[job.job]))
    for federation in state.federations:
        scrape_configs.append(
            _federation_config(federation, resolution.federations[federation.name])
        )

    document: dict[str, YamlValue] = {
        "global": {
            "scrape_interval": plane.scrape_interval,
            "scrape_timeout": plane.scrape_timeout,
            "evaluation_interval": plane.evaluation_interval,
            "external_labels": _labels_mapping(plane.external_labels),
        },
        # A glob over the release's rules directory, not a list of files. The
        # staged release decides which bundles are present; a hand-kept file
        # list here would be a second, silently divergent answer to that.
        "rule_files": [_RULES_GLOB],
        "alerting": {
            "alertmanagers": [
                {
                    "static_configs": [
                        {"targets": [f"alertmanager:{_port(plane.alertmanager.listen)}"]}
                    ]
                }
            ]
        },
        "scrape_configs": scrape_configs,
    }
    return emit(document, header=_HEADER)


_INTEGRATION_KEYS: Mapping[str, tuple[str, str, str | None]] = {
    # kind -> (alertmanager block, credential-file field, destination field)
    "telegram": ("telegram_configs", "bot_token_file", "chat_id"),
    "email": ("email_configs", "auth_password_file", "to"),
    "webhook": ("webhook_configs", "url_file", None),
    "slack": ("slack_configs", "api_url_file", "channel"),
}


def _receiver_config(receiver: Receiver, resolution: Resolution) -> dict[str, YamlValue]:
    config: dict[str, YamlValue] = {"name": receiver.name}
    grouped: dict[str, list[YamlValue]] = {}
    for integration in receiver.integrations:
        block, credential_field, destination_field = _INTEGRATION_KEYS[integration.kind]
        resolved = resolution.integrations[integration.credential_ref]
        entry: dict[str, YamlValue] = {
            credential_field: _secret_path(_ALERTMANAGER_SECRETS, resolved.credential),
            "send_resolved": integration.send_resolved,
        }
        if destination_field is not None and resolved.destination is not None:
            # Telegram's chat id is a NUMBER in Alertmanager's schema; quoted it
            # is silently rejected at config load, which presents as a receiver
            # that simply never delivers.
            if integration.kind == "telegram":
                entry[destination_field] = int(resolved.destination)
            else:
                entry[destination_field] = resolved.destination
        grouped.setdefault(block, []).append(entry)
    for block, entries in grouped.items():
        config[block] = entries
    return config


def _route_config(state: DesiredState) -> dict[str, YamlValue]:
    children: list[YamlValue] = []
    for route in state.routes:
        child: dict[str, YamlValue] = {
            "receiver": route.receiver,
            "matchers": list(route.matchers),
        }
        if route.keep_going:
            child["continue"] = True
        if route.group_by is not None:
            child["group_by"] = list(route.group_by)
        if route.group_wait is not None:
            child["group_wait"] = route.group_wait
        if route.group_interval is not None:
            child["group_interval"] = route.group_interval
        if route.repeat_interval is not None:
            child["repeat_interval"] = route.repeat_interval
        children.append(child)

    defaults = state.defaults
    root: dict[str, YamlValue] = {
        "receiver": defaults.receiver,
        "group_by": list(defaults.group_by),
        "group_wait": defaults.group_wait,
        "group_interval": defaults.group_interval,
        "repeat_interval": defaults.repeat_interval,
    }
    if children:
        root["routes"] = children
    return root


def _alertmanager(state: DesiredState, resolution: Resolution) -> str:
    plane = state.control_plane
    globals_block: dict[str, YamlValue] = {"resolve_timeout": plane.resolve_timeout}
    if plane.smtp is not None:
        globals_block["smtp_smarthost"] = plane.smtp.smarthost
        globals_block["smtp_from"] = plane.smtp.sender
        globals_block["smtp_require_tls"] = plane.smtp.require_tls
        if plane.smtp.auth_username is not None:
            globals_block["smtp_auth_username"] = plane.smtp.auth_username
    document: dict[str, YamlValue] = {
        "global": globals_block,
        "templates": [_TEMPLATES_GLOB],
        "route": _route_config(state),
    }
    if state.inhibitions:
        document["inhibit_rules"] = [
            {
                "source_matchers": list(rule.source_matchers),
                "target_matchers": list(rule.target_matchers),
                # Never omitted. An inhibition without `equal` suppresses the
                # target everywhere rather than only where the cause applies,
                # which is the commonest way an inhibition silences an
                # unrelated outage.
                "equal": list(rule.equal),
            }
            for rule in state.inhibitions
        ]
    document["receivers"] = [_receiver_config(receiver, resolution) for receiver in state.receivers]
    return emit(document, header=_HEADER)


def _compose(state: DesiredState) -> str:
    plane = state.control_plane
    bundle = state.bundle
    prometheus_port = _port(plane.prometheus.listen)
    alertmanager_port = _port(plane.alertmanager.listen)
    # Every container gets the DECLARED infrastructure zone, not the host's.
    # A container inheriting the host zone is how two services on one machine
    # write logs an operator cannot interleave; declaring it here means the
    # bundle's timestamps do not depend on what `timedatectl` happens to say.
    zone = bundle.timezone.infrastructure
    document: dict[str, YamlValue] = {
        "name": f"observability-{plane.environment}",
        "services": {
            "prometheus": {
                # Digest, not tag. A tag is a mutable pointer; the receipt has
                # to be able to say exactly what ran.
                "image": f"{plane.prometheus.image}@{plane.prometheus.digest}",
                "restart": "${OBSERVABILITY_RESTART:-unless-stopped}",
                "user": "${PROMETHEUS_USER:-65534:65534}",
                "command": [
                    f"--config.file={_PROMETHEUS_ETC}/prometheus.yml",
                    "--storage.tsdb.path=/prometheus",
                    "--storage.tsdb.retention.time=${PROMETHEUS_RETENTION:-90d}",
                    f"--web.listen-address=0.0.0.0:{prometheus_port}",
                    # Reload over the lifecycle API, so activation never has to
                    # recreate the container and lose the scrape window.
                    "--web.enable-lifecycle",
                ],
                "ports": [f"${{PROMETHEUS_LISTEN:-{plane.prometheus.listen}}}:{prometheus_port}"],
                # DIRECTORY mounts, read-only. A single-file bind mount detaches
                # its inode on rename, which is precisely why the host became
                # append-only-by-hand and unowned (AGENTS.md rule 2).
                "volumes": [
                    f"{_RELEASE}/prometheus:{_PROMETHEUS_ETC}:ro",
                    f"${{OBSERVABILITY_SECRETS:-{plane.secrets_dir}}}:{_PROMETHEUS_ETC}/secrets:ro",
                    "prometheus_data:/prometheus",
                ],
                "environment": {"TZ": zone},
            },
            "alertmanager": {
                "image": f"{plane.alertmanager.image}@{plane.alertmanager.digest}",
                "restart": "${OBSERVABILITY_RESTART:-unless-stopped}",
                "user": "${ALERTMANAGER_USER:-65534:65534}",
                "command": [
                    f"--config.file={_ALERTMANAGER_ETC}/alertmanager.yml",
                    "--storage.path=/alertmanager",
                    f"--web.listen-address=0.0.0.0:{alertmanager_port}",
                    # SINGLETON, DECLARED. Alertmanager clusters by default and
                    # binds :9094 whether or not a peer exists, so a single
                    # instance gossips with itself: on the Observer host it
                    # accumulated a 4096-message queue and logged "dropping
                    # messages because too many are queued" every fifteen
                    # minutes for weeks, with exactly one peer — itself.
                    #
                    # An empty listen address disables the cluster outright.
                    # That is the declaration this deployment was missing;
                    # nothing about routing, receivers, inhibition or delivery
                    # changes, because none of them are cluster concerns. The
                    # only behaviour that goes away is notification
                    # deduplication BETWEEN peers, and there are no peers.
                    "--cluster.listen-address=",
                ],
                "ports": [
                    f"${{ALERTMANAGER_LISTEN:-{plane.alertmanager.listen}}}:{alertmanager_port}"
                ],
                "volumes": [
                    f"{_RELEASE}/alertmanager:{_ALERTMANAGER_ETC}:ro",
                    f"${{OBSERVABILITY_SECRETS:-{plane.secrets_dir}}}:{_ALERTMANAGER_ETC}/secrets:ro",
                    "alertmanager_data:/alertmanager",
                ],
                "environment": {"TZ": zone},
            },
            "loki": {
                **_runtime_service(
                    bundle.loki.runtime,
                    command=[f"-config.file={_LOKI_ETC}/loki.yml"],
                    volumes=[f"{_RELEASE}/loki:{_LOKI_ETC}:ro", "loki_data:/loki"],
                    user="${LOKI_USER:-10001:10001}",
                ),
                "environment": {"TZ": zone},
            },
            "promtail": {
                **_runtime_service(
                    bundle.promtail.runtime,
                    command=[f"-config.file={_PROMTAIL_ETC}/promtail.yml"],
                    volumes=[
                        f"{_RELEASE}/promtail:{_PROMTAIL_ETC}:ro",
                        # Read-only, and both of them. A log shipper that can
                        # write to the tree it reads is a log shipper that can
                        # destroy the evidence it exists to preserve.
                        "${OBSERVABILITY_HOST_LOGS:-/var/log}:/var/log:ro",
                        "${OBSERVABILITY_CONTAINER_LOGS:-/var/lib/docker/containers}"
                        ":/var/lib/docker/containers:ro",
                        "promtail_data:/promtail",
                    ],
                    user="${PROMTAIL_USER:-0:0}",
                ),
                "environment": {"TZ": zone},
                # It reads the host's log tree, so it starts after the store it
                # ships to; `depends_on` here is ordering, not health.
                "depends_on": ["loki"],
            },
            "grafana": {
                **_runtime_service(
                    bundle.grafana.runtime,
                    command=[],
                    volumes=[
                        f"{_RELEASE}/grafana/provisioning:{_GRAFANA_PROVISIONING}:ro",
                        f"{_RELEASE}/grafana/dashboards:/etc/grafana/dashboards:ro",
                        "grafana_data:/var/lib/grafana",
                    ],
                    user="${GRAFANA_USER:-472:472}",
                ),
                "environment": {
                    # The infrastructure zone for the process, the presentation
                    # zone for what a reader sees. Two knobs because they are
                    # two decisions: a dashboard rendered in local time is
                    # presentation, and a log line written in local time is a
                    # data model.
                    "TZ": zone,
                    "GF_DATE_FORMATS_DEFAULT_TIMEZONE": (
                        bundle.timezone.presentation
                        if bundle.timezone.presentation is not None
                        else zone
                    ),
                    "GF_USERS_DEFAULT_THEME": "${GRAFANA_THEME:-dark}",
                    "GF_AUTH_ANONYMOUS_ENABLED": "false",
                    "GF_SECURITY_ADMIN_PASSWORD__FILE": (
                        "${GRAFANA_ADMIN_PASSWORD_FILE:-/run/secrets/grafana_admin_password}"
                    ),
                },
                "depends_on": ["prometheus", "loki"],
            },
        },
        "volumes": {
            "prometheus_data": {},
            "alertmanager_data": {},
            "loki_data": {},
            "promtail_data": {},
            "grafana_data": {},
        },
    }
    # A grafana command list of one empty element would be rendered; the image's
    # own entrypoint is correct, so the key is removed rather than emitted empty.
    services = cast(dict[str, dict[str, YamlValue]], document["services"])
    if not services["grafana"]["command"]:
        del services["grafana"]["command"]
    return emit(document, header=_HEADER)


# ── The bundle (ADR-0008) ───────────────────────────────────────────────────


def _meta_rules(state: DesiredState) -> str:
    """The control-plane meta alerts, including the ingestion-integrity gate.

    AGENTS.md rule 5 keeps product alert expressions in the product. These are
    not product alerts: no product can observe that the samples it emitted were
    refused at THIS evaluator's append path, or that this evaluator stopped
    evaluating, and an alert nobody can write is an alert nobody has.

    The gate is a CONJUNCTION and that is the whole point. On the Observer host
    all eighteen targets reported ``up == 1`` while 1,858,942 samples were
    rejected for carrying a duplicate timestamp — target health and ingestion
    integrity are separate facts, and a verification that reads only the first
    reports green while data is being dropped. The contract requires both
    predicates; this function is where they are joined, and it is deliberately
    the only place, so there is no second spelling of the gate to drift.
    """
    rules: list[YamlValue] = []
    for gate in state.bundle.gates:
        # `unless` rather than `and`: the alert fires when health holds and
        # integrity does NOT. Written as a conjunction of health with the
        # negation of integrity it would need the integrity predicate inverted
        # by the author, which is exactly the kind of thing an author gets
        # wrong once and nobody notices because the rule is then silent.
        rules.append(
            {
                "alert": _gate_alert_name(gate.name),
                "expr": f"({gate.health}) unless ({gate.integrity})",
                "for": gate.window,
                "labels": {"severity": "critical", "owner": "observability-control-plane"},
                "annotations": {
                    "summary": (
                        f"{gate.name}: the target is healthy and its samples are not being "
                        "stored"
                    ),
                    "description": (
                        "Target health and ingestion integrity are separate facts. This alert "
                        "fires exactly when the first holds and the second does not, which is "
                        "the state a scrape-health check reports as green."
                    ),
                },
            }
        )
    document: dict[str, YamlValue] = {
        "groups": [{"name": "control-plane-meta", "rules": rules}],
    }
    return emit(document, header=_HEADER)


def _gate_alert_name(name: str) -> str:
    return "".join(part.capitalize() for part in name.replace(".", "-").split("-"))


def _ingestion_rules(state: DesiredState) -> str:
    """The ingestion boundary's alerts: silence, drops, unmeasured, lag, deadman.

    Four alerts per stream, and the reason there are four rather than one is
    the defect this whole lane exists to repair: states that look alike.

    ``ShipperSilent`` is written with ``absent_over_time`` and NOT with a rate
    threshold. ``rate(arrivals[5m]) == 0`` looks like the same question and is
    not: when a shipper stops, its series stops existing, and a comparison
    against a series that does not exist matches no rows and produces no alert.
    Absence is the one query shape that survives the thing it watches going
    away.

    ``IntegrityUnmeasured`` exists because a drop counter reading zero because
    nothing was shipped and one reading zero because nothing was lost are the
    same number and opposite news. Giving the first its own alert is the only
    way an operator can tell them apart, and it is the same
    :data:`~dotmac_observability.ingestion.UNMEASURED` distinction the read-back
    and the health surface keep.

    ``IngestionDropping`` is delta-shaped over the declared window (AGENTS.md
    rule 30): a bare ``counter == 0`` is satisfiable by a reset, by a fresh
    store or by a restart, and a predicate made true that way cannot be told
    from one made true by a repair.

    Every deadman carries its sensitivity in its own annotations, INCLUDING
    when it has none. An operator reading an alert during an incident should
    not have to go and find out whether anybody has ever watched it fire; a
    deadman that has never fired is indistinguishable from one whose expression
    matches no series at all, which is the commonest way an alert is silently
    wrong.
    """
    policy = state.ingestion
    rules: list[YamlValue] = []
    for stream in policy.streams:
        signal = stream.signal
        rules.append(
            {
                "alert": _gate_alert_name(f"{signal}-shipper-silent"),
                "expr": f"absent_over_time({stream.arrival_counter}[{stream.silence_budget}])",
                "labels": {"severity": "critical", "owner": "observability-control-plane"},
                "annotations": {
                    "summary": (f"{signal}: nothing has arrived for {stream.silence_budget}"),
                    "description": (
                        "Written as an ABSENCE rather than a rate threshold. A stopped shipper "
                        "takes its series with it, and a comparison against a series that no "
                        "longer exists matches no rows and fires nothing — which is the "
                        "failure mode a metrics pipeline is worst at noticing."
                    ),
                },
            }
        )
        rules.append(
            {
                "alert": _gate_alert_name(f"{signal}-integrity-unmeasured"),
                "expr": f"absent({stream.integrity_counter})",
                "labels": {"severity": "warning", "owner": "observability-control-plane"},
                "annotations": {
                    "summary": (
                        f"{signal}: {stream.integrity_counter} has never been observed, so "
                        "nothing is known about whether records are being dropped"
                    ),
                    "description": (
                        "UNMEASURED is not zero. A drop counter reading zero because nothing "
                        "was shipped and one reading zero because nothing was lost are the "
                        "same number and opposite news; this alert is what keeps them apart."
                    ),
                },
            }
        )
        rules.append(
            {
                "alert": _gate_alert_name(f"{signal}-ingestion-dropping"),
                "expr": (f"increase({stream.integrity_counter}[{stream.integrity_window}]) > 0"),
                "for": stream.integrity_window,
                "labels": {"severity": "critical", "owner": "observability-control-plane"},
                "annotations": {
                    "summary": f"{signal}: records arrived and were not stored",
                    "description": (
                        "Delta-shaped over the declared window, never `== 0` against the "
                        "absolute counter: a bare zero is satisfiable by a reset, a fresh "
                        "store or a restart, and a predicate made true that way cannot be "
                        "told from one made true by a repair (AGENTS.md rule 30)."
                    ),
                },
            }
        )
        if stream.lag_expr is None or stream.lag_budget is None:
            # Deliberately no alert. A stream whose lag nothing measures gets a
            # declared `lag_unmeasured` in the contract instead, because the
            # alternative — an expression over a metric nothing emits — renders
            # a rule that can never fire, and a rule that can never fire reads
            # on every dashboard exactly like one that is quietly passing.
            continue
        rules.append(
            {
                "alert": _gate_alert_name(f"{signal}-ingestion-lag"),
                "expr": f"{stream.lag_expr} > {_seconds(stream.lag_budget)}",
                "for": stream.lag_budget,
                "labels": {"severity": "warning", "owner": "observability-control-plane"},
                "annotations": {
                    "summary": (f"{signal}: the store is more than {stream.lag_budget} behind"),
                    "description": (
                        "Lag is a third fact, separate from arrival and from integrity. A "
                        "stream can be arriving and storing cleanly and still be far enough "
                        "behind that a query answers about a system that no longer exists."
                    ),
                },
            }
        )

    for deadman in policy.deadman.signals:
        proved = deadman.sensitivity.last_proved
        rules.append(
            {
                "alert": _gate_alert_name(deadman.name),
                "expr": deadman.expr,
                "for": deadman.hold,
                "labels": {"severity": "critical", "owner": "observability-control-plane"},
                "annotations": {
                    "summary": deadman.summary,
                    "sensitivity": (
                        f"planted condition last proved {proved}: "
                        f"{deadman.sensitivity.planted_condition}"
                        if proved is not None
                        else (
                            "UNPROVED — this deadman has never been observed to fire, so it "
                            "is not known to work. It is indistinguishable from one whose "
                            "expression matches no series at all. Planted condition: "
                            f"{deadman.sensitivity.planted_condition}"
                        )
                    ),
                    "procedure": deadman.sensitivity.procedure_ref,
                },
            }
        )

    projection = policy.projection
    # A `planned` projection renders no lag alert, for the same reason an
    # unmeasured stream renders none: the metric does not exist, so the rule
    # would be permanently silent and permanently silent is what all-clear
    # looks like. Everything else about the projection — its retention bound,
    # its rebuild verdict, its non-authority notice — is declared and gated
    # while the status is `planned`, because those are the decisions that get
    # argued about rather than declared once the thing exists.
    if projection.status == "live":
        rules.append(
            {
                "alert": _gate_alert_name(f"{projection.name}-lag"),
                "expr": f"{projection.lag_expr} > {_seconds(projection.lag_budget)}",
                "for": projection.lag_budget,
                "labels": {"severity": "warning", "owner": "observability-control-plane"},
                "annotations": {
                    "summary": (
                        f"{projection.name}: the audit projection is more than "
                        f"{projection.lag_budget} behind {projection.derived_from}"
                    ),
                    "description": projection.non_authority_notice,
                },
            }
        )

    document: dict[str, YamlValue] = {
        "groups": [{"name": "ingestion-meta", "rules": rules}],
    }
    return emit(document, header=_HEADER)


def _seconds(duration: str) -> str:
    """A declared duration as the integer seconds a PromQL comparison needs.

    Rendered from the SAME string the alert's `for` clause carries, so the
    threshold and the hold cannot drift apart into an alert that fires on one
    budget and holds for another.
    """
    value = duration_seconds(duration)
    return str(int(value)) if value.is_integer() else str(value)


def _loki(state: DesiredState) -> str:
    loki = state.bundle.loki
    document: dict[str, YamlValue] = {
        "auth_enabled": False,
        "server": {
            "http_listen_port": int(_port(loki.runtime.listen)),
            # Explicit rather than defaulted. Loki's default gRPC port is a
            # listening socket nobody declared, and rule 19 has no vocabulary
            # for a surface that exists by omission.
            "grpc_listen_port": 0,
            "log_format": "json",
        },
        "common": {
            # The DECLARED bind host, not a literal. Loki's single-binary ring
            # registers under this address, and hardcoding a loopback here
            # would survive every environment — which is rule 14's whole point,
            # and is what `test_no_source_file_hardcodes_a_host` caught when
            # this line was first written as a constant.
            "instance_addr": _host(loki.runtime.listen),
            "path_prefix": "/loki",
            "storage": {
                "filesystem": {
                    "chunks_directory": "/loki/chunks",
                    "rules_directory": "/loki/rules",
                }
            },
            "replication_factor": 1,
            "ring": {"kvstore": {"store": "inmemory"}},
        },
        "schema_config": {
            "configs": [
                {
                    "from": "2020-10-24",
                    "store": "tsdb",
                    "object_store": "filesystem",
                    "schema": "v13",
                    "index": {"prefix": "index_", "period": "24h"},
                }
            ]
        },
        "limits_config": {
            "reject_old_samples": True,
            "reject_old_samples_max_age": loki.reject_older_than,
            "ingestion_rate_mb": loki.ingestion_rate_mb,
            "ingestion_burst_size_mb": loki.ingestion_burst_mb,
            "retention_period": loki.retention,
            # The ingestion contract's label budget, rendered into the store's
            # own limit rather than restated. A label is an index dimension and
            # the product of every label's value set is how many streams the
            # store keeps open, so the number a reviewer reads in
            # `inventory/ingestion.toml` and the number the store enforces have
            # to be one number — otherwise the document describes a policy the
            # store has never been told about.
            "max_label_names_per_series": state.ingestion.labels.max_stream_labels,
        },
        "compactor": {
            "working_directory": "/loki/compactor",
            # Without this the retention above is a comment: the limit is
            # recorded, no compactor enforces it, and the volume fills.
            "retention_enabled": True,
            "delete_request_store": "filesystem",
        },
        "ruler": {
            "alertmanager_url": (
                f"http://alertmanager:{_port(state.control_plane.alertmanager.listen)}"
            )
        },
    }
    return emit(document, header=_HEADER)


def _promtail(state: DesiredState) -> str:
    promtail = state.bundle.promtail
    jobs: list[YamlValue] = []
    for job in promtail.jobs:
        labels = _labels_mapping(job.labels)
        labels["__path__"] = job.path_glob
        entry: dict[str, YamlValue] = {
            "job_name": job.name,
            "static_configs": [{"targets": ["localhost"], "labels": labels}],
        }
        if job.decode_docker_json:
            entry["pipeline_stages"] = [
                {"json": {"expressions": {"log": "log", "stream": "stream", "time": "time"}}},
                {"output": {"source": "log"}},
            ]
        jobs.append(entry)
    document: dict[str, YamlValue] = {
        "server": {"http_listen_port": int(_port(promtail.runtime.listen)), "grpc_listen_port": 0},
        # Under /promtail rather than /tmp. A positions file in /tmp is cleared
        # by the host's own cleanup, and a shipper that loses its positions
        # re-reads every rotated file it can still see — which is how a log
        # store gains a day of duplicates from a reboot.
        "positions": {"filename": "/promtail/positions.yaml"},
        "clients": [
            {"url": f"http://loki:{_port(state.bundle.loki.runtime.listen)}/loki/api/v1/push"}
        ],
        "scrape_configs": jobs,
    }
    return emit(document, header=_HEADER)


def _grafana_datasources(state: DesiredState, resolution: Resolution) -> str:
    ports = {entry.name: entry.port for entry in state.bundle.roster if entry.kind == "service"}
    sources: list[YamlValue] = []
    for source in state.bundle.grafana.datasources:
        if source.service is not None:
            url = f"http://{source.service}:{ports[source.service]}"
        else:
            url = resolution.datasources[source.name].url
        entry: dict[str, YamlValue] = {
            "name": source.name,
            "type": source.kind,
            "access": "proxy",
            # Derived from the local roster or from the already-proved private
            # target resolution, never typed in. Both paths have one owner and
            # neither lets this public bundle disclose or invent an endpoint.
            "url": url,
            "isDefault": source.default,
            "editable": False,
        }
        if source.uid is not None:
            entry["uid"] = source.uid
        sources.append(entry)
    return emit({"apiVersion": 1, "datasources": sources}, header=_HEADER)


def _grafana_dashboards(state: DesiredState) -> str:
    providers: list[YamlValue] = []
    for provider in state.bundle.grafana.dashboard_providers:
        providers.append(
            {
                "name": provider.name,
                "orgId": 1,
                "folder": provider.folder,
                "type": "file",
                # A provisioned dashboard is not editable in the browser. That
                # is the point of provisioning it: an editable copy diverges
                # from the file, and the file is what the next release ships.
                "disableDeletion": True,
                "allowUiUpdates": False,
                "options": {
                    "path": f"/etc/grafana/dashboards/{provider.name}",
                    "foldersFromFilesStructure": False,
                },
            }
        )
    return emit({"apiVersion": 1, "providers": providers}, header=_HEADER)


def _grafana_plugins() -> str:
    """Materialize Grafana's optional plugin provisioning directory cleanly."""
    return emit({"apiVersion": 1, "apps": []}, header=_HEADER)


def _grafana_alerting() -> str:
    """Materialize Grafana's optional alerting provisioning directory cleanly."""
    return emit({"apiVersion": 1}, header=_HEADER)


def _timezone(state: DesiredState) -> str:
    """The declared infrastructure zone, as the one line ``timedatectl`` reads.

    A file rather than a command in a runbook, because the zone is part of the
    bundle's identity: a promotion that activated a bundle onto a host in
    another zone would produce receipts and rotations whose timestamps cannot
    be compared with any other host's, and nothing would say so.
    """
    return f"{state.bundle.timezone.infrastructure}\n"


def _rsyslog(state: DesiredState) -> str:
    """The Observer-owned facility routing.

    It states ownership and mode for every file it names — the thing the host's
    own configuration did not do, and the reason a privilege-dropped rsyslog
    suspended one action ten thousand times in thirty days while the mail
    facility went nowhere. Owner, group and mode are set with `FileOwner`,
    `FileGroup` and `FileCreateMode` immediately before the action that uses
    them, because rsyslog's directives are POSITIONAL: a global block at the top
    of the file governs what comes after it, and an action written above one is
    governed by whatever the previous file left behind.
    """
    syslog = state.bundle.syslog
    lines = [
        f"# {line}".rstrip()
        for line in (
            *_HEADER,
            "",
            "Every action below states its own owner, group and mode. rsyslog's",
            "directives are positional: an action written above the block that sets",
            "them inherits whatever the previously included file left behind, which",
            "is how a file ends up owned by whoever happened to be configured last.",
            "",
            "rsyslog creates NO directory. The tmpfiles configuration rendered",
            "alongside this file owns the directory and the files, as root, with the",
            "declared ownership; a privilege-dropped writer that also creates its own",
            "parents would create them owned by itself, with whatever mode its umask",
            "gave, and the declaration here would describe something that had already",
            "happened differently.",
        )
    ]
    lines.append("")
    lines.append("$CreateDirs off")
    for entry in syslog.files:
        prefix = "" if entry.synchronous else "-"
        lines += [
            "",
            f"$FileOwner {entry.owner}",
            f"$FileGroup {entry.group}",
            f"$FileCreateMode {entry.mode}",
            f"{entry.facility}\t\t\t{prefix}{entry.path}",
        ]
    return "\n".join(lines) + "\n"


def _tmpfiles(state: DesiredState) -> str:
    """The half that actually fixes the suspension storm.

    rsyslog could not create ``/var/log/mail.log`` because it runs as the
    ``syslog`` user and ``/var/log`` is ``root:syslog 0755`` — group read and
    execute, no write. The tempting repair is to widen the directory. This is
    the other one: systemd-tmpfiles, which runs as root at boot and on demand,
    creates the file with the declared owner and mode, and rsyslog then only
    ever has to APPEND to a file it already owns. The directory stays 0755.

    ``f`` rather than ``f+``: create if absent, leave the contents alone if
    present. ``f+`` truncates, which would delete a day of logs every boot.
    """
    directory = state.bundle.syslog.directory
    lines = [f"# {line}".rstrip() for line in _HEADER]
    lines.append(f"d {directory.path} {directory.mode} {directory.owner} {directory.group} -")
    for entry in state.bundle.syslog.files:
        lines.append(f"f {entry.path} {entry.mode} {entry.owner} {entry.group} -")
    return "\n".join(lines) + "\n"


def _logrotate(state: DesiredState) -> str:
    """Rotation that RECREATES the file, with the owner and mode stated.

    ``create`` with no arguments — which is what the host's global
    ``logrotate.conf`` supplies — reuses the ORIGINAL file's owner and mode.
    That works right up until the original file does not exist, at which point
    ``missingok`` skips the stanza entirely and rsyslog is left to create it
    itself, which it cannot. Stating the three values here removes the
    dependency on a file that may not be there.

    ``su`` names the privilege logrotate drops to for this stanza. Without it
    logrotate refuses to rotate inside a directory it does not own on a modern
    distribution, and the refusal is a warning in a cron mail nobody reads.

    ``postrotate`` reopens rsyslog's descriptors. Rotation renames the inode;
    a writer holding the old descriptor keeps writing into a file with no name
    until something tells it to reopen, and `copytruncate` — the usual
    shortcut — loses whatever was written between the copy and the truncate.
    """
    syslog = state.bundle.syslog
    directory = syslog.directory
    rotation = syslog.rotation
    lines = [f"# {line}".rstrip() for line in _HEADER]
    lines.append("")
    for entry in syslog.files:
        lines.append(entry.path)
    lines.append("{")
    lines.append(f"    su {directory.owner} {directory.group}")
    lines.append(f"    {rotation.frequency}")
    lines.append(f"    rotate {rotation.keep}")
    if rotation.compress:
        lines.append("    compress")
        # Compressing the newest rotation races the writer that has not yet
        # reopened. Delaying it by one cycle is the standard repair and is
        # emitted with `compress` rather than left to the operator.
        lines.append("    delaycompress")
    lines.append("    missingok")
    lines.append("    notifempty")
    lines.append("    sharedscripts")
    owners = {(entry.owner, entry.group, entry.mode) for entry in syslog.files}
    if len(owners) == 1:
        owner, group, mode = next(iter(owners))
        lines.append(f"    create {mode} {owner} {group}")
    else:
        # Several ownerships in one stanza cannot share a `create`. Rather than
        # pick one and be silently wrong for the others, the renderer refuses:
        # a bundle whose syslog files disagree about ownership needs a stanza
        # each, and that is a contract change, not a rendering trick.
        raise ValueError(
            "syslog files declare more than one owner/group/mode combination; a single "
            f"logrotate stanza cannot create all of them ({sorted(owners)})"
        )
    lines.append("    postrotate")
    lines.append("        /usr/lib/rsyslog/rsyslog-rotate")
    lines.append("    endscript")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _exposure_rules(state: DesiredState, resolution: Resolution, family: str) -> str:
    """iptables-restore fragments for one address family.

    Two properties this function exists to guarantee, both of which the host
    got wrong.

    THE CHAIN COMES FROM THE FAMILY AND THE SURFACE KIND, never from the
    author. An IPv4 container publish traverses ``FORWARD`` and therefore
    ``DOCKER-USER``; IPv6 to a published port terminates on ``INPUT``. Seven
    IPv6 DROP rules were found sitting in ``DOCKER-USER`` on this host, where no
    such packet ever arrives, so every port they name is open on IPv6 while the
    ruleset reads as though it is closed.

    THE SOURCE IS A NAMED SET, resolved late. A ``tunnel_interface`` set
    renders ``-i <interface>``, which is what a WireGuard peer set actually is:
    membership is cryptographic, so matching the interface is both simpler and
    stricter than matching a prefix. This is ``iptables`` — ``-i``, not
    nftables' ``iifname``, which has been carried across from another host's
    ruleset once already and is silently accepted by nothing.
    """
    lines = [f"# {line}".rstrip() for line in _HEADER]
    lines.append(f"# address family: {family}")
    lines.append("*filter")
    for surface in state.bundle.exposure.surfaces:
        if family not in _families(surface):
            continue
        chain = _chain_for(surface, family)
        lines.append("")
        lines.append(
            f"# {surface.name}: {surface.exposure} {surface.protocol}/{surface.port} "
            f"({surface.kind}, {family} terminates on {chain})"
        )
        match = f"-p {surface.protocol} --dport {surface.port}"
        if surface.exposure in ("none", "loopback"):
            # A loopback surface is not published at all, so the rule is a
            # terminal refusal of everything that arrives from outside. Stated
            # rather than omitted: an absent rule and a closed one look
            # identical in a diff and behave differently under a default-accept
            # policy, which is what this host has.
            lines.append(f"-A {chain} {match} -j DROP")
            continue
        lines.append(f"-A {chain} {match} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        if surface.exposure == "public":
            lines.append(f"-A {chain} {match} -j ACCEPT")
            continue
        assert surface.allow_from is not None  # proved by the semantic gate
        binding = resolution.source_sets[surface.allow_from]
        if binding.interface is not None:
            lines.append(f"-A {chain} -i {binding.interface} {match} -j ACCEPT")
        for prefix in binding.prefixes:
            lines.append(f"-A {chain} -s {prefix} {match} -j ACCEPT")
        lines.append(f"-A {chain} {match} -j DROP")
    lines.append("")
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def _families(surface: Surface) -> tuple[str, ...]:
    if surface.family == "dual_stack":
        return ("ipv4", "ipv6")
    return (surface.family,)


def _chain_for(surface: Surface, family: str) -> str:
    """Which chain a packet to this surface actually traverses.

    Not a preference. A host service is reached on ``INPUT`` in both families.
    A container publish is forwarded for IPv4 — so ``DOCKER-USER``, the chain
    Docker leaves for exactly this — and terminates on ``INPUT`` for IPv6,
    because the published v6 socket is held by the userland proxy on the host
    rather than DNAT'd through the forward path.
    """
    if surface.kind == "container_published" and family == "ipv4":
        return "DOCKER-USER"
    return "INPUT"


def _runtime_service(
    runtime: Runtime,
    *,
    command: list[YamlValue],
    volumes: list[YamlValue],
    user: str,
) -> dict[str, YamlValue]:
    port = _port(runtime.listen)
    return {
        "image": f"{runtime.image}@{runtime.digest}",
        "restart": "${OBSERVABILITY_RESTART:-unless-stopped}",
        "user": user,
        "command": command,
        "ports": [f"{runtime.listen}:{port}"],
        "volumes": volumes,
    }


def render_control_plane(state: DesiredState, resolution: Resolution) -> RenderedTree:
    """Render every configuration file for ``state``, in a fixed order.

    ``resolution`` supplies every endpoint and credential binding. It is a
    required argument rather than an optional one because a render without it
    would be a render of a control plane that scrapes nothing, and a signature
    that permits that invites a caller to produce one.
    """
    return (
        (PROMETHEUS_CONFIG, _prometheus(state, resolution)),
        (META_RULES, _meta_rules(state)),
        (INGESTION_RULES, _ingestion_rules(state)),
        (ALERTMANAGER_CONFIG, _alertmanager(state, resolution)),
        (LOKI_CONFIG, _loki(state)),
        (PROMTAIL_CONFIG, _promtail(state)),
        (GRAFANA_DATASOURCES, _grafana_datasources(state, resolution)),
        (GRAFANA_DASHBOARDS, _grafana_dashboards(state)),
        (GRAFANA_PLUGINS, _grafana_plugins()),
        (GRAFANA_ALERTING, _grafana_alerting()),
        (RSYSLOG_CONFIG, _rsyslog(state)),
        (LOGROTATE_CONFIG, _logrotate(state)),
        (TMPFILES_CONFIG, _tmpfiles(state)),
        (TIMEZONE_FILE, _timezone(state)),
        (EXPOSURE_IPV4, _exposure_rules(state, resolution, "ipv4")),
        (EXPOSURE_IPV6, _exposure_rules(state, resolution, "ipv6")),
        (COMPOSE_FILE, _compose(state)),
    )


def tree_digest(tree: RenderedTree) -> str:
    """A digest over paths AND contents, recorded in every promotion receipt.

    Both halves are hashed: a rendering that moved a file without changing any
    byte inside it is still a different deployment.
    """
    digest = hashlib.sha256()
    for path, text in tree:
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(text.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def file_digest(contents: str) -> str:
    """One rendered file's digest, as a live read-back reports it.

    Here rather than in the verifier because the renderer owns what a rendered
    file IS, digest included. A comparison module computing its own would be a
    second answer to that question, and the two would agree right up until one
    of them learned about an encoding the other did not.
    """
    return hashlib.sha256(contents.encode("utf-8")).hexdigest()


def write_tree(tree: RenderedTree, destination: Path) -> None:
    for path, text in tree:
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def differences(tree: RenderedTree, destination: Path) -> tuple[str, ...]:
    """Paths whose committed bytes disagree with a fresh render.

    Includes files that are missing on disk and files on disk that the
    renderer no longer produces — a stale file left behind still gets mounted
    into the evaluator.
    """
    drifted: list[str] = []
    rendered = dict(tree)
    for path, text in tree:
        target = destination / path
        if not target.is_file():
            drifted.append(f"{path} (missing)")
        elif target.read_text(encoding="utf-8") != text:
            drifted.append(f"{path} (differs)")
    if destination.is_dir():
        for existing in sorted(destination.rglob("*")):
            if not existing.is_file():
                continue
            relative = existing.relative_to(destination).as_posix()
            if relative not in rendered:
                drifted.append(f"{relative} (unexpected)")
    return tuple(drifted)
