"""Schema validation, typed loading, and the semantic gates.

Three layers, deliberately separate:

* **Schema** — ``contracts/*.schema.json`` decides whether a document is
  well-formed. Shape questions belong here so a malformed file fails the same
  way for every reader.
* **Loading** — a validated document becomes a frozen :mod:`.model` record.
  Nothing is constructed from an unvalidated document, so the model never has
  to defend against shapes the schema already refused.
* **Semantics** — the questions no single document can answer, because they
  are about the relationships BETWEEN documents: does this route's receiver
  exist, is this job name unique across products, does this federation rename
  what it imports.
* **Resolution** — the questions that need the PRIVATE inventory as well
  (ADR-0004): does this logical target actually resolve, does a job that claims
  to authenticate have a credential behind it, can an ``expected`` up-count be
  met by the endpoints that exist.

The fourth layer is not a fourth kind of check so much as the same semantic
question asked across the public/private boundary, and it is separate because
its INPUT is separate: public gates run for any reader of this repository,
resolution gates need material a public reader does not have. Keeping them
apart is what lets ``make check`` stay meaningful on a checkout while a
promotion still refuses an inventory that does not join.

Findings are returned, not raised. A caller that stops at the first problem
makes an operator re-run the gate once per mistake; the CLI prints all of them
and exits non-zero once.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import TypeAlias, cast

import jsonschema

from .model import (
    Bundle,
    ControlPlane,
    DesiredState,
    DirectoryContract,
    Evaluator,
    Exposure,
    Federation,
    FederationBinding,
    FederationSource,
    Grafana,
    GrafanaDashboardProvider,
    GrafanaDatasource,
    Host,
    HostBinding,
    Inhibition,
    Integration,
    Label,
    Loki,
    PrivateInventory,
    Promtail,
    PromtailJob,
    Publication,
    Receiver,
    ReceiverBinding,
    Resolution,
    ResolvedEndpoint,
    ResolvedReceiver,
    RetiredProduct,
    RosterEntry,
    Rotation,
    Route,
    RouteDefaults,
    Runtime,
    ScrapeJob,
    SecretFile,
    Smtp,
    SourceSet,
    SourceSetBinding,
    Surface,
    Syslog,
    SyslogFile,
    TargetBinding,
    TargetSet,
    Timezone,
    VerificationGate,
)

__all__ = [
    "ACCEPTED_SCHEMA_VERSION",
    "CAPTURE_SCHEMA_VERSION",
    "PRIVATE_SCAN_EXCLUSIONS",
    "SECRET_SCAN_EXCLUSIONS",
    "CaptureInventory",
    "Finding",
    "InventoryError",
    "MigrationPlan",
    "SupersedeSummary",
    "SupersessionRequest",
    "apply_supersession",
    "canonical_bytes",
    "canonical_digest",
    "classify_stored_inventory",
    "load",
    "load_capture_inventory",
    "load_private_inventory",
    "load_supersession_request",
    "migrate_capture",
    "migration_findings",
    "private_material_findings",
    "resolution_findings",
    "resolve",
    "retirement_findings",
    "scan_for_private_material",
    "scan_for_secret_material",
    "semantic_findings",
    "supersede_findings",
    "supersede_summary",
    "validate",
]

Document: TypeAlias = Mapping[str, object]

# Documented defaults for every optional control-plane knob (AGENTS.md rule
# 14). They live here, once, rather than being spelled again in the renderer.
DEFAULT_SCRAPE_INTERVAL = "30s"
DEFAULT_SCRAPE_TIMEOUT = "10s"
DEFAULT_EVALUATION_INTERVAL = "30s"
DEFAULT_RESOLVE_TIMEOUT = "5m"
# A HOST path. It was briefly spelled "/etc/prometheus/secrets", which is
# where the directory is mounted INSIDE the Prometheus container — a
# coincidence that reads as a copy-paste and invites an operator to create
# the directory in the wrong filesystem. The two namespaces are kept
# visibly distinct: the host side is configurable and lives under the
# deployment root, the container side is a renderer constant.
DEFAULT_SECRETS_DIR = "/opt/observability/secrets"
# The conventional metrics path. Not a knob: it is the value against which a
# non-default path is asked to explain itself (ADR-0004's first open
# classification, settled by METRICS-PATH-UNEXPLAINED). Making it
# configurable would let a deployment redefine what counts as conventional,
# which is the one thing the gate needs to be fixed.
DEFAULT_METRICS_PATH = "/metrics"
# IPv4 loopback. The evaluators bind an IPv4 address by contract
# (`listen` matches `^[0-9.]+:[0-9]{1,5}$`), so a v6 form cannot reach here;
# if that pattern ever widens, this prefix widens with it or the gate stops
# seeing half the addresses it exists to refuse.
_LOOPBACK_PREFIX = "127."


_INTEGER = re.compile(r"^-?[0-9]+$")

# What an INGESTION predicate has to be about. A closed vocabulary rather than
# a free-text field, because the gate this list defends is the one Observer did
# not have: eighteen targets reporting `up == 1` while 1,858,942 samples were
# refused at append. Every token below names a counter that only moves when a
# sample the scrape returned was NOT stored, so a predicate mentioning none of
# them is a predicate about something other than whether the data arrived.
# A predicate is DELTA-SHAPED when its counter is wrapped in one of these.
#
# The distinction is condition 4 of a `deployed_repaired` verdict, and it is
# the one an acceptance pass gets wrong. `<counter> == 0` is satisfiable by
# RESETTING the counter, or by a fresh TSDB, or by a container that restarted —
# and a predicate made true that way is indistinguishable from one made true by
# a repair. Observer's counter stands at ~1.86 million historical rejections;
# the assertion that matters is that it does not GROW from a recorded baseline,
# which is a statement about a delta and cannot be made true by deletion.
_RANGE_FUNCTIONS = frozenset({"increase", "rate", "irate", "delta", "idelta", "resets"})

_INGESTION_TOKENS = frozenset(
    {
        "duplicate_timestamp",
        "out_of_order",
        "out_of_bounds",
        "sample_limit",
        "exemplar_out_of_order",
        "samples_post_metric_relabeling",
        "invalid_series",
        "too_old",
    }
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One refusal, with enough detail to fix it without re-running anything."""

    code: str
    location: str
    message: str

    def render(self) -> str:
        return f"{self.code}  {self.location}: {self.message}"


class InventoryError(Exception):
    """Raised when the inventory cannot be loaded at all.

    Carries every finding rather than the first, for the same reason
    :func:`validate` returns a list.
    """

    def __init__(self, findings: Sequence[Finding]) -> None:
        self.findings = tuple(findings)
        super().__init__("; ".join(finding.render() for finding in self.findings))


# ── Schema layer ────────────────────────────────────────────────────────────


@cache
def _schema(contracts: Path, name: str) -> Mapping[str, object]:
    import json

    with (contracts / f"{name}.schema.json").open("rb") as handle:
        loaded: Mapping[str, object] = json.load(handle)
    return loaded


def _validate_document(
    contracts: Path, name: str, document: Document, location: str
) -> list[Finding]:
    validator = jsonschema.Draft202012Validator(_schema(contracts, name))
    findings: list[Finding] = []
    # Sorted so two runs over the same broken file report in the same order;
    # an unstable error list makes a CI diff unreadable.
    for error in sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path)):
        path = "/".join(str(part) for part in error.absolute_path) or "<root>"
        findings.append(Finding("SCHEMA", f"{location}#{path}", error.message))
    return findings


def _read_toml(path: Path) -> Document:
    with path.open("rb") as handle:
        loaded: Document = tomllib.load(handle)
    return loaded


# ── Loading layer ───────────────────────────────────────────────────────────
#
# Every accessor below assumes the schema already ran. The casts are safe for
# that reason and for no other; construct a record from an unvalidated
# document and they stop being safe.


def _mapping(value: object) -> Mapping[str, object]:
    """Narrow a validated sub-document.

    The three helpers here are the ONLY place this module asserts a shape mypy
    cannot see, and each is safe for exactly one reason: the JSON Schema layer
    ran first and refused anything else. A scattering of `# type: ignore`
    comments would make the same assertion in a form that also hides real
    errors, and that reads as "mypy is wrong" rather than "this was proved
    upstream".
    """
    return cast(Mapping[str, object], value)


def _rows(value: object) -> Sequence[Mapping[str, object]]:
    return cast(Sequence[Mapping[str, object]], value)


def _strings(value: object) -> tuple[str, ...]:
    return tuple(str(item) for item in cast(Sequence[object], value))


def _labels(raw: object) -> tuple[Label, ...]:
    if raw is None:
        return ()
    return tuple(Label(name=str(row["name"]), value=str(row["value"])) for row in _rows(raw))


def _secret(raw: object) -> SecretFile | None:
    if raw is None:
        return None
    row = _mapping(raw)
    return SecretFile(openbao_path=str(row["openbao_path"]), file_name=str(row["file_name"]))


def _evaluator(raw: Mapping[str, object]) -> Evaluator:
    return Evaluator(
        image=str(raw["image"]),
        digest=str(raw["digest"]),
        version=str(raw["version"]) if "version" in raw else None,
        listen=str(raw["listen"]),
    )


def _smtp(raw: object) -> Smtp | None:
    if raw is None:
        return None
    row = _mapping(raw)
    return Smtp(
        smarthost=str(row["smarthost"]),
        sender=str(row["from"]),
        auth_username=str(row["auth_username"]) if "auth_username" in row else None,
        require_tls=bool(row.get("require_tls", True)),
    )


def _control_plane(document: Document) -> ControlPlane:
    host = _mapping(document["host"])
    return ControlPlane(
        environment=str(document["environment"]),
        host=Host(target_id=str(host["target_id"])),
        prometheus=_evaluator(_mapping(document["prometheus"])),
        alertmanager=_evaluator(_mapping(document["alertmanager"])),
        release_root=str(document["release_root"]),
        secrets_dir=str(document.get("secrets_dir", DEFAULT_SECRETS_DIR)),
        external_labels=_labels(document["external_labels"]),
        scrape_interval=str(document.get("scrape_interval", DEFAULT_SCRAPE_INTERVAL)),
        scrape_timeout=str(document.get("scrape_timeout", DEFAULT_SCRAPE_TIMEOUT)),
        evaluation_interval=str(document.get("evaluation_interval", DEFAULT_EVALUATION_INTERVAL)),
        resolve_timeout=str(document.get("resolve_timeout", DEFAULT_RESOLVE_TIMEOUT)),
        smtp=_smtp(document.get("smtp")),
    )


def _publication(raw: object) -> Publication | None:
    if raw is None:
        return None
    row = _mapping(raw)
    return Publication(
        endpoints=_strings(row["endpoints"]),
        rationale=str(row["rationale"]),
    )


def _target_set(document: Document) -> TargetSet:
    jobs = _rows(document["jobs"])
    return TargetSet(
        product=str(document["product"]),
        owner=str(document["owner"]),
        jobs=tuple(
            ScrapeJob(
                job=str(job["job"]),
                target_id=str(job["target_id"]),
                scheme=str(job["scheme"]),
                metrics_path=str(job["metrics_path"]),
                authenticated=bool(job["authenticated"]),
                labels=_labels(job.get("labels")),
                static_labels=_labels(job.get("static_labels")),
                params=_params(job.get("params")),
                scrape_interval=str(job["scrape_interval"]) if "scrape_interval" in job else None,
                scrape_timeout=str(job["scrape_timeout"]) if "scrape_timeout" in job else None,
                publication=_publication(job.get("publication")),
                path_rationale=(str(job["path_rationale"]) if "path_rationale" in job else None),
                expected=int(cast(int, job["expected"])) if "expected" in job else None,
            )
            for job in jobs
        ),
    )


def _federation(document: Document) -> Federation:
    source = _mapping(document["source"])
    return Federation(
        name=str(document["name"]),
        target_id=str(document["target_id"]),
        owner=str(document["owner"]),
        source=FederationSource(
            scheme=str(source["scheme"]),
            path=str(source["path"]),
            authenticated=bool(source["authenticated"]),
        ),
        match=_strings(document["match"]),
        rename_prefix=str(document["rename_prefix"]),
        labels=_labels(document.get("labels")),
        scrape_interval=(
            str(document["scrape_interval"]) if "scrape_interval" in document else None
        ),
    )


def _receivers(document: Document) -> tuple[Receiver, ...]:
    rows = _rows(document["receivers"])
    out: list[Receiver] = []
    for row in rows:
        integrations = _rows(row["integrations"])
        out.append(
            Receiver(
                name=str(row["name"]),
                owner=str(row["owner"]),
                integrations=tuple(
                    Integration(
                        kind=str(item["type"]),
                        credential_ref=str(item["credential_ref"]),
                        send_resolved=bool(item.get("send_resolved", True)),
                    )
                    for item in integrations
                ),
                null_policy=str(row["null_policy"]) if "null_policy" in row else None,
            )
        )
    return tuple(out)


def _policies(document: Document) -> tuple[RouteDefaults, tuple[Route, ...]]:
    raw_defaults = _mapping(document["defaults"])
    defaults = RouteDefaults(
        receiver=str(raw_defaults["receiver"]),
        group_by=_strings(raw_defaults["group_by"]),
        group_wait=str(raw_defaults["group_wait"]),
        group_interval=str(raw_defaults["group_interval"]),
        repeat_interval=str(raw_defaults["repeat_interval"]),
    )
    rows = _rows(document["routes"])
    routes = tuple(
        Route(
            identifier=str(row["id"]),
            matchers=_strings(row["matchers"]),
            receiver=str(row["receiver"]),
            keep_going=bool(row.get("continue", False)),
            group_by=_strings(row["group_by"]) if "group_by" in row else None,
            group_wait=str(row["group_wait"]) if "group_wait" in row else None,
            group_interval=str(row["group_interval"]) if "group_interval" in row else None,
            repeat_interval=str(row["repeat_interval"]) if "repeat_interval" in row else None,
        )
        for row in rows
    )
    return defaults, routes


def _inhibitions(document: Document) -> tuple[Inhibition, ...]:
    rows = _rows(document["rules"])
    return tuple(
        Inhibition(
            identifier=str(row["id"]),
            source_matchers=_strings(row["source_matchers"]),
            target_matchers=_strings(row["target_matchers"]),
            equal=_strings(row["equal"]),
            rationale=str(row["rationale"]),
        )
        for row in rows
    )


# ── The bundle (ADR-0008) ───────────────────────────────────────────────────


def _runtime(raw: Mapping[str, object]) -> Runtime:
    return Runtime(
        image=str(raw["image"]),
        digest=str(raw["digest"]),
        version=str(raw["version"]) if "version" in raw else None,
        listen=str(raw["listen"]),
    )


def _params(raw: object) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Ordered pairs, in the order TOML declared them.

    ``tomllib`` preserves table order, so this is deterministic without
    sorting — which matters, because sorting here would silently reorder a
    rendered scrape config and make a byte diff say something the author did
    not do.
    """
    if raw is None:
        return ()
    table = _mapping(raw)
    return tuple((name, _strings(values)) for name, values in table.items())


def _bundle(document: Document) -> Bundle:
    timezone = _mapping(document["timezone"])
    loki = _mapping(document["loki"])
    promtail = _mapping(document["promtail"])
    grafana = _mapping(document["grafana"])
    syslog = _mapping(document["syslog"])
    directory = _mapping(syslog["directory"])
    rotation = _mapping(syslog["rotation"])
    exposure = _mapping(document["exposure"])
    verification = _mapping(document["verification"])
    return Bundle(
        timezone=Timezone(
            infrastructure=str(timezone["infrastructure"]),
            presentation=(str(timezone["presentation"]) if "presentation" in timezone else None),
            rationale=str(timezone["rationale"]),
        ),
        loki=Loki(
            runtime=_runtime(_mapping(loki["runtime"])),
            retention=str(loki["retention"]),
            reject_older_than=str(loki["reject_older_than"]),
            ingestion_rate_mb=int(cast(int, loki["ingestion_rate_mb"])),
            ingestion_burst_mb=int(cast(int, loki["ingestion_burst_mb"])),
        ),
        promtail=Promtail(
            runtime=_runtime(_mapping(promtail["runtime"])),
            jobs=tuple(
                PromtailJob(
                    name=str(job["name"]),
                    path_glob=str(job["path_glob"]),
                    labels=_labels(job["labels"]),
                    decode_docker_json=bool(job.get("decode_docker_json", False)),
                )
                for job in _rows(promtail["jobs"])
            ),
        ),
        grafana=Grafana(
            runtime=_runtime(_mapping(grafana["runtime"])),
            datasources=tuple(
                GrafanaDatasource(
                    name=str(row["name"]),
                    kind=str(row["kind"]),
                    service=str(row["service"]),
                    default=bool(row["default"]),
                )
                for row in _rows(grafana["datasources"])
            ),
            dashboard_providers=tuple(
                GrafanaDashboardProvider(name=str(row["name"]), folder=str(row["folder"]))
                for row in _rows(grafana["dashboard_providers"])
            ),
        ),
        syslog=Syslog(
            directory=DirectoryContract(
                path=str(directory["path"]),
                owner=str(directory["owner"]),
                group=str(directory["group"]),
                mode=str(directory["mode"]),
            ),
            files=tuple(
                SyslogFile(
                    facility=str(row["facility"]),
                    path=str(row["path"]),
                    owner=str(row["owner"]),
                    group=str(row["group"]),
                    mode=str(row["mode"]),
                    synchronous=bool(row.get("synchronous", False)),
                )
                for row in _rows(syslog["files"])
            ),
            rotation=Rotation(
                frequency=str(rotation["frequency"]),
                keep=int(cast(int, rotation["keep"])),
                compress=bool(rotation["compress"]),
            ),
        ),
        roster=tuple(
            RosterEntry(
                name=str(row["name"]),
                kind=str(row["kind"]),
                owner=str(row["owner"]),
                port=int(cast(int, row["port"])) if "port" in row else None,
            )
            for row in _rows(document["roster"])
        ),
        retired=tuple(
            RetiredProduct(
                name=str(row["name"]),
                tokens=_strings(row["tokens"]),
                decommissioned=str(row["decommissioned"]),
                rationale=str(row["rationale"]),
                residual_data=(str(row["residual_data"]) if "residual_data" in row else None),
            )
            for row in _rows(document["retired"])
        ),
        exposure=Exposure(
            source_sets=tuple(
                SourceSet(name=str(row["name"]), kind=str(row["kind"]))
                for row in _rows(exposure["source_sets"])
            ),
            surfaces=tuple(
                Surface(
                    name=str(row["name"]),
                    kind=str(row["kind"]),
                    port=int(cast(int, row["port"])),
                    protocol=str(row["protocol"]),
                    family=str(row["family"]),
                    exposure=str(row["exposure"]),
                    allow_from=str(row["allow_from"]) if "allow_from" in row else None,
                    authenticated=bool(row.get("authenticated", False)),
                    rationale=str(row["rationale"]) if "rationale" in row else None,
                )
                for row in _rows(exposure["surfaces"])
            ),
        ),
        gates=tuple(
            VerificationGate(
                name=str(row["name"]),
                health=str(row["health"]),
                integrity=str(row["integrity"]),
                window=str(row["window"]),
            )
            for row in _rows(verification["gates"])
        ),
    )


def _inventory_files(
    root: Path,
) -> tuple[Path, Path, Path, tuple[Path, ...], tuple[Path, ...]]:
    """Locate every input, in a fixed order.

    ``sorted`` on the directory listings is what makes rendering reproducible
    across filesystems: ``Path.glob`` yields in directory order, which differs
    between machines and changes when a file is rewritten.
    """
    return (
        root / "inventory" / "control-plane.toml",
        root / "inventory" / "bundle.toml",
        root / "routing",
        tuple(sorted((root / "inventory" / "targets").glob("*.toml"))),
        tuple(sorted((root / "inventory" / "federations").glob("*.toml"))),
    )


def load(root: Path, *, contracts: Path | None = None) -> DesiredState:
    """Read and schema-validate the whole inventory under ``root``.

    ``contracts`` defaults to ``root/contracts``. It is separable so a fixture
    tree can be validated against the REAL schemas rather than a copy — a
    fixture that carries its own copy of the contract proves the copy, and the
    two drift the first time a schema changes.

    Raises :class:`InventoryError` carrying every finding if any document is
    missing or malformed.
    """
    schema_root = contracts if contracts is not None else root / "contracts"
    control_plane_path, bundle_path, routing_dir, target_paths, federation_paths = _inventory_files(
        root
    )
    findings: list[Finding] = []

    required = {
        "control-plane": control_plane_path,
        "bundle": bundle_path,
        "receivers": routing_dir / "receivers.toml",
        "policies": routing_dir / "policies.toml",
        "inhibition": routing_dir / "inhibition.toml",
    }
    for label, path in required.items():
        if not path.is_file():
            findings.append(
                Finding(
                    "MISSING", str(path.relative_to(root)), f"required {label} document is absent"
                )
            )
    if findings:
        raise InventoryError(findings)

    control_plane_doc = _read_toml(control_plane_path)
    findings += _validate_document(
        schema_root, "control-plane", control_plane_doc, "inventory/control-plane.toml"
    )

    bundle_doc = _read_toml(bundle_path)
    findings += _validate_document(schema_root, "bundle", bundle_doc, "inventory/bundle.toml")

    target_docs: list[tuple[str, Document]] = []
    for path in target_paths:
        location = str(path.relative_to(root))
        document = _read_toml(path)
        findings += _validate_document(schema_root, "target", document, location)
        target_docs.append((location, document))

    federation_docs: list[tuple[str, Document]] = []
    for path in federation_paths:
        location = str(path.relative_to(root))
        document = _read_toml(path)
        findings += _validate_document(schema_root, "target", document, location)
        federation_docs.append((location, document))

    routing_docs: dict[str, Document] = {}
    for name in ("receivers", "policies", "inhibition"):
        location = f"routing/{name}.toml"
        document = _read_toml(routing_dir / f"{name}.toml")
        findings += _validate_document(schema_root, "routing", document, location)
        routing_docs[name] = document

    # A document is a `targets` file because it says so, not because of the
    # directory it sits in — the discriminator is checked rather than assumed.
    for location, document in target_docs:
        if document.get("kind") != "targets":
            findings.append(
                Finding(
                    "KIND", location, 'a file under inventory/targets must declare kind = "targets"'
                )
            )
    for location, document in federation_docs:
        if document.get("kind") != "federation":
            findings.append(
                Finding(
                    "KIND",
                    location,
                    'a file under inventory/federations must declare kind = "federation"',
                )
            )

    if findings:
        raise InventoryError(findings)

    defaults, routes = _policies(routing_docs["policies"])
    return DesiredState(
        control_plane=_control_plane(control_plane_doc),
        bundle=_bundle(bundle_doc),
        targets=tuple(_target_set(document) for _, document in target_docs),
        federations=tuple(_federation(document) for _, document in federation_docs),
        receivers=_receivers(routing_docs["receivers"]),
        defaults=defaults,
        routes=routes,
        inhibitions=_inhibitions(routing_docs["inhibition"]),
    )


# ── Semantic layer ──────────────────────────────────────────────────────────


def _routing_findings(state: DesiredState) -> list[Finding]:
    findings: list[Finding] = []
    declared = {receiver.name: receiver for receiver in state.receivers}

    seen_refs: dict[str, str] = {}
    for receiver in state.receivers:
        for integration in receiver.integrations:
            # A ref used by two integrations means one binding delivers to two
            # places, so revoking it for one revokes it for the other — the
            # blast-radius property ADR-0005 spent an ingress on removing.
            previous = seen_refs.get(integration.credential_ref)
            if previous is not None:
                findings.append(
                    Finding(
                        "CREDENTIAL-REF-SHARED",
                        f"routing/receivers.toml#{receiver.name}",
                        f"credential_ref {integration.credential_ref!r} is already used by "
                        f"{previous!r}; one binding reached by two integrations cannot be "
                        "revoked for one of them",
                    )
                )
            seen_refs[integration.credential_ref] = receiver.name
            if integration.kind == "email" and state.control_plane.smtp is None:
                findings.append(
                    Finding(
                        "SMTP-UNCONFIGURED",
                        f"routing/receivers.toml#{receiver.name}",
                        "an email integration needs [smtp] in inventory/control-plane.toml; "
                        "Alertmanager refuses an email receiver with no smarthost and the "
                        "router then fails to start",
                    )
                )
        if not receiver.integrations and not receiver.null_policy:
            findings.append(
                Finding(
                    "RECEIVER-SILENT",
                    f"routing/receivers.toml#{receiver.name}",
                    "a receiver with no integrations must carry a reviewed null_policy saying "
                    "why this class of alert is deliberately undelivered (AGENTS.md rule 7)",
                )
            )

    if state.defaults.receiver not in declared:
        findings.append(
            Finding(
                "ROUTE-UNDECLARED",
                "routing/policies.toml#defaults",
                f"default receiver {state.defaults.receiver!r} is not declared in receivers.toml",
            )
        )

    used = {state.defaults.receiver}
    seen_ids: set[str] = set()
    for route in state.routes:
        used.add(route.receiver)
        if route.identifier in seen_ids:
            findings.append(
                Finding(
                    "ROUTE-DUPLICATE",
                    f"routing/policies.toml#{route.identifier}",
                    "duplicate route id",
                )
            )
        seen_ids.add(route.identifier)
        if route.receiver not in declared:
            findings.append(
                Finding(
                    "ROUTE-UNDECLARED",
                    f"routing/policies.toml#{route.identifier}",
                    f"receiver {route.receiver!r} is not declared in receivers.toml",
                )
            )

    # A receiver nothing routes to is configuration that will never be
    # exercised — and the first time someone needs it they will not know it was
    # already broken.
    for name in declared:
        if name not in used:
            findings.append(
                Finding(
                    "RECEIVER-UNUSED",
                    f"routing/receivers.toml#{name}",
                    "declared but no route or default reaches it",
                )
            )

    # Rule 7 in its load-bearing form: severity classes that must land
    # somewhere real. A matcher naming the severity is how a route claims it.
    for severity in ("warning", "critical"):
        matcher = f'severity="{severity}"'
        matched = [
            route
            for route in state.routes
            if any(matcher == candidate.replace(" ", "") for candidate in route.matchers)
        ]
        if not matched:
            findings.append(
                Finding(
                    "SEVERITY-UNROUTED",
                    "routing/policies.toml",
                    f"no route matches {matcher}; {severity} alerts would fall through to "
                    f"the default receiver {state.defaults.receiver!r} unexamined",
                )
            )
            continue
        for route in matched:
            target = declared.get(route.receiver)
            if target is not None and not target.integrations:
                findings.append(
                    Finding(
                        "SEVERITY-UNDELIVERED",
                        f"routing/policies.toml#{route.identifier}",
                        f"{severity} alerts route to null receiver {target.name!r}",
                    )
                )
    return findings


def _target_findings(state: DesiredState) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[str, str] = {}

    for target_set in state.targets:
        for job in target_set.jobs:
            if job.job in seen:
                findings.append(
                    Finding(
                        "JOB-DUPLICATE",
                        f"inventory/targets#{job.job}",
                        f"job name already used by {seen[job.job]}; two jobs sharing a name "
                        "merge into one target set and neither owner sees the other's targets",
                    )
                )
            seen[job.job] = target_set.product
            # ADR-0004 left `metrics_path` classified PUBLIC and asked for the
            # judgement to be confirmed rather than assumed. It is public
            # because the conventional path is scrape protocol and discloses
            # nothing. A NON-default path is the ambiguous case the ADR named:
            # a path chosen precisely because it is unguessable is topology
            # wearing a protocol field's name, and publishing it hands over the
            # thing its author was relying on. Requiring a rationale does not
            # decide which one it is — it makes the author say so, which is the
            # only part a gate can honestly do.
            if job.metrics_path != DEFAULT_METRICS_PATH and not job.path_rationale:
                findings.append(
                    Finding(
                        "METRICS-PATH-UNEXPLAINED",
                        f"inventory/targets#{job.job}",
                        f"metrics_path is {job.metrics_path!r}, not {DEFAULT_METRICS_PATH!r}; "
                        "a non-default path needs `path_rationale` saying why it is protocol "
                        "rather than concealment (ADR-0004)",
                    )
                )

    prefixes: dict[str, str] = {}
    for federation in state.federations:
        if federation.name in seen:
            findings.append(
                Finding(
                    "JOB-DUPLICATE",
                    f"inventory/federations#{federation.name}",
                    f"federation name collides with scrape job owned by {seen[federation.name]}",
                )
            )
        seen[federation.name] = f"federation:{federation.name}"
        if federation.rename_prefix in prefixes:
            findings.append(
                Finding(
                    "FEDERATION-PREFIX-COLLISION",
                    f"inventory/federations#{federation.name}",
                    f"rename_prefix {federation.rename_prefix!r} is already used by "
                    f"{prefixes[federation.rename_prefix]}; two upstreams renaming into the "
                    "same namespace reintroduces exactly the confusion rule 9 prevents",
                )
            )
        prefixes[federation.rename_prefix] = federation.name
    return findings


def _control_plane_findings(state: DesiredState) -> list[Finding]:
    """ADR-0004's other open classification, settled as a gate.

    A `listen` value carries a host and a port, and by the letter of the rule a
    port is private. A LOOPBACK bind is different in kind: it describes this
    control plane's own posture rather than any target's location, it is the
    documented default of the public software being run, and it is the evidence
    `docs/SECURITY.md` cites that the rendered stack keeps its ports off every
    non-loopback interface — evidence that disappears if the value is withheld.

    So the judgement is conditional, and a conditional judgement is exactly the
    kind that rots as a habit. Anything that is not a loopback address is a
    resolved bind address and belongs in the private inventory.
    """
    findings: list[Finding] = []
    for name, evaluator in (
        ("prometheus", state.control_plane.prometheus),
        ("alertmanager", state.control_plane.alertmanager),
    ):
        address = evaluator.listen.rsplit(":", 1)[0]
        if not address.startswith(_LOOPBACK_PREFIX):
            findings.append(
                Finding(
                    "LISTEN-NOT-LOOPBACK",
                    f"inventory/control-plane.toml#{name}",
                    f"listen address {address!r} is not a loopback address; a loopback bind is "
                    "public because it is a posture, and anything else is a resolved bind "
                    "address that belongs in the private inventory (ADR-0004)",
                )
            )
    return findings


def _bundle_findings(state: DesiredState) -> list[Finding]:
    """The gates that need the bundle and the rest of the public inventory together.

    Every one of them exists because the corresponding thing was actually wrong
    on the Observer host, and every one of them is a question no single
    document could answer.
    """
    findings: list[Finding] = []
    bundle = state.bundle

    # ── runtimes bind loopback, exactly as the evaluators must ──────────────
    for name, runtime in (
        ("loki", bundle.loki.runtime),
        ("promtail", bundle.promtail.runtime),
        ("grafana", bundle.grafana.runtime),
    ):
        address = runtime.listen.rsplit(":", 1)[0]
        if not address.startswith(_LOOPBACK_PREFIX):
            findings.append(
                Finding(
                    "LISTEN-NOT-LOOPBACK",
                    f"inventory/bundle.toml#{name}",
                    f"listen address {address!r} is not a loopback address; the rule is the "
                    "same for a runtime as for an evaluator, because the reason is the same "
                    "(ADR-0006 section 5)",
                )
            )

    # ── the roster owns every service the bundle deploys ────────────────────
    services = {entry.name: entry for entry in bundle.roster if entry.kind == "service"}
    deployed = ("prometheus", "alertmanager", "loki", "promtail", "grafana")
    for name in deployed:
        if name not in services:
            findings.append(
                Finding(
                    "ROSTER-INCOMPLETE",
                    f"inventory/bundle.toml#roster/{name}",
                    f"the bundle deploys {name} and the roster does not own it; an unrostered "
                    "resource is unattributed, and the whole point of the roster is that "
                    "deleting something unattributed is a decision rather than a tidy-up",
                )
            )
    for entry in bundle.roster:
        if entry.owner.strip().lower() in {"unowned", "unknown", "none", "tbd"}:
            findings.append(
                Finding(
                    "ROSTER-UNOWNED",
                    f"inventory/bundle.toml#roster/{entry.name}",
                    f"owner {entry.owner!r} names nobody; a placeholder owner is worse than an "
                    "absent entry, because it reads as attributed",
                )
            )

    # ── a datasource points at a service the bundle actually deploys ────────
    defaults = [source for source in bundle.grafana.datasources if source.default]
    if len(defaults) != 1:
        findings.append(
            Finding(
                "DATASOURCE-DEFAULT",
                "inventory/bundle.toml#grafana",
                f"{len(defaults)} datasources are marked default; Grafana silently picks one "
                "when several claim it, so a dashboard's queries then depend on load order",
            )
        )
    for source in bundle.grafana.datasources:
        rostered = services.get(source.service)
        if rostered is None:
            findings.append(
                Finding(
                    "DATASOURCE-UNROSTERED",
                    f"inventory/bundle.toml#grafana/{source.name}",
                    f"datasource points at service {source.service!r}, which the roster does "
                    "not own; a datasource URL is derived from the rostered port, so this one "
                    "could only be rendered by inventing an address",
                )
            )
        elif rostered.port is None:
            findings.append(
                Finding(
                    "DATASOURCE-NO-PORT",
                    f"inventory/bundle.toml#roster/{source.service}",
                    "a service a datasource names must declare the port it listens on inside "
                    "the compose network",
                )
            )

    # ── the syslog contract can actually be satisfied ───────────────────────
    directory = bundle.syslog.directory
    for logfile in bundle.syslog.files:
        parent = logfile.path.rsplit("/", 1)[0] or "/"
        if parent != directory.path:
            findings.append(
                Finding(
                    "SYSLOG-OUTSIDE-CONTRACT",
                    f"inventory/bundle.toml#syslog/{logfile.facility}",
                    f"{logfile.path} is not inside the declared directory {directory.path}; a "
                    "file whose parent has no stated owner and mode is the exact shape of the "
                    "failure this section exists to prevent",
                )
            )
        # The OWNER digit, and the write bit inside it. Spelled as a mask rather
        # than a membership test in a string of digits: the string form was
        # written inverted the first time and passed a mode of 0440, which is
        # precisely the mode that suspends the action.
        if not int(logfile.mode[1]) & 0o2:
            findings.append(
                Finding(
                    "SYSLOG-OWNER-WRITE",
                    f"inventory/bundle.toml#syslog/{logfile.facility}",
                    f"mode {logfile.mode} does not grant the owner write; rsyslog appends to this "
                    "file as its own user, and a mode that forbids it suspends the action",
                )
            )
        if int(logfile.mode[3]) != 0:
            findings.append(
                Finding(
                    "SYSLOG-WORLD-READABLE",
                    f"inventory/bundle.toml#syslog/{logfile.facility}",
                    f"mode {logfile.mode} grants other; a log file carries message contents and "
                    "is readable through its group, which is what `adm` is for",
                )
            )
    duplicate_paths = [
        entry.path
        for entry in bundle.syslog.files
        if sum(1 for other in bundle.syslog.files if other.path == entry.path) > 1
    ]
    for path in sorted(set(duplicate_paths)):
        findings.append(
            Finding(
                "SYSLOG-PATH-DUPLICATE",
                f"inventory/bundle.toml#syslog{path}",
                "two facilities write the same file with independently declared ownership; "
                "whichever tmpfiles line is applied last silently wins",
            )
        )

    # ── exposure ────────────────────────────────────────────────────────────
    declared_sets = {source.name for source in bundle.exposure.source_sets}
    used_sets: set[str] = set()
    for surface in bundle.exposure.surfaces:
        location = f"inventory/bundle.toml#exposure/{surface.name}"
        if surface.exposure == "ingress":
            if surface.allow_from is None:
                findings.append(
                    Finding(
                        "SURFACE-NO-SOURCE",
                        location,
                        "an ingress surface must name the source set permitted to reach it; "
                        "without one the rendered rule would permit everybody, which is "
                        "`public` wearing `ingress`'s name",
                    )
                )
            elif surface.allow_from not in declared_sets:
                findings.append(
                    Finding(
                        "SURFACE-UNDECLARED-SOURCE",
                        location,
                        f"allow_from names {surface.allow_from!r}, which no source set declares",
                    )
                )
            else:
                used_sets.add(surface.allow_from)
        elif surface.allow_from is not None:
            findings.append(
                Finding(
                    "SURFACE-SOURCE-IGNORED",
                    location,
                    f"a {surface.exposure!r} surface is not reached from a source, so naming "
                    f"{surface.allow_from!r} describes a rule that will never be rendered",
                )
            )
        if surface.exposure == "public":
            if not surface.authenticated:
                findings.append(
                    Finding(
                        "SURFACE-PUBLIC-UNAUTHENTICATED",
                        location,
                        "an unauthenticated public surface is refused (AGENTS.md rule 19)",
                    )
                )
            if surface.rationale is None:
                findings.append(
                    Finding(
                        "SURFACE-PUBLIC-UNEXPLAINED",
                        location,
                        "a public surface states why it is deliberately reachable from anywhere",
                    )
                )
    for name in sorted(declared_sets - used_sets):
        findings.append(
            Finding(
                "SOURCE-SET-UNUSED",
                f"inventory/bundle.toml#exposure/{name}",
                "no surface allows from this set; an unused set is a binding that will be "
                "resolved, carried into a receipt and never consulted, which is the same "
                "stale-binding shape resolution refuses in the other direction",
            )
        )

    # ── verification conflates nothing ──────────────────────────────────────
    for gate in bundle.gates:
        location = f"inventory/bundle.toml#verification/{gate.name}"
        if gate.health.strip() == gate.integrity.strip():
            findings.append(
                Finding(
                    "GATE-CONFLATED",
                    location,
                    "the health and integrity predicates are the same expression, so the gate "
                    "asserts one fact twice; eighteen targets read up == 1 on this host while "
                    "1.8 million samples were rejected, which is precisely the pair of facts a "
                    "single predicate cannot separate",
                )
            )
        if not any(token in gate.integrity for token in _INGESTION_TOKENS):
            findings.append(
                Finding(
                    "GATE-INTEGRITY-NOT-INGESTION",
                    location,
                    "the integrity predicate mentions none of "
                    f"{', '.join(sorted(_INGESTION_TOKENS))}; a gate whose second predicate is "
                    "not about ingestion is a gate with one predicate and a longer name",
                )
            )
        if not any(f"{name}(" in gate.integrity for name in _RANGE_FUNCTIONS):
            findings.append(
                Finding(
                    "GATE-INTEGRITY-NOT-DELTA",
                    location,
                    "the integrity predicate compares a counter directly instead of wrapping it "
                    f"in one of {', '.join(sorted(_RANGE_FUNCTIONS))}. A bare `counter == 0` is "
                    "made true by RESETTING the counter, by a fresh TSDB, or by a container "
                    "restart, and a predicate satisfied that way cannot be told "
                    "satisfied by a repair. This host's counter stands at roughly 1.86 million "
                    "historical rejections and must stay visible; the assertion is that it does "
                    "not grow from a recorded baseline",
                )
            )
    return findings


def semantic_findings(state: DesiredState) -> tuple[Finding, ...]:
    """Every check that needs more than one PUBLIC document to answer.

    Deliberately runs without the private inventory, so a reader who has only
    this repository still gets every gate that public inputs can support. The
    checks that need resolution are :func:`resolution_findings`.
    """
    return tuple(
        _control_plane_findings(state)
        + _routing_findings(state)
        + _target_findings(state)
        + _bundle_findings(state)
    )


# ── Resolution layer (ADR-0004) ─────────────────────────────────────────────


def canonical_bytes(document: Mapping[str, object]) -> bytes:
    """The one canonical form a private document is hashed in.

    UTF-8, sorted keys, two-space indent, and NO trailing newline. Stated in
    the contract and implemented once here rather than left to each caller: a
    reader that adds a trailing newline before hashing reports false drift on a
    correct inventory, and "the digest disagrees" is the least debuggable
    failure a promotion can produce.
    """
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


def canonical_digest(document: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def _binding_secret(raw: object) -> SecretFile | None:
    return _secret(raw)


def load_private_inventory(path: Path, *, contracts: Path) -> PrivateInventory:
    """Read, validate and digest one ObserverInventoryV1 document.

    The digest is taken over the document as PARSED and re-serialised into the
    canonical form, not over the bytes on disk. That is deliberate: a file whose
    only difference is indentation is the same inventory, and hashing the raw
    bytes would report drift for a reformat while missing nothing. The contract
    fixes the canonical form precisely so the two readings cannot diverge.
    """
    findings: list[Finding] = []
    if not path.is_file():
        raise InventoryError(
            [Finding("MISSING", str(path), "the private inventory document is absent")]
        )
    try:
        with path.open("rb") as handle:
            document: Document = json.load(handle)
    except json.JSONDecodeError as error:
        # A partial write is the EXPECTED input on the read-back path: a
        # supersession writes the document and then re-reads the stored bytes
        # precisely so a truncated one is caught. Letting that surface as a
        # traceback would make the one failure this check exists to detect the
        # one it reports worst — and an operator following a runbook cannot act
        # on a stack trace.
        raise InventoryError(
            [
                Finding(
                    "MALFORMED",
                    f"{path}:{error.lineno}",
                    f"the document is not valid JSON ({error.msg}); if this is a read-back "
                    "after a write, the stored bytes are incomplete",
                )
            ]
        ) from error
    findings += _validate_document(contracts, "private-inventory", document, str(path))
    if findings:
        raise InventoryError(findings)

    host = _mapping(document["host"])
    # The environment's identity, version aside. Built by copying and dropping
    # one key rather than by mutating `document`, which is still needed intact
    # for the full digest immediately below.
    content = {key: value for key, value in document.items() if key != "version"}
    return PrivateInventory(
        document=str(document["document"]),
        version=int(cast(int, document["version"])),
        environment=str(document["environment"]),
        digest=canonical_digest(document),
        content_digest=canonical_digest(content),
        host=HostBinding(
            target_id=str(host["target_id"]),
            identity=str(host["identity"]),
            ssh_alias=str(host["ssh_alias"]),
        ),
        targets=tuple(
            TargetBinding(
                target_id=str(row["target_id"]),
                endpoints=_strings(row["endpoints"]),
                credential=_binding_secret(row.get("credential")),
            )
            for row in _rows(document["targets"])
        ),
        federations=tuple(
            FederationBinding(
                target_id=str(row["target_id"]),
                endpoint=str(row["endpoint"]),
                credential=_binding_secret(row.get("credential")),
            )
            for row in _rows(document["federations"])
        ),
        receivers=tuple(
            ReceiverBinding(
                credential_ref=str(row["credential_ref"]),
                credential=SecretFile(
                    openbao_path=str(_mapping(row["credential"])["openbao_path"]),
                    file_name=str(_mapping(row["credential"])["file_name"]),
                ),
                destination=str(row["destination"]) if "destination" in row else None,
            )
            for row in _rows(document["receivers"])
        ),
        source_sets=tuple(
            SourceSetBinding(
                name=str(row["name"]),
                interface=str(row["interface"]) if "interface" in row else None,
                prefixes=_strings(row["prefixes"]) if "prefixes" in row else (),
            )
            for row in _rows(document.get("source_sets", []))
        ),
    )


def resolution_findings(state: DesiredState, inventory: PrivateInventory) -> tuple[Finding, ...]:
    """Every check that needs the private inventory as well as public Git.

    Both directions, always. An unresolved public target is the obvious half;
    an unused private binding is the half that gets left out, and it is the one
    that describes a stale endpoint nobody is looking at — the exact shape of
    the CRM scrape job that stayed on the Observer host for weeks after the
    product it pointed at was gone.
    """
    findings: list[Finding] = []

    if inventory.environment != state.control_plane.environment:
        findings.append(
            Finding(
                "RESOLUTION-ENVIRONMENT",
                inventory.document,
                f"private inventory is for environment {inventory.environment!r} but the "
                f"control plane declares {state.control_plane.environment!r}; a production "
                "inventory resolved against a staging plane renders cleanly and points a "
                "staging evaluator at production",
            )
        )
    if inventory.host.target_id != state.control_plane.host.target_id:
        findings.append(
            Finding(
                "RESOLUTION-HOST",
                inventory.document,
                f"private inventory binds host {inventory.host.target_id!r} but the control "
                f"plane declares {state.control_plane.host.target_id!r}",
            )
        )

    targets = {binding.target_id: binding for binding in inventory.targets}
    federations = {binding.target_id: binding for binding in inventory.federations}
    receivers = {binding.credential_ref: binding for binding in inventory.receivers}
    used_targets: set[str] = set()
    used_federations: set[str] = set()
    used_receivers: set[str] = set()

    for target_set in state.targets:
        for job in target_set.jobs:
            location = f"inventory/targets#{job.job}"
            binding = targets.get(job.target_id)
            if job.publication is not None:
                endpoints = job.publication.endpoints
                credential = binding.credential if binding is not None else None
                if binding is not None:
                    used_targets.add(job.target_id)
                    findings.append(
                        Finding(
                            "PUBLICATION-SHADOWED",
                            location,
                            f"target_id {job.target_id!r} carries a reviewed publication AND a "
                            "private binding; the publication wins, so the binding is a second "
                            "answer to one question and the two can drift apart unnoticed",
                        )
                    )
            elif binding is None:
                findings.append(
                    Finding(
                        "RESOLUTION-MISSING",
                        location,
                        f"target_id {job.target_id!r} has no binding in the private inventory "
                        "and no reviewed publication block",
                    )
                )
                continue
            else:
                used_targets.add(job.target_id)
                endpoints = binding.endpoints
                credential = binding.credential

            if job.authenticated and credential is None:
                findings.append(
                    Finding(
                        "AUTHENTICATION-MISMATCH",
                        location,
                        f"job declares authenticated = true but the binding for "
                        f"{job.target_id!r} carries no credential; the public claim would be "
                        "unfalsifiable from Git alone, which is why it is checked here",
                    )
                )
            elif not job.authenticated and credential is not None:
                findings.append(
                    Finding(
                        "AUTHENTICATION-MISMATCH",
                        location,
                        f"job declares authenticated = false but the binding for "
                        f"{job.target_id!r} carries a credential; either the credential is "
                        "unused and should be revoked, or the public capability is wrong",
                    )
                )
            if job.expected is not None and job.expected > len(endpoints):
                findings.append(
                    Finding(
                        "TARGET-UNREACHABLE-EXPECTATION",
                        location,
                        f"expected {job.expected} up targets but the resolution yields "
                        f"{len(endpoints)}; the expectation can never be met, and a job that "
                        "resolves to too few targets produces no failures and no series",
                    )
                )

    for federation in state.federations:
        location = f"inventory/federations#{federation.name}"
        upstream = federations.get(federation.target_id)
        if upstream is None:
            findings.append(
                Finding(
                    "RESOLUTION-MISSING",
                    location,
                    f"target_id {federation.target_id!r} has no federation binding in the "
                    "private inventory",
                )
            )
            continue
        used_federations.add(federation.target_id)
        if federation.source.authenticated and upstream.credential is None:
            findings.append(
                Finding(
                    "AUTHENTICATION-MISMATCH",
                    location,
                    "federation declares authenticated = true but its binding carries no "
                    "credential",
                )
            )
        elif not federation.source.authenticated and upstream.credential is not None:
            findings.append(
                Finding(
                    "AUTHENTICATION-MISMATCH",
                    location,
                    "federation declares authenticated = false but its binding carries a "
                    "credential",
                )
            )

    for receiver in state.receivers:
        for integration in receiver.integrations:
            location = f"routing/receivers.toml#{receiver.name}"
            delivery = receivers.get(integration.credential_ref)
            if delivery is None:
                findings.append(
                    Finding(
                        "RESOLUTION-MISSING",
                        location,
                        f"credential_ref {integration.credential_ref!r} has no binding in the "
                        "private inventory",
                    )
                )
                continue
            used_receivers.add(integration.credential_ref)
            if integration.kind == "telegram":
                # Alertmanager's telegram chat id is a NUMBER. A quoted value is
                # rejected at config load, and the visible symptom is a receiver
                # that simply never delivers — the failure mode hardest to
                # notice, because nothing fires to tell you notifications broke.
                # The value is private, so this check moved here with it; what
                # a public reader loses is the check, not the guarantee.
                if delivery.destination is None or not _INTEGER.match(delivery.destination):
                    findings.append(
                        Finding(
                            "RECEIVER-CHAT-ID",
                            location,
                            "a telegram integration needs an integer chat id as its binding's "
                            "destination",
                        )
                    )
            elif integration.kind != "webhook" and delivery.destination is None:
                findings.append(
                    Finding(
                        "RECEIVER-NO-DESTINATION",
                        location,
                        f"a {integration.kind} integration needs a destination in its binding",
                    )
                )

    for unused in sorted(set(targets) - used_targets):
        findings.append(
            Finding(
                "RESOLUTION-UNUSED",
                f"{inventory.document}#targets/{unused}",
                "binding is not reached by any declared job; a resolved endpoint nothing "
                "scrapes is a stale entry that no other gate would ever mention",
            )
        )
    for unused in sorted(set(federations) - used_federations):
        findings.append(
            Finding(
                "RESOLUTION-UNUSED",
                f"{inventory.document}#federations/{unused}",
                "binding is not reached by any declared federation",
            )
        )
    for unused in sorted(set(receivers) - used_receivers):
        findings.append(
            Finding(
                "RESOLUTION-UNUSED",
                f"{inventory.document}#receivers/{unused}",
                "binding is not cited by any integration; an unused delivery credential is one "
                "nobody will think to revoke",
            )
        )

    # ── exposure source sets, in both directions and with the kind checked ──
    #
    # The kind check is the interesting one. A set declared `tunnel_interface`
    # and bound to prefixes renders a source match where an interface match was
    # intended: strictly weaker, silently different, and valid under both
    # schemas on its own. Only the join can see it.
    bindings = {binding.name: binding for binding in inventory.source_sets}
    declared_sets = {source.name: source for source in state.bundle.exposure.source_sets}
    used_sets = {
        surface.allow_from
        for surface in state.bundle.exposure.surfaces
        if surface.allow_from is not None
    }
    for name in sorted(used_sets):
        source = declared_sets.get(name)
        if source is None:
            # Already reported by the public gate; not repeated here.
            continue
        bound = bindings.get(name)
        if bound is None:
            findings.append(
                Finding(
                    "RESOLUTION-UNRESOLVED",
                    f"{inventory.document}#source_sets/{name}",
                    "no binding resolves this source set; the surface that allows from it "
                    "cannot be rendered without inventing a source",
                )
            )
            continue
        if source.kind == "tunnel_interface":
            if bound.interface is None:
                findings.append(
                    Finding(
                        "SOURCE-SET-KIND",
                        f"{inventory.document}#source_sets/{name}",
                        "the set is declared tunnel_interface and its binding carries no "
                        "interface",
                    )
                )
            if bound.prefixes:
                findings.append(
                    Finding(
                        "SOURCE-SET-KIND",
                        f"{inventory.document}#source_sets/{name}",
                        "the set is declared tunnel_interface and its binding carries "
                        "prefixes; a prefix match is not an interface match, and the "
                        "difference is invisible in the rendered rule",
                    )
                )
        elif source.kind == "address_set":
            if not bound.prefixes:
                findings.append(
                    Finding(
                        "SOURCE-SET-KIND",
                        f"{inventory.document}#source_sets/{name}",
                        "the set is declared address_set and its binding carries no prefixes",
                    )
                )
            if bound.interface is not None:
                findings.append(
                    Finding(
                        "SOURCE-SET-KIND",
                        f"{inventory.document}#source_sets/{name}",
                        "the set is declared address_set and its binding carries an interface",
                    )
                )
    for unused in sorted(set(bindings) - used_sets):
        findings.append(
            Finding(
                "RESOLUTION-UNUSED",
                f"{inventory.document}#source_sets/{unused}",
                "no surface allows from this set; a bound source nothing consults is a stale "
                "permission that survives every review because nothing reads it",
            )
        )
    return tuple(findings)


def resolve(state: DesiredState, inventory: PrivateInventory) -> Resolution:
    """Join public policy to private resolution, once, after it has been checked.

    Raises :class:`InventoryError` if :func:`resolution_findings` reports
    anything, so a :class:`Resolution` that exists is one whose every lookup is
    known to succeed. That is the property the renderer relies on: it indexes
    without guarding, and a KeyError there would be a bug in this function
    rather than a malformed input.
    """
    findings = resolution_findings(state, inventory)
    if findings:
        raise InventoryError(findings)

    targets = {binding.target_id: binding for binding in inventory.targets}
    federations = {binding.target_id: binding for binding in inventory.federations}
    receivers = {binding.credential_ref: binding for binding in inventory.receivers}

    jobs: dict[str, ResolvedEndpoint] = {}
    for target_set in state.targets:
        for job in target_set.jobs:
            if job.publication is not None:
                jobs[job.job] = ResolvedEndpoint(
                    endpoints=job.publication.endpoints, credential=None
                )
            else:
                binding = targets[job.target_id]
                jobs[job.job] = ResolvedEndpoint(
                    endpoints=binding.endpoints, credential=binding.credential
                )

    resolved_federations = {
        federation.name: ResolvedEndpoint(
            endpoints=(federations[federation.target_id].endpoint,),
            credential=federations[federation.target_id].credential,
        )
        for federation in state.federations
    }
    integrations = {
        integration.credential_ref: ResolvedReceiver(
            credential=receivers[integration.credential_ref].credential,
            destination=receivers[integration.credential_ref].destination,
        )
        for receiver in state.receivers
        for integration in receiver.integrations
    }
    source_sets = {binding.name: binding for binding in inventory.source_sets}
    return Resolution(
        inventory=inventory,
        jobs=MappingProxyType(jobs),
        federations=MappingProxyType(resolved_federations),
        integrations=MappingProxyType(integrations),
        source_sets=MappingProxyType(source_sets),
    )


# ── Secret material ─────────────────────────────────────────────────────────

# AGENTS.md rule 15: an exemption states an enforceable premise. These two
# paths are excluded because they are the detector and its sensitivity proof —
# they must contain the shapes being detected, or the detector has no evidence
# that it bites. Nothing else may be added here; the exact list is asserted by
# tests/architecture/test_no_secret_material.py.
SECRET_SCAN_EXCLUSIONS: tuple[str, ...] = (
    "src/dotmac_observability/validate.py",
    "tests/mutations/test_secret_detector_bites.py",
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PEM-PRIVATE-KEY", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("TELEGRAM-BOT-TOKEN", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("SLACK-WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/\S+")),
    ("AWS-ACCESS-KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "ASSIGNED-CREDENTIAL",
        re.compile(
            r"(?i)\b(?:authorization|bearer_token|password|passwd|api[_-]?key"
            r"|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*"
            r"[\"']?[A-Za-z0-9._\-/+=]{16,}"
        ),
    ),
)


def scan_for_secret_material(root: Path, files: Iterable[Path]) -> tuple[Finding, ...]:
    """Report any line that looks like it carries a secret VALUE.

    Deliberately shape-based rather than entropy-based: an entropy threshold
    flags every sha256 digest in the bundle locks, and a gate that cries wolf
    on legitimate content gets an ever-growing allowlist until it detects
    nothing at all.
    """
    findings: list[Finding] = []
    excluded = frozenset(SECRET_SCAN_EXCLUSIONS)
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for code, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            f"SECRET-{code}",
                            f"{relative}:{number}",
                            "looks like secret material; commit an OpenBao path and a "
                            "logical file name instead (AGENTS.md rule 1)",
                        )
                    )
    return tuple(findings)


# ── Private material (ADR-0004) ─────────────────────────────────────────────
#
# A different question from the secret scanner above, asked over the same
# corpus. Rule 1 asks whether a value is a SECRET. This asks whether a
# non-secret fact is still something to publish, which is the question a public
# repository forces and rule 1 was never meant to answer.
#
# Scope is deliberately every tracked file rather than the inventory documents,
# because the inventory documents are already covered STRUCTURALLY and better:
# the contracts close every object, so an `openbao_path` or an `endpoints` key
# in `inventory/targets/*.toml` is refused by the schema with a precise error
# and cannot reach this scanner. What the schema cannot see is a value pasted
# into a document, and that is where both of this repository's real disclosures
# happened — PR #4 was a rehearsal host address in `ARCHITECTURE.md` and
# `SECURITY.md`, PR #6 a credential basename in prose. Neither was in an
# inventory file. This detector is aimed at that.

PRIVATE_SCAN_EXCLUSIONS: tuple[str, ...] = (
    "src/dotmac_observability/validate.py",
    "tests/mutations/test_private_material_detector_bites.py",
)

_PRIVATE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ADDRESS",
        # A non-loopback IPv4 literal. 127.x is this control plane's own posture
        # and is published deliberately (see LISTEN-NOT-LOOPBACK); 0.0.0.0 is a
        # wildcard bind inside a container and names no host. Everything else
        # locates something.
        re.compile(r"(?<![\w.])(?!127\.)(?!0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    ),
    (
        "ADDRESS-V6",
        # Three alternatives, all of them unambiguously IPv6 and none of them a
        # full IPv6 grammar. The shapes that matter are the ones somebody pastes
        # out of `ip -6 addr` or a probe, which are abbreviated; a stricter
        # grammar would refuse exactly those and pass the disclosure.
        #
        # What every alternative requires is a DOUBLE colon or eight groups, so
        # a timestamp cannot trip it: `05:03:57` has single colons only, and
        # that near-miss is the reason the obvious "three or more colon groups"
        # pattern is not used here.
        re.compile(
            r"(?:[0-9a-fA-F]{1,4}:){2,}:"
            r"|[0-9a-fA-F]{1,4}::[0-9a-fA-F]"
            r"|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
        ),
    ),
    (
        "HOSTNAME",
        # A SUBDOMAIN of a real Dotmac domain. The bare domain is excluded by
        # the required leading label, which is what lets the contracts keep
        # their `https://dotmac.io/schemas/...` identifiers — those name a
        # schema namespace, not a host anyone can reach.
        re.compile(r"\b[a-z0-9][a-z0-9-]*\.dotmac\.io\b"),
    ),
    (
        "STORE-PATH",
        # An OpenBao path with at least two segments. `secret/fixture/` is
        # exempt by construction rather than by an allowlist: it is a reserved
        # prefix that names no real store namespace, so a synthetic document can
        # carry a structurally valid path without the detector having to be told
        # which file it lives in.
        re.compile(r"\bsecret/(?!fixture/)[A-Za-z0-9._-]+/[A-Za-z0-9._-]"),
    ),
)


def private_material_findings(text: str, *, location: str) -> tuple[Finding, ...]:
    """Every line of ``text`` that carries resolved material, by line number.

    Extracted from the tree scanner so that a document produced at promotion
    time — a receipt, a live observation — is held to the SAME detector as a
    tracked file, rather than to a second copy of the patterns that would drift
    from this one. A receipt is the artifact most likely to be pasted into a
    ticket, so it is the last place a second, weaker spelling of rule 18 should
    live.
    """
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for code, pattern in _PRIVATE_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        f"PRIVATE-{code}",
                        f"{location}:{number}",
                        "looks like resolved material; public Git carries the LOGICAL "
                        "description and the private inventory carries the resolution "
                        "(AGENTS.md rule 18, ADR-0004)",
                    )
                )
    return tuple(findings)


def scan_for_private_material(root: Path, files: Iterable[Path]) -> tuple[Finding, ...]:
    """Report any line carrying resolved material ADR-0004 keeps out of Git.

    Not a substitute for the structural half. The contracts refuse a private
    field in an inventory document outright; this catches the same material
    written into prose, a workflow, a comment or a rendered artefact, where no
    schema is looking.
    """
    findings: list[Finding] = []
    excluded = frozenset(PRIVATE_SCAN_EXCLUSIONS)
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings.extend(private_material_findings(text, location=relative))
    return tuple(findings)


def validate(
    root: Path,
    *,
    contracts: Path | None = None,
    private_inventory: Path | None = None,
) -> tuple[Finding, ...]:
    """Schema plus semantics for the inventory under ``root``.

    ``private_inventory`` is optional, and its absence is not a pass. Without
    it the resolution gates simply do not run, which is the correct behaviour
    for a public reader and the wrong behaviour for a promotion — so the
    promotion lane supplies one and the CLI says which mode it ran in, rather
    than letting "no findings" mean two different things silently.
    """
    schema_root = contracts if contracts is not None else root / "contracts"
    try:
        state = load(root, contracts=contracts)
    except InventoryError as error:
        return error.findings
    findings = semantic_findings(state)
    if private_inventory is None:
        return findings
    try:
        inventory = load_private_inventory(private_inventory, contracts=schema_root)
    except InventoryError as error:
        return findings + error.findings
    return findings + resolution_findings(state, inventory)


# ── Superseding a private inventory (compare-and-set) ───────────────────────


@dataclass(frozen=True, slots=True)
class SupersedeSummary:
    """What changed between two versions of one private inventory.

    Deliberately holds LOGICAL names and counts only. `target_id` and
    `credential_ref` are public vocabulary (ADR-0004) and a reviewer needs them
    to see what moved; endpoints, store paths, file names and destinations are
    the resolved material this summary exists to avoid printing.

    The credential figures are counts rather than names for the same reason a
    basename is private: naming which binding lost its credential is naming the
    binding.
    """

    document: str
    previous_version: int
    next_version: int
    previous_digest: str
    next_digest: str
    targets_added: tuple[str, ...]
    targets_removed: tuple[str, ...]
    federations_added: tuple[str, ...]
    federations_removed: tuple[str, ...]
    receivers_added: tuple[str, ...]
    receivers_removed: tuple[str, ...]
    credentials_before: int
    credentials_after: int

    def render(self) -> str:
        lines = [
            f"supersedes {self.document} v{self.previous_version} "
            f"sha256={self.previous_digest}",
            f"        -> {self.document} v{self.next_version} sha256={self.next_digest}",
        ]
        for label, added, removed in (
            ("targets", self.targets_added, self.targets_removed),
            ("federations", self.federations_added, self.federations_removed),
            ("receivers", self.receivers_added, self.receivers_removed),
        ):
            if added:
                lines.append(f"  + {label}: {', '.join(added)}")
            if removed:
                lines.append(f"  - {label}: {', '.join(removed)}")
        lines.append(
            f"  credential bindings: {self.credentials_before} -> {self.credentials_after}"
        )
        return "\n".join(lines)


def _credential_count(inventory: PrivateInventory) -> int:
    bound = [binding.credential for binding in inventory.targets]
    bound += [binding.credential for binding in inventory.federations]
    bound += [binding.credential for binding in inventory.receivers]
    return sum(1 for credential in bound if credential is not None)


def supersede_findings(
    previous: PrivateInventory,
    following: PrivateInventory,
    *,
    expect_previous_digest: str,
) -> tuple[Finding, ...]:
    """Refuse anything that is not an in-place succession of one document.

    ``expect_previous_digest`` is the compare-and-set half, and it is required
    rather than optional. Writing a new version by overwriting whatever is
    currently stored is a lost update waiting to happen: two operators editing
    from the same starting point produce two v2 documents, the second write
    wins silently, and the change the first one made — a retired target
    removed, say — is back in the environment with nothing to show it ever
    left. Naming the version you believe you are replacing turns that into a
    refusal instead of a surprise.
    """
    findings: list[Finding] = []
    if previous.digest != expect_previous_digest:
        findings.append(
            Finding(
                "SUPERSEDE-PREVIOUS-DIGEST",
                previous.document,
                "the previous document does not hash to the digest this supersession names, "
                "so it is not the version being replaced; re-read the stored document and "
                "rebase the change onto it rather than overwriting",
            )
        )
    if following.document != previous.document:
        findings.append(
            Finding(
                "SUPERSEDE-DOCUMENT",
                following.document,
                f"document name changed from {previous.document!r}; a rename is a new "
                "document, not a new version, and every receipt naming the old one becomes "
                "unresolvable",
            )
        )
    if following.environment != previous.environment:
        findings.append(
            Finding(
                "SUPERSEDE-ENVIRONMENT",
                following.document,
                f"environment changed from {previous.environment!r} to "
                f"{following.environment!r}",
            )
        )
    if following.version != previous.version + 1:
        findings.append(
            Finding(
                "SUPERSEDE-VERSION",
                following.document,
                f"version must be exactly {previous.version + 1}, got {following.version}; a "
                "skipped number leaves a version nobody can produce and a reused one makes "
                "two documents answer to the same name",
            )
        )
    if following.content_digest == previous.content_digest:
        findings.append(
            Finding(
                "SUPERSEDE-NO-CHANGE",
                following.document,
                "the two versions describe an identical environment and differ only in their "
                "version number; a bump with no change makes two receipts look like different "
                "environments when nothing moved",
            )
        )
    return tuple(findings)


def supersede_summary(previous: PrivateInventory, following: PrivateInventory) -> SupersedeSummary:
    """Describe the change in logical names and counts, never in resolved values."""

    def names(inventory: PrivateInventory, group: str) -> set[str]:
        if group == "receivers":
            return {binding.credential_ref for binding in inventory.receivers}
        rows = inventory.targets if group == "targets" else inventory.federations
        return {binding.target_id for binding in rows}

    def moved(group: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        before, after = names(previous, group), names(following, group)
        return tuple(sorted(after - before)), tuple(sorted(before - after))

    targets_added, targets_removed = moved("targets")
    federations_added, federations_removed = moved("federations")
    receivers_added, receivers_removed = moved("receivers")
    return SupersedeSummary(
        document=following.document,
        previous_version=previous.version,
        next_version=following.version,
        previous_digest=previous.digest,
        next_digest=following.digest,
        targets_added=targets_added,
        targets_removed=targets_removed,
        federations_added=federations_added,
        federations_removed=federations_removed,
        receivers_added=receivers_added,
        receivers_removed=receivers_removed,
        credentials_before=_credential_count(previous),
        credentials_after=_credential_count(following),
    )


# ── Applying a reviewed supersession request ────────────────────────────────


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    """The logical facts a capture-format migration needs and the capture lacks.

    Every field is a NAME. Not one is a resolved value, which is what lets the
    whole plan sit in public Git and be reviewed before anything reads the
    store. The one resolved value a migration needs — the host binding — is not
    here and cannot be: it arrives as a file on the runner, from a configured
    private source, and is shredded with the store credential.
    """

    document: str
    host_target_id: str
    federations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SupersessionRequest:
    """A reviewed, PUBLIC instruction to change a private inventory.

    Two kinds, and the boundary between them is the same one ADR-0006 drew.

    ``retire`` removes entries, which needs only their logical names — already
    public under ADR-0004.

    ``migrate-capture`` rewrites a document written against the PRE-CONTRACT
    capture format into the accepted one. It carries no resolved value either:
    every byte of the result comes from the store, and the single field the
    capture does not hold (the host binding) is supplied to the tool as a file
    from a configured private source rather than through this document.

    What still has no field anywhere is ADDING a target, which genuinely needs
    a resolved endpoint. That boundary is unchanged.
    """

    kind: str
    previous_format: str
    migrate: MigrationPlan | None
    document: str
    previous_version: int
    previous_digest: str
    storage_shape: str
    """The CONFIRMED storage shape, reviewed rather than discovered.

    An earlier draft had the workflow detect this at run time and then write
    immediately, which is detection rather than confirmation — the same defect
    as a probe whose result nobody reads before acting on it. Discovery now
    reports and stops; a human puts the answer here; the mutation refuses if the
    store disagrees.
    """
    rationale: str
    targets: tuple[str, ...]
    federations: tuple[str, ...]
    receivers: tuple[str, ...]


def load_supersession_request(path: Path, *, contracts: Path) -> SupersessionRequest:
    if not path.is_file():
        raise InventoryError([Finding("MISSING", str(path), "the supersession request is absent")])
    document = _read_toml(path)
    findings = _validate_document(contracts, "supersession-request", document, str(path))
    if findings:
        raise InventoryError(findings)
    previous = _mapping(document["previous"])
    storage = _mapping(document["storage"])
    retire = _mapping(document.get("retire", {}))

    def group(name: str) -> tuple[str, ...]:
        raw = retire.get(name)
        return () if raw is None else _strings(raw)

    migrate_raw = document.get("migrate")
    migrate = None
    if migrate_raw is not None:
        plan = _mapping(migrate_raw)
        migrate = MigrationPlan(
            document=str(plan["document"]),
            host_target_id=str(plan["host_target_id"]),
            federations=_strings(plan["federations"]),
        )

    return SupersessionRequest(
        kind=str(document["kind"]),
        previous_format=str(previous["format"]),
        migrate=migrate,
        document=str(document["document"]),
        previous_version=int(cast(int, previous["version"])),
        previous_digest=str(previous["sha256"]),
        storage_shape=str(storage["shape"]),
        rationale=str(document["rationale"]),
        targets=group("targets"),
        federations=group("federations"),
        receivers=group("receivers"),
    )


def apply_supersession(
    request: SupersessionRequest, previous: PrivateInventory, stored: Mapping[str, object]
) -> tuple[Mapping[str, object], tuple[Finding, ...]]:
    """Produce the next version's document, or say why the request cannot apply.

    ``stored`` is the raw parsed document rather than the loaded record,
    because what is written back must be the stored bytes minus the retired
    entries — not a re-serialisation of this package's model. A model-shaped
    rewrite would silently drop any field a future schema version adds and this
    loader does not yet read, turning an unrelated deployment's data into
    collateral of a retirement.
    """
    findings: list[Finding] = []
    if request.kind != "retire":
        # A migration is applied by `migrate_capture`, which reads the previous
        # version through the CAPTURE contract. Letting it reach here would mean
        # loading a capture-format document through the accepted one, which is
        # the failure this whole path exists to remove.
        return {}, (
            Finding(
                "REQUEST-KIND",
                request.document,
                f"apply_supersession applies a retirement; this request is {request.kind!r}",
            ),
        )
    if request.document != previous.document:
        findings.append(
            Finding(
                "REQUEST-DOCUMENT",
                request.document,
                f"the request names document {request.document!r} but the stored document is "
                f"{previous.document!r}; a request aimed at another environment's inventory "
                "is refused rather than applied",
            )
        )
    if request.previous_version != previous.version:
        findings.append(
            Finding(
                "REQUEST-VERSION",
                request.document,
                f"the request supersedes version {request.previous_version} but the stored "
                f"document is version {previous.version}",
            )
        )
    if request.previous_digest != previous.digest:
        findings.append(
            Finding(
                "REQUEST-PREVIOUS-DIGEST",
                request.document,
                "the stored document does not hash to the digest this request names, so it is "
                "not the version the request was reviewed against; re-read it, rebase the "
                "request and have the change reviewed again",
            )
        )
    if findings:
        return {}, tuple(findings)

    following = {key: value for key, value in stored.items() if key != "version"}
    following["version"] = previous.version + 1

    def retire(group: str, key: str, names: tuple[str, ...]) -> None:
        rows = cast(Sequence[Mapping[str, object]], following.get(group, []))
        present = {str(row[key]) for row in rows}
        for name in names:
            if name not in present:
                # A no-op removal means the request is stale or names the wrong
                # entry. Applying it quietly would produce a version whose diff
                # does not match the change that was reviewed.
                findings.append(
                    Finding(
                        "REQUEST-ABSENT",
                        f"{request.document}#{group}/{name}",
                        f"the request retires {name!r} from {group}, which the stored document "
                        "does not contain",
                    )
                )
        following[group] = [row for row in rows if str(row[key]) not in set(names)]

    retire("targets", "target_id", request.targets)
    retire("federations", "target_id", request.federations)
    retire("receivers", "credential_ref", request.receivers)
    if findings:
        return {}, tuple(findings)
    return following, ()


# ── The capture format, and migrating out of it (ADR-0008) ──────────────────
#
# The production private inventory is stored in the shape the 2026-08-29 census
# produced, three PRs before the contract existed. Both supersession tools load
# the previous version through `load_private_inventory`, which validates it, so
# the workflow fails at its FIRST tool step with 68 schema errors — after
# passing its own precondition guard, which only checks that public inventory
# exists. That is the worst available failure shape: it looks like a corrupt
# document rather than a document in a known older format.
#
# Three functions fix that. `classify_stored_inventory` says WHICH format the
# store holds, before anything tries to load it. `load_capture_inventory` reads
# the old shape. `migrate_capture` rewrites it into the accepted contract using
# only values the store already held, plus a host binding supplied privately —
# which is provisioning without disclosure, and the only way to add
# `host.identity` and `host.ssh_alias` without a resolved value passing through
# public Git or a CI input.

CAPTURE_SCHEMA_VERSION = "observability-private-inventory.v1 (PROPOSED)"
ACCEPTED_SCHEMA_VERSION = "observability-private-inventory.v1"


@dataclass(frozen=True, slots=True)
class CaptureInventory:
    """A stored document in the PRE-CONTRACT capture format.

    Deliberately not a :class:`PrivateInventory`. It has no ``document`` name,
    no host binding and no federations array, so constructing one would mean
    inventing three things — and a type that can be constructed from a document
    that does not contain the values is a type that will be.

    ``raw`` is kept because the migration writes the STORED document forward
    rather than a re-serialisation of this record. A model-shaped rewrite drops
    every key the loader does not read, which for a document nobody has fully
    enumerated is an unbounded loss.
    """

    version: int
    environment: str
    digest: str
    raw: Mapping[str, object]


def classify_stored_inventory(document: Mapping[str, object]) -> str:
    """Which contract a stored document is written against, from its own claim.

    Reads ``schema_version`` and nothing else. Deliberately not a heuristic
    over the key set: a document that has drifted into a third shape must
    present as unrecognised rather than be sorted into whichever known format
    it resembles most, because the two known formats are migrated by different
    code and being wrong about which one is holding a production estate.

    Returns the declared version string, or ``"unrecognised"``.
    """
    declared = document.get("schema_version")
    if declared in (CAPTURE_SCHEMA_VERSION, ACCEPTED_SCHEMA_VERSION):
        return str(declared)
    return "unrecognised"


def load_capture_inventory(path: Path, *, contracts: Path) -> CaptureInventory:
    """Read and validate one document in the capture format.

    The contract it validates against is strict about KEYS and permissive about
    leaf types, because the census read out the key set and never read out the
    types. A contract that invented them would be asserting something nobody
    measured; the migration closes the gap the honest way, by refusing and
    naming the key when a leaf is not a shape it can map.
    """
    if not path.is_file():
        raise InventoryError(
            [Finding("MISSING", str(path), "the stored inventory document is absent")]
        )
    try:
        with path.open("rb") as handle:
            document: Document = json.load(handle)
    except json.JSONDecodeError as error:
        raise InventoryError(
            [
                Finding(
                    "MALFORMED",
                    f"{path}:{error.lineno}",
                    f"the document is not valid JSON ({error.msg})",
                )
            ]
        ) from error
    findings = _validate_document(contracts, "private-inventory-capture", document, str(path))
    if findings:
        raise InventoryError(findings)
    return CaptureInventory(
        version=int(cast(int, document["version"])),
        environment=str(document["environment"]),
        digest=canonical_digest(document),
        raw=document,
    )


def _capture_credential(raw: object) -> Mapping[str, object] | None:
    """Accept only the shape the accepted contract requires, or nothing.

    Returning ``None`` for an unmappable leaf rather than guessing is the whole
    discipline here: the caller turns it into a finding that names the entry,
    and a guess never reaches the store.
    """
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        return None
    if "openbao_path" not in raw or "file_name" not in raw:
        return None
    return {"openbao_path": str(raw["openbao_path"]), "file_name": str(raw["file_name"])}


def migrate_capture(
    capture: CaptureInventory,
    request: SupersessionRequest,
    host_binding: Mapping[str, object],
    federation_ids: Iterable[str],
) -> tuple[Mapping[str, object], tuple[Finding, ...]]:
    """Rewrite a capture-format document into the accepted contract.

    Every value in the result comes from ``capture`` except the host binding,
    which the capture does not hold at all and which is supplied privately by
    the caller. ``federation_ids`` is the PUBLIC inventory's own list of
    federation target ids, cross-checked against the request's declaration —
    the split between scrape targets and federations is declared and verified,
    never inferred from a name, because a name-shaped heuristic moves a scrape
    target into the federation array the first time somebody calls one
    ``something-federation``.

    Two fields the capture carries move OUT of the private half rather than
    across it: ``params`` and ``static_labels`` are scrape protocol and logical
    labelling, both public under ADR-0006 section 5's reasoning, and both now
    have a home in ``observability-target.v2``. The migration therefore drops
    them from the private document and reports what it dropped, so a reviewer
    can see that the public inventory has to carry them before a render is
    correct.
    """
    findings: list[Finding] = []
    location = request.document

    if request.migrate is None:  # pragma: no cover - the contract branch forbids it
        return {}, (Finding("REQUEST-KIND", location, "a migration needs a [migrate] block"),)
    plan = request.migrate

    if request.previous_format != CAPTURE_SCHEMA_VERSION:
        findings.append(
            Finding(
                "REQUEST-FORMAT",
                location,
                f"the request declares the stored version is {request.previous_format!r} but "
                "this is a capture-format migration",
            )
        )
    if request.previous_version != capture.version:
        findings.append(
            Finding(
                "REQUEST-VERSION",
                location,
                f"the request migrates version {request.previous_version} but the store holds "
                f"version {capture.version}",
            )
        )
    if request.previous_digest != capture.digest:
        findings.append(
            Finding(
                "REQUEST-PREVIOUS-DIGEST",
                location,
                "the stored document does not hash to the digest this request names. If the "
                "migration has already run, the store now holds an accepted-contract document "
                "and this request has been applied; `inventory-classify` says which it is "
                "without reading a value",
            )
        )
    if plan.host_target_id != str(host_binding.get("target_id", "")):
        findings.append(
            Finding(
                "MIGRATE-HOST-TARGET",
                location,
                "the supplied host binding is for a different logical host than the request "
                "declares; a binding written under the wrong target_id resolves cleanly and "
                "points a promotion at the wrong estate",
            )
        )
    for key in ("target_id", "identity", "ssh_alias"):
        if not str(host_binding.get(key, "")):
            findings.append(
                Finding(
                    "MIGRATE-HOST-INCOMPLETE",
                    location,
                    f"the supplied host binding has no {key}; the accepted contract requires "
                    "all three, and the capture format holds none of them",
                )
            )

    declared_federations = set(plan.federations)
    public_federations = set(federation_ids)
    if declared_federations != public_federations:
        findings.append(
            Finding(
                "MIGRATE-FEDERATION-SPLIT",
                location,
                f"the request declares federations {sorted(declared_federations)} and the "
                f"public inventory declares {sorted(public_federations)}; the split has to be "
                "the same on both sides or one array ends up holding an entry the renderer "
                "looks for in the other",
            )
        )

    if "alertmanager_endpoints" in capture.raw:
        findings.append(
            Finding(
                "MIGRATE-UNCARRIED",
                f"{location}#alertmanager_endpoints",
                "the capture holds alertmanager_endpoints, which the accepted contract has no "
                "field for. It is not silently dropped: the rendered compose file already "
                "names the alertmanager service, so the value is redundant rather than lost — "
                "confirm that in the request's rationale and remove this key from the store in "
                "the same migration",
            )
        )

    targets: list[Mapping[str, object]] = []
    federations: list[Mapping[str, object]] = []
    moved_to_public: list[str] = []
    for row in _rows(capture.raw["targets"]):
        target_id = str(row["target_id"])
        endpoints = _strings(row["resolved_endpoints"])
        if "tls_config" in row:
            findings.append(
                Finding(
                    "MIGRATE-TLS-CONFIG",
                    f"{location}#targets/{target_id}",
                    "this target carries a tls_config, which the accepted contract has no field "
                    "for. Refusing rather than dropping it: a TLS server-identity binding "
                    "changes how the target is verified, and losing it silently weakens a live "
                    "scrape",
                )
            )
        for public_key in ("params", "static_labels"):
            if public_key in row:
                moved_to_public.append(f"{target_id}.{public_key}")
        credential = None
        if "credential" in row:
            credential = _capture_credential(row["credential"])
            if credential is None:
                findings.append(
                    Finding(
                        "MIGRATE-CREDENTIAL-SHAPE",
                        f"{location}#targets/{target_id}",
                        "the stored credential is not an object carrying openbao_path and "
                        "file_name, and the migration will not guess one; complete the entry "
                        "in the store's own shape first",
                    )
                )
        if target_id in declared_federations:
            if len(endpoints) != 1:
                findings.append(
                    Finding(
                        "MIGRATE-FEDERATION-ENDPOINTS",
                        f"{location}#federations/{target_id}",
                        f"a federation binding holds exactly one endpoint and this one holds "
                        f"{len(endpoints)}",
                    )
                )
                continue
            entry: dict[str, object] = {"target_id": target_id, "endpoint": endpoints[0]}
            if credential is not None:
                entry["credential"] = credential
            federations.append(entry)
        else:
            target: dict[str, object] = {"target_id": target_id, "endpoints": list(endpoints)}
            if credential is not None:
                target["credential"] = credential
            targets.append(target)

    receivers: list[Mapping[str, object]] = []
    for row in _rows(cast(Sequence[object], capture.raw.get("receiver_bindings", []))):
        name = str(row["receiver"])
        credential = _capture_credential(row.get("credential_file"))
        if credential is None:
            findings.append(
                Finding(
                    "MIGRATE-RECEIVER-CREDENTIAL",
                    f"{location}#receivers/{name}",
                    "the capture holds only a credential FILE and the accepted contract needs "
                    "the store path with it. The migration cannot invent a path: complete this "
                    "binding in the store's own shape before migrating",
                )
            )
            continue
        receiver: dict[str, object] = {"credential_ref": name, "credential": credential}
        if "destination" in row:
            receiver["destination"] = str(row["destination"])
        receivers.append(receiver)

    if findings:
        return {}, tuple(findings)

    produced: dict[str, object] = {
        "schema_version": ACCEPTED_SCHEMA_VERSION,
        "document": plan.document,
        "version": capture.version + 1,
        "environment": capture.environment,
        "host": {
            "target_id": str(host_binding["target_id"]),
            "identity": str(host_binding["identity"]),
            "ssh_alias": str(host_binding["ssh_alias"]),
        },
        "targets": targets,
        "federations": federations,
        "receivers": receivers,
    }
    return produced, ()


def migration_findings(
    capture: CaptureInventory, produced: PrivateInventory, *, expect_previous_digest: str
) -> tuple[Finding, ...]:
    """Prove a migrated document legitimately replaces the capture it came from.

    The analogue of :func:`supersede_findings` for a previous version that
    cannot be loaded as a :class:`PrivateInventory` — which is the whole reason
    the migration exists. The three properties it can still check are the three
    that matter: the compare-and-set precondition still holds, the version
    advances by exactly one, and the environment does not move.

    It deliberately does NOT check "something changed". A migration changes the
    schema version and adds a host binding by construction, so the check would
    be vacuous here in a way it is not for a retirement.
    """
    findings: list[Finding] = []
    if capture.digest != expect_previous_digest:
        findings.append(
            Finding(
                "SUPERSEDE-PRECONDITION",
                produced.document,
                "the capture does not hash to the digest the caller expected to be replacing",
            )
        )
    if produced.version != capture.version + 1:
        findings.append(
            Finding(
                "SUPERSEDE-VERSION",
                produced.document,
                f"version {produced.version} does not follow {capture.version}",
            )
        )
    if produced.environment != capture.environment:
        findings.append(
            Finding(
                "SUPERSEDE-ENVIRONMENT",
                produced.document,
                "the migration changed the environment; a format migration moves no estate",
            )
        )
    if produced.digest == capture.digest:  # pragma: no cover - unreachable in practice
        findings.append(
            Finding(
                "SUPERSEDE-UNCHANGED",
                produced.document,
                "the migrated document is byte-identical to the capture",
            )
        )
    return tuple(findings)


def retirement_findings(
    state: DesiredState, tree: Sequence[tuple[str, str]]
) -> tuple[Finding, ...]:
    """Refuse a rendered tree that mentions a product whose monitoring was retired.

    Reads the RENDERED bytes rather than the inventory, and that is the whole
    reason it is worth having. An inventory scan sees the documents somebody
    remembered to look in; the rendered tree is every surface the bundle
    actually produces — the scrape configs, the meta rules, the Alertmanager
    routes and receivers, the Grafana datasources and dashboard providers, the
    promtail jobs, the compose file and the host artefacts. A retired product
    reappearing in any of them fails here.

    It is also the answer to a specific reporting problem. "No CRM references"
    over a config tree the sweep failed to load looks exactly like "no CRM
    references" over a clean one, and an item recorded as unknown twice starts
    reading as absent. A gate over bytes the renderer just produced cannot read
    nothing: if the tree were empty the render itself would have failed.

    Matching is case-insensitive and substring, deliberately loose. A false
    positive here costs one review comment and a token that is too specific
    costs a missed reference — and the tokens are declared per product rather
    than derived, because the spellings genuinely differ across surfaces.
    """
    findings: list[Finding] = []
    for product in state.bundle.retired:
        for token in product.tokens:
            needle = token.lower()
            for path, text in tree:
                if needle in text.lower():
                    findings.append(
                        Finding(
                            "RETIRED-PRODUCT-REFERENCED",
                            f"{path}#{product.name}",
                            f"the rendered tree mentions {token!r}, and {product.name!r} was "
                            f"decommissioned on {product.decommissioned}. A monitoring binding "
                            "pointed at a retired transport keeps the dependency alive in this "
                            "plane's view of the world after the writer is gone",
                        )
                    )
    return tuple(findings)
