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

Findings are returned, not raised. A caller that stops at the first problem
makes an operator re-run the gate once per mistake; the CLI prints all of them
and exits non-zero once.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import TypeAlias, cast

import jsonschema

from .model import (
    ControlPlane,
    DesiredState,
    Evaluator,
    Federation,
    FederationSource,
    Host,
    Inhibition,
    Integration,
    Label,
    Receiver,
    Route,
    RouteDefaults,
    ScrapeJob,
    SecretFile,
    Smtp,
    TargetSet,
)

__all__ = [
    "SECRET_SCAN_EXCLUSIONS",
    "Finding",
    "InventoryError",
    "load",
    "scan_for_secret_material",
    "semantic_findings",
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


_INTEGER = re.compile(r"^-?[0-9]+$")


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


def _require(secret: SecretFile | None) -> SecretFile:
    """Assert a schema-required credential is present.

    `_secret` is Optional because most callers hold an optional credential. An
    integration's is required by the contract, and an `assert` here beats a
    silent `None` reaching the renderer as a missing file path.
    """
    assert (
        secret is not None
    ), "the routing contract requires every integration to carry a credential"
    return secret


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
        host=Host(identity=str(host["identity"]), ssh_alias=str(host["ssh_alias"])),
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


def _target_set(document: Document) -> TargetSet:
    jobs = _rows(document["jobs"])
    return TargetSet(
        product=str(document["product"]),
        owner=str(document["owner"]),
        jobs=tuple(
            ScrapeJob(
                job=str(job["job"]),
                scheme=str(job["scheme"]),
                metrics_path=str(job["metrics_path"]),
                endpoints=_strings(job["endpoints"]),
                labels=_labels(job.get("labels")),
                scrape_interval=str(job["scrape_interval"]) if "scrape_interval" in job else None,
                scrape_timeout=str(job["scrape_timeout"]) if "scrape_timeout" in job else None,
                credential=_secret(job.get("credential")),
                expected=int(cast(int, job["expected"])) if "expected" in job else None,
            )
            for job in jobs
        ),
    )


def _federation(document: Document) -> Federation:
    source = _mapping(document["source"])
    return Federation(
        name=str(document["name"]),
        owner=str(document["owner"]),
        source=FederationSource(
            scheme=str(source["scheme"]),
            endpoint=str(source["endpoint"]),
            path=str(source["path"]),
            credential=_secret(source.get("credential")),
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
                        credential=_require(_secret(item["credential"])),
                        destination=str(item["destination"]) if "destination" in item else None,
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


def _inventory_files(root: Path) -> tuple[Path, Path, tuple[Path, ...], tuple[Path, ...]]:
    """Locate every input, in a fixed order.

    ``sorted`` on the directory listings is what makes rendering reproducible
    across filesystems: ``Path.glob`` yields in directory order, which differs
    between machines and changes when a file is rewritten.
    """
    return (
        root / "inventory" / "control-plane.toml",
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
    control_plane_path, routing_dir, target_paths, federation_paths = _inventory_files(root)
    findings: list[Finding] = []

    required = {
        "control-plane": control_plane_path,
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

    for receiver in state.receivers:
        for integration in receiver.integrations:
            if integration.kind == "telegram":
                # Alertmanager's telegram chat id is a NUMBER. A quoted value is
                # rejected at config load, and the visible symptom is a receiver
                # that simply never delivers — the failure mode hardest to
                # notice, because nothing fires to tell you notifications broke.
                if integration.destination is None or not _INTEGER.match(integration.destination):
                    findings.append(
                        Finding(
                            "RECEIVER-CHAT-ID",
                            f"routing/receivers.toml#{receiver.name}",
                            "a telegram integration needs an integer chat id in `destination`; "
                            f"got {integration.destination!r}",
                        )
                    )
            elif integration.kind == "email" and state.control_plane.smtp is None:
                findings.append(
                    Finding(
                        "SMTP-UNCONFIGURED",
                        f"routing/receivers.toml#{receiver.name}",
                        "an email integration needs [smtp] in inventory/control-plane.toml; "
                        "Alertmanager refuses an email receiver with no smarthost and the "
                        "router then fails to start",
                    )
                )
            elif integration.kind != "webhook" and integration.destination is None:
                findings.append(
                    Finding(
                        "RECEIVER-NO-DESTINATION",
                        f"routing/receivers.toml#{receiver.name}",
                        f"a {integration.kind} integration needs a `destination`",
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
            if job.expected is not None and job.expected > len(job.endpoints):
                findings.append(
                    Finding(
                        "TARGET-UNREACHABLE-EXPECTATION",
                        f"inventory/targets#{job.job}",
                        f"expected {job.expected} up targets but only {len(job.endpoints)} "
                        "endpoints are declared; the expectation can never be met",
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


def semantic_findings(state: DesiredState) -> tuple[Finding, ...]:
    """Every check that needs more than one document to answer."""
    return tuple(_routing_findings(state) + _target_findings(state))


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


def validate(root: Path, *, contracts: Path | None = None) -> tuple[Finding, ...]:
    """Schema plus semantics for the inventory under ``root``."""
    try:
        state = load(root, contracts=contracts)
    except InventoryError as error:
        return error.findings
    return semantic_findings(state)
