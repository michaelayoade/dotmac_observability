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
    ControlPlane,
    DesiredState,
    Evaluator,
    Federation,
    FederationBinding,
    FederationSource,
    Host,
    HostBinding,
    Inhibition,
    Integration,
    Label,
    PrivateInventory,
    Publication,
    Receiver,
    ReceiverBinding,
    Resolution,
    ResolvedEndpoint,
    ResolvedReceiver,
    Route,
    RouteDefaults,
    ScrapeJob,
    SecretFile,
    Smtp,
    TargetBinding,
    TargetSet,
)

__all__ = [
    "PRIVATE_SCAN_EXCLUSIONS",
    "SECRET_SCAN_EXCLUSIONS",
    "Finding",
    "InventoryError",
    "canonical_bytes",
    "canonical_digest",
    "load",
    "load_private_inventory",
    "resolution_findings",
    "resolve",
    "scan_for_private_material",
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


def semantic_findings(state: DesiredState) -> tuple[Finding, ...]:
    """Every check that needs more than one PUBLIC document to answer.

    Deliberately runs without the private inventory, so a reader who has only
    this repository still gets every gate that public inputs can support. The
    checks that need resolution are :func:`resolution_findings`.
    """
    return tuple(
        _control_plane_findings(state) + _routing_findings(state) + _target_findings(state)
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
    with path.open("rb") as handle:
        document: Document = json.load(handle)
    findings += _validate_document(contracts, "private-inventory", document, str(path))
    if findings:
        raise InventoryError(findings)

    host = _mapping(document["host"])
    return PrivateInventory(
        document=str(document["document"]),
        version=int(cast(int, document["version"])),
        environment=str(document["environment"]),
        digest=canonical_digest(document),
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
    return Resolution(
        inventory=inventory,
        jobs=MappingProxyType(jobs),
        federations=MappingProxyType(resolved_federations),
        integrations=MappingProxyType(integrations),
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
        for number, line in enumerate(text.splitlines(), start=1):
            for code, pattern in _PRIVATE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            f"PRIVATE-{code}",
                            f"{relative}:{number}",
                            "looks like resolved material; public Git carries the LOGICAL "
                            "description and the private inventory carries the resolution "
                            "(AGENTS.md rule 18, ADR-0004)",
                        )
                    )
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
