"""The typed desired state of one observability control plane.

Every record here is a frozen dataclass with a fully annotated public surface
and no ``Any``: the standards profile declares this module a typed contract
surface, so an untyped or mutable field fails conformance rather than review.

Immutability is not decoration. The renderer, the validators and (from PR 6)
the drift comparison all read the same object; if any of them could mutate it,
"the desired state" would depend on the order the callers ran in, and the
byte-determinism gate in AGENTS.md rule 13 would be checking a moving target.

Ordering is likewise part of the contract. Collections are tuples in the order
the inventory declared them — never sets, never sorted at render time — so a
reviewer who moves a job up in a TOML file sees exactly that move in the
rendered diff, and nothing else changes.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "ControlPlane",
    "DesiredState",
    "Evaluator",
    "Federation",
    "FederationSource",
    "Host",
    "Inhibition",
    "Integration",
    "Label",
    "Receiver",
    "Route",
    "RouteDefaults",
    "ScrapeJob",
    "SecretFile",
    "Smtp",
    "TargetSet",
]


@dataclass(frozen=True, slots=True)
class Label:
    """One label name/value pair.

    An ordered pair rather than a mapping entry so that rendering never has to
    sort a dict to be deterministic, and so a duplicate name is a visible
    duplicate row instead of a silently overwritten key.
    """

    name: str
    value: str


@dataclass(frozen=True, slots=True)
class SecretFile:
    """A pointer to secret material — never the material.

    ``openbao_path`` says where an operator obtains the value; ``file_name`` is
    the basename the evaluator reads from its secrets directory. AGENTS.md rule
    1 exists because these two strings are safe to commit and the value is not.
    """

    openbao_path: str
    file_name: str


@dataclass(frozen=True, slots=True)
class Evaluator:
    """A pinned Prometheus or Alertmanager image and where it listens.

    ``digest`` is the identity; ``version`` is human evidence recorded in
    receipts. A tag is neither.
    """

    image: str
    digest: str
    version: str | None
    listen: str


@dataclass(frozen=True, slots=True)
class Host:
    identity: str
    ssh_alias: str


@dataclass(frozen=True, slots=True)
class Smtp:
    """Global mail settings, required as soon as any receiver sends email.

    Alertmanager refuses a configuration whose email receiver has no smarthost,
    and the refusal presents as a router that will not start — so the absence
    is a validation finding here rather than a discovery at activation.
    """

    smarthost: str
    sender: str
    auth_username: str | None
    require_tls: bool


@dataclass(frozen=True, slots=True)
class ControlPlane:
    environment: str
    host: Host
    prometheus: Evaluator
    alertmanager: Evaluator
    release_root: str
    secrets_dir: str
    external_labels: tuple[Label, ...]
    scrape_interval: str
    scrape_timeout: str
    evaluation_interval: str
    resolve_timeout: str
    smtp: Smtp | None


@dataclass(frozen=True, slots=True)
class ScrapeJob:
    job: str
    scheme: str
    metrics_path: str
    endpoints: tuple[str, ...]
    labels: tuple[Label, ...]
    scrape_interval: str | None
    scrape_timeout: str | None
    credential: SecretFile | None
    expected: int | None
    """How many targets this job must report up.

    Live verification compares against this number because a job that resolves
    to zero targets produces no failures and no series — indistinguishable, to
    every alert written over it, from a healthy system.
    """


@dataclass(frozen=True, slots=True)
class TargetSet:
    product: str
    owner: str
    jobs: tuple[ScrapeJob, ...]


@dataclass(frozen=True, slots=True)
class FederationSource:
    scheme: str
    endpoint: str
    path: str
    credential: SecretFile | None


@dataclass(frozen=True, slots=True)
class Federation:
    """One upstream Prometheus whose series are imported.

    ``rename_prefix`` is mandatory and is the whole point of the record.
    Imported ``up`` and ``scrape_*`` describe the UPSTREAM's view of its own
    targets. Left under their original names they join this plane's own health
    series, and a central rule such as ``up == 0`` then pages on a target this
    plane neither owns nor can fix — which has happened, and was fixed by
    renaming rather than by tuning the rule out.
    """

    name: str
    owner: str
    source: FederationSource
    match: tuple[str, ...]
    rename_prefix: str
    labels: tuple[Label, ...]
    scrape_interval: str | None


@dataclass(frozen=True, slots=True)
class Integration:
    kind: str
    credential: SecretFile
    destination: str | None
    send_resolved: bool


@dataclass(frozen=True, slots=True)
class Receiver:
    """A notification destination, or a reviewed decision not to have one.

    ``integrations`` may be empty only when ``null_policy`` says in words why
    this class of alert is deliberately undelivered and what observes it
    instead. An empty receiver with no policy is the silent-drop that AGENTS.md
    rule 7 exists to refuse.
    """

    name: str
    owner: str
    integrations: tuple[Integration, ...]
    null_policy: str | None


@dataclass(frozen=True, slots=True)
class RouteDefaults:
    receiver: str
    group_by: tuple[str, ...]
    group_wait: str
    group_interval: str
    repeat_interval: str


@dataclass(frozen=True, slots=True)
class Route:
    identifier: str
    matchers: tuple[str, ...]
    receiver: str
    keep_going: bool
    group_by: tuple[str, ...] | None
    group_wait: str | None
    group_interval: str | None
    repeat_interval: str | None


@dataclass(frozen=True, slots=True)
class Inhibition:
    identifier: str
    source_matchers: tuple[str, ...]
    target_matchers: tuple[str, ...]
    equal: tuple[str, ...]
    rationale: str


@dataclass(frozen=True, slots=True)
class DesiredState:
    """Everything this repository intends the control plane to be.

    One object, assembled from the whole inventory, is what makes rule 12
    possible: desired state, live state and the last verified receipt can only
    be compared independently if the first of them exists as a single value
    rather than as a habit of reading files in the right order.
    """

    control_plane: ControlPlane
    targets: tuple[TargetSet, ...]
    federations: tuple[Federation, ...]
    receivers: tuple[Receiver, ...]
    defaults: RouteDefaults
    routes: tuple[Route, ...]
    inhibitions: tuple[Inhibition, ...]
