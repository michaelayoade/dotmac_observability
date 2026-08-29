"""The typed desired state of one observability control plane, and its resolution.

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

## Two halves, and why they are separate types

ADR-0004 splits the inputs in two, and this module keeps the split visible in
the type system rather than in a naming convention.

:class:`DesiredState` is everything public Git carries: logical identities,
owners, protocol, capabilities, policy. It is complete on its own as a
description and deliberately incomplete as a deployment — nothing in it says
where anything is.

:class:`PrivateInventory` is the resolved material: what a ``target_id``
points at, which credential a target uses, which chat a receiver reaches, and
the host's real identity. Every document written against it is private; only
its version and digest are ever published.

:class:`Resolution` is the two joined, and the renderer takes it rather than
taking the inventory directly. That is the load-bearing choice in this module.
Joining is where a public target with no binding, a binding nothing uses, or a
job that claims to authenticate against a credential-less binding are all
caught; by the time a :class:`Resolution` exists, every lookup the renderer
performs is known to succeed. A renderer that resolved as it went would meet
those failures one at a time, half-way through producing a file, and would
report the first rather than all of them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

__all__ = [
    "ControlPlane",
    "DesiredState",
    "Evaluator",
    "Federation",
    "FederationBinding",
    "FederationSource",
    "Host",
    "HostBinding",
    "Inhibition",
    "Integration",
    "Label",
    "PrivateInventory",
    "Publication",
    "Receiver",
    "ReceiverBinding",
    "Resolution",
    "ResolvedEndpoint",
    "ResolvedReceiver",
    "Route",
    "RouteDefaults",
    "ScrapeJob",
    "SecretFile",
    "Smtp",
    "TargetBinding",
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
    the basename the evaluator reads from its secrets directory.

    Both strings are PRIVATE under ADR-0004, which is a change from where this
    record started. Rule 1 says neither is a secret value, and that is still
    true; the store path describes credential custody layout and the basename
    names which credential a target uses, and both are bindings. So this record
    is now reachable only from :class:`PrivateInventory` — public Git cites a
    logical ``credential_ref`` and a boolean ``authenticated`` instead.
    """

    openbao_path: str
    file_name: str


@dataclass(frozen=True, slots=True)
class Publication:
    """A reviewed decision to publish a resolved endpoint in public Git.

    ADR-0004's per-target exception. Legitimate for a target already on the
    public internet, where indirection buys nothing — and never available by
    omission: the contract requires the endpoints, the rationale, the approver
    and the date together, so an endpoint cannot be written down anywhere that
    does not also record who accepted publishing it.

    When present, these endpoints are used INSTEAD of a private binding, so the
    exception is also the resolution and the two can never disagree.
    """

    endpoints: tuple[str, ...]
    rationale: str
    approved_by: str
    approved_on: str


@dataclass(frozen=True, slots=True)
class Evaluator:
    """A pinned Prometheus or Alertmanager image and where it listens.

    ``digest`` is the identity; ``version`` is human evidence recorded in
    receipts. A tag is neither.

    ``listen`` stays public while its address is a loopback address, and is
    refused otherwise — the conditional ADR-0004 flagged, now a gate
    (``LISTEN-NOT-LOOPBACK``). A loopback bind is this control plane's own
    posture, which publishing lets a reviewer disagree with; any other address
    is a resolved bind address, which is a map.
    """

    image: str
    digest: str
    version: str | None
    listen: str


@dataclass(frozen=True, slots=True)
class Host:
    """The LOGICAL host, and nothing else.

    Its resolved identity and SSH alias live in :class:`HostBinding`. Both
    purposes the removed fields served — a receipt recording which host was
    changed, and an operator comparing the named target with the declared one —
    are served there, by a document a promotion already has to read.
    """

    target_id: str


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
    """One scrape job, described logically.

    ``job`` is what Prometheus labels the series with; ``target_id`` is what
    the endpoint is looked up by. They are deliberately separate fields even
    when they would read the same, because collapsing them would tie a rename
    of the series label to a rename of the resolution key.

    ``authenticated`` is a CAPABILITY, which ADR-0004 publishes, as against the
    credential binding, which it does not. Resolution refuses a disagreement
    in either direction, so the public claim is falsifiable from the private
    inventory rather than decorative.
    """

    job: str
    target_id: str
    scheme: str
    metrics_path: str
    authenticated: bool
    labels: tuple[Label, ...]
    scrape_interval: str | None
    scrape_timeout: str | None
    publication: Publication | None
    path_rationale: str | None
    expected: int | None
    """How many targets this job must report up.

    Live verification compares against this number because a job that resolves
    to zero targets produces no failures and no series — indistinguishable, to
    every alert written over it, from a healthy system. Checked against the
    RESOLVED endpoint count, since the public document no longer knows one.
    """


@dataclass(frozen=True, slots=True)
class TargetSet:
    product: str
    owner: str
    jobs: tuple[ScrapeJob, ...]


@dataclass(frozen=True, slots=True)
class FederationSource:
    scheme: str
    path: str
    authenticated: bool


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
    target_id: str
    owner: str
    source: FederationSource
    match: tuple[str, ...]
    rename_prefix: str
    labels: tuple[Label, ...]
    scrape_interval: str | None


@dataclass(frozen=True, slots=True)
class Integration:
    """One delivery mechanism on a receiver, cited logically.

    ``credential_ref`` names a binding in the private inventory. Public Git
    records that this receiver reaches Telegram using a credential called
    ``oncall``; which token file that is, and which chat it delivers to, are
    resolved at promotion time.
    """

    kind: str
    credential_ref: str
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

    Complete as a description, deliberately incomplete as a deployment. It says
    what is scraped, how, by whom and with what policy, and nothing at all
    about where. Rendering needs a :class:`Resolution`.
    """

    control_plane: ControlPlane
    targets: tuple[TargetSet, ...]
    federations: tuple[Federation, ...]
    receivers: tuple[Receiver, ...]
    defaults: RouteDefaults
    routes: tuple[Route, ...]
    inhibitions: tuple[Inhibition, ...]


# ── The private half (ADR-0004) ─────────────────────────────────────────────
#
# Instances of every record below are private. The TYPES are public, for the
# same reason the schema is: a shape discloses nothing, and publishing it is
# what lets a reviewer disagree with the split.


@dataclass(frozen=True, slots=True)
class HostBinding:
    target_id: str
    identity: str
    ssh_alias: str


@dataclass(frozen=True, slots=True)
class TargetBinding:
    target_id: str
    endpoints: tuple[str, ...]
    credential: SecretFile | None


@dataclass(frozen=True, slots=True)
class FederationBinding:
    target_id: str
    endpoint: str
    credential: SecretFile | None


@dataclass(frozen=True, slots=True)
class ReceiverBinding:
    credential_ref: str
    credential: SecretFile
    destination: str | None


@dataclass(frozen=True, slots=True)
class PrivateInventory:
    """One resolved environment — the document the plan calls ObserverInventoryV1.

    ``document``, ``version`` and ``digest`` are its public identity, and the
    only part of it a receipt or an authorization ever records. All three
    together: a digest cannot say which document was supposed to produce it,
    and a version is a label anyone can reuse.

    ``digest`` is computed over the canonical form stated in the contract —
    UTF-8, sorted keys, two-space indent, no trailing newline — because a
    reader that adds a trailing newline before hashing reports false drift on a
    correct inventory.
    """

    document: str
    version: int
    environment: str
    digest: str
    host: HostBinding
    targets: tuple[TargetBinding, ...]
    federations: tuple[FederationBinding, ...]
    receivers: tuple[ReceiverBinding, ...]


# ── The join ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    endpoints: tuple[str, ...]
    credential: SecretFile | None


@dataclass(frozen=True, slots=True)
class ResolvedReceiver:
    credential: SecretFile
    destination: str | None


@dataclass(frozen=True, slots=True)
class Resolution:
    """A desired state joined to one private inventory, with every lookup proved.

    The mappings are keyed by the PUBLIC identifier the renderer already
    holds — a job name, a federation name, a ``credential_ref`` — rather than
    by ``target_id``, so the renderer never performs the join itself and cannot
    perform it differently from the validator that checked it.

    They are mappings rather than tuples because they are lookups and are never
    iterated: their order cannot reach the rendered bytes, so it is not part of
    the determinism contract the way :class:`DesiredState`'s tuples are. They
    are read-only proxies rather than plain dicts so that "frozen" means what
    the rest of this module means by it.
    """

    inventory: PrivateInventory
    jobs: Mapping[str, ResolvedEndpoint]
    federations: Mapping[str, ResolvedEndpoint]
    integrations: Mapping[str, ResolvedReceiver]
