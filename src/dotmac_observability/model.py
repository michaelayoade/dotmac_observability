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
    "AcceptedAttribute",
    "AttributeValidation",
    "Attribution",
    "Bundle",
    "ControlAttribute",
    "ControlPlane",
    "ControlRecord",
    "Deadman",
    "DeadmanSignal",
    "DesiredState",
    "DirectoryContract",
    "Evaluator",
    "Exposure",
    "Federation",
    "FederationBinding",
    "FederationSource",
    "Grafana",
    "GrafanaDashboardProvider",
    "GrafanaDatasource",
    "Host",
    "HostBinding",
    "Identifier",
    "Ingestion",
    "Inhibition",
    "Integration",
    "Label",
    "LabelBudget",
    "LagUnmeasured",
    "Loki",
    "PlantedProbe",
    "PrivateInventory",
    "Projection",
    "Promtail",
    "PromtailJob",
    "Publication",
    "Rebuild",
    "Receiver",
    "ReceiverBinding",
    "RejectionRule",
    "Resolution",
    "ResolvedEndpoint",
    "ResolvedReceiver",
    "ResourceField",
    "RetentionClass",
    "RetiredProduct",
    "RosterEntry",
    "Rotation",
    "Route",
    "RouteDefaults",
    "Runtime",
    "ScrapeJob",
    "SecretFile",
    "Sensitivity",
    "Smtp",
    "SourceSet",
    "SourceSetBinding",
    "Stream",
    "Surface",
    "Syslog",
    "SyslogFile",
    "TargetBinding",
    "TargetSet",
    "Timezone",
    "VerificationGate",
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
    omission: the contract requires the endpoints and the rationale together,
    so an endpoint cannot be written down anywhere that does not also say why
    publishing it is acceptable.

    It carries NO approver, deliberately. A name in a tracked file is
    self-attested — nothing verifies it and the person named never sees it — so
    it manufactures the appearance of an approval record where there is none.
    What authorizes this disclosure is the protected-branch review that merged
    it: externally attested, with immutable coordinates. The rationale lives
    here because a reviewer has to be able to disagree with it.

    When present, these endpoints are used INSTEAD of a private binding, so the
    exception is also the resolution and the two can never disagree.
    """

    endpoints: tuple[str, ...]
    rationale: str


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
    static_labels: tuple[Label, ...]
    """Labels identifying the TARGET, as against ``labels``, which describe the product.

    Two tuples rather than one because they answer different questions and a
    reviewer needs to see which is which — ``product = dotmac-erp`` is a fact
    about the software, ``instance = dotmac-db-primary`` is a fact about the
    thing being scraped. They render onto the same static config, in this
    order, so a job carrying both produces one block rather than two.

    Added by ADR-0008 because the running configuration assigns instance labels
    and the contract had nowhere to put them, which made byte-parity with the
    as-built impossible for every job that carries one — and an unrepresentable
    difference is indistinguishable from a real one in a drift comparison.
    """
    params: tuple[tuple[str, tuple[str, ...]], ...]
    """URL query parameters, as ordered pairs of name to values.

    A tuple of pairs rather than a mapping for the reason :class:`Label` is a
    pair: rendering never has to sort a dict to be deterministic, and a
    duplicate name is a visible duplicate row instead of a silently overwritten
    key.

    Added by ADR-0008 because a live target needs one. The OpenBao job sends
    ``format=prometheus``; without it OpenBao answers with its own JSON, which
    Prometheus accepts as a successful scrape and stores nothing from — a
    target that reads green and delivers no series.
    """
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
    bundle: Bundle
    """Everything deployed that is not a target, a route or a receiver.

    Part of the SAME desired state rather than a second one, because a
    promotion that can activate the evaluators without the log store, the
    rotation contract and the exposure policy is a promotion that can leave the
    host in a combination nobody described. One value, one digest, one
    activation.
    """
    ingestion: Ingestion
    """What the fleet shipper may put into this control plane, and what it may not.

    Part of the same desired state for the same reason the bundle is. The log
    store's label limit, the alerts that notice a stopped shipper and the
    retention every stream ages out under are all rendered from this document,
    so a promotion able to activate the evaluators without it would be a
    promotion that accepts an unspecified wire.
    """
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

    ``content_digest`` is the same hash over the document with ``version``
    removed: the identity of the ENVIRONMENT, as against the identity of the
    record. Two versions sharing a content digest describe the same estate and
    differ only in their numbering, which is a thing worth being able to say —
    and worth refusing, when somebody bumps a version having changed nothing.
    A comparison of full digests cannot detect that at all, because
    incrementing the version is itself a change to the bytes.
    """

    document: str
    version: int
    environment: str
    digest: str
    content_digest: str
    host: HostBinding
    targets: tuple[TargetBinding, ...]
    federations: tuple[FederationBinding, ...]
    receivers: tuple[ReceiverBinding, ...]
    source_sets: tuple[SourceSetBinding, ...]
    """What each named exposure source set resolves to.

    Private for the same reason an endpoint is: a management prefix is a map of
    where the operators are, and a tunnel interface name is one hop from it.
    Empty is legitimate — a bundle whose surfaces are all loopback names no
    source set — and resolution refuses in both directions, so a set nobody
    allows from is a finding just as an unresolved ``allow_from`` is.
    """


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
    source_sets: Mapping[str, SourceSetBinding]


# ── The bundle (ADR-0008) ───────────────────────────────────────────────────
#
# Everything the control plane deploys that is not a scrape target, a route or
# a receiver. It lives in the same DesiredState for one reason: a promotion
# that can activate the evaluators without the log store, the rotation
# contract and the exposure policy is a promotion that can leave the host in a
# combination nobody described. One bundle, one digest, one activation.


@dataclass(frozen=True, slots=True)
class Runtime:
    """A pinned image and where it listens — the same shape as :class:`Evaluator`.

    Kept as its own record rather than reusing ``Evaluator`` because the two
    are governed by different documents: an evaluator is named by
    ``observability-control-plane.v2`` and a runtime by
    ``observability-bundle.v1``. Sharing the type would make a change to one
    contract silently a change to the other.
    """

    image: str
    digest: str
    version: str | None
    listen: str


@dataclass(frozen=True, slots=True)
class Timezone:
    """UTC for infrastructure, optionally something else for a reader.

    ``infrastructure`` is a constant in the contract rather than a gate here,
    so a non-UTC value is not a shape this repository can hold. ``presentation``
    reaches Grafana's provisioning and nothing else — no evaluator, no log
    file, no receipt — because rendering a local zone for a reader is
    presentation while storing one is a data model.
    """

    infrastructure: str
    presentation: str | None
    rationale: str


@dataclass(frozen=True, slots=True)
class Loki:
    runtime: Runtime
    retention: str
    reject_older_than: str
    ingestion_rate_mb: int
    ingestion_burst_mb: int


@dataclass(frozen=True, slots=True)
class PromtailJob:
    name: str
    path_glob: str
    labels: tuple[Label, ...]
    decode_docker_json: bool


@dataclass(frozen=True, slots=True)
class Promtail:
    runtime: Runtime
    jobs: tuple[PromtailJob, ...]


@dataclass(frozen=True, slots=True)
class GrafanaDatasource:
    name: str
    kind: str
    service: str
    default: bool


@dataclass(frozen=True, slots=True)
class GrafanaDashboardProvider:
    name: str
    folder: str


@dataclass(frozen=True, slots=True)
class Grafana:
    runtime: Runtime
    datasources: tuple[GrafanaDatasource, ...]
    dashboard_providers: tuple[GrafanaDashboardProvider, ...]


@dataclass(frozen=True, slots=True)
class DirectoryContract:
    path: str
    owner: str
    group: str
    mode: str


@dataclass(frozen=True, slots=True)
class SyslogFile:
    """One facility routed to one file, with the file's ownership stated.

    The ownership is the whole record. rsyslog on the Observer host runs
    privilege-dropped and was told to write a file it could not create, so it
    suspended the action, resumed it, and suspended it again — ten thousand
    times in thirty days, with the mail facility going nowhere throughout. The
    repair is that something other than rsyslog creates the file, with this
    owner, this group and this mode, before rsyslog opens it and again after
    every rotation.
    """

    facility: str
    path: str
    owner: str
    group: str
    mode: str
    synchronous: bool


@dataclass(frozen=True, slots=True)
class Rotation:
    frequency: str
    keep: int
    compress: bool


@dataclass(frozen=True, slots=True)
class Syslog:
    directory: DirectoryContract
    files: tuple[SyslogFile, ...]
    rotation: Rotation


@dataclass(frozen=True, slots=True)
class RosterEntry:
    """One owned runtime resource.

    The roster is what makes an unattributed resource a finding. A container,
    network or volume present on the host and absent here is owned by nobody,
    and deleting something owned by nobody is a decision that needs a manifest
    and an approval — not a `docker prune`, which decides it for you and leaves
    no record of what it decided.
    """

    name: str
    kind: str
    owner: str
    port: int | None


@dataclass(frozen=True, slots=True)
class RetiredProduct:
    """A product whose monitoring is gone, and must stay gone.

    A grep proves a tree was clean on the day somebody ran it. This is the
    standing version: the tokens are checked against every rendered byte, so a
    scrape job, alert group, route, datasource or dashboard provider that
    reappears under the same name fails the build rather than a review.

    ``residual_data`` records what still carries the product's labels in
    RETAINED data, which is the distinction most easily mis-reported. A series
    or log stream recorded before the retirement is history and ages out with
    retention; a scrape job is a live dependency. Saying which is which stops
    the next reader concluding either that the retirement is incomplete or that
    the data has already gone.
    """

    name: str
    tokens: tuple[str, ...]
    decommissioned: str
    rationale: str
    residual_data: str | None


@dataclass(frozen=True, slots=True)
class SourceSet:
    """A named, typed set of permitted sources — never a literal.

    ``kind`` decides how it renders. ``tunnel_interface`` becomes an interface
    match, which is what a WireGuard peer set actually is: membership is
    cryptographic rather than addressed, so matching the interface is both
    simpler and stricter than matching a prefix. ``address_set`` becomes source
    matches. Neither the interface name nor the prefixes are held here; they
    are bound from the private inventory.
    """

    name: str
    kind: str


@dataclass(frozen=True, slots=True)
class Surface:
    """One published surface, and which packet path reaches it.

    ``kind`` is load-bearing and is why this record exists rather than a pair
    of strings. On this host an IPv4 container publish traverses ``FORWARD``
    and therefore ``DOCKER-USER``, while IPv6 terminates on ``INPUT``. Seven
    IPv6 DROP rules were found sitting in ``DOCKER-USER``, where no IPv6 packet
    to a published port ever arrives, so every port they name is open. Deriving
    the chain from ``kind`` and the family — rather than letting an author pick
    one — makes that unrepresentable.
    """

    name: str
    kind: str
    port: int
    protocol: str
    family: str
    exposure: str
    allow_from: str | None
    authenticated: bool
    rationale: str | None


@dataclass(frozen=True, slots=True)
class Exposure:
    source_sets: tuple[SourceSet, ...]
    surfaces: tuple[Surface, ...]


@dataclass(frozen=True, slots=True)
class VerificationGate:
    """Target health and ingestion integrity, as two predicates that must both hold.

    Eighteen of eighteen targets read ``up == 1`` on the Observer host while
    1.8 million samples were rejected at ingestion. A gate carrying only a
    health predicate would have passed that, which is why this record cannot
    be constructed with one: the contract requires both fields and the renderer
    emits their conjunction.
    """

    name: str
    health: str
    integrity: str
    window: str


@dataclass(frozen=True, slots=True)
class Bundle:
    timezone: Timezone
    loki: Loki
    promtail: Promtail
    grafana: Grafana
    syslog: Syslog
    roster: tuple[RosterEntry, ...]
    retired: tuple[RetiredProduct, ...]
    exposure: Exposure
    gates: tuple[VerificationGate, ...]


# ── The ingestion boundary (ADR-0011) ───────────────────────────────────────
#
# What arrives, from the one fleet shipper. The types are here rather than in
# `ingestion.py` for the same reason every other record is: `model` is the
# typed contract surface named by `.dotmac/standards-profile.json`, and a
# decision module that also defined its own inputs would be two authorities.


@dataclass(frozen=True, slots=True)
class ResourceField:
    """One piece of resource identity every accepted record carries.

    ``cardinality`` is not decoration. It decides whether the field may become
    a stream label, and the decision has to be made where the field is
    declared: an unbounded field promoted to a label is a store that stops
    answering queries, and by the time it does the labels are already written.
    """

    field: str
    required: bool
    cardinality: str
    rationale: str


@dataclass(frozen=True, slots=True)
class Identifier:
    """One of the identifiers that must not collapse into another.

    ``means`` is an enum rather than prose because the property being defended
    is that no two of them mean the same thing, and free text cannot be
    compared. A request, a business flow, a trace, a span and a durable audit
    event are five different questions; a deployment that spells them all
    ``request_id`` can ask one.
    """

    name: str
    means: str
    transport: str
    signals: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Attribution:
    """How a record reports where it believes its client address came from.

    ``unresolved`` is a constant in the contract rather than a gate here, so
    the shape cannot express the mistake: a resolver reporting ``direct`` when
    it could not establish the peer has manufactured an attribution, and every
    later reader treats a manufactured one exactly like an observed one.
    """

    values: tuple[str, ...]
    unresolved: str
    rationale: str


@dataclass(frozen=True, slots=True)
class LabelBudget:
    max_stream_labels: int
    rationale: str


@dataclass(frozen=True, slots=True)
class AttributeValidation:
    """What an accepted attribute's value is checked against.

    ``opaque`` is the only kind that accepts a value without looking at it, and
    it carries a rationale for exactly that reason. A field accepted and never
    validated is a field this control plane has taken responsibility for and
    does not look at.
    """

    kind: str
    values: tuple[str, ...]
    shape: str | None
    rationale: str | None


@dataclass(frozen=True, slots=True)
class AcceptedAttribute:
    name: str
    signals: tuple[str, ...]
    disposition: str
    cardinality: str
    validation: AttributeValidation
    rationale: str


@dataclass(frozen=True, slots=True)
class PlantedProbe:
    """Synthetic material one rejection rule must refuse.

    The value is named rather than written: ``value_shape`` indexes a table in
    :mod:`~dotmac_observability.ingestion` that assembles the string at check
    time. A repository that had to commit realistic credential-shaped strings
    in order to prove it refuses them would be defeating its own scanner to do
    it.
    """

    attribute: str
    value_shape: str


@dataclass(frozen=True, slots=True)
class RejectionRule:
    name: str
    kind: str
    match: str
    rationale: str
    planted: tuple[PlantedProbe, ...]


@dataclass(frozen=True, slots=True)
class ControlAttribute:
    name: str
    value_shape: str


@dataclass(frozen=True, slots=True)
class ControlRecord:
    """A record that must be ACCEPTED, checked in the same pass as the rejections.

    The positive control for a negative suite. A classifier that refuses every
    record satisfies every rejection probe ever written, and nothing about the
    refusals distinguishes it from a correct one.
    """

    name: str
    signal: str
    attributes: tuple[ControlAttribute, ...]


@dataclass(frozen=True, slots=True)
class LagUnmeasured:
    """Why a stream's lag is not measured, and what will measure it.

    The alternative was naming a metric nothing emits. That renders an alert
    that can never fire, which is indistinguishable on every dashboard from one
    that is quietly passing — the defect AGENTS.md rule 8 names. A declared
    unmeasured region with an owner is worse news and better evidence.
    """

    rationale: str
    monitored_by: str


@dataclass(frozen=True, slots=True)
class Stream:
    """One signal's ingestion health, as three facts one counter cannot separate.

    ``arrival_counter`` and ``integrity_counter`` are deliberately different
    series. A drop counter that is not moving describes a healthy pipeline and
    a stopped one identically, so silence is detected on arrivals and only on
    arrivals — by ABSENCE, because a rate over a series that has ceased to
    exist is not zero, it is nothing, and matches no rows to alert on.
    """

    signal: str
    arrival_counter: str
    integrity_counter: str
    integrity_window: str
    lag_expr: str | None
    lag_budget: str | None
    lag_unmeasured: LagUnmeasured | None
    silence_budget: str
    retention_class: str
    rationale: str


@dataclass(frozen=True, slots=True)
class Sensitivity:
    """The planted condition that makes a deadman fire, and when it last did.

    ``last_proved`` is nullable and null is the honest value. A deadman that
    has never fired is not known to work: it is indistinguishable from one
    whose expression matches no series at all, which is the most common way an
    alert is silently wrong. The null is counted by a ratchet and stamped into
    the rendered alert's own annotations, so an operator reading it in an
    incident learns that nobody has watched it work.
    """

    planted_condition: str
    procedure_ref: str
    last_proved: str | None


@dataclass(frozen=True, slots=True)
class DeadmanSignal:
    name: str
    expr: str
    hold: str
    summary: str
    sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class Deadman:
    unproved_declared: int
    signals: tuple[DeadmanSignal, ...]


@dataclass(frozen=True, slots=True)
class Rebuild:
    procedure_ref: str
    compare: str
    last_rebuilt: str | None
    verdict: str


@dataclass(frozen=True, slots=True)
class Projection:
    """The central audit projection, and why it is never the evidence.

    Audit is durable evidence owned by each application's own database, written
    in the same transaction as the decision it records. This is a searchable
    copy with a lag. ``authoritative`` is a constant in the contract so no
    document can express the other value — a projection that CAN be declared
    authoritative eventually is, usually in the hour when the application
    database is the thing that is down.
    """

    name: str
    status: str
    authoritative: bool
    derived_from: str
    lag_expr: str
    lag_budget: str
    source_retention: str
    retention_class: str
    non_authority_notice: str
    rebuild: Rebuild


@dataclass(frozen=True, slots=True)
class RetentionClass:
    """One retention and access decision, with the question it answers.

    ``kind`` separates two constraints that point in opposite directions.
    Telemetry is kept while it is operationally useful and may be shortened
    freely. An audit projection's retention is bounded from ABOVE by its
    source's, because a projection retained longer than the rows it derives
    from becomes, on the day the source ages one out, the last copy of it — and
    a last copy is authoritative whatever any document says.
    """

    name: str
    kind: str
    duration: str
    access: tuple[str, ...]
    last_copy: bool
    rationale: str


@dataclass(frozen=True, slots=True)
class Ingestion:
    resource: tuple[ResourceField, ...]
    identifiers: tuple[Identifier, ...]
    attribution: Attribution
    labels: LabelBudget
    attributes: tuple[AcceptedAttribute, ...]
    rejected: tuple[RejectionRule, ...]
    accepted_control: tuple[ControlRecord, ...]
    streams: tuple[Stream, ...]
    deadman: Deadman
    projection: Projection
    retention: tuple[RetentionClass, ...]


@dataclass(frozen=True, slots=True)
class SourceSetBinding:
    """What a named source set resolves to. PRIVATE.

    ``interface`` for a ``tunnel_interface`` set, ``prefixes`` for an
    ``address_set``. Exactly one is present, and resolution refuses the other
    combination in both directions — a set typed as an interface with prefixes
    behind it renders a rule that matches the wrong thing while validating
    cleanly.
    """

    name: str
    interface: str | None
    prefixes: tuple[str, ...]
