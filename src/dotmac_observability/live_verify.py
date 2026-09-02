"""Read-back verification: the six conditions that separate the two verdicts.

AGENTS.md rule 29 states the distinction this module exists to make checkable.
``rendered_guarded`` means a defect is unrepresentable in newly rendered
bundles — durable, real, and NOT a repair, because the host is not yet running
a rendered bundle. ``deployed_repaired`` requires all six conditions below to
hold at once. Claiming the second while holding the first is the specific error
the vocabulary was introduced to prevent, and until now nothing but discipline
stopped it.

## Why this module performs no I/O

It takes a :class:`LiveState` — a parsed
``observability-live-observation.v1`` document — and compares it with the
desired state, the rendered tree and a recorded baseline. Reaching the host is
the promotion facility's job (see :mod:`dotmac_observability.promote`); the
comparison is this module's, and separating them is what lets every one of the
six conditions be exercised in a unit test without a running evaluator, a
container or a daemon. A verifier that could only be tested against a live
stack would be tested rarely, and the conditions it checks are precisely the
ones that must not be wrong.

## The six conditions

1. **The complete rendered tree matches live state.** Every rendered path
   present with the rendered digest, and nothing else present. Compared, not
   sampled — and an observation listing no files is refused rather than passing
   as "nothing differs", because a read-back that failed reports exactly as a
   clean one does.
2. **Every declared target is healthy.** Per job, the number of active targets
   equals the declared ``expected`` and every one of them is up.
3. **The rejected-sample count did not increase, and the counter was not
   reset.** Stated as a delta from a recorded baseline. See "Why a reset cannot
   pass" below — this is the condition most easily made true by erasing the
   evidence it exists to preserve.
4. **Routes resolve and the canary was delivered at the receiver.** Not at
   Alertmanager's outbound attempt: a 200 from a delivery API is not evidence a
   human can be reached.
5. **Both address families were probed, each with a positive control in the
   same pass.** IPv4 to a container publish traverses ``FORWARD`` and therefore
   ``DOCKER-USER``; IPv6 to the same port terminates on ``INPUT`` because the
   published socket is held by the userland proxy. A v4-only check has passed
   over a live v6 exposure on this fleet more than once, and seven IPv6 rules
   were found sitting in a chain no IPv6 packet traverses.
6. **Rollback restored the previous digest.** A rollback that has never been
   exercised is a plan, not a capability.

## Why a reset cannot pass

``counter == 0`` is satisfiable four ways, and only one of them is a repair.
The counter can be reset, the TSDB can be recreated, the container can be
restarted, or the fault can genuinely have stopped. Every check below is built
so the first three REFUSE rather than pass:

* a value BELOW the baseline is ``INTEGRITY-COUNTER-RESET`` — the only way a
  monotonic counter goes backwards;
* a ``process_start_time`` that moved is ``INTEGRITY-PROCESS-RESTARTED``, which
  catches the reset that climbed back PAST the baseline and would otherwise
  read as a healthy delta;
* a baseline of zero is ``INTEGRITY-BASELINE-ZERO``, because a zero baseline
  makes the delta trivially satisfiable and is indistinguishable from a counter
  reset immediately before the baseline was taken;
* a window shorter than the gate's own ``window`` is
  ``INTEGRITY-WINDOW-TOO-SHORT``, because "no increase" measured over no
  elapsed time is arithmetic rather than evidence;
* an absent baseline is ``INTEGRITY-BASELINE-ABSENT``, never an assumed zero.

None of those is a warning. The verdict is a conjunction, so any one of them
holds the result at ``rendered_guarded``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .model import DesiredState, Resolution, Surface
from .render import RenderedTree, file_digest
from .validate import Finding, InventoryError, _validate_document

__all__ = [
    "CONDITIONS",
    "VERDICT_DEPLOYED_REPAIRED",
    "VERDICT_RENDERED_GUARDED",
    "ConditionResult",
    "IntegrityReading",
    "LiveCanary",
    "LiveProbe",
    "LiveRelease",
    "LiveRollback",
    "LiveRoute",
    "LiveRule",
    "LiveState",
    "LiveTarget",
    "TreeEntry",
    "Verification",
    "chain_for",
    "declared_probe_slots",
    "expectation_for",
    "families_of",
    "integrity_counters",
    "live_state",
    "load_live_observation",
    "observation_document",
    "render_verification",
    "rules_semantic_digest",
    "verify",
]


VERDICT_RENDERED_GUARDED = "rendered_guarded"
VERDICT_DEPLOYED_REPAIRED = "deployed_repaired"

#: The six conditions, numbered as ``docs/inventories/observer-as-built.md``
#: §17 numbers them. The numbering is part of the contract: a report that
#: renumbers them stops matching the document operators read.
CONDITIONS: tuple[tuple[int, str], ...] = (
    (1, "the complete rendered tree matches live state"),
    (2, "every declared target is healthy"),
    (3, "no new rejected samples, against a baseline that was not reset"),
    (4, "routes resolve and the canary was delivered at the receiver"),
    (5, "both address families probed, each with a positive control"),
    (6, "rollback restored the previous digest"),
)

_DURATION = re.compile(r"^(\d+)([smhd])$")
_DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _duration_seconds(value: str) -> int | None:
    """Seconds in a Prometheus-style duration, or ``None`` if it is not one.

    Deliberately narrow. The gate's window comes from a contract that already
    constrains its spelling, so anything this cannot read is a shape the
    contract should have refused, and guessing at it would turn a schema defect
    into a silently weaker check.
    """
    match = _DURATION.match(value)
    if match is None:
        return None
    return int(match.group(1)) * _DURATION_SECONDS[match.group(2)]


# ── The observation, as typed records ───────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TreeEntry:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class LiveRelease:
    current: str
    previous: str | None


@dataclass(frozen=True, slots=True)
class LiveTarget:
    job: str
    health: str


@dataclass(frozen=True, slots=True)
class LiveRule:
    group: str
    name: str
    health: str


@dataclass(frozen=True, slots=True)
class LiveRoute:
    identifier: str
    receiver: str


@dataclass(frozen=True, slots=True)
class IntegrityReading:
    """One read of an ingestion counter, with the evidence that it is comparable.

    ``process_start_time`` is not decoration and is not for reporting. Two
    readings of a monotonic counter are only comparable while the process that
    owns it has not restarted, and a restart is exactly how a counter reset
    hides: the value returns to zero, climbs, and eventually passes the
    baseline, at which point a value comparison alone reports a healthy delta
    over a period when every sample was being dropped.
    """

    counter: str
    value: int
    process_start_time: float


@dataclass(frozen=True, slots=True)
class LiveCanary:
    fired: bool
    delivered: bool
    recovered: bool
    receiver: str
    receiver_evidence_ref: str | None


@dataclass(frozen=True, slots=True)
class LiveProbe:
    surface: str
    family: str
    chain: str
    expectation: str
    outcome: str
    control_outcome: str
    control_evidence_ref: str | None


@dataclass(frozen=True, slots=True)
class LiveRollback:
    exercised: bool
    restored_release: str | None
    restored_digest: str | None
    succeeded: bool


@dataclass(frozen=True, slots=True)
class LiveState:
    """One read-back of a running control plane — the third comparable artifact.

    Frozen and ordered for the same reason :class:`~dotmac_observability.model
    .DesiredState` is: the verifier, the drift comparison and the receipt
    builder all read this object, and a mutable one would make what "live
    state" means depend on which of them ran first.
    """

    observed_at: str
    environment: str
    host_target_id: str
    release: LiveRelease
    tree: tuple[TreeEntry, ...]
    targets: tuple[LiveTarget, ...]
    rules: tuple[LiveRule, ...]
    routes: tuple[LiveRoute, ...]
    integrity: IntegrityReading
    canary: LiveCanary
    probes: tuple[LiveProbe, ...]
    rollback: LiveRollback | None


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return value


def _rows(value: object) -> Sequence[Mapping[str, object]]:
    assert isinstance(value, Sequence)
    return [_mapping(row) for row in value]


def load_live_observation(path: Path, *, contracts: Path) -> LiveState:
    """Read and validate one observation document, then type it.

    Nothing is constructed from an unvalidated document — the same premise the
    inventory loader rests on, and what makes the casts below safe. A malformed
    observation raises with every schema finding rather than the first, because
    an operator reading a failed promotion should not have to re-run it once
    per mistake.
    """
    with path.open("rb") as handle:
        document: Mapping[str, object] = json.load(handle)
    findings = _validate_document(contracts, "live-observation", document, path.name)
    if findings:
        raise InventoryError(findings)
    return live_state(document)


def live_state(document: Mapping[str, object]) -> LiveState:
    """Type a document already known to satisfy the contract."""
    release = _mapping(document["release"])
    integrity = _mapping(document["integrity"])
    canary = _mapping(document["canary"])
    rollback_raw = document.get("rollback")
    rollback = None
    if rollback_raw is not None:
        row = _mapping(rollback_raw)
        restored_release = row["restored_release"]
        restored_digest = row["restored_digest"]
        rollback = LiveRollback(
            exercised=bool(row["exercised"]),
            restored_release=None if restored_release is None else str(restored_release),
            restored_digest=None if restored_digest is None else str(restored_digest),
            succeeded=bool(row["succeeded"]),
        )
    previous = release["previous"]
    evidence = canary.get("receiver_evidence_ref")
    return LiveState(
        observed_at=str(document["observed_at"]),
        environment=str(document["environment"]),
        host_target_id=str(document["host_target_id"]),
        release=LiveRelease(
            current=str(release["current"]),
            previous=None if previous is None else str(previous),
        ),
        tree=tuple(
            TreeEntry(path=str(row["path"]), sha256=str(row["sha256"]))
            for row in _rows(document["tree"])
        ),
        targets=tuple(
            LiveTarget(job=str(row["job"]), health=str(row["health"]))
            for row in _rows(document["targets"])
        ),
        rules=tuple(
            LiveRule(group=str(row["group"]), name=str(row["name"]), health=str(row["health"]))
            for row in _rows(document["rules"])
        ),
        routes=tuple(
            LiveRoute(identifier=str(row["id"]), receiver=str(row["receiver"]))
            for row in _rows(document["routes"])
        ),
        integrity=IntegrityReading(
            counter=str(integrity["counter"]),
            value=int(str(integrity["value"])),
            process_start_time=float(str(integrity["process_start_time"])),
        ),
        canary=LiveCanary(
            fired=bool(canary["fired"]),
            delivered=bool(canary["delivered"]),
            recovered=bool(canary["recovered"]),
            receiver=str(canary["receiver"]),
            receiver_evidence_ref=None if evidence is None else str(evidence),
        ),
        probes=tuple(
            LiveProbe(
                surface=str(row["surface"]),
                family=str(row["family"]),
                chain=str(row["chain"]),
                expectation=str(row["expectation"]),
                outcome=str(row["outcome"]),
                control_outcome=str(_mapping(row["control"])["outcome"]),
                control_evidence_ref=(
                    None
                    if _mapping(row["control"]).get("evidence_ref") is None
                    else str(_mapping(row["control"])["evidence_ref"])
                ),
            )
            for row in _rows(document["probes"])
        ),
        rollback=rollback,
    )


# ── Derivations shared with the renderer ────────────────────────────────────
#
# The chain and the families a surface must be probed on are derived here from
# the same two fields the renderer derives them from, and never taken from the
# observation. A prober that declared its own expectation could declare the
# wrong one and pass; deriving both means the observation supplies only what
# was measured.


def families_of(surface: Surface) -> tuple[str, ...]:
    if surface.family == "dual_stack":
        return ("ipv4", "ipv6")
    return (surface.family,)


def chain_for(surface: Surface, family: str) -> str:
    """Which chain a packet to this surface actually traverses.

    Identical to the renderer's derivation, and identical DELIBERATELY: the
    check compares where a rule was observed against where the packet goes, so
    a second spelling of this rule would let the two agree with each other
    while both being wrong about the host.
    """
    if surface.kind == "container_published" and family == "ipv4":
        return "DOCKER-USER"
    return "INPUT"


def expectation_for(surface: Surface) -> str:
    """What the declared exposure says a probe FROM OUTSIDE should see.

    ``none`` and ``loopback`` are not published beyond the host and must refuse.
    ``ingress`` publishes no host port of its own — it is reached through the
    ingress, so a direct probe must also refuse. Only ``public`` is reachable,
    and only alongside a reviewed exception and a declared authentication
    requirement, which the semantic gates already checked.
    """
    return "reachable" if surface.exposure == "public" else "refused"


# ── The result ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ConditionResult:
    number: int
    name: str
    findings: tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings


@dataclass(frozen=True, slots=True)
class Verification:
    """The six conditions and the verdict they add up to.

    The verdict is a conjunction and is DERIVED rather than stored, so there is
    no field an optimistic caller can set. ``deployed_repaired`` is returned
    only when all six conditions are present and every one of them passed;
    every other state, including "five passed and one was not measured", is
    ``rendered_guarded``.
    """

    conditions: tuple[ConditionResult, ...]

    def __post_init__(self) -> None:
        numbers = tuple(condition.number for condition in self.conditions)
        expected = tuple(number for number, _ in CONDITIONS)
        if numbers != expected:
            raise ValueError(
                f"a verification reports conditions {numbers}, not {expected}. "
                "The verdict is a conjunction of all six; a partial report would make "
                "'deployed_repaired' mean 'the conditions somebody chose to run passed'."
            )

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(finding for condition in self.conditions for finding in condition.findings)

    @property
    def verdict(self) -> str:
        if all(condition.passed for condition in self.conditions):
            return VERDICT_DEPLOYED_REPAIRED
        return VERDICT_RENDERED_GUARDED

    def unmet(self) -> tuple[ConditionResult, ...]:
        return tuple(condition for condition in self.conditions if not condition.passed)


# ── Condition 1: the whole tree ─────────────────────────────────────────────


def _tree_findings(tree: RenderedTree, live: LiveState) -> list[Finding]:
    findings: list[Finding] = []
    if not live.tree:
        # The vacuity guard, and the one most worth stating. A read-back that
        # listed nothing produces an empty difference set, which is exactly
        # what a clean one produces. Refusing the empty case is the only way
        # "no differences" can mean the tree was compared.
        findings.append(
            Finding(
                "TREE-NOT-READ",
                "live.tree",
                "the observation lists no files under the active release. A read-back that "
                "found nothing reports identically to a clean one, so this is refused rather "
                "than treated as a match.",
            )
        )
        return findings

    expected = {path: file_digest(contents) for path, contents in tree}
    observed = {entry.path: entry.sha256 for entry in live.tree}
    for path, digest in expected.items():
        if path not in observed:
            findings.append(
                Finding("TREE-MISSING", path, "the render produces this file; the host has not")
            )
        elif observed[path] != digest:
            findings.append(
                Finding(
                    "TREE-DIFFERS",
                    path,
                    f"expected {digest[:12]}, live {observed[path][:12]} — the host is not "
                    "running the bytes this promotion rendered",
                )
            )
    for path in observed:
        if path not in expected:
            findings.append(
                Finding(
                    "TREE-UNEXPECTED",
                    path,
                    "present under the active release and produced by no render. A stale file "
                    "left behind is still mounted into the evaluator.",
                )
            )
    return findings


# ── Condition 2: every declared target healthy ──────────────────────────────


def _target_findings(state: DesiredState, resolution: Resolution, live: LiveState) -> list[Finding]:
    findings: list[Finding] = []
    if not live.targets:
        findings.append(
            Finding(
                "TARGETS-NOT-READ",
                "live.targets",
                "the observation lists no active targets. Zero targets produces no failures "
                "and no series, and is indistinguishable from a healthy system to every alert "
                "written over it.",
            )
        )
        return findings

    counted: dict[str, list[LiveTarget]] = {}
    for target in live.targets:
        counted.setdefault(target.job, []).append(target)

    declared: dict[str, int] = {}
    for target_set in state.targets:
        for scrape_job in target_set.jobs:
            resolved = resolution.jobs[scrape_job.job]
            declared[scrape_job.job] = (
                scrape_job.expected if scrape_job.expected is not None else len(resolved.endpoints)
            )
    for federation in state.federations:
        declared[federation.name] = 1

    for job, expected in declared.items():
        observed = counted.get(job, [])
        if not observed:
            findings.append(
                Finding(
                    "TARGET-ABSENT",
                    job,
                    f"declared with {expected} expected target(s) and present in no live "
                    "target list. An absent job is not a quiet job.",
                )
            )
            continue
        if len(observed) != expected:
            findings.append(
                Finding(
                    "TARGET-COUNT",
                    job,
                    f"declared {expected} target(s), live reports {len(observed)}",
                )
            )
        unhealthy = [target for target in observed if target.health != "up"]
        if unhealthy:
            findings.append(
                Finding(
                    "TARGET-UNHEALTHY",
                    job,
                    f"{len(unhealthy)} of {len(observed)} target(s) are not up",
                )
            )

    for job in counted:
        if job not in declared:
            findings.append(
                Finding(
                    "TARGET-UNDECLARED",
                    job,
                    "scraped live and declared by no inventory document. This is the shape of "
                    "the job that outlived its product on this host by weeks.",
                )
            )
    return findings


# ── Condition 2 (continued): rules exist and evaluate ───────────────────────


def _rule_findings(state: DesiredState, live: LiveState) -> list[Finding]:
    """AGENTS.md rule 10 — absence is never recovery evidence.

    A deleted rule, a failed evaluation and a vanished target all present as
    "not firing", so this counts rules that EXIST and evaluate cleanly, and
    reports the ones the desired state declares and the evaluator did not load.
    """
    findings: list[Finding] = []
    declared = {_meta_alert_name(gate.name) for gate in state.bundle.gates}
    if not declared:
        return findings
    loaded = {rule.name: rule for rule in live.rules}
    if not loaded:
        findings.append(
            Finding(
                "RULES-NOT-READ",
                "live.rules",
                "the observation lists no loaded rules while the bundle declares "
                f"{len(declared)}. An evaluator with no rules fires nothing, which reads "
                "exactly like an evaluator with nothing to fire about.",
            )
        )
        return findings
    for name in sorted(declared):
        rule = loaded.get(name)
        if rule is None:
            findings.append(
                Finding("RULE-ABSENT", name, "declared by the bundle and loaded by no evaluator")
            )
        elif rule.health != "ok":
            findings.append(
                Finding("RULE-UNHEALTHY", name, f"loaded and evaluating {rule.health!r}")
            )
    return findings


def _meta_alert_name(name: str) -> str:
    """The alert name the renderer derives from a gate name.

    Spelled here as well as in the renderer because this module compares the
    LIVE name against the declared one, and importing the renderer's private
    helper would couple a comparison to a formatting detail. The two are held
    together by a test rather than by an import.
    """
    return "".join(part.capitalize() for part in name.replace(".", "-").split("-"))


# ── Condition 3: the ingestion delta ────────────────────────────────────────


def _integrity_findings(
    state: DesiredState, live: LiveState, baseline: LiveState | None
) -> list[Finding]:
    findings: list[Finding] = []
    if baseline is None:
        findings.append(
            Finding(
                "INTEGRITY-BASELINE-ABSENT",
                "baseline",
                "no pre-promotion reading was supplied, so no delta can be computed. An "
                "absent baseline is not a baseline of zero: assuming one would make the "
                "check pass on a host that has been dropping samples for months.",
            )
        )
        return findings

    before = baseline.integrity
    after = live.integrity
    if before.counter != after.counter:
        findings.append(
            Finding(
                "INTEGRITY-COUNTER-MISMATCH",
                after.counter,
                f"the baseline read {before.counter!r}; two different counters cannot be "
                "compared, and a comparison that ignored the name would silently report a "
                "delta of zero between unrelated series",
            )
        )
        return findings

    if before.value == 0:
        findings.append(
            Finding(
                "INTEGRITY-BASELINE-ZERO",
                after.counter,
                "the baseline is zero. A zero baseline makes 'no increase' trivially "
                "satisfiable and is indistinguishable from a counter reset taken immediately "
                "before the baseline. The historical rejections must stay visible.",
            )
        )

    if after.process_start_time != before.process_start_time:
        findings.append(
            Finding(
                "INTEGRITY-PROCESS-RESTARTED",
                after.counter,
                "the evaluator process restarted between the baseline and this reading, so "
                "the counter is not continuous across them. This is the case a value "
                "comparison alone passes: a reset counter climbs back past the baseline and "
                "reports a healthy delta over the period every sample was dropped.",
            )
        )

    if after.value < before.value:
        findings.append(
            Finding(
                "INTEGRITY-COUNTER-RESET",
                after.counter,
                f"went backwards, {before.value} to {after.value}. A monotonic counter only "
                "does that when it is reset, and a predicate made true by a reset cannot be "
                "told from one made true by a repair.",
            )
        )
    elif after.value > before.value:
        findings.append(
            Finding(
                "INTEGRITY-INCREASED",
                after.counter,
                f"rose by {after.value - before.value} since the baseline. Target health and "
                "ingestion integrity are separate facts; this is the half a scrape-health "
                "check reports as green.",
            )
        )

    findings.extend(_window_findings(state, live, baseline))
    return findings


def _window_findings(state: DesiredState, live: LiveState, baseline: LiveState) -> list[Finding]:
    """The delta must be measured over at least the gate's own window.

    "No increase" observed over no elapsed time is arithmetic, not evidence: a
    reading taken twice in the same second cannot have grown. The gates declare
    how long a condition must hold before it means anything, so the longest of
    them is what this measurement has to span.
    """
    findings: list[Finding] = []
    windows = [_duration_seconds(gate.window) for gate in state.bundle.gates]
    unreadable = [
        gate.name
        for gate, seconds in zip(state.bundle.gates, windows, strict=True)
        if seconds is None
    ]
    if unreadable:
        findings.append(
            Finding(
                "INTEGRITY-WINDOW-UNREADABLE",
                ", ".join(sorted(unreadable)),
                "the gate declares a window this verifier cannot read, so the observation "
                "window cannot be checked against it",
            )
        )
    required = max((seconds for seconds in windows if seconds is not None), default=0)
    elapsed = _elapsed_seconds(baseline.observed_at, live.observed_at)
    if elapsed is None:
        findings.append(
            Finding(
                "INTEGRITY-WINDOW-UNREADABLE",
                "observed_at",
                "the baseline and the reading do not carry comparable timestamps",
            )
        )
        return findings
    if elapsed < 0:
        findings.append(
            Finding(
                "INTEGRITY-WINDOW-INVERTED",
                "observed_at",
                "the reading is older than the baseline it is compared against",
            )
        )
        return findings
    if elapsed < required:
        findings.append(
            Finding(
                "INTEGRITY-WINDOW-TOO-SHORT",
                "observed_at",
                f"{int(elapsed)}s elapsed since the baseline; the gates require {required}s. "
                "A delta of zero over a window shorter than the gate proves that the counter "
                "did not move in less time than the gate takes to notice.",
            )
        )
    return findings


def _elapsed_seconds(earlier: str, later: str) -> float | None:
    from datetime import datetime

    try:
        start = datetime.fromisoformat(earlier.replace("Z", "+00:00"))
        end = datetime.fromisoformat(later.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (end - start).total_seconds()


# ── Condition 4: routes and delivery ────────────────────────────────────────


def _delivery_findings(state: DesiredState, live: LiveState) -> list[Finding]:
    findings: list[Finding] = []
    declared = {route.identifier: route.receiver for route in state.routes}
    observed = {route.identifier: route.receiver for route in live.routes}
    if declared and not observed:
        findings.append(
            Finding(
                "ROUTES-NOT-READ",
                "live.routes",
                f"the observation resolves no routes while {len(declared)} are declared",
            )
        )
    for identifier, receiver in declared.items():
        if identifier not in observed:
            findings.append(
                Finding("ROUTE-ABSENT", identifier, "declared and resolved by no live route")
            )
        elif observed[identifier] != receiver:
            findings.append(
                Finding(
                    "ROUTE-RECEIVER-DIFFERS",
                    identifier,
                    f"declared {receiver!r}, live resolves to {observed[identifier]!r}",
                )
            )

    canary = live.canary
    if not canary.fired:
        findings.append(
            Finding(
                "CANARY-NOT-FIRED",
                canary.receiver,
                "no canary alert fired, so nothing was routed and nothing was delivered",
            )
        )
    if canary.receiver not in {receiver.name for receiver in state.receivers}:
        findings.append(
            Finding(
                "CANARY-RECEIVER-UNDECLARED",
                canary.receiver,
                "the canary was routed to a receiver this inventory does not declare",
            )
        )
    if not canary.delivered:
        findings.append(
            Finding(
                "CANARY-NOT-DELIVERED",
                canary.receiver,
                "the canary was not observed arriving at the receiver. Alertmanager's "
                "outbound attempt succeeding is not the same fact.",
            )
        )
    elif canary.receiver_evidence_ref is None:
        findings.append(
            Finding(
                "CANARY-DELIVERY-UNPROVEN",
                canary.receiver,
                "delivery is claimed with no reference to where at the receiver it was seen. "
                "A boolean with nothing behind it is the claim, not the proof.",
            )
        )
    if not canary.recovered:
        findings.append(
            Finding(
                "CANARY-NOT-RECOVERED",
                canary.receiver,
                "the canary did not resolve. A firing alert that never clears leaves the "
                "next real one indistinguishable from this test.",
            )
        )
    return findings


# ── Condition 5: both families, each with a positive control ────────────────


def _probe_findings(state: DesiredState, live: LiveState) -> list[Finding]:
    findings: list[Finding] = []
    surfaces = state.bundle.exposure.surfaces
    if surfaces and not live.probes:
        findings.append(
            Finding(
                "PROBES-NOT-READ",
                "live.probes",
                f"the observation carries no probe while {len(surfaces)} surface(s) are "
                "declared. No probes and all probes passing produce the same empty finding "
                "list, so the empty case is refused.",
            )
        )
        return findings

    seen: dict[tuple[str, str], LiveProbe] = {}
    for probe in live.probes:
        seen[(probe.surface, probe.family)] = probe

    declared: set[tuple[str, str]] = set()
    for surface in surfaces:
        for family in families_of(surface):
            declared.add((surface.name, family))
            observed = seen.get((surface.name, family))
            if observed is None:
                findings.append(
                    Finding(
                        "PROBE-FAMILY-MISSING",
                        f"{surface.name}/{family}",
                        f"declared {surface.family!r} and probed on no {family}. The two "
                        "families take different paths to the same port, so one family's "
                        "result says nothing about the other's.",
                    )
                )
                continue
            findings.extend(_one_probe_findings(surface, family, observed))

    for surface_name, family in sorted(seen):
        if (surface_name, family) not in declared:
            findings.append(
                Finding(
                    "PROBE-UNDECLARED-SURFACE",
                    f"{surface_name}/{family}",
                    "probed and declared by no exposure policy",
                )
            )
    return findings


def _one_probe_findings(surface: Surface, family: str, probe: LiveProbe) -> list[Finding]:
    findings: list[Finding] = []
    where = f"{surface.name}/{family}"

    expected_chain = chain_for(surface, family)
    if probe.chain != expected_chain:
        findings.append(
            Finding(
                "PROBE-CHAIN-INERT",
                where,
                f"the rule was observed in {probe.chain!r}; a {family} packet to a "
                f"{surface.kind!r} surface traverses {expected_chain!r}. A rule in a chain "
                "the traffic never enters reads as closed and is open — this is the exact "
                "shape of the seven dead rules found on this host.",
            )
        )

    expected = expectation_for(surface)
    if probe.expectation != expected:
        findings.append(
            Finding(
                "PROBE-EXPECTATION-WRONG",
                where,
                f"the probe expected {probe.expectation!r}; the declared exposure "
                f"{surface.exposure!r} means {expected!r}. An expectation typed by the prober "
                "rather than derived from the policy can be wrong in the direction that "
                "passes.",
            )
        )

    # The positive control is read BEFORE the outcome, deliberately. A refusal
    # with no working control is not a refusal that was measured — an unplugged
    # cable, a wrong address family and a dead prober all present as `refused`.
    if probe.control_outcome != "reachable":
        findings.append(
            Finding(
                "PROBE-CONTROL-FAILED",
                where,
                f"the positive control was {probe.control_outcome!r}, so this pass proves the "
                "prober ran, not that the surface behaves as declared. Every result for this "
                "family is unproven.",
            )
        )
        return findings
    if probe.control_evidence_ref is None:
        findings.append(
            Finding(
                "PROBE-CONTROL-UNPROVEN",
                where,
                "the positive control reports success with no evidence reference",
            )
        )

    if probe.outcome == "inconclusive":
        findings.append(Finding("PROBE-INCONCLUSIVE", where, "the probe reached no conclusion"))
    elif probe.outcome != probe.expectation:
        code = (
            "PROBE-UNEXPECTED-REACHABLE"
            if probe.outcome == "reachable"
            else "PROBE-UNEXPECTED-REFUSED"
        )
        findings.append(
            Finding(
                code,
                where,
                f"expected {probe.expectation!r}, observed {probe.outcome!r}",
            )
        )
    return findings


# ── Condition 6: rollback ───────────────────────────────────────────────────


def _rollback_findings(
    live: LiveState, *, previous_digest: str | None, first_promotion: bool
) -> list[Finding]:
    findings: list[Finding] = []
    rollback = live.rollback
    if rollback is None or not rollback.exercised:
        findings.append(
            Finding(
                "ROLLBACK-NOT-EXERCISED",
                live.release.current,
                "no rollback was exercised in this pass. A rollback that has never been run "
                "is a plan, not a capability, and this is the condition a lane skips when the "
                "forward path works.",
            )
        )
        return findings
    if not rollback.succeeded:
        findings.append(
            Finding("ROLLBACK-FAILED", live.release.current, "the rollback did not complete")
        )
    if first_promotion:
        # Nothing to restore TO, and saying so is better than inventing a
        # comparison against a digest that does not exist.
        return findings
    if rollback.restored_release is None:
        findings.append(
            Finding(
                "ROLLBACK-TARGET-ABSENT",
                live.release.current,
                "the rollback restored no release pointer, which invalidates rule 11's "
                "guarantee that failure returns to the exact preceding release",
            )
        )
    if previous_digest is None:
        findings.append(
            Finding(
                "ROLLBACK-BASELINE-ABSENT",
                live.release.current,
                "no digest is recorded for the previous release, so 'restored the previous "
                "digest' has nothing to compare against",
            )
        )
    elif rollback.restored_digest != previous_digest:
        findings.append(
            Finding(
                "ROLLBACK-DIGEST-MISMATCH",
                live.release.current,
                f"restored {(rollback.restored_digest or 'nothing')[:12]}, the previous "
                f"release was accepted at {previous_digest[:12]}. A pointer restored without "
                "the bytes is the failure this comparison exists to catch.",
            )
        )
    return findings


# ── The whole verification ──────────────────────────────────────────────────


def verify(
    state: DesiredState,
    resolution: Resolution,
    tree: RenderedTree,
    live: LiveState,
    *,
    baseline: LiveState | None,
    previous_digest: str | None = None,
    first_promotion: bool = False,
) -> Verification:
    """Compare a read-back with the desired state, and report all six conditions.

    ``baseline`` is a live observation taken BEFORE the promotion — the same
    document type, which is why there is no separate baseline contract to keep
    in sync. It is ``| None`` rather than required so that a caller who did not
    record one gets ``INTEGRITY-BASELINE-ABSENT`` and a held verdict, instead
    of being unable to produce a verification at all and reporting nothing.

    Every condition is evaluated even when an earlier one has already failed.
    An operator fixing a promotion should see the whole picture once, not
    discover the next problem after each repair.
    """
    identity = _identity_findings(state, live)
    grouped: dict[int, list[Finding]] = {number: [] for number, _ in CONDITIONS}
    grouped[1].extend(identity)
    grouped[1].extend(_tree_findings(tree, live))
    grouped[2].extend(_target_findings(state, resolution, live))
    grouped[2].extend(_rule_findings(state, live))
    grouped[3].extend(_integrity_findings(state, live, baseline))
    grouped[4].extend(_delivery_findings(state, live))
    grouped[5].extend(_probe_findings(state, live))
    grouped[6].extend(
        _rollback_findings(live, previous_digest=previous_digest, first_promotion=first_promotion)
    )
    return Verification(
        conditions=tuple(
            ConditionResult(number=number, name=name, findings=tuple(grouped[number]))
            for number, name in CONDITIONS
        )
    )


def _identity_findings(state: DesiredState, live: LiveState) -> list[Finding]:
    """The observation is of the control plane this desired state describes.

    Cheap, and it closes the way every other check in this module can be made
    to pass at once: verify a production desired state against a rehearsal
    host's read-back and most conditions hold, because the rehearsal was built
    from the same inputs.
    """
    findings: list[Finding] = []
    if live.environment != state.control_plane.environment:
        findings.append(
            Finding(
                "OBSERVATION-ENVIRONMENT",
                live.environment,
                f"the desired state describes {state.control_plane.environment!r}",
            )
        )
    if live.host_target_id != state.control_plane.host.target_id:
        findings.append(
            Finding(
                "OBSERVATION-HOST",
                live.host_target_id,
                f"the desired state binds {state.control_plane.host.target_id!r}",
            )
        )
    return findings


def rules_semantic_digest(live: LiveState) -> str:
    """A digest over the loaded rule set's IDENTITY — group and name, sorted.

    Not over the expressions, which the bundles already pin by digest, and not
    over evaluation state, which changes every scrape. It answers one question:
    is the evaluator running the same rules it was running at the last accepted
    promotion.

    It lives here, with live state, because the receipt WRITES it and the drift
    comparison READS it, and two modules computing it separately would agree
    with each other until one of them learned about a sort order the other did
    not. One spelling, two callers.
    """
    import hashlib

    digest = hashlib.sha256()
    for rule in sorted(live.rules, key=lambda item: (item.group, item.name)):
        digest.update(rule.group.encode("utf-8"))
        digest.update(b"\0")
        digest.update(rule.name.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def render_verification(verification: Verification) -> str:
    """A fixed-order, six-line summary plus the findings, for a job log.

    Ordered by condition number rather than by outcome so two runs are
    diffable, and it always prints all six rows — including the ones that
    passed — because a report listing only failures cannot be told from a
    report of a run that checked less.
    """
    lines = [f"verdict: {verification.verdict}"]
    for condition in verification.conditions:
        mark = "pass" if condition.passed else "FAIL"
        lines.append(f"  {condition.number}. [{mark}] {condition.name}")
    for finding in verification.findings:
        lines.append(f"    {finding.render()}")
    return "\n".join(lines)


def observation_document(live: LiveState) -> Mapping[str, object]:
    """Round-trip a typed observation back to its document form.

    Used by the receipt builder and by tests that need to assert the contract
    accepts what this module produces. Kept here rather than in a serializer
    module because a type and its document form drifting apart is exactly the
    kind of defect one file makes visible and two files hide.
    """
    document: dict[str, object] = {
        "schema_version": "observability-live-observation.v1",
        "observed_at": live.observed_at,
        "environment": live.environment,
        "host_target_id": live.host_target_id,
        "release": {"current": live.release.current, "previous": live.release.previous},
        "tree": [{"path": entry.path, "sha256": entry.sha256} for entry in live.tree],
        "targets": [{"job": target.job, "health": target.health} for target in live.targets],
        "rules": [
            {"group": rule.group, "name": rule.name, "health": rule.health} for rule in live.rules
        ],
        "routes": [{"id": route.identifier, "receiver": route.receiver} for route in live.routes],
        "integrity": {
            "counter": live.integrity.counter,
            "value": live.integrity.value,
            "process_start_time": live.integrity.process_start_time,
        },
        "canary": _canary_document(live.canary),
        "probes": [_probe_document(probe) for probe in live.probes],
    }
    if live.rollback is not None:
        document["rollback"] = {
            "exercised": live.rollback.exercised,
            "restored_release": live.rollback.restored_release,
            "restored_digest": live.rollback.restored_digest,
            "succeeded": live.rollback.succeeded,
        }
    return document


def _canary_document(canary: LiveCanary) -> dict[str, object]:
    document: dict[str, object] = {
        "fired": canary.fired,
        "delivered": canary.delivered,
        "recovered": canary.recovered,
        "receiver": canary.receiver,
    }
    if canary.receiver_evidence_ref is not None:
        document["receiver_evidence_ref"] = canary.receiver_evidence_ref
    return document


def _probe_document(probe: LiveProbe) -> dict[str, object]:
    control: dict[str, object] = {"outcome": probe.control_outcome}
    if probe.control_evidence_ref is not None:
        control["evidence_ref"] = probe.control_evidence_ref
    return {
        "surface": probe.surface,
        "family": probe.family,
        "chain": probe.chain,
        "expectation": probe.expectation,
        "outcome": probe.outcome,
        "control": control,
    }


def declared_probe_slots(state: DesiredState) -> tuple[tuple[str, str], ...]:
    """Every (surface, family) pair a complete probe pass must cover.

    Exported because the promotion facility needs to know what to probe before
    it probes, and deriving that list twice — once to run the probes and once
    to check them — is how a dual-stack surface ends up probed on one family by
    a prober that believed it had covered both.
    """
    slots: list[tuple[str, str]] = []
    for surface in state.bundle.exposure.surfaces:
        for family in families_of(surface):
            slots.append((surface.name, family))
    return tuple(slots)


def integrity_counters(state: DesiredState) -> tuple[str, ...]:
    """The ingestion counters the declared gates name, in declaration order.

    Read out of the gate's own integrity predicate rather than configured
    separately, so the counter a promotion reads back is by construction the
    counter the gate asserts about. Two lists would let a promotion prove a
    delta on a counter no alert watches.
    """
    found: list[str] = []
    for gate in state.bundle.gates:
        for token in _METRIC_NAME.findall(gate.integrity):
            if token not in found:
                found.append(token)
    return tuple(found)


_METRIC_NAME = re.compile(r"\b[a-z_][a-z0-9_]*_total\b")
