"""One passing read-back of the reference control plane, and its parts.

Shared by the verifier, receipt, drift and executor tests. It lives in its own
module rather than in ``conftest.py`` because ``conftest`` says of itself that
fixtures there are paths and nothing constructs state; and rather than in one
of the test modules, because a test importing another test module makes the
import order part of what is being asserted.

The whole point of the builders below is that :func:`passing` is COMPLETE. A
test that starts from a minimal observation and asserts one finding cannot tell
a check that bites from a check whose other inputs were simply absent, so every
negative test copies this and breaks exactly one thing.
"""

from __future__ import annotations

import dataclasses

from dotmac_observability.live_verify import (
    IntegrityReading,
    LiveCanary,
    LiveProbe,
    LiveRelease,
    LiveRollback,
    LiveRoute,
    LiveRule,
    LiveState,
    LiveTarget,
    TreeEntry,
    Verification,
    chain_for,
    expectation_for,
    families_of,
    integrity_counters,
    verify,
)
from dotmac_observability.receipt import (
    Authorization,
    BundleRecord,
    CheckResult,
    ImageRecord,
    Runs,
)
from dotmac_observability.render import file_digest, render_control_plane
from dotmac_observability.validate import load, load_private_inventory
from tests.conftest import CONTRACTS, REFERENCE, REFERENCE_PRIVATE, resolved

STATE = load(REFERENCE, contracts=CONTRACTS)
RESOLUTION = resolved(REFERENCE)
TREE = render_control_plane(STATE, RESOLUTION)

# Opaque to every consumer. What matters is that the rollback restored the
# release the previous promotion was accepted with, not what it is called.
PREVIOUS_RELEASE = "/opt/observability/releases/0001"
CURRENT_RELEASE = "/opt/observability/releases/0002"
PREVIOUS_DIGEST = "a" * 64

BASELINE_AT = "2026-09-01T11:00:00+00:00"
OBSERVED_AT = "2026-09-01T12:00:00+00:00"
# The measurement recorded in `docs/inventories/observer-as-built.md` §17. Used
# as the baseline here for the same reason it is the baseline there: a delta is
# only meaningful against a number that was actually seen.
COUNTER_VALUE = 1_864_926
PROCESS_START = 1_788_000_000.0


def counter_name() -> str:
    counters = integrity_counters(STATE)
    assert counters, "the reference bundle declares no integrity counter"
    return counters[0]


def targets() -> tuple[LiveTarget, ...]:
    """One entry per endpoint the inventory expects to be up."""
    rows: list[LiveTarget] = []
    for target_set in STATE.targets:
        for job in target_set.jobs:
            expected = job.expected if job.expected is not None else 1
            rows.extend(LiveTarget(job=job.job, health="up") for _ in range(expected))
    for federation in STATE.federations:
        rows.append(LiveTarget(job=federation.name, health="up"))
    return tuple(rows)


def rules() -> tuple[LiveRule, ...]:
    return tuple(
        LiveRule(
            group="control-plane-meta",
            name="".join(part.capitalize() for part in gate.name.replace(".", "-").split("-")),
            health="ok",
        )
        for gate in STATE.bundle.gates
    )


def probes() -> tuple[LiveProbe, ...]:
    rows: list[LiveProbe] = []
    for surface in STATE.bundle.exposure.surfaces:
        for family in families_of(surface):
            expectation = expectation_for(surface)
            rows.append(
                LiveProbe(
                    surface=surface.name,
                    family=family,
                    chain=chain_for(surface, family),
                    expectation=expectation,
                    outcome=expectation,
                    control_outcome="reachable",
                    control_evidence_ref=f"control/{surface.name}/{family}",
                )
            )
    return tuple(rows)


def passing() -> LiveState:
    """A read-back in which all six conditions hold."""
    return LiveState(
        observed_at=OBSERVED_AT,
        environment=STATE.control_plane.environment,
        host_target_id=STATE.control_plane.host.target_id,
        release=LiveRelease(current=CURRENT_RELEASE, previous=PREVIOUS_RELEASE),
        tree=tuple(TreeEntry(path=path, sha256=file_digest(text)) for path, text in TREE),
        targets=targets(),
        rules=rules(),
        routes=tuple(
            LiveRoute(identifier=route.identifier, receiver=route.receiver)
            for route in STATE.routes
        ),
        integrity=IntegrityReading(
            counter=counter_name(), value=COUNTER_VALUE, process_start_time=PROCESS_START
        ),
        canary=LiveCanary(
            fired=True,
            delivered=True,
            recovered=True,
            receiver=STATE.defaults.receiver,
            receiver_evidence_ref="delivery/0001",
        ),
        probes=probes(),
        rollback=LiveRollback(
            exercised=True,
            restored_release=PREVIOUS_RELEASE,
            restored_digest=PREVIOUS_DIGEST,
            succeeded=True,
        ),
    )


def baseline() -> LiveState:
    """The same read-back, taken before the promotion."""
    return dataclasses.replace(passing(), observed_at=BASELINE_AT)


# ── The promotion inputs the receipt and executor tests share ───────────────

INVENTORY = load_private_inventory(REFERENCE_PRIVATE, contracts=CONTRACTS)
REVISION = "1" * 40
# The owner's canonical form, prefix included. A test that stripped it would
# stop exercising the field the contract actually declares.
PLAN_DIGEST = "sha256:" + "9" * 64
# A DIFFERENT value from PLAN_DIGEST, deliberately. The two were conflated
# once across this fleet in a binding that could not be equal for any input;
# a fixture reusing one for both would exercise the conflation rather than
# the distinction.
EXECUTION_PLAN_DIGEST = "sha256:" + "7" * 64

IMAGES: tuple[ImageRecord, ...] = (
    ImageRecord(
        service="prometheus",
        repository="docker.io/prom/prometheus",
        digest=STATE.control_plane.prometheus.digest,
    ),
    ImageRecord(
        service="alertmanager",
        repository="docker.io/prom/alertmanager",
        digest=STATE.control_plane.alertmanager.digest,
    ),
)

BUNDLES: tuple[BundleRecord, ...] = (
    BundleRecord(
        product="dotmac-erp", source_revision="2" * 40, rules_sha256="3" * 64, rule_count=7
    ),
)

# All six the contract requires, and no more: the receipt's `validation` object
# is closed, so a check with no field cannot be reported and a field with no
# check cannot be omitted.
PASSED: dict[str, CheckResult] = {
    name: CheckResult(passed=True)
    for name in (
        "render_check",
        "secret_scan",
        "promtool_config",
        "promtool_rules",
        "amtool_config",
        "compose_config",
    )
}

RUNS = Runs(ci="ci/1", rehearsal="rehearsal/1", promotion="promotion/1")

AUTHORIZATION = Authorization(
    plan_digest=PLAN_DIGEST,
    approval_decision_ref="decision/1",
    execution_plan_digest=EXECUTION_PLAN_DIGEST,
)


def verification() -> Verification:
    """The verification a clean promotion of the reference tree produces.

    Built here so the receipt, drift and executor tests all assert against the
    same one. A second construction of it in one of those modules would drift
    from this one exactly when a condition changed, which is the moment the
    tests most need to agree.
    """
    return verify(
        STATE,
        RESOLUTION,
        TREE,
        passing(),
        baseline=baseline(),
        previous_digest=PREVIOUS_DIGEST,
        first_promotion=False,
    )
