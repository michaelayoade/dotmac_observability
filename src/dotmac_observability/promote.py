"""The promotion executor: the state machine, and the facility contract it drives.

``docs/ARCHITECTURE.md`` §"Promotion" specifies a state machine — ``FETCHED``,
``VALIDATED``, ``REHEARSED``, ``STAGED``, ``RELOADED``, ``VERIFIED``,
``ACCEPTED`` — in which no stage is skippable and every stage before
``ACCEPTED`` rolls back to the exact preceding release. That specification has
had no executor. This module is it.

## What is here, and what is deliberately not

Here: the ORDER, the refusals, the rollback decision, and the receipt that is
written whichever way it ends. Not here: anything that touches a host. Every
host effect is a method on :class:`PromotionFacility`, a Protocol this
repository declares and does not implement, because the mechanics belong to
``dotmac-deployment-foundation`` (see the ownership table in
``docs/ARCHITECTURE.md``). A control plane that grew its own SSH transport
would be a second answer to how a release reaches a host, and the second answer
is the one that never gets the fixes.

The split has a second, larger benefit: the state machine is exercised in unit
tests against a recording double, so "no stage is skippable" and "a failure
after staging rolls back" are properties with tests rather than sentences in a
document.

## Two refusals that happen before anything is fetched

**The target is NAMED, never inferred.** AGENTS.md rule 17: the target host is
named by a human in the authorizing request, never read out of an inventory
row. :func:`promote` therefore takes ``named_target`` and refuses when it
disagrees with the control plane's declared host — the inventory is what the
name is CHECKED against, never where it comes from.

**The revision is asserted by an oracle.** AGENTS.md rule 3 and Governance ADR
0013: a repository-local claim is derived from repository-local facts, and
"this commit is the protected-main tip" is not one of those. The caller supplies
an :class:`AssertedRevision` carrying the revision and an immutable external
run reference; a promotion with no oracle is refused rather than trusted.

## Why the rollback boundary sits where it does

Nothing is rolled back before ``STAGED``, because before ``STAGED`` nothing on
the host has changed — a fetch or a validation failure leaves the previous
release running and untouched, and invoking a rollback there would be a host
mutation performed in response to a failure that did not cause one. From
``STAGED`` onward every failure rolls back to the pointer captured at staging,
which is the only pointer this repository ever treats as the rollback target.

A receipt is written in every case: accepted, rolled back, or failed. A
promotion that leaves no record is indistinguishable from one that never ran.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from .live_verify import (
    VERDICT_DEPLOYED_REPAIRED,
    LiveState,
    Verification,
    declared_probe_slots,
    integrity_counters,
    verify,
)
from .model import DesiredState, PrivateInventory, Resolution
from .receipt import (
    OUTCOME_ACCEPTED,
    OUTCOME_FAILED,
    OUTCOME_ROLLED_BACK,
    Authorization,
    BundleRecord,
    CheckResult,
    ImageRecord,
    Runs,
    build_receipt,
)
from .render import RenderedTree, render_control_plane, tree_digest
from .validate import Finding

__all__ = [
    "STATES",
    "AssertedRevision",
    "FetchedBundle",
    "ObservationRequest",
    "PromotionFacility",
    "PromotionOutcome",
    "StagedRelease",
    "promote",
]

#: The state machine, in order. Read by the executor and by the tests that
#: prove no stage is skipped; a stage added to the architecture document and
#: not to this tuple fails the test that compares the two.
STATES: tuple[str, ...] = (
    "FETCHED",
    "VALIDATED",
    "REHEARSED",
    "STAGED",
    "RELOADED",
    "VERIFIED",
    "ACCEPTED",
)

#: The point after which a failure must restore the previous release. Named
#: rather than written as an index comparison, because "everything after
#: staging" is the rule and an off-by-one in it is a promotion that leaves a
#: half-applied host.
_ROLLBACK_FROM = STATES.index("STAGED")


@dataclass(frozen=True, slots=True)
class AssertedRevision:
    """The exact commit being promoted, plus the oracle that says it is current.

    ``oracle_ref`` is an immutable external run identifier — the workflow run
    that resolved the protected branch and found this SHA at its tip. It is
    required because the alternative is a repository reading its own HEAD and
    calling the answer a protected-main assertion, which is precisely the
    self-attestation Governance ADR 0013 refuses.
    """

    revision: str
    oracle_ref: str


@dataclass(frozen=True, slots=True)
class FetchedBundle:
    """One product bundle, retrieved and digest-verified by the facility."""

    product: str
    source_revision: str
    rules_sha256: str
    rule_count: int


@dataclass(frozen=True, slots=True)
class StagedRelease:
    """The release directory the facility created, and what preceded it.

    ``previous`` is captured BEFORE activation and is the only rollback target
    this executor will use. Null is legitimate exactly once, on a host that has
    never held a release; every later null is the failure rule 11 describes and
    is refused here rather than discovered during a rollback that has nothing
    to restore.
    """

    current: str
    previous: str | None


@dataclass(frozen=True, slots=True)
class ObservationRequest:
    """What the facility must read back, derived from the desired state.

    The executor computes this rather than letting the facility decide, and the
    reason is condition 5. A prober choosing its own surface list probes what it
    knows about; this list is derived from the exposure policy, so a
    ``dual_stack`` surface produces two slots whether or not the prober would
    have thought to try the second family.
    """

    release: str
    probe_slots: tuple[tuple[str, str], ...]
    integrity_counters: tuple[str, ...]
    paths: tuple[str, ...]


class PromotionFacility(Protocol):
    """Every host effect a promotion needs, and nothing else.

    Implemented by ``dotmac-deployment-foundation``, never here. The methods
    are named for the state each one completes, so a reader can hold this
    Protocol beside the state table in ``docs/ARCHITECTURE.md`` and see that
    they are the same list.

    Each method may raise; the executor treats any exception as that stage
    failing and takes the rollback decision from WHICH stage it was.
    """

    def fetch(self, revision: AssertedRevision) -> Sequence[FetchedBundle]:
        """FETCHED — retrieve every pinned bundle artifact and verify its digest."""

    def check_configuration(self, tree: RenderedTree) -> Mapping[str, CheckResult]:
        """VALIDATED — run the evaluator toolchain over the rendered bytes.

        ``promtool check config``, ``promtool check rules``, ``amtool
        check-config`` and ``docker compose config``. The keys are the receipt's
        validation field names, so a check the receipt has no field for cannot
        be silently reported.
        """

    def rehearse(self, tree: RenderedTree, request: ObservationRequest) -> LiveState:
        """REHEARSED — apply the whole release to a disposable host and read it back."""

    def stage(self, tree: RenderedTree, *, target: str) -> StagedRelease:
        """STAGED — create the immutable release directory and capture the pointer."""

    def reload(self, *, target: str, release: str) -> None:
        """RELOADED — make the evaluators take the new configuration."""

    def observe(self, *, target: str, request: ObservationRequest) -> LiveState:
        """VERIFIED (the reading half) — read live state back from the host."""

    def rollback(self, *, target: str, release: str) -> LiveState:
        """Restore ``release``, then READ THE HOST BACK and return what it found.

        The return type is the whole contract here. A rollback method returning
        ``None`` would let "the command did not raise" stand in for "the host
        recovered", and those are different facts. The returned observation
        must carry a ``rollback`` record — the restored pointer and the digest
        actually read back — or the executor records the rollback as unobserved.
        """

    def accept(self, *, target: str, release: str) -> None:
        """ACCEPTED — make this release the new rollback target."""


@dataclass(frozen=True, slots=True)
class PromotionOutcome:
    """What happened, whichever way it went.

    ``states`` is the prefix of :data:`STATES` actually reached, which is how
    "no stage is skippable" is checkable after the fact rather than only
    asserted in prose.
    """

    outcome: str
    states: tuple[str, ...]
    findings: tuple[Finding, ...]
    receipt: Mapping[str, object] | None
    verification: Verification | None = None
    staged: StagedRelease | None = None
    rolled_back_to: str | None = None


def _refusal(code: str, location: str, message: str) -> PromotionOutcome:
    return PromotionOutcome(
        outcome=OUTCOME_FAILED,
        states=(),
        findings=(Finding(code, location, message),),
        receipt=None,
    )


def promote(
    facility: PromotionFacility,
    state: DesiredState,
    resolution: Resolution,
    inventory: PrivateInventory,
    *,
    named_target: str,
    revision: AssertedRevision,
    authorization: Authorization,
    authorized_images: Sequence[ImageRecord],
    baseline: LiveState | None,
    previous_digest: str | None,
    first_promotion: bool,
    runs: Runs,
    started_at: str,
    finished_at: str,
) -> PromotionOutcome:
    """Drive the state machine, and return what it proved.

    Never raises for a promotion failure. A caller that had to catch an
    exception to learn a promotion failed would have no receipt at the point it
    most needs one, and the receipt is the record that distinguishes a failed
    promotion from one nobody ran.
    """
    refusal = _preconditions(
        state, named_target=named_target, revision=revision, authorization=authorization
    )
    if refusal is not None:
        return refusal

    tree = render_control_plane(state, resolution)
    request_paths = tuple(path for path, _ in tree)
    reached: list[str] = []
    staged: StagedRelease | None = None
    bundles: tuple[FetchedBundle, ...] = ()
    validation: dict[str, CheckResult] = {}
    live: LiveState | None = None
    verification: Verification | None = None

    def inputs() -> _ReceiptInputs:
        """Whatever is known so far, so a stop at any stage still writes a receipt."""
        return _ReceiptInputs(
            state=state,
            inventory=inventory,
            tree=tree,
            revision=revision,
            authorization=authorization,
            images=authorized_images,
            bundles=bundles,
            live=live,
            validation=validation,
            runs=runs,
            started_at=started_at,
            finished_at=finished_at,
        )

    try:
        bundles = tuple(facility.fetch(revision))
        reached.append("FETCHED")

        validation = dict(facility.check_configuration(tree))
        reached.append("VALIDATED")
        failed = sorted(name for name, result in validation.items() if not result.passed)
        if failed:
            return _stop(
                reached,
                staged,
                findings=(
                    Finding(
                        "PROMOTION-VALIDATION-FAILED",
                        ", ".join(failed),
                        "the evaluator toolchain refused the rendered configuration. Nothing "
                        "has been staged, so the previous release is still running untouched.",
                    ),
                ),
                receipt_inputs=inputs(),
            )

        rehearsal_request = ObservationRequest(
            release="rehearsal",
            probe_slots=declared_probe_slots(state),
            integrity_counters=integrity_counters(state),
            paths=request_paths,
        )
        rehearsal = facility.rehearse(tree, rehearsal_request)
        reached.append("REHEARSED")
        rehearsed = verify(
            state,
            resolution,
            tree,
            rehearsal,
            baseline=None,
            previous_digest=None,
            first_promotion=True,
        )
        # The rehearsal is held to conditions 1, 2, 4 and 5 only. Condition 3
        # needs a baseline this host does not have — a disposable host's
        # ingestion counter starts at zero, which is exactly the state
        # `INTEGRITY-BASELINE-ZERO` refuses on production and is unavoidable
        # here — and condition 6's rollback target does not exist on a host
        # holding its first release. Applying the production conjunction to a
        # rehearsal would make it permanently unpassable, which teaches a lane
        # to skip the rehearsal.
        rehearsal_findings = tuple(
            finding
            for condition in rehearsed.conditions
            if condition.number in _REHEARSAL_CONDITIONS
            for finding in condition.findings
        )
        if rehearsal_findings:
            return _stop(reached, staged, findings=rehearsal_findings, receipt_inputs=inputs())

        staged = facility.stage(tree, target=named_target)
        reached.append("STAGED")
        if staged.previous is None and not first_promotion:
            return _stop(
                reached,
                staged,
                findings=(
                    Finding(
                        "PROMOTION-NO-ROLLBACK-TARGET",
                        named_target,
                        "staging captured no previous release pointer on a host that is not "
                        "receiving its first. There is no rollback target, so the guarantee "
                        "rule 11 makes cannot be kept and the promotion stops here.",
                    ),
                ),
                facility=facility,
                target=named_target,
                receipt_inputs=inputs(),
            )

        facility.reload(target=named_target, release=staged.current)
        reached.append("RELOADED")

        request = ObservationRequest(
            release=staged.current,
            probe_slots=declared_probe_slots(state),
            integrity_counters=integrity_counters(state),
            paths=request_paths,
        )
        live = facility.observe(target=named_target, request=request)
        reached.append("VERIFIED")
    except Exception as error:  # a failure at any stage is a promotion failure
        return _stop(
            reached,
            staged,
            findings=(
                Finding(
                    "PROMOTION-STAGE-RAISED",
                    _next_state(reached),
                    f"{type(error).__name__}: {error}",
                ),
            ),
            facility=facility,
            target=named_target,
            receipt_inputs=inputs(),
        )

    verification = verify(
        state,
        resolution,
        tree,
        live,
        baseline=baseline,
        previous_digest=previous_digest,
        first_promotion=first_promotion,
    )
    if verification.verdict != VERDICT_DEPLOYED_REPAIRED:
        return _stop(
            reached,
            staged,
            findings=verification.findings,
            facility=facility,
            target=named_target,
            verification=verification,
            receipt_inputs=inputs(),
        )

    try:
        facility.accept(target=named_target, release=staged.current if staged else "")
    except Exception as error:  # acceptance is the last host effect and can fail too
        return _stop(
            reached,
            staged,
            findings=(
                Finding("PROMOTION-STAGE-RAISED", "ACCEPTED", f"{type(error).__name__}: {error}"),
            ),
            facility=facility,
            target=named_target,
            verification=verification,
            receipt_inputs=inputs(),
        )
    reached.append("ACCEPTED")
    document = build_receipt(
        outcome=OUTCOME_ACCEPTED,
        state=state,
        control_plane_revision=revision.revision,
        authorization=authorization,
        inventory=inventory,
        tree=tree,
        images=authorized_images,
        bundles=[_bundle_record(bundle) for bundle in bundles],
        live=live,
        verification=verification,
        validation=validation,
        runs=runs,
        started_at=started_at,
        finished_at=finished_at,
    )
    return PromotionOutcome(
        outcome=OUTCOME_ACCEPTED,
        states=tuple(reached),
        findings=(),
        receipt=document,
        verification=verification,
        staged=staged,
    )


#: The conditions a REHEARSAL is held to. Three and six are excluded with a
#: stated premise rather than by omission — see the comment at their exclusion.
_REHEARSAL_CONDITIONS = frozenset({1, 2, 4, 5})


@dataclass(frozen=True, slots=True)
class _ReceiptInputs:
    """Everything a receipt needs, carried so the failure path can write one too.

    Grouped rather than passed as twelve arguments to the stop helper, because
    the failure path is the one a reader skims and a twelve-argument call there
    is how a field ends up omitted from exactly the receipt that mattered.

    ``live`` is optional because a promotion can fail before anything was read
    back. The receipt contract permits a non-accepted outcome with no release,
    live or canary block for that reason.
    """

    state: DesiredState
    inventory: PrivateInventory
    tree: RenderedTree
    revision: AssertedRevision
    authorization: Authorization
    images: Sequence[ImageRecord]
    bundles: Sequence[FetchedBundle]
    live: LiveState | None
    validation: Mapping[str, CheckResult]
    runs: Runs
    started_at: str
    finished_at: str


def _stop(
    reached: Sequence[str],
    staged: StagedRelease | None,
    *,
    findings: tuple[Finding, ...],
    receipt_inputs: _ReceiptInputs,
    facility: PromotionFacility | None = None,
    target: str | None = None,
    verification: Verification | None = None,
) -> PromotionOutcome:
    """End the promotion, rolling back if and only if something was staged.

    The rollback itself can fail, and when it does the outcome stays ``failed``
    rather than becoming ``rolled-back``: a rollback that did not complete has
    left the host in a state a human has to look at, and recording it as a tidy
    rollback is the report that stops anyone looking.
    """
    states = tuple(reached)
    rolled_back_to: str | None = None
    extra: list[Finding] = list(findings)
    outcome = OUTCOME_FAILED
    # What the receipt's live block describes. For a rolled-back promotion it
    # becomes the read-back of the RESTORED host, because that is what the host
    # is running when the receipt is filed.
    observed: LiveState | None = receipt_inputs.live

    staged_reached = len(states) > _ROLLBACK_FROM
    if staged_reached and staged is not None and facility is not None and target is not None:
        if staged.previous is None:
            extra.append(
                Finding(
                    "ROLLBACK-IMPOSSIBLE",
                    target,
                    "a release was staged and no previous pointer was captured, so there is "
                    "nothing to restore. This is the state rule 11 exists to make impossible.",
                )
            )
        else:
            try:
                restored = facility.rollback(target=target, release=staged.previous)
            except Exception as error:  # a failed rollback is reportable, not fatal
                extra.append(
                    Finding(
                        "ROLLBACK-RAISED",
                        target,
                        f"the rollback to the previous release failed: "
                        f"{type(error).__name__}: {error}. The host needs a human.",
                    )
                )
            else:
                # The facility returns a READ-BACK of the restored host, and
                # that is what makes this a rollback rather than a claim about
                # one: `rollback()` returning without raising says a command
                # succeeded, and only an observation says the host came back.
                if restored.rollback is None:
                    extra.append(
                        Finding(
                            "ROLLBACK-UNOBSERVED",
                            target,
                            "the restore returned a read-back carrying no rollback record, so "
                            "nothing observed which release the host is now running. A "
                            "command that returned is not a host that recovered.",
                        )
                    )
                else:
                    rolled_back_to = staged.previous
                    outcome = OUTCOME_ROLLED_BACK
                    observed = restored

    document = build_receipt(
        outcome=outcome,
        state=receipt_inputs.state,
        control_plane_revision=receipt_inputs.revision.revision,
        authorization=receipt_inputs.authorization,
        inventory=receipt_inputs.inventory,
        tree=receipt_inputs.tree,
        images=receipt_inputs.images,
        bundles=[_bundle_record(bundle) for bundle in receipt_inputs.bundles],
        live=observed,
        verification=verification if verification is not None else _empty_verification(),
        validation=receipt_inputs.validation,
        runs=receipt_inputs.runs,
        started_at=receipt_inputs.started_at,
        finished_at=receipt_inputs.finished_at,
    )
    return PromotionOutcome(
        outcome=outcome,
        states=states,
        findings=tuple(extra),
        receipt=document,
        verification=verification,
        staged=staged,
        rolled_back_to=rolled_back_to,
    )


def _empty_verification() -> Verification:
    from .live_verify import CONDITIONS, ConditionResult

    return Verification(
        conditions=tuple(
            ConditionResult(number=number, name=name, findings=()) for number, name in CONDITIONS
        )
    )


def _bundle_record(bundle: FetchedBundle) -> BundleRecord:
    return BundleRecord(
        product=bundle.product,
        source_revision=bundle.source_revision,
        rules_sha256=bundle.rules_sha256,
        rule_count=bundle.rule_count,
    )


def _next_state(reached: Sequence[str]) -> str:
    index = len(reached)
    return STATES[index] if index < len(STATES) else STATES[-1]


def _preconditions(
    state: DesiredState,
    *,
    named_target: str,
    revision: AssertedRevision,
    authorization: Authorization,
) -> PromotionOutcome | None:
    """Refusals that must happen before a single byte is fetched."""
    if not named_target:
        return _refusal(
            "PROMOTION-TARGET-UNNAMED",
            "named_target",
            "no target was named. The host is named by a human in the authorizing request "
            "and never inferred from an inventory row (AGENTS.md rule 17).",
        )
    declared = state.control_plane.host.target_id
    if named_target != declared:
        return _refusal(
            "PROMOTION-TARGET-MISMATCH",
            named_target,
            f"the named target is not the host this control plane declares ({declared!r}). "
            "The inventory is what the name is CHECKED against, never where it comes from.",
        )
    if len(revision.revision) != 40 or any(
        character not in "0123456789abcdef" for character in revision.revision
    ):
        return _refusal(
            "PROMOTION-REVISION-NOT-EXACT",
            revision.revision,
            "a promotion targets an exact commit. A branch name, a tag alone or 'latest' is "
            "not a promotion target (AGENTS.md rule 3).",
        )
    if not revision.oracle_ref:
        return _refusal(
            "PROMOTION-REVISION-UNPROVEN",
            revision.revision,
            "no external oracle asserts this commit is the protected-main tip. A repository "
            "reading its own HEAD and calling the answer a protected-main assertion is the "
            "self-attestation Governance ADR 0013 refuses.",
        )
    if not authorization.plan_digest or not authorization.approval_decision_ref:
        return _refusal(
            "PROMOTION-UNAUTHORIZED",
            "authorization",
            "no approved plan was supplied. This repository authorizes nothing and never "
            "attests an approval to itself (AGENTS.md rule 20): a promotion consumes a plan "
            "the deployment control plane approved, or it does not run.",
        )
    return None


def rendered_digest_of(state: DesiredState, resolution: Resolution) -> str:
    """The digest a promotion of this desired state would record.

    Exported so a plan proposal can name the exact bytes it is asking approval
    for, and so a reader can re-derive the receipt's ``rendered_digest`` from
    the repository at the receipt's own revision.
    """
    return tree_digest(render_control_plane(state, resolution))
