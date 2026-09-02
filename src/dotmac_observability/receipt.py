"""The promotion receipt: what a promotion PROVED, written so a reader can re-check it.

A promotion that leaves no record is indistinguishable from one that never
ran, so a receipt is written for a failure and a rollback too
(``outcome: accepted | rolled-back | failed``). This module builds one from
typed inputs and — the half that matters more — refuses one that claims more
than it proved.

## Building and checking are separate, deliberately

:func:`build_receipt` produces a document; :func:`receipt_findings` decides
whether a document is honest. They are not folded together because the checks
must also run over a receipt this module did NOT build: one from an earlier
promotion, one from a rehearsal, one pasted into a ticket by an operator. A
validator reachable only through the builder can be bypassed by any writer that
skips the builder, which over a long enough programme is every writer.

## What the schema cannot say

``contracts/promotion-receipt.schema.json`` decides shape. It cannot decide
that an ``accepted`` outcome is inconsistent with a failed validation check, a
target count that does not add up, a rule set that loaded nothing, or a canary
that was never delivered — those are relationships between fields, and a
document can satisfy every field constraint while asserting a promotion that
did not happen. Each of them is a finding below, and each is stated as a
refusal of the ACCEPTED outcome specifically: a failed promotion is allowed to
record failed checks, because that is what it is for.

## Authorization is consumed, never defined

``authorization`` is a reference into ``dotmac-deployment-control``'s
approved-plan record — a ``plan_digest`` and an ``approval_decision_ref``. This
module re-derives nothing about approval and validates no signature. AGENTS.md
rule 20: this repository is an adopter of the deployment control plane, not a
second one, and a self-attested approval is worse than none because it looks
like a record.

The digest is compared as an OPAQUE STRING against the authorization the
promotion was handed. It is deliberately not parsed, re-hashed or normalized:
the owner's canonical form carries its ``sha256:`` prefix, the owner forbids
consumers from stripping it, and a forked parser surfaces later as a false
"the plan changed" that nobody can explain.

## A receipt is scanned before it is written

The receipt is the artifact most likely to be pasted into a ticket, so
:func:`receipt_findings` runs the SAME private-material detector the tracked
tree is held to (``validate.private_material_findings``). Not a second copy of
the patterns — the one detector, so a shape it learns to catch is caught here
too.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .live_verify import (
    VERDICT_DEPLOYED_REPAIRED,
    LiveState,
    Verification,
    rules_semantic_digest,
)
from .model import DesiredState, PrivateInventory
from .render import RenderedTree, tree_digest
from .validate import Finding, _validate_document, private_material_findings

__all__ = [
    "SCHEMA_VERSION",
    "Authorization",
    "BundleRecord",
    "CheckResult",
    "ImageRecord",
    "Runs",
    "build_receipt",
    "load_receipt",
    "receipt_findings",
]

SCHEMA_VERSION = "observability-promotion-receipt.v2"

OUTCOME_ACCEPTED = "accepted"
OUTCOME_ROLLED_BACK = "rolled-back"
OUTCOME_FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Authorization:
    """A reference into the deployment control plane's approved-plan record.

    Every field is the owner's spelling. ``plan_digest`` is held as the owner
    emits it and compared as an opaque string; ``approval_decision_ref`` is an
    opaque reference resolvable there and never a person's name.
    """

    plan_digest: str
    approval_decision_ref: str
    approval_policy_code: str | None = None
    approval_policy_version: int | None = None


@dataclass(frozen=True, slots=True)
class ImageRecord:
    service: str
    repository: str
    digest: str


@dataclass(frozen=True, slots=True)
class BundleRecord:
    product: str
    source_revision: str
    rules_sha256: str
    rule_count: int


@dataclass(frozen=True, slots=True)
class CheckResult:
    passed: bool
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class Runs:
    """Immutable external run identifiers.

    ``None`` means the step genuinely did not run, and a reader must treat the
    corresponding claim as unproven rather than assumed. That distinction is
    why these are nullable rather than defaulted to a placeholder string: a
    placeholder reads as a run that happened.
    """

    ci: str | None
    rehearsal: str | None
    promotion: str | None


def build_receipt(
    *,
    outcome: str,
    state: DesiredState,
    control_plane_revision: str,
    authorization: Authorization,
    inventory: PrivateInventory,
    tree: RenderedTree,
    images: Sequence[ImageRecord],
    bundles: Sequence[BundleRecord],
    live: LiveState | None,
    verification: Verification,
    validation: Mapping[str, CheckResult],
    runs: Runs,
    started_at: str,
    finished_at: str,
    canary_receiver: str | None = None,
) -> dict[str, object]:
    """Assemble a receipt from what the promotion actually observed.

    Every count comes from ``live`` rather than from an argument, which is the
    point of taking the observation instead of the numbers: a builder that
    accepted ``targets_up`` as an integer would let a caller write down a
    number nothing measured.

    ``live`` is ``| None`` for the promotion that failed before anything was
    read back — at fetch, or when the evaluator toolchain refused the rendered
    bytes. Such a receipt carries no ``release``, ``live`` or ``canary`` block
    at all, which the contract permits for a non-accepted outcome. Writing
    zeros instead would record "0 of 0 targets up", and a count of zero read
    as a measurement is the absence-is-not-evidence mistake pointing the other
    way.
    """
    if outcome == OUTCOME_ACCEPTED and live is None:
        raise ValueError(
            "an accepted receipt asserts a read-back; building one with no live state would "
            "record an acceptance nothing measured"
        )
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "outcome": outcome,
        "environment": state.control_plane.environment,
        "control_plane_revision": control_plane_revision,
        "authorization": _authorization_document(authorization),
        "private_inventory": {
            "document": inventory.document,
            "version": inventory.version,
            "sha256": inventory.digest,
        },
        "rendered_digest": tree_digest(tree),
        "images": [
            {"service": image.service, "repository": image.repository, "digest": image.digest}
            for image in images
        ],
        "bundles": [
            {
                "product": bundle.product,
                "source_revision": bundle.source_revision,
                "rules_sha256": bundle.rules_sha256,
                "rule_count": bundle.rule_count,
            }
            for bundle in bundles
        ],
        "evaluator": {
            "prometheus_version": state.control_plane.prometheus.version or "unknown",
            "alertmanager_version": state.control_plane.alertmanager.version or "unknown",
        },
        "host": {"target_id": state.control_plane.host.target_id},
        "validation": {
            name: _check_document(result) for name, result in sorted(validation.items())
        },
        "runs": {"ci": runs.ci, "rehearsal": runs.rehearsal, "promotion": runs.promotion},
        "timestamps": {"started_at": started_at, "finished_at": finished_at},
    }
    if live is not None:
        document["release"] = {
            "previous": live.release.previous,
            "current": live.release.current,
        }
        document["live"] = {
            "targets_expected": _expected_total(state, live),
            "targets_up": sum(1 for target in live.targets if target.health == "up"),
            "rules_loaded": len(live.rules),
            # AGENTS.md rule 10, in the one line where it is easiest to get
            # wrong: counted from rules that EXIST and evaluate cleanly, never
            # from the absence of a firing alert.
            "rules_healthy": sum(1 for rule in live.rules if rule.health == "ok"),
            "rules_semantic_digest": rules_semantic_digest(live),
            "routes_verified": len(live.routes),
        }
        document["canary"] = _canary_document(live, canary_receiver)
        if live.rollback is not None:
            document["rollback"] = {
                "exercised": live.rollback.exercised,
                "restored_release": live.rollback.restored_release,
                "succeeded": live.rollback.succeeded,
            }
    # The verdict is not a receipt field, and that is on purpose: a receipt
    # records facts a later reader can re-check, and a verdict is a conclusion
    # drawn from them. What the verdict decides is whether `outcome` may be
    # `accepted` at all, which `receipt_findings` enforces below.
    _ = verification
    return document


def _authorization_document(authorization: Authorization) -> dict[str, object]:
    document: dict[str, object] = {
        "plan_digest": authorization.plan_digest,
        "approval_decision_ref": authorization.approval_decision_ref,
    }
    if authorization.approval_policy_code is not None:
        document["approval_policy_code"] = authorization.approval_policy_code
    if authorization.approval_policy_version is not None:
        document["approval_policy_version"] = authorization.approval_policy_version
    return document


def _check_document(result: CheckResult) -> dict[str, object]:
    document: dict[str, object] = {"passed": result.passed}
    if result.detail is not None:
        document["detail"] = result.detail
    return document


def _canary_document(live: LiveState, receiver: str | None) -> dict[str, object]:
    return {
        "fired": live.canary.fired,
        "delivered": live.canary.delivered,
        "recovered": live.canary.recovered,
        "receiver": receiver if receiver is not None else live.canary.receiver,
    }


def _expected_total(state: DesiredState, live: LiveState) -> int:
    """How many targets the inventory says should be up.

    Declared rather than observed, so ``targets_expected == targets_up`` is a
    comparison between an intention and a measurement. Reading both from the
    live document would make the equality a tautology, which is the shape of
    check that stays green through every outage it was written for.
    """
    total = 0
    for target_set in state.targets:
        for job in target_set.jobs:
            total += job.expected if job.expected is not None else 0
    total += len(state.federations)
    if total == 0:  # pragma: no cover — an inventory declaring no expectation
        total = len(live.targets)
    return total


def load_receipt(path: Path) -> Mapping[str, object]:
    with path.open("rb") as handle:
        document: Mapping[str, object] = json.load(handle)
    return document


def receipt_findings(
    document: Mapping[str, object],
    *,
    contracts: Path,
    location: str = "receipt",
    first_promotion: bool = False,
    verification: Verification | None = None,
    authorized_images: Sequence[ImageRecord] | None = None,
    authorized_plan_digest: str | None = None,
    tree: RenderedTree | None = None,
) -> tuple[Finding, ...]:
    """Every reason this receipt should not be believed.

    Returns findings rather than raising for the same reason the inventory
    gates do: an operator reading a refused receipt should see all of it once.
    """
    findings: list[Finding] = list(
        _validate_document(contracts, "promotion-receipt", document, location)
    )
    if findings:
        # Every check below reads fields by name. Running them over a document
        # the schema has already refused would report a cascade of consequences
        # of one shape error, and bury the error itself.
        return tuple(findings)

    findings.extend(private_material_findings(json.dumps(document, indent=2), location=location))
    findings.extend(_release_findings(document, first_promotion=first_promotion))
    findings.extend(
        _authorization_findings(document, authorized_plan_digest=authorized_plan_digest)
    )
    findings.extend(_image_findings(document, authorized_images=authorized_images))
    findings.extend(_digest_findings(document, tree=tree))
    findings.extend(_accepted_findings(document, verification=verification))
    return tuple(findings)


def _release_findings(document: Mapping[str, object], *, first_promotion: bool) -> list[Finding]:
    if "release" not in document:
        # A promotion that failed before staging. The contract permits the
        # absent block for a non-accepted outcome, and there is no rollback
        # target to be missing because nothing was activated.
        return []
    release = _table(document, "release")
    if release.get("previous") is None and not first_promotion:
        return [
            Finding(
                "RECEIPT-NO-ROLLBACK-TARGET",
                "release.previous",
                "null on a promotion that is not the first. The rollback target was not "
                "captured, which invalidates rule 11's guarantee, so this is a receipt worth "
                "refusing rather than filing.",
            )
        ]
    return []


def _authorization_findings(
    document: Mapping[str, object], *, authorized_plan_digest: str | None
) -> list[Finding]:
    if authorized_plan_digest is None:
        return []
    recorded = str(_table(document, "authorization").get("plan_digest"))
    if recorded == authorized_plan_digest:
        return []
    return [
        Finding(
            "RECEIPT-PLAN-DIGEST",
            "authorization.plan_digest",
            "the receipt records a different plan from the one the promotion was authorized "
            "to execute. Compared as an opaque string: the digest's canonical form belongs "
            "to the deployment control plane and is never re-derived here.",
        )
    ]


def _image_findings(
    document: Mapping[str, object], *, authorized_images: Sequence[ImageRecord] | None
) -> list[Finding]:
    if authorized_images is None:
        return []
    recorded = {
        (str(row["service"]), str(row["repository"]), str(row["digest"]))
        for row in _rows(document, "images")
    }
    approved = {(image.service, image.repository, image.digest) for image in authorized_images}
    if recorded == approved:
        return []
    return [
        Finding(
            "RECEIPT-IMAGE-SET",
            "images",
            "what ran is not what was approved. A receipt recording different images from "
            "the approved plan's set is the finding, not a formatting difference.",
        )
    ]


def _digest_findings(document: Mapping[str, object], *, tree: RenderedTree | None) -> list[Finding]:
    if tree is None:
        return []
    expected = tree_digest(tree)
    recorded = str(document.get("rendered_digest"))
    if recorded == expected:
        return []
    return [
        Finding(
            "RECEIPT-RENDERED-DIGEST",
            "rendered_digest",
            f"records {recorded[:12]}; the tree this promotion rendered digests to "
            f"{expected[:12]}",
        )
    ]


def _accepted_findings(
    document: Mapping[str, object], *, verification: Verification | None
) -> list[Finding]:
    """Everything an ``accepted`` outcome asserts, checked against the record.

    Scoped to ``accepted`` on purpose. A ``failed`` receipt recording a failed
    check, zero healthy rules and an undelivered canary is a correct receipt —
    refusing it would push a lane towards writing no receipt at all, which is
    the state this contract exists to end.
    """
    if str(document.get("outcome")) != OUTCOME_ACCEPTED:
        return []
    findings: list[Finding] = []

    for name, result in sorted(_table(document, "validation").items()):
        if not _mapping(result).get("passed"):
            findings.append(
                Finding(
                    "RECEIPT-ACCEPTED-WITH-FAILED-CHECK",
                    f"validation.{name}",
                    "an accepted promotion records a validation check that did not pass",
                )
            )

    live = _table(document, "live")
    expected = int(str(live.get("targets_expected")))
    up = int(str(live.get("targets_up")))
    if up != expected:
        findings.append(
            Finding(
                "RECEIPT-ACCEPTED-TARGETS",
                "live.targets_up",
                f"{up} of {expected} declared targets were up when this was accepted",
            )
        )
    loaded = int(str(live.get("rules_loaded")))
    healthy = int(str(live.get("rules_healthy")))
    if loaded == 0:
        findings.append(
            Finding(
                "RECEIPT-ACCEPTED-NO-RULES",
                "live.rules_loaded",
                "accepted with no rule loaded. An evaluator with nothing to evaluate reports "
                "exactly like one with nothing to report, which rule 10 refuses to accept as "
                "health.",
            )
        )
    elif healthy != loaded:
        findings.append(
            Finding(
                "RECEIPT-ACCEPTED-UNHEALTHY-RULES",
                "live.rules_healthy",
                f"{healthy} of {loaded} loaded rules evaluated cleanly",
            )
        )

    canary = _table(document, "canary")
    if not canary.get("delivered"):
        findings.append(
            Finding(
                "RECEIPT-ACCEPTED-CANARY",
                "canary.delivered",
                "accepted without the canary being observed at the receiver",
            )
        )

    runs = _table(document, "runs")
    if runs.get("promotion") is None:
        findings.append(
            Finding(
                "RECEIPT-ACCEPTED-UNPROVEN-RUN",
                "runs.promotion",
                "accepted with no external run identifier. A repository-local claim is "
                "derived from repository-local facts; that a promotion RAN needs an oracle "
                "outside this repository (Governance ADR 0013).",
            )
        )

    if verification is not None and verification.verdict != VERDICT_DEPLOYED_REPAIRED:
        unmet = ", ".join(str(condition.number) for condition in verification.unmet())
        findings.append(
            Finding(
                "RECEIPT-ACCEPTED-WITHOUT-VERDICT",
                "outcome",
                f"accepted while verification holds at {verification.verdict!r}; "
                f"condition(s) {unmet} are unmet",
            )
        )
    return findings


def _table(document: Mapping[str, object], key: str) -> Mapping[str, object]:
    return _mapping(document.get(key, {}))


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _rows(document: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    value = document.get(key, [])
    if not isinstance(value, Sequence) or isinstance(value, str):
        return []
    return [_mapping(row) for row in value]
