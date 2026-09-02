"""Three-way drift: desired state, live state, and the last verified receipt.

AGENTS.md rule 12 states the premise: drift is the disagreement between three
independently comparable artifacts, and a design that can only read one of them
cannot detect drift at all. This module is the comparison, and its most
important behaviour is what it does when it is handed fewer than three.

## Each pair means something different

Reporting "they disagree" would waste the whole design. Which PAIR disagrees is
the diagnosis:

* **desired vs live** — the repository says one thing and the host is doing
  another. Either a change was merged and never promoted, or somebody edited
  the host. AGENTS.md rule 2 says the second is drift to be reported and
  reverted, never a fix to be kept.
* **live vs receipt** — the host has moved since the last accepted promotion.
  Something changed after acceptance without going through promotion, which is
  the only pair that can say so.
* **receipt vs desired** — the last accepted promotion executed a different
  desired state from the one in the repository now. A promotion that never
  happened, or a revert that was never promoted.

## Two artifacts are not a comparison

A caller holding a receipt and a live observation, with no desired state, can
compute a perfectly good-looking disagreement — and cannot tell an unpromoted
change from a host edit, because the artifact that separates those two is the
one it does not have. :func:`compare` therefore reports
``DRIFT-INCOMPARABLE`` and performs the pairs it can rather than silently
presenting a two-way answer as a three-way one. A partial comparison labelled
as a full one is worse than no comparison, because a reader acts on it.

## What each pair can actually compare

Not everything, and saying which is part of being honest about the result.
Desired against live is a per-file comparison of the rendered tree, because
both sides carry every path. Live against the receipt is the receipt's own
recorded facts — the release pointer, the rule set's semantic digest, the
target counts, the route count — because those are what a receipt holds; it
does not carry per-file digests and pretending otherwise would invent a
comparison. Receipt against desired is the rendered digest, which both sides
have exactly.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .live_verify import LiveState, rules_semantic_digest
from .render import RenderedTree, file_digest, tree_digest
from .validate import Finding

__all__ = ["DriftReport", "compare"]


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Findings grouped by which pair produced them.

    Grouped rather than flattened because the grouping IS the diagnosis, and a
    flat list would make a reader re-derive it from the finding codes.
    """

    desired_vs_live: tuple[Finding, ...]
    live_vs_receipt: tuple[Finding, ...]
    receipt_vs_desired: tuple[Finding, ...]
    incomparable: tuple[Finding, ...]

    @property
    def findings(self) -> tuple[Finding, ...]:
        return (
            self.incomparable
            + self.desired_vs_live
            + self.live_vs_receipt
            + self.receipt_vs_desired
        )

    @property
    def clean(self) -> bool:
        """True only when all three artifacts were present and all three pairs agreed.

        An absent artifact makes this false. "No findings" over two artifacts
        is not a clean result; it is an incomplete one, and the distinction is
        exactly what rule 12 asks this module to keep.
        """
        return not self.findings


def compare(
    *,
    tree: RenderedTree | None,
    live: LiveState | None,
    receipt: Mapping[str, object] | None,
) -> DriftReport:
    """Compare whichever artifacts were supplied, and say which were not."""
    incomparable: list[Finding] = []
    for name, artifact in (("desired", tree), ("live", live), ("receipt", receipt)):
        if artifact is None:
            incomparable.append(
                Finding(
                    "DRIFT-INCOMPARABLE",
                    name,
                    f"the {name} artifact was not supplied. Drift is the disagreement between "
                    "three artifacts; with two, an unpromoted change and a host edit are "
                    "indistinguishable, so this result is incomplete rather than clean.",
                )
            )

    desired_vs_live = _desired_vs_live(tree, live)
    live_vs_receipt = _live_vs_receipt(live, receipt)
    receipt_vs_desired = _receipt_vs_desired(tree, receipt)
    return DriftReport(
        desired_vs_live=desired_vs_live,
        live_vs_receipt=live_vs_receipt,
        receipt_vs_desired=receipt_vs_desired,
        incomparable=tuple(incomparable),
    )


def _desired_vs_live(tree: RenderedTree | None, live: LiveState | None) -> tuple[Finding, ...]:
    if tree is None or live is None:
        return ()
    findings: list[Finding] = []
    if not live.tree:
        return (
            Finding(
                "DRIFT-LIVE-TREE-NOT-READ",
                "live.tree",
                "the observation lists no files, which produces the same empty difference "
                "set as a host that matches perfectly",
            ),
        )
    expected = {path: file_digest(contents) for path, contents in tree}
    observed = {entry.path: entry.sha256 for entry in live.tree}
    for path, digest in expected.items():
        if path not in observed:
            findings.append(
                Finding(
                    "DRIFT-DESIRED-LIVE",
                    path,
                    "rendered by this repository and absent from the host: an unpromoted "
                    "change, or a file removed on the host",
                )
            )
        elif observed[path] != digest:
            findings.append(
                Finding(
                    "DRIFT-DESIRED-LIVE",
                    path,
                    f"repository renders {digest[:12]}, host holds {observed[path][:12]} — "
                    "an unpromoted change or a hand edit (rule 2)",
                )
            )
    for path in observed:
        if path not in expected:
            findings.append(
                Finding(
                    "DRIFT-DESIRED-LIVE",
                    path,
                    "present on the host and produced by no render. A stale file in the "
                    "release directory is still mounted into the evaluator.",
                )
            )
    return tuple(findings)


def _live_vs_receipt(
    live: LiveState | None, receipt: Mapping[str, object] | None
) -> tuple[Finding, ...]:
    if live is None or receipt is None:
        return ()
    findings: list[Finding] = []
    recorded_release = str(_table(receipt, "release").get("current"))
    if live.release.current != recorded_release:
        findings.append(
            Finding(
                "DRIFT-LIVE-RECEIPT",
                "release.current",
                f"the host is running {live.release.current!r}; the last accepted receipt "
                f"records {recorded_release!r}. Something activated a release outside "
                "promotion.",
            )
        )

    recorded = _table(receipt, "live")
    observed_digest = rules_semantic_digest(live)
    if str(recorded.get("rules_semantic_digest")) != observed_digest:
        findings.append(
            Finding(
                "DRIFT-LIVE-RECEIPT",
                "live.rules_semantic_digest",
                "the evaluator is running a different rule SET from the one accepted. Not a "
                "different evaluation state — a different set, which only a change to what "
                "was loaded can produce.",
            )
        )

    up = sum(1 for target in live.targets if target.health == "up")
    if up != int(str(recorded.get("targets_up", -1))):
        findings.append(
            Finding(
                "DRIFT-LIVE-RECEIPT",
                "live.targets_up",
                f"{up} targets up now; {recorded.get('targets_up')} at acceptance",
            )
        )
    if len(live.routes) != int(str(recorded.get("routes_verified", -1))):
        findings.append(
            Finding(
                "DRIFT-LIVE-RECEIPT",
                "live.routes_verified",
                f"{len(live.routes)} routes resolve now; "
                f"{recorded.get('routes_verified')} at acceptance",
            )
        )
    return tuple(findings)


def _receipt_vs_desired(
    tree: RenderedTree | None, receipt: Mapping[str, object] | None
) -> tuple[Finding, ...]:
    if tree is None or receipt is None:
        return ()
    expected = tree_digest(tree)
    recorded = str(receipt.get("rendered_digest"))
    if recorded == expected:
        return ()
    return (
        Finding(
            "DRIFT-RECEIPT-DESIRED",
            "rendered_digest",
            f"the last accepted promotion rendered {recorded[:12]}; this repository renders "
            f"{expected[:12]}. A change was merged and never promoted, or a promoted change "
            "was reverted without a promotion.",
        ),
    )


def _table(document: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = document.get(key, {})
    return value if isinstance(value, Mapping) else {}
