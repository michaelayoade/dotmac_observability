"""AGENTS.md rule 15 — the unmonitored ledger is a two-directional ratchet.

The failure this guards against is subtle. A repository that documents its
gaps once, at the start, and never revisits the document ends up describing a
system that no longer exists: rules get detectors and the ledger keeps
claiming they have none, or a new rule arrives unmonitored and the ledger never
learns about it. Both directions make the document worse than nothing, because
a reader trusts it.
"""

from __future__ import annotations

import re

from tests.conftest import REPO_ROOT

AGENTS = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
LEDGER = (REPO_ROOT / "docs" / "CONTROL_EXCEPTIONS.md").read_text(encoding="utf-8")

_RULE = re.compile(r"^\s*(\d+)\. \*\*", re.MULTILINE)
# The monitoring token is free text, not a PR number. It was `PR (\d+)` until
# a rule arrived whose guard lands with an external release rather than a
# local PR — and the digit-only pattern did not fail, it simply stopped
# seeing that rule. A ratchet with a blind spot is worse than no ratchet,
# because it reports green over the gap.
_UNMONITORED = re.compile(r"`none yet \(([^`)]+)\)`")
_LEDGER_ROW = re.compile(r"^\| (\d+) \| .+ \| .+ \| ([^|]+?) \|$", re.MULTILINE)
_DECLARED = re.compile(r"^declared-unmonitored: (\d+)$", re.MULTILINE)


def _agents_unmonitored() -> dict[int, str]:
    """Rule number -> the token naming what will monitor it, from AGENTS.md."""
    starts = [(int(match.group(1)), match.start()) for match in _RULE.finditer(AGENTS)]
    assert starts, "no numbered rules found in AGENTS.md; the parser has drifted"
    out: dict[int, str] = {}
    for index, (number, start) in enumerate(starts):
        end = starts[index + 1][1] if index + 1 < len(starts) else len(AGENTS)
        found = _UNMONITORED.search(AGENTS[start:end])
        if found is not None:
            out[number] = found.group(1).strip()
    return out


def _ledger_rows() -> dict[int, str]:
    return {int(rule): token.strip() for rule, token in _LEDGER_ROW.findall(LEDGER)}


def test_the_rules_are_numbered_contiguously_from_one():
    numbers = [int(match.group(1)) for match in _RULE.finditer(AGENTS)]
    # The index in the project's CLAUDE.md has drifted from AGENTS.md before on
    # this fleet. Contiguity is the cheapest thing that makes a silent renumber
    # visible.
    assert numbers == list(range(1, len(numbers) + 1))


def test_the_parser_can_still_see_the_rules():
    # A regex that matches nothing makes every other test here pass for the
    # wrong reason. This is the sensitivity proof for the parser itself.
    assert len(_RULE.findall(AGENTS)) >= 10
    assert (
        _agents_unmonitored()
    ), "AGENTS.md declares no unmonitored rule; if that is true, delete this ledger"


def test_every_unmonitored_rule_has_a_ledger_row():
    missing = set(_agents_unmonitored()) - set(_ledger_rows())
    assert (
        not missing
    ), f"AGENTS.md rules {sorted(missing)} say 'none yet' with no row in CONTROL_EXCEPTIONS.md"


def test_no_ledger_row_outlives_its_rule():
    stale = set(_ledger_rows()) - set(_agents_unmonitored())
    assert not stale, (
        f"CONTROL_EXCEPTIONS.md still lists rules {sorted(stale)}, which AGENTS.md now claims "
        "are enforced; remove the row in the same change that added the detector"
    )


def test_the_ledger_and_the_rules_agree_on_what_closes_each_gap():
    agents = _agents_unmonitored()
    for rule, token in _ledger_rows().items():
        assert (
            agents[rule] == token
        ), f"rule {rule}: AGENTS.md says {agents[rule]!r}, ledger says {token!r}"


def test_the_parser_reads_a_non_numeric_monitoring_token():
    """Sensitivity proof for the generalised token.

    A rule whose guard arrives with an external release names that release, not
    a local PR number. The earlier digit-only pattern skipped such a rule in
    SILENCE — every assertion here still passed while one gap went uncounted,
    which is the precise failure a ratchet exists to prevent. This test fails
    if the parser ever regresses to numbers only.
    """
    tokens = set(_agents_unmonitored().values())
    assert tokens, "no unmonitored rules parsed at all"
    assert any(not token.startswith("PR ") for token in tokens), (
        "every monitoring token is a PR number; if that is genuinely true now, delete "
        "this test rather than weakening it"
    )


def test_the_declared_count_is_the_ratchet():
    declared = _DECLARED.search(LEDGER)
    assert declared is not None, "CONTROL_EXCEPTIONS.md must carry a `declared-unmonitored: N` line"
    # Fails when the count RISES (a gap was added without being counted) and
    # when it FALLS (a gap was closed without being celebrated). Either way the
    # number is edited deliberately, which is the point.
    assert int(declared.group(1)) == len(_ledger_rows())


def test_grandfathered_and_enforced_stay_distinct_words():
    assert "Grandfathered" in LEDGER
    assert "There are none" in LEDGER
