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
_UNMONITORED = re.compile(r"`none yet \(PR (\d+)\)`")
# A gap nobody in this repository can close by writing code. Kept separate
# because a PR number promises someone can finish the work.
_BLOCKED = re.compile(r"`none yet \(decision: ([a-z][a-z0-9-]+)\)`")
_LEDGER_ROW = re.compile(r"^\| (\d+) \| .+ \| .+ \| PR (\d+) \|$", re.MULTILINE)
_DECISION_ROW = re.compile(r"^\| ([a-z][a-z0-9-]+) \| .+ \| .+ \| .+ \|$", re.MULTILINE)
_DECLARED = re.compile(r"^declared-unmonitored: (\d+)$", re.MULTILINE)
_DECLARED_DECISIONS = re.compile(r"^declared-decisions: (\d+)$", re.MULTILINE)


def _agents_unmonitored() -> dict[int, int]:
    """Rule number -> PR that will monitor it, read from AGENTS.md."""
    starts = [(int(match.group(1)), match.start()) for match in _RULE.finditer(AGENTS)]
    assert starts, "no numbered rules found in AGENTS.md; the parser has drifted"
    out: dict[int, int] = {}
    for index, (number, start) in enumerate(starts):
        end = starts[index + 1][1] if index + 1 < len(starts) else len(AGENTS)
        found = _UNMONITORED.search(AGENTS[start:end])
        if found is not None:
            out[number] = int(found.group(1))
    return out


def _ledger_rows() -> dict[int, int]:
    return {int(rule): int(pr) for rule, pr in _LEDGER_ROW.findall(LEDGER)}


def _agents_blocked() -> dict[int, str]:
    """Rule number -> decision slug, for gaps waiting on a person, not a PR."""
    starts = [(int(match.group(1)), match.start()) for match in _RULE.finditer(AGENTS)]
    out: dict[int, str] = {}
    for index, (number, start) in enumerate(starts):
        end = starts[index + 1][1] if index + 1 < len(starts) else len(AGENTS)
        found = _BLOCKED.search(AGENTS[start:end])
        if found is not None:
            out[number] = found.group(1)
    return out


# Markdown table HEADERS are indistinguishable from rows to a regex, and both
# tables in this file are four cells wide. Excluding the two literal header
# labels is narrower than requiring slugs to look a particular way, which would
# silently drop a future one-word slug instead of failing.
_TABLE_HEADINGS = frozenset({"rule", "decision"})


def _decision_rows() -> set[str]:
    return {slug for slug in _DECISION_ROW.findall(LEDGER) if slug not in _TABLE_HEADINGS}


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


def test_the_ledger_and_the_rules_agree_on_which_pr_closes_each_gap():
    agents = _agents_unmonitored()
    for rule, pr in _ledger_rows().items():
        assert (
            agents[rule] == pr
        ), f"rule {rule}: AGENTS.md says PR {agents[rule]}, ledger says PR {pr}"


def test_the_declared_count_is_the_ratchet():
    declared = _DECLARED.search(LEDGER)
    assert declared is not None, "CONTROL_EXCEPTIONS.md must carry a `declared-unmonitored: N` line"
    # Fails when the count RISES (a gap was added without being counted) and
    # when it FALLS (a gap was closed without being celebrated). Either way the
    # number is edited deliberately, which is the point.
    assert int(declared.group(1)) == len(_ledger_rows())


def test_the_decision_row_parser_ignores_only_the_table_headings():
    # Sensitivity proof for the exclusion above: it must remove the headings and
    # nothing else, or a real row could vanish and every check below would pass.
    raw = set(_DECISION_ROW.findall(LEDGER))
    assert raw >= _TABLE_HEADINGS, "the ledger's table headings changed; the parser has drifted"
    assert raw - _TABLE_HEADINGS == _decision_rows()
    assert _decision_rows(), "no decision rows parsed"


def test_every_blocked_rule_names_a_recorded_decision():
    blocked = _agents_blocked()
    assert blocked, (
        "AGENTS.md declares no decision-blocked rule; if that became true, delete the "
        "decisions table and this test rather than leaving a check that cannot fail"
    )
    missing = set(blocked.values()) - _decision_rows()
    assert not missing, f"AGENTS.md names decisions {sorted(missing)} with no row in the ledger"


def test_no_decision_row_outlives_its_rule():
    stale = _decision_rows() - set(_agents_blocked().values())
    assert not stale, (
        f"the ledger still lists decisions {sorted(stale)} that no rule waits on; remove the "
        "row in the same change that resolves the decision"
    )


def test_the_declared_decision_count_is_also_a_ratchet():
    declared = _DECLARED_DECISIONS.search(LEDGER)
    assert declared is not None, "CONTROL_EXCEPTIONS.md must carry a `declared-decisions: N` line"
    assert int(declared.group(1)) == len(_decision_rows())


def test_a_rule_is_never_both_unmonitored_and_blocked():
    # The two states demand different actions — write the detector, or get an
    # answer. A rule claiming both tells a reader to do neither.
    both = set(_agents_unmonitored()) & set(_agents_blocked())
    assert not both, f"rules {sorted(both)} claim both a PR and a decision"


def test_grandfathered_and_enforced_stay_distinct_words():
    assert "Grandfathered" in LEDGER
    assert "There are none" in LEDGER
