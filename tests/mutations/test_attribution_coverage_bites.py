"""Sensitivity proof for the coverage derivation.

`test_attribution_coverage.py` asserts that the real `derive_verdict` behaves.
That is a check over a clean implementation, and a check over a clean subject
proves nothing about itself. Here the plausible WRONG derivations are written
out explicitly and the contract is required to reject each of them -- then a
near-miss that is merely spelled differently is required to pass, so the
contract is not simply refusing everything that is not identical source.

Each mutant below is a real thing somebody writes. None of them is a strawman:
the "errors are a detail" mutant is what you get by reading the happy path
first, and the "empty errors means none seen yet" mutant is what you get from a
collector that appends errors after deciding the verdict.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable

import pytest

from dotmac_observability.attribution import (
    DECLARED_FAMILIES,
    Custody,
    FamilyScan,
    RedactionVault,
    Verdict,
    derive_custody,
    derive_verdict,
    project_envelope,
)
from tests.attribution_fixtures import clean_scans, coverage_of, observation

Derivation = Callable[..., Verdict]


def _absent_rows(derivation: Derivation) -> list[tuple[bool, bool, bool, bool]]:
    """Every input row on which ``derivation`` says ABSENT."""
    rows = []
    for attempted, completed, errors, found in itertools.product((False, True), repeat=4):
        verdict = derivation(
            attempted=attempted, completed=completed, errors=int(errors), found=int(found)
        )
        if verdict is Verdict.ABSENT:
            rows.append((attempted, completed, errors, found))
    return rows


def _honours_the_one_path(derivation: Derivation) -> bool:
    return _absent_rows(derivation) == [(True, True, False, False)]


# ── The plants ──────────────────────────────────────────────────────────────


def _errors_are_a_detail(*, attempted, completed, errors, found) -> Verdict:
    """Reads the happy path first and treats an error as colour. Very common."""
    if not attempted:
        return Verdict.UNKNOWN
    if not completed:
        return Verdict.UNKNOWN
    return Verdict.SCANNED if found else Verdict.ABSENT


def _errors_only_matter_when_something_was_found(*, attempted, completed, errors, found) -> Verdict:
    """Errors treated as a caveat on a positive result rather than on the scan.

    The reasoning sounds fine out loud -- "if we found nothing and also hit an
    error, we still found nothing" -- and it is precisely backwards: the error
    is the reason the count of zero means nothing.
    """
    if not attempted or not completed:
        return Verdict.UNKNOWN
    if errors and found:
        return Verdict.UNKNOWN
    return Verdict.SCANNED if found else Verdict.ABSENT


def _found_checked_first(*, attempted, completed, errors, found) -> Verdict:
    """Branch order inverted -- 'nothing found' short-circuits everything else."""
    if not found:
        return Verdict.ABSENT
    if not attempted or not completed or errors:
        return Verdict.UNKNOWN
    return Verdict.SCANNED


def _bounded_scan_counts_as_finished(*, attempted, completed, errors, found) -> Verdict:
    """Drops the `completed` branch: a scan that hit its bound reads as clean."""
    if not attempted:
        return Verdict.UNKNOWN
    if errors:
        return Verdict.UNKNOWN
    return Verdict.SCANNED if found else Verdict.ABSENT


def _never_ran_is_clean(*, attempted, completed, errors, found) -> Verdict:
    """The worst one: a family that was never scanned reads as having nothing."""
    if errors:
        return Verdict.UNKNOWN
    return Verdict.SCANNED if found else Verdict.ABSENT


@pytest.mark.parametrize(
    "mutant",
    [
        _errors_are_a_detail,
        _errors_only_matter_when_something_was_found,
        _found_checked_first,
        _bounded_scan_counts_as_finished,
        _never_ran_is_clean,
    ],
    ids=lambda fn: fn.__name__.strip("_"),
)
def test_the_contract_rejects_each_wrong_derivation(mutant):
    assert not _honours_the_one_path(mutant), (
        f"{mutant.__name__} widens the path to ABSENT and the contract accepted it; "
        "the check is not sensitive to the defect it exists for"
    )


def test_the_contract_accepts_the_real_derivation():
    assert _honours_the_one_path(derive_verdict)


def test_the_contract_accepts_a_correct_near_miss():
    """Different spelling, same behaviour. The guard must not require identity.

    Without this, the contract could be a source comparison in disguise and
    would fail every legitimate refactor while still passing a semantically
    identical rewrite of the bug.
    """

    def rewritten(*, attempted, completed, errors, found) -> Verdict:
        complete_and_clean = attempted and completed and not errors
        if not complete_and_clean:
            return Verdict.UNKNOWN
        return Verdict.ABSENT if found == 0 else Verdict.SCANNED

    assert _honours_the_one_path(rewritten)


# ── Custody ─────────────────────────────────────────────────────────────────


def test_an_unowned_consumer_defaulting_to_attributed_is_rejected():
    """The plant: custody assumed present unless something says otherwise.

    That reads a bare `DATABASE_URL` as somebody's, which is exactly the
    consumer nobody is answerable for.
    """

    def optimistic(*, owner_unit, owner_principal) -> Custody:
        return Custody.UNATTRIBUTED if owner_unit == "none" else Custody.ATTRIBUTED

    assert optimistic(owner_unit=None, owner_principal=None) is Custody.ATTRIBUTED
    assert derive_custody(owner_unit=None, owner_principal=None) is Custody.UNATTRIBUTED


# ── Completeness of the family set ──────────────────────────────────────────


@pytest.mark.parametrize("dropped", DECLARED_FAMILIES)
def test_dropping_any_single_family_is_refused(dropped):
    """One plant per family, because a completeness check with a gap has a gap.

    A projection that only verified the families it happened to iterate over
    would pass a spot check and file an incomplete census as a complete one.
    """
    scans = clean_scans()
    del scans[dropped]
    with pytest.raises(ValueError, match=dropped):
        project_envelope(observation(), scans, vault=RedactionVault())


def test_an_unattempted_family_still_appears_as_unknown_rather_than_vanishing():
    """The silent version of the same defect: present, but omitted from output.

    An omitted family is read by every consumer as a family with nothing in it,
    which is the one reading that must never be available by accident.
    """
    scans = clean_scans(
        anacron=FamilyScan(family="anacron", attempted=False, completed=False),
    )
    envelope = project_envelope(observation(), scans, vault=RedactionVault())
    entries = {entry["family"]: entry for entry in coverage_of(envelope)}
    assert set(entries) == set(DECLARED_FAMILIES)
    assert entries["anacron"]["verdict"] == Verdict.UNKNOWN.value
    # Spelled as the absence of the reassuring reading, not only the presence of
    # the honest one: those are different assertions and the first is the one a
    # consumer acts on.
    assert Verdict.ABSENT.value not in {
        entry["verdict"] for entry in coverage_of(envelope) if entry["family"] == "anacron"
    }


def test_an_error_count_reaches_the_envelope_so_unknown_is_explainable():
    """A verdict with no reason attached gets overridden by whoever is in a hurry.

    The count, not the message: a message on this path carries the DSN it
    failed to parse, which is the leak the error path is famous for.
    """
    scans = clean_scans(
        cron=FamilyScan(
            family="cron", attempted=True, completed=True, errors=("denied", "parse"), found=0
        ),
    )
    envelope = project_envelope(observation(), scans, vault=RedactionVault())
    entry = next(item for item in coverage_of(envelope) if item["family"] == "cron")
    assert entry["verdict"] == Verdict.UNKNOWN.value
    assert entry["error_count"] == 2
    assert "denied" not in str(envelope), "a classification string reached the public envelope"
