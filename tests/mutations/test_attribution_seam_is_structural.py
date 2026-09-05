"""The seam's failure half must survive an artifact boundary. It did not.

`classify` asked `isinstance(error, SourceError)` and two call sites said
`except SourceMissing`. Both work perfectly in-process, and neither works
across a distribution boundary: a `HostSource` implementation lives in another
artifact, its `SourceMissing` is a DIFFERENT class, so it matched nothing, fell
through to the catch-all and was classified `parse`.

The concrete consequence was a clean host with no `/etc/cron.d` reporting a
parse error on `cron` -- the identical defect this module's own commit message
claims to have found and fixed, reintroduced from the other side of the seam.

**Every exception in this file is defined HERE and shares no base with
`SourceError`.** That is what makes these tests mean anything: importing the
collector's own exception classes would exercise the in-process path and prove
exactly nothing about the boundary. These are not the real Foundation classes
-- this repository cannot import that artifact and must not try -- they are
foreign-to-the-collector classes with the same shape, which is precisely the
property under test.
"""

from __future__ import annotations

import pytest

from dotmac_observability.attribution import DECLARED_FAMILIES, RedactionVault, Verdict
from dotmac_observability.attribution_enumerators import (
    HOST_SOURCE_CONTRACT_VERSION,
    OBSERVATION_ERROR_CLASSES_V2,
    SOURCE_ERROR_CLASSES,
    UNKNOWN_SOURCE_ERROR,
    UnsupportedHostSource,
    check_contract_version,
    classify,
    enumerate_all,
    enumerate_family,
    observation_error,
)

# ── A foreign artifact's exceptions ─────────────────────────────────────────
#
# Deliberately rooted at `Exception`, exactly as a separately released
# implementation's would be. Nothing below inherits from anything the collector
# defines, and that is the entire point.


class ForeignError(Exception):
    """The other artifact's base. Unrelated to `SourceError` by construction."""

    error_class = "unsupported"


class ForeignMissing(ForeignError):
    error_class = "missing"


class ForeignDenied(ForeignError):
    error_class = "denied"


class ForeignParse(ForeignError):
    error_class = "parse"


class ForeignFuture(ForeignError):
    """A source speaking a vocabulary this collector predates."""

    error_class = "quarantined"


class ForeignSilent(Exception):
    """No `error_class` at all -- an exception from a library the source wraps."""


class ForeignMalformed(Exception):
    """An `error_class` that is not a string. Someone passed the class object."""

    error_class = ForeignMissing


class ForeignHost:
    """A minimal foreign `HostSource`: it raises, and it advertises a version."""

    host_source_contract_version = HOST_SOURCE_CONTRACT_VERSION

    def __init__(self, error: Exception) -> None:
        self._error = error

    def exists(self, path: str) -> bool:
        raise self._error

    def list_dir(self, directory: str):
        raise self._error

    def read_text(self, path: str) -> str:
        raise self._error

    def run(self, argv):
        raise self._error


# ── The six required proofs ─────────────────────────────────────────────────


def test_a_foreign_missing_classifies_as_missing():
    assert classify(ForeignMissing()) == "missing"


def test_a_foreign_denial_classifies_as_denied():
    assert classify(ForeignDenied()) == "denied"


def test_a_foreign_parse_failure_classifies_as_parse():
    assert classify(ForeignParse()) == "parse"


@pytest.mark.parametrize(
    "error",
    [ForeignFuture(), ForeignSilent(), ForeignMalformed(), ValueError("bare")],
    ids=["unknown-code", "no-attribute", "not-a-string", "unrelated-exception"],
)
def test_an_unrecognized_code_classifies_as_unknown_and_never_as_something_reassuring(error):
    """Four shapes, one answer, and the answer is never a guess.

    `parse` was the old default and it was wrong twice over: it claimed we had
    failed to understand the HOST when we had failed to understand the SOURCE,
    and it made a foreign `missing` -- the commonest thing a clean host produces
    -- indistinguishable from a corrupt unit file.
    """
    assert classify(error) == UNKNOWN_SOURCE_ERROR
    assert classify(error) != "parse"
    assert observation_error(classify(error)) in OBSERVATION_ERROR_CLASSES_V2


def test_a_clean_host_with_no_cron_directory_does_not_report_a_parse_error():
    """The regression, stated as the case that produced it.

    A host with no `/etc/crontab` and no `/etc/cron.d` is a complete answer:
    `cron` is ABSENT. Under nominal matching the foreign `missing` became
    `parse`, so every such host -- which is most of them -- carried an error and
    derived UNKNOWN, and the census could never state an absence at all.
    """
    outcome = enumerate_family("cron", ForeignHost(ForeignMissing()), vault=RedactionVault())
    assert outcome.scan.errors == (), f"a clean host reported {outcome.scan.errors}"
    assert outcome.scan.verdict() is Verdict.ABSENT
    assert "parse" not in outcome.scan.errors


def test_a_classifier_that_answers_unknown_to_everything_fails_its_positive_control():
    """The dual. A broken-shut classifier satisfies every negative case above.

    `classify` returning `UNKNOWN_SOURCE_ERROR` unconditionally passes all four
    unknown-code parameters, and would pass them forever. So the same run
    requires it to admit known-good inputs -- every member of the closed source
    vocabulary, mapped to itself, not to the sentinel.
    """
    for code in SOURCE_ERROR_CLASSES:
        planted = type("Planted", (Exception,), {"error_class": code})()
        assert classify(planted) == code, f"{code} was swallowed into the unknown sentinel"
        assert classify(planted) != UNKNOWN_SOURCE_ERROR
    # And the negative, in the same run, so neither direction can be satisfied
    # by a constant.
    assert classify(ForeignFuture()) == UNKNOWN_SOURCE_ERROR


# ── The consequences, end to end ────────────────────────────────────────────


def test_a_foreign_denial_reaches_the_verdict_as_unknown():
    """A denial must not read as an empty host, whichever artifact raised it."""
    outcome = enumerate_family(
        "systemd_service", ForeignHost(ForeignDenied()), vault=RedactionVault()
    )
    assert "denied" in outcome.scan.errors
    assert outcome.scan.verdict() is Verdict.UNKNOWN


def test_an_unrecognized_foreign_failure_never_infers_absent():
    """`UNKNOWN`, across every family, from a source nobody can classify."""
    outcomes = enumerate_all(ForeignHost(ForeignFuture()), vault=RedactionVault())
    assert set(outcomes) == set(DECLARED_FAMILIES)
    for family, outcome in outcomes.items():
        assert outcome.scan.verdict() is Verdict.UNKNOWN, family
        assert UNKNOWN_SOURCE_ERROR in outcome.scan.errors, family


def test_the_mapping_from_source_code_to_observation_code_is_total():
    """A partial map would raise INSIDE an error handler.

    Which is the worst place in this module for a second failure: the first one
    is already being recorded, and the second one escapes the family walk
    entirely.
    """
    for code in (*SOURCE_ERROR_CLASSES, UNKNOWN_SOURCE_ERROR):
        assert observation_error(code) in OBSERVATION_ERROR_CLASSES_V2


def test_the_source_vocabulary_is_closed_and_contains_missing():
    """`missing` is the load-bearing member and the one v1 could not spell."""
    assert "missing" in SOURCE_ERROR_CLASSES
    assert UNKNOWN_SOURCE_ERROR not in SOURCE_ERROR_CLASSES, (
        "the unknown sentinel must not be something a source can legitimately declare; "
        "otherwise a source can assert that its own failures are unclassifiable"
    )


# ── Contract version ────────────────────────────────────────────────────────


def test_a_source_advertising_nothing_is_refused_rather_than_run():
    """An unversioned seam is exactly the one whose `missing` might be anything.

    Refused rather than degraded: a census run against unknown failure
    semantics produces a document that looks exactly like a good one, and every
    downstream reader takes it at face value.
    """

    class Unversioned(ForeignHost):
        host_source_contract_version = None  # type: ignore[assignment]

    with pytest.raises(UnsupportedHostSource):
        enumerate_all(Unversioned(ForeignMissing()), vault=RedactionVault())
    with pytest.raises(UnsupportedHostSource):
        check_contract_version(object())


def test_a_source_advertising_a_different_version_is_refused():
    class Newer(ForeignHost):
        host_source_contract_version = "host-source.v9"

    with pytest.raises(UnsupportedHostSource, match="host-source.v9"):
        enumerate_all(Newer(ForeignMissing()), vault=RedactionVault())


def test_a_matching_version_is_accepted_so_the_check_is_not_broken_shut():
    """Positive control for the refusal above, which would otherwise refuse all."""
    assert check_contract_version(ForeignHost(ForeignMissing())) == HOST_SOURCE_CONTRACT_VERSION


# ── Cancellation is not a source failure ────────────────────────────────────


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit], ids=["ctrl-c", "exit"])
def test_a_cancelled_run_is_not_recorded_as_a_source_failure(interrupt):
    """`Exception`, never `BaseException`, at the seam boundary.

    Swallowing a cancellation here would file a document reporting a failure on
    every family the walk had not yet reached -- a complete-looking census
    produced by someone pressing Ctrl-C.
    """

    class Cancelling(ForeignHost):
        def list_dir(self, directory: str):
            raise interrupt()

        def read_text(self, path: str) -> str:
            raise interrupt()

    with pytest.raises(interrupt):
        enumerate_family("systemd_service", Cancelling(ForeignMissing()), vault=RedactionVault())
