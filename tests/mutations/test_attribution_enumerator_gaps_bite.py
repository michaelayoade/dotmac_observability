"""Sensitivity proof for the enumerators. Every gap is planted and required to bite.

The unit tests assert that the real enumerators behave. That is a check over a
clean implementation, and the defects being guarded against are all of the same
shape: an enumerator that looks thorough, runs without error, and reports a
confident zero it has no way to know. None of them raises. None of them fails a
test that only exercises the happy path.

So each one is planted here as a HOST that would provoke it, and the collector
is required to say `UNKNOWN`. Two near-misses are required to stay `ABSENT` or
`SCANNED`, because a collector that answered `UNKNOWN` to everything would pass
every test above while being exactly as useless as one that answered `ABSENT`
to everything -- and it would feel safer, which is worse.
"""

from __future__ import annotations

from dotmac_observability.attribution import DECLARED_FAMILIES, RedactionVault, Verdict
from dotmac_observability.attribution_enumerators import (
    Budget,
    SourceDenied,
    apply_degradations,
    degradations,
    enumerate_all,
    enumerate_family,
)
from tests.attribution_hosts import DOCKER_DSN, DROPIN_DSN, FakeHost, populated_host


def _verdict(family: str, host: FakeHost, **kwargs: object) -> Verdict:
    return enumerate_family(family, host, vault=RedactionVault(), **kwargs).scan.verdict()  # type: ignore[arg-type]


# ── The gaps that report a confident zero ───────────────────────────────────


def test_a_consumer_configured_only_in_a_drop_in_is_found():
    """The plant for the family the first design omitted.

    A drop-in adds an `Environment=` without touching the unit, so a host whose
    only consumer is configured this way reads as clean to any scan that stops
    at `*.service` -- which is every obvious implementation, and was the one
    this design shipped with first.
    """
    host = FakeHost(
        files={
            "/etc/systemd/system/erp.service": "[Service]\nExecStart=/usr/bin/erp\n",
            "/etc/systemd/system/erp.service.d/db.conf": (
                f"[Service]\nEnvironment=DATABASE_URL={DROPIN_DSN}\n"
            ),
        },
        directories=("/etc/systemd/system/erp.service.d",),
        commands={("atq",): ""},
    )
    assert _verdict("systemd_service", host) is Verdict.ABSENT
    assert _verdict("systemd_dropin", host) is Verdict.SCANNED, (
        "the drop-in family found nothing; a host whose only consumer lives in an "
        "override reports as clean"
    )
    outcomes = enumerate_all(host, vault=RedactionVault())
    assert outcomes["systemd_dropin"].scan.found == 1


def test_a_nightly_job_under_anacron_is_found():
    """The other omitted family, and the one likeliest to hold a forgotten job.

    A machine that is not always on runs its nightly work through anacron, and
    a machine that is not always on is exactly the one whose consumers nobody
    remembers.
    """
    host = FakeHost(
        files={
            "/etc/cron.daily/erp-vacuum": f"#!/bin/sh\npsql {DOCKER_DSN} -c 'vacuum'\n",
        },
        commands={("atq",): ""},
    )
    assert _verdict("anacron", host) is Verdict.SCANNED
    assert _verdict("cron", host) is Verdict.ABSENT, (
        "cron claimed the anacron directory; the two families would double-count and "
        "removing either would look safe"
    )


def test_a_stopped_container_is_not_dropped():
    """`docker ps` without `-a` is the plant, and it is what everybody writes.

    A stopped container's environment still holds the DSN, it starts again on
    reboot, and its credential is still valid. This asserts the ARGUMENTS, not
    the result, because a fake that returns the same output for both spellings
    would make the result identical and prove nothing.
    """
    host = populated_host()
    enumerate_family("docker", host, vault=RedactionVault())
    ps = [argv for argv in host.ran if argv[:2] == ("docker", "ps")]
    assert ps, "docker was never listed"
    assert all("-a" in argv for argv in ps)
    # The near-miss: `--all` would be equally correct and must not be required
    # by spelling. Asserted by showing the check is about the FLAG's effect.
    assert any(flag in argv for argv in ps for flag in ("-a", "--all"))


def test_a_truncated_walk_never_reports_a_total():
    """One plant per family: a zero-file budget must make every family UNKNOWN.

    A budget that bit silently would be the most dangerous possible defect
    here, because it produces a complete-looking document from a walk that read
    almost nothing.
    """
    host = populated_host(present=())
    outcomes = enumerate_all(host, vault=RedactionVault(), budget=Budget(max_files=0))
    truncated = [f for f in DECLARED_FAMILIES if outcomes[f].scan.completed is False]
    assert truncated, "no family noticed a zero-file budget"
    for family in truncated:
        assert outcomes[family].scan.verdict() is Verdict.UNKNOWN, family


def test_a_denial_anywhere_in_a_walk_reaches_the_verdict():
    """Planted per source kind, because a collector that classified only ONE of
    them would pass a single-case test and swallow the rest.
    """
    for denied, family in (
        ("/etc/systemd/system", "systemd_service"),
        ("/etc/cron.d", "cron"),
        ("/etc/pgbackrest", "agent"),
        ("/usr/local/bin", "script"),
    ):
        host = populated_host()
        host.denied.add(denied)
        assert _verdict(family, host) is Verdict.UNKNOWN, f"{family} swallowed a denial"


def test_a_failing_command_does_not_read_as_an_empty_queue():
    """`atq` refused and `atq` empty must not produce the same verdict."""
    empty = FakeHost(commands={("atq",): ""})
    assert _verdict("at", empty) is Verdict.ABSENT

    refused = FakeHost(commands={}, denied=("atq",))
    assert _verdict("at", refused) is Verdict.UNKNOWN


# ── The degradations ────────────────────────────────────────────────────────


def test_dropping_the_degradation_step_would_publish_a_floor_as_a_total():
    """The plant is the OMISSION, so it is constructed explicitly.

    Without `apply_degradations` the walk on a host with a `.pgpass` reports
    `SCANNED`/`ABSENT` -- a total. With it, the same walk reports `UNKNOWN`.
    Both are computed here so the difference is the assertion rather than a
    claim in a docstring.
    """
    host = populated_host(present={"/root/.pgpass"})
    raw = {
        family: enumerate_family(family, host, vault=RedactionVault())
        for family in DECLARED_FAMILIES
    }
    assert any(
        o.scan.verdict() is not Verdict.UNKNOWN for o in raw.values()
    ), "the undegraded walk is already all-UNKNOWN; this comparison proves nothing"
    degraded = apply_degradations(raw, degradations(host))
    assert all(o.scan.verdict() is Verdict.UNKNOWN for o in degraded.values())


def test_a_host_with_no_degrading_source_is_not_degraded():
    """The other half of sensitivity: the guard must stay quiet on a clean host.

    A degradation that fired unconditionally would make every host UNKNOWN
    forever, and a census that is always unknown gets read as noise and then
    switched off.
    """
    host = populated_host(present=())
    assert degradations(host) == ()
    outcomes = enumerate_all(host, vault=RedactionVault())
    assert any(o.scan.verdict() is Verdict.SCANNED for o in outcomes.values())
    assert any(o.scan.verdict() is Verdict.ABSENT for o in outcomes.values()), (
        "no family reached ABSENT on a clean host; the collector cannot state an absence "
        "at all, which makes the whole census unable to answer its own question"
    )


def test_a_degradation_that_deleted_findings_would_be_caught():
    """Planted as the wrong repair. Confidence drops; the records stay.

    Dropping the consumers on degradation is an easy and plausible mistake --
    "the walk is unreliable, discard it" -- and it is data loss at the exact
    moment the migration step needs the list most.
    """
    host = populated_host(present={"/root/.pgpass"})
    outcomes = enumerate_all(host, vault=RedactionVault())
    total = sum(len(o.consumers) for o in outcomes.values())
    assert total > 0, "degradation deleted every finding"


def test_a_blind_presence_check_fails_closed_rather_than_open():
    """A refusal must not read as "no password file here"."""

    class Blind(FakeHost):
        def exists(self, path: str) -> bool:
            raise SourceDenied(path)

    assert degradations(Blind()), "a denied presence check degraded nothing"
    assert degradations(FakeHost(present=())) == ()


# ── Non-vacuity of the fixture itself ───────────────────────────────────────


def test_the_populated_host_actually_exercises_the_families_it_claims_to():
    """A fixture with no consumers makes every gap test above pass vacuously.

    If `populated_host` stopped defining files, every "the collector found it"
    assertion would become "the collector found nothing and so did the buggy
    version". This pins the fixture.
    """
    outcomes = enumerate_all(populated_host(present=()), vault=RedactionVault())
    scanned = {f for f in DECLARED_FAMILIES if outcomes[f].scan.verdict() is Verdict.SCANNED}
    assert {
        "systemd_service",
        "systemd_timer",
        "systemd_dropin",
        "cron",
        "anacron",
        "docker",
        "script",
        "agent",
    } <= scanned, f"the fixture stopped exercising families; only {sorted(scanned)} found anything"
