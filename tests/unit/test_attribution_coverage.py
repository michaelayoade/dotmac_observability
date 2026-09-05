"""A verdict is DERIVED. `ABSENT` is not a value anybody gets to type.

The failure this file exists to make impossible is quiet and one-directional. A
census that reports "nothing on this host references the database" is acted on:
somebody decommissions, rotates or firewalls. If a denied `sudo`, an unparsable
unit file or a scan that hit its bound can produce that same sentence, the
census is not merely incomplete -- it is confidently wrong in the direction that
causes an outage.

So the truth table below is exhaustive rather than illustrative, and `ABSENT` is
asserted to be reachable through exactly ONE of its sixteen rows.
"""

from __future__ import annotations

import dataclasses
import inspect
import itertools

import pytest

from dotmac_observability.attribution import (
    DECLARED_FAMILIES,
    Custody,
    FamilyScan,
    Verdict,
    derive_custody,
    derive_verdict,
    refuses_to_read,
)


def test_absent_has_exactly_one_reachable_path():
    """Exhaustive over the whole input space, not a handful of examples.

    Sixteen rows, one `ABSENT`. Any change that widens the path -- dropping the
    `completed` branch, treating an empty error tuple as "no errors seen yet",
    reordering the branches so `found == 0` is checked first -- adds a second
    row and fails here with the row named.
    """
    absent_rows = []
    for attempted, completed, errors, found in itertools.product((False, True), repeat=4):
        verdict = derive_verdict(
            attempted=attempted, completed=completed, errors=int(errors), found=int(found)
        )
        if verdict is Verdict.ABSENT:
            absent_rows.append((attempted, completed, errors, found))
    assert absent_rows == [(True, True, False, False)], (
        "ABSENT became reachable through additional paths; a scan that was denied, "
        "unfinished or errored now reports as a clean host"
    )


def test_every_failure_shape_is_the_same_verdict():
    """Denial, parse failure, bound, never-ran: all UNKNOWN, all indistinguishable.

    They are the same epistemic state -- we do not know -- and giving any of
    them a more reassuring spelling is how a partial census gets read as a
    complete one.
    """
    assert derive_verdict(attempted=False, completed=False, errors=0, found=0) is Verdict.UNKNOWN
    assert derive_verdict(attempted=True, completed=True, errors=1, found=0) is Verdict.UNKNOWN
    assert derive_verdict(attempted=True, completed=False, errors=0, found=0) is Verdict.UNKNOWN
    # The nastiest row: a scan that found something AND errored. It is UNKNOWN,
    # not SCANNED, because the count is a floor rather than a total.
    assert derive_verdict(attempted=True, completed=True, errors=2, found=5) is Verdict.UNKNOWN


def test_a_scan_cannot_carry_a_verdict_it_disagrees_with():
    """`FamilyScan` stores evidence and no verdict field.

    A stored verdict alongside its evidence is two copies of one fact, and the
    copy that gets published is always the stale one. `verdict()` recomputes.
    """
    names = {f.name for f in dataclasses.fields(FamilyScan)}
    assert "verdict" not in names
    assert names == {"family", "attempted", "completed", "errors", "found", "evidence"}
    scan = FamilyScan(family="cron", attempted=True, completed=True, errors=(), found=0)
    assert scan.verdict() is Verdict.ABSENT
    assert dataclasses.replace(scan, errors=("denied",)).verdict() is Verdict.UNKNOWN


def test_liveness_cannot_downgrade_a_configured_consumer():
    """Reachability is a different question and is not an input to either derivation.

    The tempting shortcut is to mark a consumer absent because the database
    refused the connection. That deletes a real, configured, credential-holding
    consumer from the census on the strength of a firewall rule, and it is the
    exact opposite of what a decommissioning decision needs. Neither derivation
    accepts a liveness signal, so the shortcut has nowhere to be taken.
    """
    forbidden = {"alive", "live", "liveness", "reachable", "reachability", "connected", "up"}
    for function in (derive_verdict, derive_custody):
        parameters = set(inspect.signature(function).parameters)
        assert not (parameters & forbidden), (
            f"{function.__name__} accepts a liveness signal; a consumer that is configured "
            "is configured whether or not the database answers today"
        )
    # And behaviourally: a family that found two consumers reports two, with no
    # channel by which an unreachable database could reduce that to zero.
    found = FamilyScan(family="docker", attempted=True, completed=True, errors=(), found=2)
    assert found.verdict() is Verdict.SCANNED
    assert found.found == 2


@pytest.mark.parametrize(
    ("unit", "principal", "expected"),
    [
        ("erp-worker.service", None, Custody.ATTRIBUTED),
        (None, "erpsvc", Custody.ATTRIBUTED),
        ("erp-worker.service", "erpsvc", Custody.ATTRIBUTED),
        (None, None, Custody.UNATTRIBUTED),
        ("", "", Custody.UNATTRIBUTED),
    ],
)
def test_custody_needs_someone_who_can_be_asked(unit, principal, expected):
    assert derive_custody(owner_unit=unit, owner_principal=principal) is expected


def test_a_bare_database_url_is_unattributed_rather_than_clean():
    """Michael's rule, as the assertion it becomes.

    A `DATABASE_URL` sitting in an environment with no owning unit, job,
    container or principal is a live connection nobody is answerable for. It is
    the finding, not the absence of one -- and the failure mode being closed
    here is a census that silently drops it because it could not name an owner.
    """
    verdict = derive_custody(owner_unit=None, owner_principal=None)
    assert verdict is Custody.UNATTRIBUTED
    assert verdict.value == "UNATTRIBUTED"
    assert set(Custody) == {Custody.ATTRIBUTED, Custody.UNATTRIBUTED}, (
        "a third custody value would let 'we could not tell' hide between the two "
        "that a reader acts on"
    )


def test_the_password_file_is_never_parsed_and_the_near_miss_still_is():
    """`.pgpass` is cleartext passwords; reading it to attribute anything is absurd.

    The near-miss is the half that proves the guard is a guard rather than a
    keyword sweep: `pg_hba.conf` names authentication METHODS, carries no
    secret, and a collector that needs it must still be allowed to read it.
    """
    for refused in ("/home/erpsvc/.pgpass", "/root/.pgpass", "/opt/app/pgpass.conf"):
        assert refuses_to_read(refused), f"{refused} must never be opened"
    for permitted in (
        "/etc/postgresql/16/main/pg_hba.conf",
        "/etc/systemd/system/erp-worker.service",
        "/opt/app/pgpass.conf.example",
    ):
        assert not refuses_to_read(permitted), (
            f"{permitted} is refused; the guard has widened into a keyword sweep and will "
            "be switched off the first time it blocks a real scan"
        )


def test_the_declared_families_include_the_two_the_first_design_missed():
    """A family nobody enumerated reads as a family with nothing in it.

    `systemd_dropin` and `anacron` are both real launch paths on these hosts,
    and the first version of this design had neither. A host whose only
    consumer launches from a drop-in would have filed as clean.
    """
    assert "systemd_dropin" in DECLARED_FAMILIES
    assert "anacron" in DECLARED_FAMILIES
    assert len(set(DECLARED_FAMILIES)) == len(DECLARED_FAMILIES), "a family is declared twice"
