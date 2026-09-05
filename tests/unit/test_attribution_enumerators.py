"""The enumerators feed the derivation honestly, or the derivation is worthless.

`derive_verdict` can only be as truthful as what it is handed. A collector that
returns `found=0, errors=(), completed=True` after being refused permission
produces a perfectly derived `ABSENT` from a lie, and every guard in
`attribution.py` passes it through. So these tests are about the INPUTS: that a
denial is an error, that a budget exhaustion is `completed=False`, that a
structurally unreadable family says so, and that a family that ran and found
nothing is distinguishable from a family nobody ran.

Everything runs against `tests/attribution_hosts.FakeHost`. No host, no daemon,
no container, no network -- which is possible only because `HostSource` is a
Protocol this repository declares and does not implement.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence

import pytest

from dotmac_observability.attribution import (
    DECLARED_FAMILIES,
    Custody,
    RedactionVault,
    Verdict,
    refuses_to_read,
)
from dotmac_observability.attribution_enumerators import (
    HOST_SOURCE_CONTRACT_VERSION,
    OBSERVATION_ERROR_CLASSES_V2,
    OBSERVATION_SCHEMA_VERSION_V2,
    Budget,
    FamilyOutcome,
    HostSource,
    SourceDenied,
    SourceTimeout,
    build_observation,
    custody_counts,
    degradations,
    enumerate_all,
    enumerate_family,
)
from tests.attribution_hosts import CRON_DSN, DOCKER_DSN, DROPIN_DSN, FakeHost, populated_host


def _all(
    host: HostSource,
    *,
    skip: Sequence[str] = (),
    principals: Sequence[str] = (),
    budget: Budget | None = None,
) -> dict[str, FamilyOutcome]:
    return enumerate_all(
        host, vault=RedactionVault(), skip=skip, principals=principals, budget=budget
    )


# ── Every family is present, every time ─────────────────────────────────────


def test_every_declared_family_gets_exactly_one_result():
    """A family missing from the output reads as a family with nothing in it.

    This is the merged envelope's central requirement, asserted at the source
    that produces the input rather than only at the projection that consumes
    it -- a collector that drops a family would otherwise fail late, with an
    error about the envelope rather than about the walk.
    """
    outcomes = _all(populated_host())
    assert set(outcomes) == set(DECLARED_FAMILIES)


def test_a_family_whose_enumerator_raises_still_appears_as_unknown():
    """The failure that would otherwise delete a family silently.

    A source that raises on everything must not produce a short document; it
    must produce eleven rows that all say UNKNOWN.
    """

    class Hostile:
        host_source_contract_version = HOST_SOURCE_CONTRACT_VERSION

        def exists(self, path: str) -> bool:
            raise SourceDenied(path)

        def list_dir(self, directory: str):
            raise SourceDenied(directory)

        def read_text(self, path: str) -> str:
            raise SourceDenied(path)

        def run(self, argv):
            raise SourceDenied("run")

    outcomes = enumerate_all(Hostile(), vault=RedactionVault())
    assert set(outcomes) == set(DECLARED_FAMILIES)
    for family, outcome in outcomes.items():
        assert outcome.scan.verdict() is Verdict.UNKNOWN, family


def test_the_two_families_the_first_design_missed_actually_find_things():
    """`systemd_dropin` and `anacron` are enumerated, not merely declared.

    Declaring a family and giving it an enumerator that always returns nothing
    would satisfy every completeness check in the merged battery while leaving
    exactly the gap those two families were added to close.
    """
    outcomes = _all(populated_host())
    assert outcomes["systemd_dropin"].scan.found == 1
    assert outcomes["anacron"].scan.found == 1
    assert outcomes["systemd_dropin"].scan.verdict() is Verdict.SCANNED
    assert outcomes["anacron"].scan.verdict() is Verdict.SCANNED


# ── Honesty about what the walk did ─────────────────────────────────────────


def test_a_denial_is_an_error_and_not_an_empty_result():
    """The whole point. A refused directory must not read as an empty one."""
    host = populated_host()
    host.denied.add("/etc/cron.d")
    outcome = enumerate_family("cron", host, vault=RedactionVault())
    assert "denied" in outcome.scan.errors
    assert outcome.scan.verdict() is Verdict.UNKNOWN


def test_a_timeout_is_classified_rather_than_swallowed():
    host = populated_host()
    host.timed_out.add("/etc/systemd/system")
    outcome = enumerate_family("systemd_service", host, vault=RedactionVault())
    assert "timeout" in outcome.scan.errors
    assert outcome.scan.verdict() is Verdict.UNKNOWN


def test_a_bounded_walk_that_hit_its_limit_is_incomplete_not_empty():
    """`completed=False`, which derives UNKNOWN however many were found.

    A budget is the mechanism that keeps this collector from hanging on a
    pathological host, and the cost of having one is that it must be visible
    when it bites. A truncated walk reporting a total is the worst outcome
    available: it is confident, wrong, and indistinguishable from a good run.
    """
    host = populated_host()
    outcome = enumerate_family(
        "systemd_service", host, vault=RedactionVault(), budget=Budget(max_files=0)
    )
    assert outcome.scan.completed is False
    assert outcome.scan.verdict() is Verdict.UNKNOWN


def test_a_byte_budget_also_reports_incompleteness():
    host = populated_host()
    outcome = enumerate_family(
        "systemd_service", host, vault=RedactionVault(), budget=Budget(max_bytes=1)
    )
    assert outcome.scan.completed is False


def test_a_family_that_ran_and_found_nothing_differs_from_one_nobody_ran():
    """`ABSENT` versus `UNKNOWN`, from the two inputs that produce them.

    The first cut of this module got this wrong in the reassuring direction --
    it set `attempted=False` when a family found no candidate FILES, so a host
    with no Compose projects reported UNKNOWN forever and a real absence could
    never be stated. `skip` is now the only thing that sets `attempted=False`.
    """
    outcomes = _all(populated_host(), skip=("at",))
    assert outcomes["at"].scan.attempted is False
    assert outcomes["at"].scan.verdict() is Verdict.UNKNOWN
    assert outcomes["compose"].scan.attempted is True
    assert outcomes["compose"].scan.verdict() is Verdict.ABSENT


def test_skipping_an_undeclared_family_is_refused():
    with pytest.raises(KeyError, match="kubernetes_cronjob"):
        _all(populated_host(), skip=("kubernetes_cronjob",))


def test_an_undeclared_family_name_raises_rather_than_returning_empty():
    with pytest.raises(KeyError, match="kubernetes_cronjob"):
        enumerate_family("kubernetes_cronjob", populated_host(), vault=RedactionVault())


def test_a_missing_named_file_is_a_complete_answer_and_a_missing_discovered_one_is_not():
    """The distinction that made `cron` report an error on every clean host.

    `/etc/crontab` not existing means this host has no `/etc/crontab` -- a real
    and complete answer. A file the walk LISTED and then could not read is a
    different event and stays an error, which is why the flag is per-call.
    """
    bare = FakeHost(files={}, commands={("atq",): ""})
    assert enumerate_family("cron", bare, vault=RedactionVault()).scan.errors == ()
    assert enumerate_family("cron", bare, vault=RedactionVault()).scan.verdict() is Verdict.ABSENT

    vanishing = FakeHost(files={"/etc/cron.d/job": "x"}, directories=("/etc/cron.d",))
    vanishing.files.clear()
    vanishing.directories = {"/etc/cron.d", "/etc/cron.d/job"}
    outcome = enumerate_family("cron", vanishing, vault=RedactionVault())
    assert outcome.scan.errors, "a discovered file that could not be read reported nothing"


def test_every_error_this_module_emits_is_in_the_contract_vocabulary():
    """A free-text reason on this path carries the DSN it failed to parse."""
    host = populated_host()
    host.denied.add("/etc/cron.d")
    host.timed_out.add("/etc/systemd/system")
    for outcome in _all(host).values():
        for error in outcome.scan.errors:
            assert error in OBSERVATION_ERROR_CLASSES_V2, error


# ── Custody ─────────────────────────────────────────────────────────────────


def test_a_dsn_in_a_shared_environment_file_is_unattributed():
    """Michael's bare `DATABASE_URL`, as the case that actually produces it.

    `/etc/environment` is read by every login shell and belongs to no unit,
    job or container. Naming the FILE as the owning unit would manufacture
    custody that does not exist and turn the finding into a reassuring
    `ATTRIBUTED` -- which is the one outcome that must not be available.
    """
    host = populated_host()
    host.files["/etc/environment"] = (
        "DATABASE_URL=postgresql://orphan:pw-orph@erp-db.invalid:5432/erpdb\n"
    )
    outcome = enumerate_family("script", host, vault=RedactionVault())
    orphans = [r for r in outcome.consumers if r.custody is Custody.UNATTRIBUTED]
    assert len(orphans) == 1
    assert orphans[0].owner_unit is None
    assert orphans[0].owner_principal is None


def test_a_unit_owned_consumer_is_attributed():
    outcome = enumerate_family("systemd_service", populated_host(), vault=RedactionVault())
    assert [r.custody for r in outcome.consumers] == [Custody.ATTRIBUTED]
    assert outcome.consumers[0].owner_unit == "erp-worker.service"
    assert outcome.consumers[0].owner_principal == "erpsvc"


def test_custody_counts_separate_the_two_readings():
    host = populated_host()
    host.files["/etc/environment"] = (
        "DATABASE_URL=postgresql://orphan:pw-orph@erp-db.invalid:5432/erpdb\n"
    )
    attributed, unattributed = custody_counts(_all(host))
    assert unattributed == 1
    assert attributed > 0, "a run with no attributed consumer would make the split meaningless"


# ── Containment ─────────────────────────────────────────────────────────────


def test_every_record_keeps_its_resolved_components_out_of_repr():
    outcome = enumerate_family("systemd_service", populated_host(), vault=RedactionVault())
    record = outcome.consumers[0]
    assert "erp-db.invalid" not in repr(record)
    assert "erpsvc" not in repr(record)
    assert "erpdb" not in repr(record)
    assert not hasattr(record, "password")
    hidden = {f.name for f in dataclasses.fields(record) if not f.repr}
    assert {"db_host", "db_port", "db_user", "db_name", "launch_path", "secret_pointer"} <= hidden


def test_the_walk_poisons_everything_it_read():
    """Poisoned on ARRIVAL, not on use.

    A value poisoned only when it reaches a record is unpoisoned for the
    duration of every parse in between, which is the window an exception
    escapes through.
    """
    vault = RedactionVault()
    enumerate_all(populated_host(), vault=vault)
    for value in ("erp-db.invalid", "pw-fixture", CRON_DSN, DROPIN_DSN, DOCKER_DSN):
        assert vault.contains(value), f"{value} was read and not poisoned"


def test_the_password_file_is_never_opened():
    """Checked against what the collector DID, not against what it returned.

    `.pgpass` is cleartext passwords. A collector that read it to attribute
    anything would have to hold a live password in memory to decide it is one,
    and it learns nothing the launch referencing it does not already say.
    """
    host = populated_host(present={"/root/.pgpass"})
    enumerate_all(host, vault=RedactionVault(), principals=("erpsvc",))
    opened = [path for path in host.read_paths if refuses_to_read(path)]
    assert opened == [], f"the collector opened {opened}"


# ── Degradation ─────────────────────────────────────────────────────────────


def test_a_password_file_degrades_every_family_rather_than_being_ignored():
    """Presence is the finding: some process can connect with no visible DSN.

    Severe on purpose. Every family becomes UNKNOWN because the file is
    readable by any process running as its owner, and that owner can launch
    from any family. Softening it would mean publishing a floor as a total.
    """
    host = populated_host(present={"/root/.pgpass"})
    outcomes = _all(host)
    for family, outcome in outcomes.items():
        assert "ambiguous" in outcome.scan.errors, family
        assert outcome.scan.verdict() is Verdict.UNKNOWN, family


def test_a_degradation_keeps_the_consumers_already_found():
    """Confidence in COMPLETENESS drops; what was seen was still seen.

    Dropping the records would turn a coverage caveat into data loss, and the
    records are exactly what the migration step needs.
    """
    host = populated_host(present={"/root/.pgpass"})
    outcomes = _all(host)
    assert outcomes["systemd_service"].consumers, "a degradation deleted real findings"


def test_a_source_that_cannot_answer_presence_fails_closed():
    """An unanswerable question about a credential file degrades coverage too.

    Failing open here would mean a host where `exists` is denied reports as a
    host with no password file, which is the reassuring reading of a refusal.
    """

    class Blind(FakeHost):
        def exists(self, path: str) -> bool:
            raise SourceDenied(path)

    found = degradations(Blind())
    assert found, "a denied presence check reported nothing to degrade"


def test_pgbouncer_and_pgservice_are_expressed_as_degradations():
    host = populated_host(
        present={"/etc/pgbouncer/pgbouncer.ini", "/etc/postgresql-common/pg_service.conf"}
    )
    reasons = " ".join(d.reason for d in degradations(host))
    assert "pooler" in reasons
    assert "PGSERVICE" in reasons


def test_a_ci_runner_reports_dynamic_rather_than_a_confident_zero():
    """A runner receives its DSN at job time; disk cannot hold it.

    Finding nothing in a runner's configuration is not evidence of anything, so
    the family must not be allowed to say `ABSENT` on that basis.
    """
    host = populated_host()
    host.files["/etc/gitlab-runner/config.toml"] = '[[runners]]\n  executor = "docker"\n'
    outcome = enumerate_family("ci_runner", host, vault=RedactionVault())
    assert "dynamic" in outcome.scan.errors
    assert outcome.scan.verdict() is Verdict.UNKNOWN


def test_a_script_that_talks_to_postgres_with_no_visible_dsn_is_dynamic():
    host = populated_host()
    host.files["/usr/local/bin/report"] = '#!/bin/sh\npsql "$CONNECTION" -c "select 1"\n'
    outcome = enumerate_family("script", host, vault=RedactionVault())
    assert "dynamic" in outcome.scan.errors


def test_pgservice_in_an_environment_is_ambiguous_not_a_clean_record():
    host = FakeHost(
        files={"/etc/systemd/system/svc.service": "[Service]\nEnvironment=PGSERVICE=erp\n"}
    )
    outcome = enumerate_family("systemd_service", host, vault=RedactionVault())
    assert "ambiguous" in outcome.scan.errors
    assert outcome.scan.found == 1, "the consumer was dropped instead of being flagged"


# ── Stopped containers ──────────────────────────────────────────────────────


def test_docker_enumerates_stopped_containers():
    """`docker ps -a`, never `docker ps`.

    A stopped container is a configured consumer: its environment still holds
    the DSN, it starts again on reboot, and its credential is still valid.
    Dropping it is the liveness downgrade the derivation refuses one level up,
    arriving through the collector instead.
    """
    host = populated_host()
    enumerate_family("docker", host, vault=RedactionVault())
    listings = [argv for argv in host.ran if argv[:2] == ("docker", "ps")]
    assert listings, "docker was never listed"
    for argv in listings:
        assert "-a" in argv, "stopped containers were excluded from the census"


def test_compose_reads_projects_from_disk_rather_than_a_running_daemon():
    host = populated_host()
    host.files["/etc/docker/compose/erp/docker-compose.yml"] = (
        f"services:\n  api:\n    environment:\n      DATABASE_URL: {DOCKER_DSN}\n"
    )
    outcome = enumerate_family("compose", host, vault=RedactionVault())
    assert outcome.scan.found == 1
    assert outcome.consumers[0].owner_unit == "erp"


# ── The private document ────────────────────────────────────────────────────


def test_the_observation_carries_every_family_and_refuses_a_short_one():
    outcomes = _all(populated_host())
    document = build_observation(
        outcomes,
        target_id="erp-production",
        observed_at="2026-09-05T09:00:00Z",
        host_identity_digest="sha256:" + "ab" * 32,
        collector_artifact_digest="sha256:" + "cd" * 32,
        source_artifact_digest="sha256:" + "ef" * 32,
    )
    assert document["schema_version"] == OBSERVATION_SCHEMA_VERSION_V2
    families = document["families"]
    assert isinstance(families, list)
    assert [entry["family"] for entry in families] == list(DECLARED_FAMILIES)
    short = dict(outcomes)
    del short["anacron"]
    with pytest.raises(ValueError, match="anacron"):
        build_observation(
            short,
            target_id="erp-production",
            observed_at="2026-09-05T09:00:00Z",
            host_identity_digest="sha256:" + "ab" * 32,
            collector_artifact_digest="sha256:" + "cd" * 32,
            source_artifact_digest="sha256:" + "ef" * 32,
        )


def test_the_seam_is_a_protocol_this_repository_does_not_implement():
    """The same arrangement as `promote.PromotionFacility`, and for one reason.

    A control plane that grew its own transport becomes a second answer to how
    a host is touched. It is also what makes every test in this file possible
    with no host at all.
    """
    assert getattr(HostSource, "_is_protocol", False), "the seam stopped being a Protocol"
    assert HOST_SOURCE_CONTRACT_VERSION
    for method in ("exists", "list_dir", "read_text", "run"):
        assert hasattr(HostSource, method), method
    with pytest.raises(TypeError):
        HostSource()  # type: ignore[misc]


def test_a_timeout_class_maps_to_the_contract_vocabulary():
    assert SourceTimeout.error_class in OBSERVATION_ERROR_CLASSES_V2
    assert SourceDenied.error_class == "denied"
