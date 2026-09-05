"""Where a Postgres consumer can be launched from, family by family, honestly.

`attribution.py` owns the DERIVATION -- `ABSENT` reachable through one path,
`UNATTRIBUTED` as the fourth verdict, the vault, the closed envelope. This
module owns the ENUMERATION that feeds it, and its whole job is to feed it
truthfully: a denial is an error, an unrecognized launch form is an error, a
walk that hit its budget is `completed=False`. A partial walk must never report
zero, because zero is the number somebody decommissions on.

**It reaches nothing.** :class:`HostSource` is a Protocol this repository
DECLARES and does not implement, exactly as `promote.PromotionFacility` is --
the mechanics of reaching a host belong elsewhere (`docs/ARCHITECTURE.md`,
"Ownership"), and a control plane that grew its own transport becomes a second
answer to how a host is touched. That split is also what makes every family
here testable against a recording double with no host, no daemon and no
container, which is the only reason a census this invasive can be reviewed at
all.

A concrete source has to satisfy four methods and nothing else: :meth:`exists`,
:meth:`list_dir`, :meth:`read_text` and :meth:`run`. Each may raise
:class:`SourceDenied`, :class:`SourceMissing`, :class:`SourceTimeout` or
:class:`SourceUnsupported`, and every one of those is classified into the
observation's error vocabulary rather than swallowed. Nothing else about the
implementation is this module's business -- and nothing it returns is ever
printed, because everything it returns is poisoned on arrival.

**The residual gaps are expressed, never omitted.** A `.pgpass` on the host
means some local process can authenticate with no DSN any reader can see; a
pgbouncer masks its own clients, which may not even be on this host; a CI
runner injects its DSN at job time, so the runner's configuration on disk
cannot contain it; `PGSERVICE` resolves connection parameters through a file
the launch does not name; a script invoked through a variable has no resolvable
path; and a stopped container is a configured consumer whose configuration is
still on the host. Each of those is a coverage-degrading FACT that lands as a
classified error on the families it degrades -- and, because an error derives
`UNKNOWN` regardless of the count, it correctly stops those families claiming a
number as a total. None of them is ever a silence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Final, Protocol

from .attribution import (
    DECLARED_FAMILIES,
    Custody,
    FamilyScan,
    RedactionVault,
    derive_custody,
    safe_error,
)

__all__ = [
    "DEGRADING_SOURCES",
    "ERROR_CLASSES",
    "Budget",
    "ConsumerRecord",
    "Degradation",
    "FamilyOutcome",
    "HostSource",
    "SourceDenied",
    "SourceError",
    "SourceMissing",
    "SourceTimeout",
    "SourceUnsupported",
    "apply_degradations",
    "build_observation",
    "classify",
    "custody_counts",
    "degradations",
    "enumerate_all",
    "enumerate_family",
]

# The observation contract's `errors` vocabulary, and nothing outside it. A
# free-text reason on this path carries the DSN it failed to parse, which is
# the leak the error path is famous for.
ERROR_CLASSES: Final[tuple[str, ...]] = (
    "denied",
    "parse",
    "syntax",
    "ambiguous",
    "dynamic",
    "timeout",
    "unsupported",
)


# ── The seam ────────────────────────────────────────────────────────────────


class SourceError(Exception):
    """Base for every way a host read can fail. Carries a CLASS, never a value.

    A source implementation raises these instead of returning an error string,
    because a string is what gets logged and a class is what gets counted.
    """

    error_class = "unsupported"


class SourceDenied(SourceError):
    """Permission refused. NOT an empty result -- the difference is the point."""

    error_class = "denied"


class SourceMissing(SourceError):
    """The path or program is not there. A genuine absence, not a refusal."""

    error_class = "unsupported"


class SourceTimeout(SourceError):
    error_class = "timeout"


class SourceUnsupported(SourceError):
    """The host cannot answer this question at all -- no `docker`, no `atq`."""

    error_class = "unsupported"


def classify(error: BaseException) -> str:
    """Map any failure onto the contract's error vocabulary.

    The default is `parse` rather than `unsupported` for anything that is not a
    :class:`SourceError`: an unexpected exception mid-read is a failure to
    UNDERSTAND the host, and calling it "unsupported" would quietly reclassify
    a bug as a host limitation. The exception itself is reduced to a type name
    by the caller; nothing of it reaches the observation.
    """
    if isinstance(error, SourceError):
        return error.error_class
    return "parse"


class HostSource(Protocol):
    """Four methods. Declared here, implemented elsewhere (see the docstring).

    Every return value is treated as poisoned the instant it arrives: unit
    text, container inspection output, environment files and crontabs all carry
    connection strings, and a source that returned something safe would be the
    exception rather than the rule.
    """

    def exists(self, path: str) -> bool:
        """Whether ``path`` is present. Presence alone is sometimes the finding."""
        ...

    def list_dir(self, directory: str) -> Sequence[str]:
        """Absolute paths directly under ``directory``. Not recursive."""
        ...

    def read_text(self, path: str) -> str:
        """The file's contents. Poisoned by the caller before anything else."""
        ...

    def run(self, argv: Sequence[str]) -> str:
        """Standard output of a read-only program. Never a shell string.

        A list rather than a string so no implementation is tempted to
        interpolate a path into a shell command -- and so a reviewer can see
        that every argument this module passes is a literal.
        """
        ...


@dataclass(frozen=True)
class Budget:
    """A bounded scan. Exhausting a bound means `completed=False`, not zero.

    The numbers are knobs with documented defaults (AGENTS.md rule 14) and are
    deliberately generous: a budget tight enough to bite on a normal host would
    make `UNKNOWN` the usual answer, and a census that is usually unknown gets
    read as noise.
    """

    max_files: int = 4000
    max_bytes: int = 8_000_000
    max_entries: int = 2000


@dataclass
class _Ledger:
    """Mutable accounting for one family's walk. Never leaves this module."""

    files: int = 0
    read_bytes: int = 0
    entries: int = 0
    errors: list[str] = field(default_factory=list)
    exhausted: bool = False

    def note(self, error_class: str) -> None:
        if error_class not in ERROR_CLASSES:  # pragma: no cover - guarded by tests
            raise ValueError(f"{error_class!r} is not in the observation's error vocabulary")
        self.errors.append(error_class)

    def spend_file(self, budget: Budget) -> bool:
        self.files += 1
        if self.files > budget.max_files:
            self.exhausted = True
            return False
        return True

    def spend_bytes(self, size: int, budget: Budget) -> bool:
        self.read_bytes += size
        if self.read_bytes > budget.max_bytes:
            self.exhausted = True
            return False
        return True


# ── What a walk produces ────────────────────────────────────────────────────


@dataclass(frozen=True)
class ConsumerRecord:
    """One configured consumer. Every resolved component is `repr=False`.

    This is the PRIVATE side: an instance of it belongs in a
    `postgres-consumer-attribution-observation` document held in an approved
    private store, and never in Git or on stdout. There is no password field,
    here or in the contract -- the value is poisoned and dropped at parse time.
    """

    family: str
    custody: Custody
    owner_unit: str | None = field(repr=False, default=None)
    owner_principal: str | None = field(repr=False, default=None)
    launch_path: str | None = field(repr=False, default=None)
    db_host: str | None = field(repr=False, default=None)
    db_port: int | None = field(repr=False, default=None)
    db_user: str | None = field(repr=False, default=None)
    db_name: str | None = field(repr=False, default=None)
    secret_pointer: str | None = field(repr=False, default=None)


@dataclass(frozen=True)
class FamilyOutcome:
    """One family's scan and the consumers it contributed."""

    scan: FamilyScan
    consumers: tuple[ConsumerRecord, ...] = ()


@dataclass(frozen=True)
class Degradation:
    """A fact that makes a count a floor rather than a total.

    It carries the families it degrades and a classification -- never a path,
    never a principal, never a value. `.pgpass` under one user's home is
    reported as "a password file exists", because the home directory is a
    username and a username is resolved material (AGENTS.md rule 18).
    """

    reason: str
    error_class: str
    families: tuple[str, ...]


# ── Parsing ─────────────────────────────────────────────────────────────────
#
# All of this runs over text the source handed back, in memory. Nothing here
# opens anything, and nothing here is ever formatted into a message.

_DSN = re.compile(r"\bpostgres(?:ql)?://[^\s\"'<>`]+")
# Connection parameters supplied piecemeal rather than as a URL. `PGPASSWORD`
# is matched so its VALUE can be poisoned; it is never stored, and the
# contract has no field it could be stored in.
_PG_ENV = re.compile(
    r"\b(DATABASE_URL|PG(?:HOST|PORT|USER|DATABASE|PASSWORD|PASSFILE|SERVICE|SERVICEFILE)"
    r"|POSTGRES_(?:HOST|PORT|USER|DB|DSN))\s*=\s*[\"']?([^\s\"']*)"
)
_ENVIRONMENT_FILE = re.compile(r"^EnvironmentFile\s*=\s*-?(\S+)", re.MULTILINE)
_UNIT_USER = re.compile(r"^User\s*=\s*(\S+)", re.MULTILINE)
_UNIT_EXEC = re.compile(r"^ExecStart\s*=\s*(\S+)", re.MULTILINE)
_CRON_LINE = re.compile(r"^\s*(?:[-@*0-9][^\n]*?)\s+(\S+)\s*$")
# A launch whose program is a variable cannot be resolved statically. This is
# the `dynamic` classification's trigger, not a curiosity.
_UNRESOLVED_INVOCATION = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")

# Paths whose mere PRESENCE degrades coverage, and what they degrade. Declared
# in one place so the policy is arguable in review rather than scattered
# through eleven enumerators.
DEGRADING_SOURCES: Final[tuple[tuple[str, str, str], ...]] = (
    # A `.pgpass` means a local process can authenticate with NO DSN a reader
    # can see. It does not hide the launch, it hides the connection -- so a
    # family that found nothing cannot claim it found everything. Every family
    # is degraded because a `.pgpass` is readable by any process running as its
    # owner, and its owner can launch from any of them. This is severe on
    # purpose: the remedy is to remove the file, which is also the right
    # security outcome, and softening it would mean publishing a total that is
    # actually a floor.
    (
        "/root/.pgpass",
        "a password file lets a local process connect with no visible DSN",
        "ambiguous",
    ),
    (
        "/etc/pgbouncer/pgbouncer.ini",
        "a connection pooler masks its own clients, which may not be on this host",
        "ambiguous",
    ),
    (
        "/etc/postgresql-common/pg_service.conf",
        "PGSERVICE resolves connection parameters through a file the launch does not name",
        "ambiguous",
    ),
)


def _poison_all(text: str, vault: RedactionVault) -> None:
    """Poison every connection-shaped thing in ``text`` before anything reads it.

    Called on arrival rather than on use. A value poisoned only when it reaches
    a record is a value that was unpoisoned for the duration of every parse in
    between, which is exactly the window an exception would escape through.
    """
    vault.poison(text)
    for match in _DSN.finditer(text):
        vault.poison(match.group(0))
    for match in _PG_ENV.finditer(text):
        vault.poison(match.group(2))


_Components = tuple[str | None, int | None, str | None, str | None]


def _components(dsn: str, vault: RedactionVault) -> _Components:
    """Host, port, user and database from a DSN. The password is dropped.

    Failure returns all-``None`` rather than raising: an unparsable DSN is
    still EVIDENCE that a consumer exists, and losing the consumer because its
    connection string was malformed would be the census undercounting for the
    most trivial possible reason. The caller records a `parse` error alongside.
    """
    from urllib.parse import unquote, urlsplit

    try:
        split = urlsplit(dsn)
        vault.poison(split.password)
        host = split.hostname or None
        port = split.port
        user = unquote(split.username) if split.username else None
        database = unquote(split.path.lstrip("/")) or None
    except BaseException:
        # Deliberately swallowed to a None-tuple, and deliberately NOT
        # re-raised with the DSN in the message: `str(exc)` on a URL failure
        # quotes the URL. The caller notes a `parse` error.
        return (None, None, None, None)
    for component in (host, user, database):
        vault.poison(component)
    return (host, port, user, database)


def _consumers_in(
    text: str,
    *,
    family: str,
    owner_unit: str | None,
    owner_principal: str | None,
    launch_path: str | None,
    vault: RedactionVault,
    ledger: _Ledger,
) -> list[ConsumerRecord]:
    """Every consumer visible in one blob of configuration.

    Two shapes are recognized and both count. A DSN is the obvious one. A set
    of `PG*`/`POSTGRES_*` variables is the one that is easy to miss and easy to
    dismiss as "not really a connection string" -- it is exactly a connection
    string, assembled by libpq instead of by the author.
    """
    _poison_all(text, vault)
    records: list[ConsumerRecord] = []
    custody = derive_custody(owner_unit=owner_unit, owner_principal=owner_principal)

    for match in _DSN.finditer(text):
        host, port, user, database = _components(match.group(0), vault)
        if host is None and user is None and database is None:
            ledger.note("parse")
        records.append(
            ConsumerRecord(
                family=family,
                custody=custody,
                owner_unit=owner_unit,
                owner_principal=owner_principal,
                launch_path=launch_path,
                db_host=host,
                db_port=port,
                db_user=user,
                db_name=database,
            )
        )

    piecemeal = {match.group(1): match.group(2) for match in _PG_ENV.finditer(text)}
    if piecemeal and not records:
        if "PGSERVICE" in piecemeal or "PGSERVICEFILE" in piecemeal:
            # The connection parameters live in a file this launch does not
            # name. We know a consumer exists and cannot say what it connects
            # to, which is `ambiguous` and must not be silently dropped.
            ledger.note("ambiguous")
        port_text = piecemeal.get("PGPORT", "")
        records.append(
            ConsumerRecord(
                family=family,
                custody=custody,
                owner_unit=owner_unit,
                owner_principal=owner_principal,
                launch_path=launch_path,
                db_host=piecemeal.get("PGHOST") or piecemeal.get("POSTGRES_HOST"),
                db_port=int(port_text) if port_text.isdigit() else None,
                db_user=piecemeal.get("PGUSER") or piecemeal.get("POSTGRES_USER"),
                db_name=piecemeal.get("PGDATABASE") or piecemeal.get("POSTGRES_DB"),
                secret_pointer=piecemeal.get("PGPASSFILE"),
            )
        )

    ledger.entries += len(records)
    return records


# ── Reading, with every failure classified ──────────────────────────────────


def _read(
    source: HostSource,
    path: str,
    *,
    vault: RedactionVault,
    ledger: _Ledger,
    budget: Budget,
    optional: bool = False,
) -> str | None:
    """Read one file, spending budget and classifying every failure.

    Returns ``None`` on any failure OR on budget exhaustion, and the two are
    distinguished in the ledger rather than by the return value -- an
    exhausted walk sets `exhausted`, which becomes `completed=False`, while a
    denial appends `denied`, which becomes an error. Collapsing them would let
    a walk that ran out of budget look like a walk that was refused, and both
    would look like a walk that found nothing.
    """
    if not ledger.spend_file(budget):
        return None
    try:
        text = source.read_text(path)
    except SourceMissing:
        if optional:
            # A NAMED path that is not there is a complete answer: this host has
            # no `/etc/crontab`. A path the walk DISCOVERED and then could not
            # read is a different thing and is still an error, which is why this
            # is a per-call flag rather than a blanket rule for SourceMissing.
            return None
        ledger.note("unsupported")
        return None
    except BaseException as error:
        ledger.note(classify(error))
        # `safe_error` is called for its discipline, not its value: the type
        # name is discarded here so that nothing at all from the exception can
        # reach the observation. The call documents that the value was never
        # available to be leaked rather than merely unused.
        _ = safe_error(error)
        return None
    if not ledger.spend_bytes(len(text), budget):
        return None
    vault.poison(text)
    return text


def _list(source: HostSource, directory: str, *, ledger: _Ledger, budget: Budget) -> list[str]:
    """List one directory, classifying failure. A missing directory is not an error.

    `SourceMissing` is swallowed deliberately and it is the only one that is:
    `/etc/cron.d` not existing means this host has no `cron.d`, which is a real
    and complete answer. A DENIED `/etc/cron.d` means the opposite and is
    recorded, because the two present identically to a naive reader.
    """
    try:
        entries = list(source.list_dir(directory))
    except SourceMissing:
        return []
    except BaseException as error:
        ledger.note(classify(error))
        return []
    if len(entries) > budget.max_entries:
        ledger.exhausted = True
        return entries[: budget.max_entries]
    return entries


def _run(
    source: HostSource, argv: Sequence[str], *, vault: RedactionVault, ledger: _Ledger
) -> str | None:
    try:
        output = source.run(argv)
    except BaseException as error:
        ledger.note(classify(error))
        return None
    vault.poison(output)
    return output


def _outcome(
    family: str, ledger: _Ledger, consumers: Sequence[ConsumerRecord], *, attempted: bool = True
) -> FamilyOutcome:
    """Assemble the scan. The verdict is NOT computed here -- `FamilyScan` derives it.

    `attempted` means the walk RAN, not that it found a file to read. Spelling
    it as "we found at least one candidate" was a real defect in the first cut
    of this module: a host with no Compose projects reported `attempted=False`,
    which derives UNKNOWN, so "this host runs no Compose" was indistinguishable
    from "nobody looked". The only thing that sets it False is an operator
    explicitly skipping the family, which is a fact worth reporting as UNKNOWN.

    `completed` is the negation of exhaustion and nothing else. Writing it as
    "we got to the end of the loop" would make a walk that broke out early on
    its budget indistinguishable from one that finished.
    """
    return FamilyOutcome(
        scan=FamilyScan(
            family=family,
            attempted=attempted,
            completed=not ledger.exhausted,
            errors=tuple(ledger.errors),
            found=len(consumers),
        ),
        consumers=tuple(consumers),
    )


# ── The eleven families ─────────────────────────────────────────────────────
#
# Each takes the same arguments and returns the same shape, so `enumerate_all`
# needs no per-family special case and a reader can compare them side by side.
# Where a family is STRUCTURALLY limited, the limit is a classified error in
# that family's own walk rather than a caveat in a document nobody reads.

_UNIT_DIRS: Final = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")
_CRON_FILES: Final = ("/etc/crontab",)
_CRON_DIRS: Final = ("/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron")
_ANACRON_FILES: Final = ("/etc/anacrontab",)
_ANACRON_DIRS: Final = ("/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")
_COMPOSE_DIRS: Final = ("/etc/docker/compose", "/opt/compose", "/srv/compose")
_SCRIPT_DIRS: Final = ("/usr/local/bin", "/usr/local/sbin", "/opt/bin")
# Shared environment, inherited by login shells and anything they launch. A DSN
# here belongs to NO unit, job or container -- which is exactly Michael's bare
# `DATABASE_URL` with no attributable custody, and it derives UNATTRIBUTED
# rather than being dropped for having no owner to name. It sits in the
# `script` family because operator-invoked and shell-inherited launches are
# what that family covers; it is emphatically not a systemd source, because
# systemd does not read these files for services.
_SHARED_ENVIRONMENT: Final = ("/etc/environment", "/etc/profile")
_AGENT_DIRS: Final = ("/etc/pgbackrest", "/etc/barman.d", "/etc/prometheus/exporters")
_CI_RUNNER_PATHS: Final = ("/etc/gitlab-runner/config.toml", "/etc/actions-runner/.env")


def _units(
    source: HostSource,
    *,
    suffix: str,
    family: str,
    vault: RedactionVault,
    budget: Budget,
) -> FamilyOutcome:
    """Units of one suffix across every unit directory, plus their env files."""
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    for directory in _UNIT_DIRS:
        for path in _list(source, directory, ledger=ledger, budget=budget):
            if not path.endswith(suffix):
                continue
            text = _read(source, path, vault=vault, ledger=ledger, budget=budget)
            if text is None:
                continue
            unit = path.rsplit("/", 1)[-1]
            principal = _first(_UNIT_USER, text)
            consumers.extend(
                _consumers_in(
                    text,
                    family=family,
                    owner_unit=unit,
                    owner_principal=principal,
                    launch_path=path,
                    vault=vault,
                    ledger=ledger,
                )
            )
            for referenced in _ENVIRONMENT_FILE.findall(text):
                environment = _read(source, referenced, vault=vault, ledger=ledger, budget=budget)
                if environment is None:
                    continue
                consumers.extend(
                    _consumers_in(
                        environment,
                        family=family,
                        owner_unit=unit,
                        owner_principal=principal,
                        launch_path=referenced,
                        vault=vault,
                        ledger=ledger,
                    )
                )
            exec_start = _first(_UNIT_EXEC, text)
            if exec_start and _UNRESOLVED_INVOCATION.search(exec_start):
                # The program is named by a variable. Whatever it connects to
                # cannot be read from this file, and pretending otherwise is
                # how a real consumer becomes an absence.
                ledger.note("dynamic")
    return _outcome(family, ledger, consumers)


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match else None


def _systemd_service(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    return _units(source, suffix=".service", family="systemd_service", vault=vault, budget=budget)


def _systemd_timer(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    return _units(source, suffix=".timer", family="systemd_timer", vault=vault, budget=budget)


def _systemd_dropin(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """`*.service.d/*.conf` and `*.timer.d/*.conf`.

    The family the first design omitted. A drop-in can add an `Environment=` or
    replace an `ExecStart=` without touching the unit, so a host whose only
    consumer is configured this way reads as clean to any scan that stops at
    `*.service` -- which is every obvious implementation.
    """
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    for directory in _UNIT_DIRS:
        for entry in _list(source, directory, ledger=ledger, budget=budget):
            if not entry.endswith((".service.d", ".timer.d")):
                continue
            unit = entry.rsplit("/", 1)[-1].removesuffix(".d")
            for path in _list(source, entry, ledger=ledger, budget=budget):
                if not path.endswith(".conf"):
                    continue
                text = _read(source, path, vault=vault, ledger=ledger, budget=budget)
                if text is None:
                    continue
                consumers.extend(
                    _consumers_in(
                        text,
                        family="systemd_dropin",
                        owner_unit=unit,
                        owner_principal=_first(_UNIT_USER, text),
                        launch_path=path,
                        vault=vault,
                        ledger=ledger,
                    )
                )
    return _outcome("systemd_dropin", ledger, consumers)


def _tabular(
    source: HostSource,
    *,
    files: Sequence[str],
    directories: Sequence[str],
    family: str,
    vault: RedactionVault,
    budget: Budget,
) -> FamilyOutcome:
    """Crontab-shaped families: named files plus every entry in some directories.

    A crontab in `/var/spool/cron/crontabs` is owned by the user it is named
    after, which is the only attribution available for it -- and it is real
    attribution, so those entries are `ATTRIBUTED` rather than orphaned.
    """
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    named = set(files)
    paths = list(files)
    for directory in directories:
        paths.extend(_list(source, directory, ledger=ledger, budget=budget))
    for path in paths:
        name = path.rsplit("/", 1)[-1]
        if name.endswith((".dpkg-old", ".dpkg-dist", ".rpmsave", "~")):
            continue
        text = _read(
            source, path, vault=vault, ledger=ledger, budget=budget, optional=path in named
        )
        if text is None:
            continue
        spooled = "/cron" in path and "/spool/" in path
        consumers.extend(
            _consumers_in(
                text,
                family=family,
                owner_unit=name,
                owner_principal=name if spooled else None,
                launch_path=path,
                vault=vault,
                ledger=ledger,
            )
        )
        for line in text.splitlines():
            match = _CRON_LINE.match(line)
            if match and _UNRESOLVED_INVOCATION.search(match.group(1)):
                ledger.note("dynamic")
    return _outcome(family, ledger, consumers)


def _cron(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    return _tabular(
        source,
        files=_CRON_FILES,
        directories=_CRON_DIRS,
        family="cron",
        vault=vault,
        budget=budget,
    )


def _anacron(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """`/etc/anacrontab` and the period directories it drives.

    The other family the first design omitted, and the one most likely to hold
    a nightly database job on a machine that is not always on -- which is
    precisely the machine whose consumers nobody remembers.
    """
    return _tabular(
        source,
        files=_ANACRON_FILES,
        directories=_ANACRON_DIRS,
        family="anacron",
        vault=vault,
        budget=budget,
    )


def _at(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """Queued `at` jobs, read through `atq` and `at -c`.

    Every job is read individually because `at -c` is the only way to see the
    command, and the queue is bounded by the same budget as a directory walk --
    a host with ten thousand queued jobs exhausts the budget and says so.
    """
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    queue = _run(source, ("atq",), vault=vault, ledger=ledger)
    if queue is None:
        return _outcome("at", ledger, consumers)
    for line in queue.splitlines():
        job = line.split("\t", 1)[0].strip().split(" ", 1)[0]
        if not job.isdigit():
            continue
        if not ledger.spend_file(budget):
            break
        text = _run(source, ("at", "-c", job), vault=vault, ledger=ledger)
        if text is None:
            continue
        consumers.extend(
            _consumers_in(
                text,
                family="at",
                owner_unit=f"at:{job}",
                owner_principal=None,
                launch_path=None,
                vault=vault,
                ledger=ledger,
            )
        )
    return _outcome("at", ledger, consumers)


def _docker(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """Every container, INCLUDING stopped ones.

    `docker ps -a`, never `docker ps`. A stopped container is a configured
    consumer: its environment still holds the DSN, it still starts on the next
    reboot, and its credential is still valid. Dropping it because it is not
    running today is the liveness downgrade the derivation refuses one level
    up, arriving through the collector instead.
    """
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    listing = _run(
        source,
        ("docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}}"),
        vault=vault,
        ledger=ledger,
    )
    if listing is None:
        return _outcome("docker", ledger, consumers)
    for line in listing.splitlines():
        parts = line.split()
        if not parts:
            continue
        container, name = parts[0], (parts[1] if len(parts) > 1 else parts[0])
        if not ledger.spend_file(budget):
            break
        text = _run(source, ("docker", "inspect", container), vault=vault, ledger=ledger)
        if text is None:
            continue
        consumers.extend(
            _consumers_in(
                text,
                family="docker",
                owner_unit=name,
                owner_principal=None,
                launch_path=None,
                vault=vault,
                ledger=ledger,
            )
        )
    return _outcome("docker", ledger, consumers)


def _compose(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """Compose projects on disk, and the `.env` files beside them.

    Read from disk rather than from a running daemon, and the difference is the
    point: a project that is currently down is still a declared consumer.
    """
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    for root in _COMPOSE_DIRS:
        for project in _list(source, root, ledger=ledger, budget=budget):
            for path in _list(source, project, ledger=ledger, budget=budget):
                name = path.rsplit("/", 1)[-1]
                if name not in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", ".env"):
                    continue
                text = _read(source, path, vault=vault, ledger=ledger, budget=budget)
                if text is None:
                    continue
                consumers.extend(
                    _consumers_in(
                        text,
                        family="compose",
                        owner_unit=project.rsplit("/", 1)[-1],
                        owner_principal=None,
                        launch_path=path,
                        vault=vault,
                        ledger=ledger,
                    )
                )
    return _outcome("compose", ledger, consumers)


def _ci_runner(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """Runners, which are STRUCTURALLY unreadable and say so.

    A CI runner receives its DSN from the platform at job time. The runner's
    configuration on disk cannot contain it, so finding nothing here is not
    evidence of anything -- and a family that reported `ABSENT` on that basis
    would be asserting a total it has no way to know. Every runner present
    contributes a `dynamic` error, which derives `UNKNOWN`, which is the
    truthful answer. The variables the platform injects are visible only in the
    CI system, and attributing them is a job for whoever owns that system.
    """
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    for path in _CI_RUNNER_PATHS:
        text = _read(source, path, vault=vault, ledger=ledger, budget=budget, optional=True)
        if text is None:
            continue
        ledger.note("dynamic")
        consumers.extend(
            _consumers_in(
                text,
                family="ci_runner",
                owner_unit=path.rsplit("/", 1)[-1],
                owner_principal=None,
                launch_path=path,
                vault=vault,
                ledger=ledger,
            )
        )
    return _outcome("ci_runner", ledger, consumers)


def _script(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """Operator scripts. A script invoked through a variable is `dynamic`.

    The interesting failure here is not the script that contains a DSN -- that
    one is found. It is the script that builds its connection string from
    variables set somewhere this walk cannot see, which produces a `dynamic`
    error rather than an unremarkable zero.
    """
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    for path in _SHARED_ENVIRONMENT:
        text = _read(source, path, vault=vault, ledger=ledger, budget=budget, optional=True)
        if text is None:
            continue
        consumers.extend(
            _consumers_in(
                text,
                family="script",
                # No owner, deliberately and correctly. A shared environment
                # file is read by every login shell; naming the file as the
                # "unit" would manufacture custody that does not exist and turn
                # an UNATTRIBUTED finding into a reassuring ATTRIBUTED one.
                owner_unit=None,
                owner_principal=None,
                launch_path=path,
                vault=vault,
                ledger=ledger,
            )
        )
    for directory in _SCRIPT_DIRS:
        for path in _list(source, directory, ledger=ledger, budget=budget):
            text = _read(source, path, vault=vault, ledger=ledger, budget=budget)
            if text is None:
                continue
            if "psql" not in text and "pg_dump" not in text and not _DSN.search(text):
                continue
            found = _consumers_in(
                text,
                family="script",
                owner_unit=path.rsplit("/", 1)[-1],
                owner_principal=None,
                launch_path=path,
                vault=vault,
                ledger=ledger,
            )
            if not found:
                # It talks to Postgres and no connection string is visible. The
                # parameters come from somewhere this walk cannot reach.
                ledger.note("dynamic")
            consumers.extend(found)
    return _outcome("script", ledger, consumers)


def _agent(source: HostSource, *, vault: RedactionVault, budget: Budget) -> FamilyOutcome:
    """Backup and exporter agents, which hold long-lived credentials by design."""
    ledger = _Ledger()
    consumers: list[ConsumerRecord] = []
    for directory in _AGENT_DIRS:
        for path in _list(source, directory, ledger=ledger, budget=budget):
            text = _read(source, path, vault=vault, ledger=ledger, budget=budget)
            if text is None:
                continue
            consumers.extend(
                _consumers_in(
                    text,
                    family="agent",
                    owner_unit=path.rsplit("/", 1)[-1],
                    owner_principal=None,
                    launch_path=path,
                    vault=vault,
                    ledger=ledger,
                )
            )
    return _outcome("agent", ledger, consumers)


_ENUMERATORS: Final = {
    "systemd_service": _systemd_service,
    "systemd_timer": _systemd_timer,
    "systemd_dropin": _systemd_dropin,
    "cron": _cron,
    "anacron": _anacron,
    "at": _at,
    "docker": _docker,
    "compose": _compose,
    "ci_runner": _ci_runner,
    "script": _script,
    "agent": _agent,
}


def enumerate_family(
    family: str, source: HostSource, *, vault: RedactionVault, budget: Budget | None = None
) -> FamilyOutcome:
    """One family, by name. Raises on an undeclared name rather than returning empty."""
    if family not in _ENUMERATORS:
        raise KeyError(f"{family!r} is not a declared family; see attribution.DECLARED_FAMILIES")
    return _ENUMERATORS[family](source, vault=vault, budget=budget or Budget())


# ── Coverage degradation ────────────────────────────────────────────────────


def degradations(source: HostSource, *, principals: Iterable[str] = ()) -> tuple[Degradation, ...]:
    """Facts that make every count a floor rather than a total.

    Checked by PRESENCE only -- nothing here is opened. A `.pgpass` is read by
    no part of this collector at any point (`attribution.NEVER_READ`), because
    every line of it is `host:port:db:user:PASSWORD` in cleartext and a
    collector would have to hold a live password in memory to decide that it is
    one. Its presence is the whole finding: some local process can authenticate
    with no DSN a reader can see.

    ``principals`` lets a caller name additional home directories to check
    without this module holding a list of usernames -- a username is resolved
    material and would not survive rule 18 in a tracked file.
    """
    found: list[Degradation] = []
    candidates = list(DEGRADING_SOURCES)
    for principal in principals:
        candidates.append(
            (
                f"/home/{principal}/.pgpass",
                "a password file lets a local process connect with no visible DSN",
                "ambiguous",
            )
        )
    for path, reason, error_class in candidates:
        try:
            present = source.exists(path)
        except BaseException:
            # A source that cannot answer "does this exist" leaves the question
            # open, and an open question about a credential file degrades
            # coverage exactly as a positive answer does. Failing closed here
            # is the only safe direction.
            present = True
        if present:
            found.append(
                Degradation(reason=reason, error_class=error_class, families=DECLARED_FAMILIES)
            )
    return tuple(found)


def apply_degradations(
    outcomes: dict[str, FamilyOutcome], found: Sequence[Degradation]
) -> dict[str, FamilyOutcome]:
    """Fold each degradation into the families it degrades.

    A degradation becomes a classified ERROR on the family's scan, which
    derives `UNKNOWN` whatever the count is. That is deliberate and it is the
    merged contract's own reasoning: a scan that found something and also hit
    an error is `UNKNOWN`, because the count is a floor rather than a total.
    The consumers already found are KEPT -- a degradation reduces confidence in
    completeness, never in what was actually seen.
    """
    degraded = dict(outcomes)
    for degradation in found:
        for family in degradation.families:
            if family not in degraded:
                continue
            outcome = degraded[family]
            degraded[family] = FamilyOutcome(
                scan=replace(outcome.scan, errors=(*outcome.scan.errors, degradation.error_class)),
                consumers=outcome.consumers,
            )
    return degraded


def enumerate_all(
    source: HostSource,
    *,
    vault: RedactionVault,
    budget: Budget | None = None,
    principals: Iterable[str] = (),
    skip: Iterable[str] = (),
) -> dict[str, FamilyOutcome]:
    """Every declared family, exactly once, degradations applied.

    ``skip`` is how a family is excluded, and it is the ONLY thing that sets
    `attempted=False`. Excluding a family produces a row saying so rather than
    no row at all, because a missing row reads to every consumer as a family
    with nothing in it.

    The result is keyed by the declared set and nothing else, so a family that
    raised on its way in still appears -- as `attempted` with a classified
    error, which derives `UNKNOWN`. A family that vanished from the output
    because its enumerator blew up would be read by every consumer as a family
    with nothing in it, which is the one reading this whole design refuses.
    """
    limit = budget or Budget()
    skipped = set(skip)
    unknown = skipped - set(DECLARED_FAMILIES)
    if unknown:
        raise KeyError(f"cannot skip undeclared families {sorted(unknown)}")
    outcomes: dict[str, FamilyOutcome] = {}
    for family in DECLARED_FAMILIES:
        if family in skipped:
            # The one thing that sets `attempted=False`, and it derives UNKNOWN.
            # An operator who excludes a family gets a document saying so, not a
            # document missing a row -- a missing row reads as a clean family.
            outcomes[family] = _outcome(family, _Ledger(), (), attempted=False)
            continue
        try:
            outcomes[family] = enumerate_family(family, source, vault=vault, budget=limit)
        except BaseException as error:
            ledger = _Ledger()
            ledger.note(classify(error))
            outcomes[family] = _outcome(family, ledger, (), attempted=True)
    return apply_degradations(outcomes, degradations(source, principals=principals))


def build_observation(
    outcomes: dict[str, FamilyOutcome],
    *,
    target_id: str,
    observed_at: str,
    host_identity_digest: str,
) -> dict[str, object]:
    """The PRIVATE document, matching `postgres-consumer-attribution-observation`.

    Returned rather than written. Nothing in this repository puts an instance
    of this on disk: it holds resolved hosts, ports, users, databases and
    launch paths, and ADR-0004 keeps every one of those out of a checkout. A
    caller that persists it is responsible for putting it in an approved
    private store, and the only thing that may travel further is its digest.
    """
    missing = set(DECLARED_FAMILIES) - set(outcomes)
    if missing:
        raise ValueError(f"an observation carries every declared family; missing {sorted(missing)}")
    return {
        "schema_version": "observability-consumer-attribution-observation.v1",
        "target_id": target_id,
        "observed_at": observed_at,
        "host_identity_digest": host_identity_digest,
        "consumers": [
            {
                "family": record.family,
                "custody": record.custody.value,
                "owner_unit": record.owner_unit,
                "owner_principal": record.owner_principal,
                "launch_path": record.launch_path,
                "db_host": record.db_host,
                "db_port": record.db_port,
                "db_user": record.db_user,
                "db_name": record.db_name,
                "secret_pointer": record.secret_pointer,
            }
            for family in DECLARED_FAMILIES
            for record in outcomes[family].consumers
        ],
        "families": [
            {
                "family": family,
                "attempted": outcomes[family].scan.attempted,
                "completed": outcomes[family].scan.completed,
                "errors": list(outcomes[family].scan.errors),
                "found": outcomes[family].scan.found,
            }
            for family in DECLARED_FAMILIES
        ],
    }


def custody_counts(outcomes: dict[str, FamilyOutcome]) -> tuple[int, int]:
    """Attributed and unattributed consumer totals, for the public envelope."""
    attributed = 0
    unattributed = 0
    for outcome in outcomes.values():
        for record in outcome.consumers:
            if record.custody is Custody.ATTRIBUTED:
                attributed += 1
            else:
                unattributed += 1
    return attributed, unattributed
