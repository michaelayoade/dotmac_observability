"""Who owns a Postgres consumer, derived from a bounded scan that never speaks.

Two problems live here, and conflating them is how the v1 design leaked.

The FIRST is epistemic. A census that reports "no cron entry references this
database" is worth something only if the cron scan actually ran, actually
finished, and actually hit no error. The v1 shape let a caller construct that
sentence directly, so a denied `sudo`, an unparsable unit file and a genuinely
clean host all filed the same reassuring answer. Here a verdict is DERIVED from
what the scan attempted, completed, errored on and found -- `ABSENT` is
reachable through exactly one path (`attempted and completed and not errors and
found == 0`) and is not a value any caller can type. `UNKNOWN` is the shape of
every failure, and a DSN with no attributable custody derives `UNATTRIBUTED`
rather than reading as clean.

The SECOND is containment. The raw inputs -- systemd environments, Docker
inspection output, environment files, DSNs -- are parsed in process memory and
must never reach stdout, a temporary file, an exception, a `repr`, a receipt or
a log. The v1 design formatted errors as ``"{}: {}".format(type(e).__name__,
e)``, and ``str(exc)`` on a connection failure carries the parsed DSN; that
exact defect is what :func:`safe_error` exists to make unspellable. Material is
poisoned into a :class:`RedactionVault` at parse time, every dataclass holding
parsed material sets ``repr=False``, :class:`Target` has no password field to
begin with, and :func:`assert_clean` aborts the run rather than emitting a
payload a poisoned value survived into.

This module OWNS neither authorization nor challenge semantics. Permission to
inspect a target is `ConsumerAttributionAuthorizationV1`, owned by
`dotmac-deployment-control`; the nonce, freshness and target binding are
`AttributionChallengeV1`, owned by the observation authority. Both are
independently verified before this lane runs, and this lane records WHICH ones
it executed under -- an `authorization_digest`, a `challenge_digest` and an
`authority_ref` -- exactly as promotion records a `plan_digest` and an
`approval_decision_ref` (AGENTS.md rule 20). Neither upstream document is
defined here, not even as a local convenience shape: a second definition drifts
from the first, and then two systems disagree about what was permitted.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, NoReturn

__all__ = [
    "ATTRIBUTION_SCHEMA_VERSION",
    "ATTRIBUTION_SCHEMA_VERSION_V2",
    "CLASSIFIED_FIELDS",
    "CLASSIFIED_FIELDS_BY_VERSION",
    "CLASSIFIED_FIELDS_V2",
    "DECLARED_FAMILIES",
    "ENVELOPE_FIELDS",
    "ENVELOPE_FIELDS_BY_VERSION",
    "ENVELOPE_FIELDS_V2",
    "ENVELOPE_VERSIONS",
    "NEVER_READ",
    "Custody",
    "FamilyScan",
    "LeakRefusal",
    "RedactionVault",
    "Target",
    "UnclassifiedField",
    "Verdict",
    "derive_custody",
    "derive_verdict",
    "discharges_rotation_interlock",
    "install_leak_guards",
    "parse_dsn",
    "project_envelope",
    "refuses_to_read",
    "run_guarded",
    "safe_error",
    "verify_request",
]

ATTRIBUTION_SCHEMA_VERSION: Final = "observability-consumer-attribution-envelope.v1"
ATTRIBUTION_SCHEMA_VERSION_V2: Final = "observability-consumer-attribution-envelope.v2"

# The envelope versions this module can project into. A caller names one; there
# is deliberately no "latest" alias, because a document whose shape depends on
# when it was produced cannot be compared with one produced last month.
ENVELOPE_VERSIONS: Final[tuple[str, ...]] = (
    ATTRIBUTION_SCHEMA_VERSION,
    ATTRIBUTION_SCHEMA_VERSION_V2,
)

# Every place a Postgres consumer can be launched from on the estate's hosts.
# `systemd_dropin` and `anacron` are here because the v1 design omitted them,
# and an omitted family is not a clean host -- it is an unscanned one that
# reports as clean. The envelope requires EXACTLY ONE result per name, so a
# family that was never attempted files `UNKNOWN` rather than nothing at all.
DECLARED_FAMILIES: Final[tuple[str, ...]] = (
    "systemd_service",
    "systemd_timer",
    "systemd_dropin",
    "cron",
    "anacron",
    "at",
    "docker",
    "compose",
    "ci_runner",
    "script",
    "agent",
)


# Files a credential collector must never open, by BASENAME. `.pgpass` is the
# one that matters: every line in it is `host:port:db:user:PASSWORD` in
# cleartext, so a collector that reads it in order to attribute a consumer has
# to hold a live password in memory to decide that it is one -- and it learns
# nothing about attribution it could not learn from the launch that references
# it. The near-miss is deliberate: `pg_hba.conf` describes authentication
# METHODS and carries no secret, so it is not on this list and must not be
# swept onto it by a broader pattern.
NEVER_READ: Final[tuple[str, ...]] = (".pgpass", ".pgservice.conf", "pgpass.conf")


def refuses_to_read(path: str) -> bool:
    """Whether ``path`` names a file this collector may never open.

    Matched on the trailing basename rather than the full path, so a `.pgpass`
    under any home directory is refused without the refusal needing a list of
    home directories -- which would be a list of usernames, and therefore
    private material of exactly the kind rule 18 keeps out.
    """
    basename = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return basename in NEVER_READ


class Verdict(str, Enum):
    """Coverage of ONE family on ONE host. Derived, never assigned."""

    SCANNED = "SCANNED"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class Custody(str, Enum):
    """Whether a discovered consumer has an owner anyone can be asked about."""

    ATTRIBUTED = "ATTRIBUTED"
    UNATTRIBUTED = "UNATTRIBUTED"


class LeakRefusal(Exception):
    """A payload carried poisoned material. The run aborts; it does not redact.

    Redacting and continuing is the wrong repair: it means the payload was
    built from material that should never have reached the builder, and a
    redactor only has to miss one spelling.
    """


class UnclassifiedField(Exception):
    """A field reached the projection that nobody has decided is public.

    Default-deny for tomorrow's field. The projection refuses a name it does
    not know rather than passing it through, so a collector that grows a
    `db_host` cannot publish it by being written after this module was.
    """


def derive_verdict(
    *,
    attempted: bool,
    completed: bool,
    errors: int,
    found: int,
) -> Verdict:
    """The only way a :class:`Verdict` is ever produced.

    ``ABSENT`` means "a complete, successful, bounded scan looked and found
    nothing", and the branch order below is what makes that the ONLY reading
    it can have. Everything that is not that -- never attempted, a denial, a
    parse failure, a syntax error, an ambiguity, a dynamic launch path that
    cannot be resolved statically, a bounded scan that hit its limit -- is
    ``UNKNOWN``, because all of those are the same epistemic state and
    reporting any of them as ``ABSENT`` is a false negative in the one
    direction that matters.
    """
    if not attempted:
        return Verdict.UNKNOWN
    if errors:
        return Verdict.UNKNOWN
    if not completed:
        return Verdict.UNKNOWN
    return Verdict.SCANNED if found else Verdict.ABSENT


def derive_custody(*, owner_unit: str | None, owner_principal: str | None) -> Custody:
    """A bare `DATABASE_URL` without attributable custody is not clean.

    ``ATTRIBUTED`` requires SOMETHING a human can be asked about -- a unit, a
    job, a container, an owning principal. A DSN found in an environment with
    neither is `UNATTRIBUTED`: it is a real consumer whose owner is unknown,
    which is a finding, not an absence.
    """
    if owner_unit or owner_principal:
        return Custody.ATTRIBUTED
    return Custody.UNATTRIBUTED


def safe_error(exc: BaseException) -> str:
    """A type name. Never ``str(exc)``, never ``repr(exc)``, never args.

    The v1 design wrote ``"{}: {}".format(type(e).__name__, e)``. On a libpq
    failure ``str(exc)`` is a sentence containing the host, port, user and
    frequently the database name straight out of the DSN that was being parsed
    -- so the leak arrived through the error path, which is the path nobody
    tests. There is deliberately no argument that re-enables detail.
    """
    return type(exc).__name__


@dataclass(frozen=True)
class Target:
    """One logical consumer target. There is NO password field, by design.

    A field that can hold a secret will eventually hold one, and then every
    `repr`, every `dataclasses.asdict` and every traceback frame carries it.
    The password is poisoned into the vault and dropped at parse time, so the
    question "did we redact it" never arises. `host` and `database` are
    parsed material and therefore `repr=False`: they are private under
    AGENTS.md rule 18 and exist here only to be digested, never emitted.
    """

    target_id: str
    host: str = field(repr=False, default="")
    port: int = field(repr=False, default=0)
    user: str = field(repr=False, default="")
    database: str = field(repr=False, default="")


@dataclass(frozen=True)
class FamilyScan:
    """What one family's bounded scan actually did. Verdict is not stored.

    Storing a verdict alongside the evidence would let the two disagree, and
    the disagreeing copy is always the one that gets published. :meth:`verdict`
    recomputes from the evidence every time it is asked.
    """

    family: str
    attempted: bool
    completed: bool
    errors: tuple[str, ...] = ()
    found: int = 0
    # Parsed material never leaves this object; it is here so a caller can
    # digest it and is excluded from `repr` for the reason in `Target`.
    evidence: tuple[str, ...] = field(repr=False, default=())

    def verdict(self) -> Verdict:
        return derive_verdict(
            attempted=self.attempted,
            completed=self.completed,
            errors=len(self.errors),
            found=self.found,
        )


class RedactionVault:
    """Poisoned values, held so a payload can be REFUSED for containing one.

    Never serialized: :meth:`__reduce__` and :meth:`__getstate__` raise, so a
    vault cannot reach a pickle, a receipt or a `json.dumps` `default=` hook by
    accident. :meth:`__repr__` prints a COUNT, because the natural
    implementation -- printing the set -- turns every debugger session, every
    pytest assertion rewrite and every logged traceback into the disclosure the
    vault exists to prevent.
    """

    __slots__ = ("_values",)

    def __init__(self) -> None:
        self._values: set[str] = set()

    def poison(self, value: str | None) -> None:
        """Record a value as unpublishable. Short values are still recorded.

        A minimum length would be a silent allowlist: a two-character password
        is still a password, and a three-character database name is still the
        thing rule 18 keeps out of public Git.
        """
        if value:
            self._values.add(value)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return f"<RedactionVault {len(self._values)} poisoned value(s)>"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise LeakRefusal("a RedactionVault is never serialized")

    def __getstate__(self) -> NoReturn:
        raise LeakRefusal("a RedactionVault is never serialized")

    def contains(self, value: str) -> bool:
        return value in self._values

    def assert_clean(self, payload: object) -> None:
        """Walk ``payload`` and raise :class:`LeakRefusal` on any poisoned value.

        Substring matching, not equality: the leak that happened in practice
        was a DSN embedded in a longer error sentence, and an equality check
        passes that cleanly. The refusal message names the KEY PATH and never
        the value -- an exception that reports what it found would leak through
        the one channel guaranteed to be printed.
        """
        for where in _walk(payload, ""):
            path, text = where
            for poisoned in self._values:
                if poisoned in text:
                    raise LeakRefusal(
                        f"payload{path} carries poisoned material; the run is aborted "
                        "rather than redacted (AGENTS.md rule 18)"
                    )


def _count(observed: Mapping[str, object], name: str) -> int:
    """A count, refused rather than coerced when it is not one.

    `int(value)` on a string would accept `"3"` and quietly accept whatever a
    collector emitted; a count that arrives as text has already lost the
    distinction between "none found" and "not measured".
    """
    value = observed.get(name, 0)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer count, not {type(value).__name__}")
    return value


def _walk(node: object, where: str) -> Iterable[tuple[str, str]]:
    """Every string reachable in ``node``, with its key path.

    Keys are walked as well as values: a dict keyed by hostname discloses the
    hostname just as loudly as one that stores it.
    """
    if isinstance(node, str):
        yield where, node
    elif isinstance(node, Mapping):
        for key, value in node.items():
            if isinstance(key, str):
                yield f"{where}/<key>", key
            yield from _walk(value, f"{where}/{key}")
    elif isinstance(node, list | tuple | set | frozenset):
        for index, value in enumerate(node):
            yield from _walk(value, f"{where}/{index}")
    elif node is not None and not isinstance(node, bool | int | float):
        yield where, str(node)


# ── Projection ──────────────────────────────────────────────────────────────
#
# The public envelope's field list, closed and enumerated. The rule 18 half
# that matters is what is ABSENT: there is no `db_host`, `db_port`, `db_user`,
# `db_name`, `launch_path`, `secret_pointers` or `env_var_names` key, so a
# destination for resolved material does not exist to be filled. Containment by
# construction, not by a redactor that has to be right every time.

ENVELOPE_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "target_id",
    "observation_digest",
    "collector_artifact_digest",
    "authorization_digest",
    "challenge_digest",
    "authority_ref",
    "host_identity_digest",
    "observed_at",
    "coverage",
    "counts",
)

# v2 adds `source_artifact_digest`: the `HostSource` implementation that read
# the host, and the remote helper it executed, as one digest over the artifact
# containing both. It is here in the ENVELOPE rather than only in the private
# observation because a gate reads the envelope, and a reader deciding whether
# an attribution claim is trustworthy should not have to fetch a private
# document to learn which implementation decided that a path was `missing`.
ENVELOPE_FIELDS_V2: Final[tuple[str, ...]] = (*ENVELOPE_FIELDS, "source_artifact_digest")

ENVELOPE_FIELDS_BY_VERSION: Final[Mapping[str, tuple[str, ...]]] = {
    ATTRIBUTION_SCHEMA_VERSION: ENVELOPE_FIELDS,
    ATTRIBUTION_SCHEMA_VERSION_V2: ENVELOPE_FIELDS_V2,
}

# Names a projection input may carry and what happens to each. `False` means
# the field is private material: it is accepted as an INPUT so a collector need
# not pre-filter, and it is dropped rather than published. Anything not named
# here at all raises `UnclassifiedField`, which is what makes tomorrow's new
# field fail loudly instead of leaking by default.
CLASSIFIED_FIELDS: Final[Mapping[str, bool]] = {
    "target_id": True,
    "observation_digest": True,
    "collector_artifact_digest": True,
    "authorization_digest": True,
    "challenge_digest": True,
    "authority_ref": True,
    "host_identity_digest": True,
    "observed_at": True,
    "consumers_attributed": True,
    "consumers_unattributed": True,
    "db_host": False,
    "db_port": False,
    "db_user": False,
    "db_name": False,
    "dsn": False,
    "password": False,
    "launch_path": False,
    "secret_pointers": False,
    "env_var_names": False,
    "environment_file": False,
    "container_id": False,
    "unit_path": False,
}


# Version-SPECIFIC, and that is the whole point of the mapping rather than one
# shared table. A single `CLASSIFIED_FIELDS` would widen v1 the moment v2
# landed: `project_envelope` would start accepting `source_artifact_digest` for
# a v1 projection, and v1 -- a published, closed contract with no such field --
# would have silently gained one. The failure would be invisible, because the
# field would simply be dropped rather than rejected, and a v1 envelope would
# then exist that a v1 reader believes was produced under v1 rules.
CLASSIFIED_FIELDS_V2: Final[Mapping[str, bool]] = {
    **CLASSIFIED_FIELDS,
    "source_artifact_digest": True,
}

CLASSIFIED_FIELDS_BY_VERSION: Final[Mapping[str, Mapping[str, bool]]] = {
    ATTRIBUTION_SCHEMA_VERSION: CLASSIFIED_FIELDS,
    ATTRIBUTION_SCHEMA_VERSION_V2: CLASSIFIED_FIELDS_V2,
}


def discharges_rotation_interlock(envelope: Mapping[str, object]) -> bool:
    """Whether this envelope can release the thing rotation waits on.

    Exactly one question, and deliberately not more: does the envelope identify
    BOTH artifacts whose behaviour the coverage claim depends on? A v1 envelope
    cannot, because it has no field naming the `HostSource` implementation that
    decided which failures were reported as `missing` -- and that decision is
    what separates a clean host from an unreadable one.

    What this does NOT decide: whether coverage is complete, whether every
    consumer has been migrated, or whether any given verdict is good enough.
    Those belong to the rotation lane, which owns the interlock. This answers
    only the version-and-binding half, which is the half that lives here.
    """
    if envelope.get("schema_version") != ATTRIBUTION_SCHEMA_VERSION_V2:
        return False
    return all(
        isinstance(envelope.get(name), str) and bool(envelope.get(name))
        for name in ("collector_artifact_digest", "source_artifact_digest")
    )


def verify_request(
    *,
    authorization_digest: str,
    challenge_digest: str,
    authority_ref: str,
) -> dict[str, str]:
    """Record which independently verified inputs this observation ran under.

    This is NOT a signature check and NOT an approval check, and the name is
    kept from the design brief only so the call site reads the same. Permission
    is `ConsumerAttributionAuthorizationV1` and belongs to
    `dotmac-deployment-control`; the nonce, freshness, target binding and
    output-signature semantics are `AttributionChallengeV1` and belong to the
    observation authority. Both are verified upstream by their owners.

    The split is the point: one document saying "you may look at this host" and
    "here is a nonce, sign the answer" would let whoever granted permission also
    define what counts as proof of what happened. Two issuers, two documents,
    neither able to close the loop alone -- and this lane, which can close
    neither, records all three references so a reader can resolve each in the
    system that took its decision.

    What is checked here is only that all three are PRESENT and non-empty. A
    stronger check would require knowing the upstream shapes, and knowing them
    here means defining them here (AGENTS.md rule 20).
    """
    missing = [
        name
        for name, value in (
            ("authorization_digest", authorization_digest),
            ("challenge_digest", challenge_digest),
            ("authority_ref", authority_ref),
        )
        if not value or not value.strip()
    ]
    if missing:
        raise ValueError(
            f"an attribution observation records {', '.join(missing)}; each names a "
            "DIFFERENT authority and none is derivable from the others"
        )
    return {
        "authorization_digest": authorization_digest,
        "challenge_digest": challenge_digest,
        "authority_ref": authority_ref,
    }


def project_envelope(
    observed: Mapping[str, object],
    scans: Mapping[str, FamilyScan],
    *,
    vault: RedactionVault,
    version: str = ATTRIBUTION_SCHEMA_VERSION,
) -> dict[str, object]:
    """Build the PUBLIC envelope from private observation, then prove it clean.

    Three refusals, in order, and each catches something the others do not.
    An unclassified input name raises :class:`UnclassifiedField`. A missing or
    extra declared family is refused, because a family reported for some hosts
    and omitted for others is read as a clean host by every consumer. And the
    finished payload is walked against the vault, so a poisoned value that
    reached a public field through any route at all aborts the run.

    ``version`` selects the field allowlist, and the default is v1 so that
    adding v2 cannot widen v1 by accident. A v1 projection handed
    `source_artifact_digest` raises :class:`UnclassifiedField` exactly as it
    would for any other field v1 does not know about -- which is the correct
    answer, because v1 is a published closed contract with no such property.
    """
    if version not in ENVELOPE_VERSIONS:
        raise ValueError(f"{version!r} is not an envelope version; known: {ENVELOPE_VERSIONS}")
    classified = CLASSIFIED_FIELDS_BY_VERSION[version]
    unclassified = sorted(set(observed) - set(classified))
    if unclassified:
        raise UnclassifiedField(
            f"{unclassified} reached the projection with no publication decision under "
            f"{version}. Classify each in CLASSIFIED_FIELDS_BY_VERSION[{version!r}] as public "
            "or private; a field is never published because nobody said otherwise"
        )

    declared = set(DECLARED_FAMILIES)
    supplied = set(scans)
    if supplied != declared:
        raise ValueError(
            f"coverage must carry exactly one result per declared family; "
            f"missing {sorted(declared - supplied)}, unexpected {sorted(supplied - declared)}"
        )

    envelope: dict[str, object] = {
        "schema_version": version,
        "target_id": observed["target_id"],
        "observation_digest": observed["observation_digest"],
        "collector_artifact_digest": observed["collector_artifact_digest"],
        "host_identity_digest": observed["host_identity_digest"],
        "observed_at": observed["observed_at"],
        "coverage": [
            {
                "family": name,
                "verdict": scans[name].verdict().value,
                "found": scans[name].found,
                "error_count": len(scans[name].errors),
            }
            for name in DECLARED_FAMILIES
        ],
        "counts": {
            "families_declared": len(DECLARED_FAMILIES),
            "families_scanned": sum(
                1 for scan in scans.values() if scan.verdict() is Verdict.SCANNED
            ),
            "families_absent": sum(
                1 for scan in scans.values() if scan.verdict() is Verdict.ABSENT
            ),
            "families_unknown": sum(
                1 for scan in scans.values() if scan.verdict() is Verdict.UNKNOWN
            ),
            "consumers_attributed": _count(observed, "consumers_attributed"),
            "consumers_unattributed": _count(observed, "consumers_unattributed"),
        },
    }
    if version == ATTRIBUTION_SCHEMA_VERSION_V2:
        envelope["source_artifact_digest"] = observed["source_artifact_digest"]
    envelope.update(
        verify_request(
            authorization_digest=str(observed["authorization_digest"]),
            challenge_digest=str(observed["challenge_digest"]),
            authority_ref=str(observed["authority_ref"]),
        )
    )
    expected = set(ENVELOPE_FIELDS_BY_VERSION[version])
    if set(envelope) != expected:
        # A structural check on the OUTPUT, not just the input. The field list
        # and the builder are two spellings of one shape, and the published one
        # is always the stale one.
        raise ValueError(
            f"the {version} envelope must carry exactly {sorted(expected)}; "
            f"built {sorted(envelope)}"
        )
    vault.assert_clean(envelope)
    return envelope


# ── Entry-point containment ─────────────────────────────────────────────────


def install_leak_guards() -> None:
    """Silence tracebacks process-wide.

    A traceback prints SOURCE LINES and, for a chained exception, the message
    of every frame -- so an unhandled failure mid-parse writes the DSN to
    stderr no matter how careful every `except` in this module is. `0` is the
    value that suppresses the traceback body entirely; any positive number
    still prints frames.
    """
    sys.tracebacklimit = 0


def run_guarded(main: Callable[[], int]) -> int:
    """Run ``main`` so that NOTHING carrying parsed material reaches stderr.

    `BaseException`, not `Exception`, and deliberately: a `KeyboardInterrupt`
    or a `SystemExit` raised from inside a parse unwinds through frames holding
    the DSN, and the default handler prints them. The cost is that Ctrl-C
    reports as a type name, which is the correct trade for a collector that
    reads credentials.
    """
    install_leak_guards()
    try:
        return main()
    except BaseException as exc:  # containment: see the docstring
        sys.stderr.write(f"attribution: refused ({safe_error(exc)})\n")
        return 1


def parse_dsn(raw: str, *, target_id: str, vault: RedactionVault) -> Target:
    """Parse a DSN in memory, poison every component, return no password.

    `urllib.parse` is used through a local import so that a module-level import
    cannot be mistaken for a network capability; nothing here resolves a name
    or opens a socket. The password is poisoned and DROPPED -- it is never
    stored on the returned :class:`Target`, because a field that can hold it
    will eventually print it.
    """
    from urllib.parse import unquote, urlsplit

    vault.poison(raw)
    try:
        split = urlsplit(raw)
        host = split.hostname or ""
        port = split.port or 0
        user = unquote(split.username or "")
        database = unquote(split.path.lstrip("/"))
        vault.poison(split.password)
    except BaseException as exc:
        # The v1 leak, closed: the message is a TYPE NAME. `str(exc)` on a URL
        # parse failure quotes the URL it failed on.
        raise ValueError(f"unparsable consumer DSN ({safe_error(exc)})") from None
    for component in (host, user, database):
        vault.poison(component)
    if host and port:
        # The PAIR, never the bare port. Poisoning "5432" on its own would make
        # every sha256 digest that happens to contain those four hex characters
        # abort a clean run, and a guard that fires on correct input gets
        # switched off long before it catches anything.
        vault.poison(f"{host}:{port}")
    return Target(target_id=target_id, host=host, port=port, user=user, database=database)
