"""A recording host double. No host, no daemon, no container, no network.

The same arrangement `tests/unit/test_promotion_executor.py` uses for the
promotion facility, and for the same reason: `HostSource` is a Protocol this
repository declares and does not implement, so every enumerator can be driven
through every one of its failure paths without anything being reachable.

Denials, timeouts and unsupported programs are first-class here rather than an
afterthought. They are the inputs that decide whether a family reports UNKNOWN
or reports a confident zero, which is the entire question this census exists to
answer -- so a double that could only model success would prove the least
interesting half.

Every hostname is `.invalid` and no IPv4 or IPv6 literal appears anywhere.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from dotmac_observability.attribution_enumerators import (
    HOST_SOURCE_CONTRACT_VERSION,
    SourceDenied,
    SourceMissing,
    SourceTimeout,
    SourceUnsupported,
)

# A DSN whose every component is synthetic and unresolvable.
# The users are realistic identifiers rather than four-letter abbreviations,
# and that is load-bearing rather than cosmetic. `RedactionVault.assert_clean`
# matches SUBSTRINGS with no minimum length -- deliberately, because a minimum
# length is a silent allowlist and a two-character password is still a
# password. The consequence is that a very short private value collides with
# unrelated public text: a database user `anac` is a substring of the family
# name `anacron`, and `cont` is a substring of an `authority_ref` reading
# `control:decision/...`. Both aborted a correct projection while this fixture
# used them.
#
# That is a REAL operational characteristic of the merged containment design,
# not a fixture artefact, and it is pinned by
# `test_a_short_private_value_can_abort_a_correct_run` below rather than being
# quietly engineered away. The behaviour fails closed -- refuse, no output --
# which is the right direction, but an operator meeting it needs to recognise
# it rather than assume a leak.
UNIT_DSN = "postgresql://erp_worker:pw-fixture@erp-db.invalid:5432/erp_main"
CRON_DSN = "postgresql://erp_backup:pw-nightly@erp-db.invalid:5432/erp_main"
DROPIN_DSN = "postgresql://erp_override:pw-dropin@erp-db.invalid:5432/erp_main"
ANACRON_DSN = "postgresql://erp_nightly:pw-anac@erp-db.invalid:5432/erp_main"
DOCKER_DSN = "postgresql://erp_api:pw-cont@erp-db.invalid:5432/erp_main"


class FakeHost:
    """A filesystem and a command table, with declared failures.

    `list_dir` is derived from the file map rather than declared separately, so
    a fixture cannot claim a directory holds a file it never defined -- a
    mismatch there would make an enumerator look thorough while reading
    nothing.
    """

    # A source ADVERTISES which `HostSource` contract it implements, and the
    # collector refuses a mismatch. The double carries it as an instance
    # attribute so a test can set a wrong one without subclassing.
    host_source_contract_version = HOST_SOURCE_CONTRACT_VERSION

    def __init__(
        self,
        files: Mapping[str, str] | None = None,
        *,
        commands: Mapping[tuple[str, ...], str] | None = None,
        denied: Sequence[str] = (),
        timed_out: Sequence[str] = (),
        unsupported: Sequence[str] = (),
        present: Sequence[str] = (),
        directories: Sequence[str] = (),
    ) -> None:
        self.files = dict(files or {})
        self.commands = dict(commands or {})
        self.denied = set(denied)
        self.timed_out = set(timed_out)
        self.unsupported = set(unsupported)
        self.present = set(present)
        self.directories = set(directories)
        # Every path and argv actually touched, so a test can assert what a
        # collector DID rather than only what it returned. `.pgpass` never
        # being opened is checkable only against this.
        self.read_paths: list[str] = []
        self.listed: list[str] = []
        self.ran: list[tuple[str, ...]] = []

    def _refuse(self, key: str) -> None:
        if key in self.denied:
            raise SourceDenied(key)
        if key in self.timed_out:
            raise SourceTimeout(key)
        if key in self.unsupported:
            raise SourceUnsupported(key)

    def exists(self, path: str) -> bool:
        self._refuse(path)
        return path in self.present or path in self.files

    def list_dir(self, directory: str) -> Sequence[str]:
        self.listed.append(directory)
        self._refuse(directory)
        prefix = directory.rstrip("/") + "/"
        children = {
            prefix + path[len(prefix) :].split("/", 1)[0]
            for path in list(self.files) + list(self.directories)
            if path.startswith(prefix)
        }
        if not children and directory not in self.directories:
            raise SourceMissing(directory)
        return sorted(children)

    def read_text(self, path: str) -> str:
        self.read_paths.append(path)
        self._refuse(path)
        if path not in self.files:
            raise SourceMissing(path)
        return self.files[path]

    def run(self, argv: Sequence[str]) -> str:
        key = tuple(argv)
        self.ran.append(key)
        self._refuse(" ".join(key))
        if key not in self.commands:
            raise SourceUnsupported(" ".join(key))
        return self.commands[key]


def populated_host(**overrides: object) -> FakeHost:
    """One consumer in each of the families a file-based walk can see.

    Deliberately includes a drop-in and an anacron job -- the two families the
    original design omitted -- because a fixture that exercises only the
    obvious families would let their enumerators be empty and still pass.
    """
    files = {
        "/etc/systemd/system/erp-worker.service": (
            "[Service]\nUser=erpsvc\n"
            f"Environment=DATABASE_URL={UNIT_DSN}\n"
            "ExecStart=/usr/local/bin/erp-worker\n"
        ),
        "/etc/systemd/system/erp-report.timer": (
            f"[Timer]\nOnCalendar=daily\nEnvironment=DATABASE_URL={UNIT_DSN}\n"
        ),
        "/etc/systemd/system/erp-worker.service.d/override.conf": (
            f"[Service]\nEnvironment=DATABASE_URL={DROPIN_DSN}\n"
        ),
        "/etc/cron.d/erp-backup": f"0 2 * * * root DATABASE_URL={CRON_DSN} /usr/local/bin/backup\n",
        "/etc/anacrontab": f"1 5 erp.daily DATABASE_URL={ANACRON_DSN} /usr/local/bin/nightly\n",
        "/usr/local/bin/backup": f"#!/bin/sh\npsql {CRON_DSN} -c 'select 1'\n",
        "/etc/pgbackrest/pgbackrest.conf": f"[global]\npg1-socket-path={UNIT_DSN}\n",
    }
    host = FakeHost(
        files=files,
        commands={
            ("docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}}"): "abc erp-api\n",
            ("docker", "inspect", "abc"): f'[{{"Env":["DATABASE_URL={DOCKER_DSN}"]}}]',
            ("atq",): "",
        },
        directories=("/etc/systemd/system/erp-worker.service.d",),
    )
    for name, value in overrides.items():
        setattr(host, name, value)
    return host
