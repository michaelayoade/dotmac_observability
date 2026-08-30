#!/usr/bin/env python3
"""Prove the rendered rotation contract survives a real rotation.

Run by CI, never on a workstation, and never against a live host: everything
happens inside one directory under ``$RUNNER_TEMP``, with an rsyslogd started
in the foreground on its own socket and killed at the end. ``/var/log`` is
never touched and no unit is installed.

WHAT IS BEING PROVED, and why a unit test could not.

The Observer host's mail facility went nowhere for a month. ``/var/log`` is
``root:syslog 0755``; rsyslog drops privilege to the ``syslog`` user; the file
it was told to write did not exist; a privilege-dropped writer cannot create a
file in a directory it has no write bit on. The action suspended, resumed and
suspended again — 10,161 times in thirty days — and every message routed to it
was discarded.

The rendered contract fixes that by having something ELSE create the file:
systemd-tmpfiles at boot, logrotate after every rotation, both as root, both
with the owner, group and mode stated. A Python test can assert the rendered
bytes contain ``create 0640 syslog adm``. It cannot assert that logrotate
accepts the stanza, that the file it creates is one rsyslog can open, or that a
message written to the mail facility comes out the other side. Those are
properties of three programs agreeing, and only running them settles it.

THE NEGATIVE CONTROLS ARE THE POINT. A proof that has never been observed to
fail is a proof that might be checking nothing — the rotation could "succeed"
because the checker looked at the wrong file, or because the assertion was
written inverted. So the same proof runs three more times against deliberately
broken configurations, and each of those runs MUST fail:

* the owner is removed from ``create`` — the file comes back owned by root and
  the privilege-dropped writer cannot append to it, which is the original
  failure exactly;
* the mode is removed — the file comes back with logrotate's default, which is
  not the declared one;
* the ``postrotate`` reopen is removed — rsyslog keeps writing into the renamed
  inode and the new file stays empty, which is the failure that looks like
  success because rotation itself worked.
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

CANARY_BEFORE = "dotmac-rotation-canary-before"
CANARY_AFTER = "dotmac-rotation-canary-after"


class ProofFailure(Exception):
    """A property the proof asserts did not hold."""


@dataclass(frozen=True)
class Contract:
    """The owner, group and mode the rendered tmpfiles line declares.

    Parsed out of the RENDERED artefact rather than hardcoded here, so this
    script cannot pass by checking values the renderer no longer emits.
    """

    path: Path
    owner: str
    group: str
    mode: str


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, **kwargs)  # type: ignore[arg-type]


def _parse_tmpfiles(rendered: Path, target: str) -> Contract:
    line = None
    for candidate in (
        (rendered / "host" / "tmpfiles.d" / "observability.conf").read_text().splitlines()
    ):
        if candidate.startswith(f"f {target} "):
            line = candidate
            break
    if line is None:
        raise ProofFailure(f"the rendered tmpfiles config declares no file entry for {target}")
    _, path, mode, owner, group, *_ = line.split()
    return Contract(path=Path(path), owner=owner, group=group, mode=mode)


def _ensure_account(name: str) -> None:
    try:
        pwd.getpwnam(name)
    except KeyError:
        _run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name])
    try:
        grp.getgrnam(name)
    except KeyError:
        _run(["groupadd", "--system", name])


def _prepare(work: Path, rendered: Path, contract: Contract) -> tuple[Path, Path, Path]:
    """Build an isolated /var/log analogue with the declared ownership.

    The DIRECTORY is created with the same mode the rendered contract declares
    for the real one — 0755, owned by root — precisely so the proof is run
    against the permission situation that broke, rather than against a
    convenient one. If the repair depended on widening the directory, it would
    fail here.
    """
    shutil.rmtree(work, ignore_errors=True)
    logs = work / "log"
    logs.mkdir(parents=True)
    directory_line = next(
        line
        for line in (rendered / "host" / "tmpfiles.d" / "observability.conf")
        .read_text()
        .splitlines()
        if line.startswith("d ")
    )
    _, _, dir_mode, dir_owner, dir_group, *_ = directory_line.split()
    os.chmod(logs, int(dir_mode, 8))
    shutil.chown(logs, dir_owner, dir_group)

    target = logs / contract.path.name
    # tmpfiles' job, done by hand because systemd-tmpfiles refuses a relocated
    # tree: create as root, with the declared owner, group and mode. This is
    # the step whose ABSENCE is the whole fault.
    target.touch()
    shutil.chown(target, contract.owner, contract.group)
    os.chmod(target, int(contract.mode, 8))

    spool = work / "spool"
    spool.mkdir()
    shutil.chown(spool, contract.owner, contract.owner)
    return logs, target, spool


def _rsyslog_config(work: Path, rendered: Path, logs: Path, spool: Path, socket: Path) -> Path:
    """The rendered rsyslog drop-in, retargeted at the isolated tree.

    Only the PATHS are rewritten. The `$FileOwner`, `$FileGroup`,
    `$FileCreateMode` and facility lines are the rendered bytes, unmodified —
    rewriting those would be proving a config this repository does not produce.
    """
    body = (rendered / "host" / "rsyslog.d" / "40-observability.conf").read_text()
    body = body.replace("/var/log", str(logs))
    config = work / "rsyslog.conf"
    config.write_text(
        "\n".join(
            [
                'module(load="imuxsock" SysSock.Name="' + str(socket) + '")',
                "$WorkDirectory " + str(spool),
                "$PrivDropToUser syslog",
                "$PrivDropToGroup syslog",
                "$RepeatedMsgReduction off",
                body,
                "",
            ]
        )
    )
    return config


def _start(config: Path, pidfile: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        ["rsyslogd", "-n", "-f", str(config), "-i", str(pidfile)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)
    if process.poll() is not None:
        raise ProofFailure(f"rsyslogd exited immediately: {process.stderr.read()!r}")  # type: ignore[union-attr]
    return process


def _log(socket: Path, message: str) -> None:
    """Write a controlled MAIL-facility message.

    `-p mail.info` is the point: the facility whose file could not be created
    is the facility the canary uses, so a repair that fixed some other file
    would not pass.
    """
    result = _run(["logger", "-u", str(socket), "-p", "mail.info", "-t", "rotation-proof", message])
    if result.returncode != 0:
        raise ProofFailure(f"logger refused the message: {result.stderr}")
    time.sleep(1)


def _expect_contains(path: Path, needle: str) -> None:
    if not path.is_file():
        raise ProofFailure(f"{path} does not exist")
    if needle not in path.read_text(errors="replace"):
        raise ProofFailure(f"{path} does not contain {needle!r}")


def _expect_ownership(path: Path, contract: Contract) -> None:
    info = path.stat()
    owner = pwd.getpwuid(info.st_uid).pw_name
    group = grp.getgrgid(info.st_gid).gr_name
    mode = oct(info.st_mode & 0o7777)[2:].rjust(4, "0")
    if owner != contract.owner:
        raise ProofFailure(f"{path} is owned by {owner!r}, not {contract.owner!r}")
    if group != contract.group:
        raise ProofFailure(f"{path} has group {group!r}, not {contract.group!r}")
    if mode != contract.mode:
        raise ProofFailure(f"{path} has mode {mode}, not {contract.mode}")


def prove(rendered: Path, work: Path, stanza_text: str | None = None) -> None:
    """Run one full rotation cycle and assert every property.

    ``stanza_text`` overrides the rendered logrotate stanza, which is how the
    negative controls are run: same code, broken input, and the run must raise.
    """
    contract = _parse_tmpfiles(rendered, "/var/log/mail.log")
    _ensure_account(contract.owner)
    _ensure_account(contract.group)
    logs, target, spool = _prepare(work, rendered, contract)
    socket = work / "log.sock"
    pidfile = work / "rsyslogd.pid"

    config = _rsyslog_config(work, rendered, logs, spool, socket)
    process = _start(config, pidfile)
    try:
        _log(socket, CANARY_BEFORE)
        _expect_contains(target, CANARY_BEFORE)
        _expect_ownership(target, contract)

        stanza = stanza_text
        if stanza is None:
            stanza = (rendered / "host" / "logrotate.d" / "observability").read_text()
        stanza = stanza.replace("/var/log", str(logs))
        # The rendered postrotate calls the distribution's own helper, which
        # signals the SYSTEM rsyslog. This instance has its own pidfile, so the
        # helper is replaced by the same signal aimed at the right process —
        # the property under test is "the writer is told to reopen", not which
        # script does the telling.
        stanza = stanza.replace("/usr/lib/rsyslog/rsyslog-rotate", f"kill -HUP $(cat {pidfile})")
        stanza_path = work / "logrotate.conf"
        stanza_path.write_text(stanza)

        state = work / "logrotate.state"
        result = _run(
            ["logrotate", "--force", "--state", str(state), "--verbose", str(stanza_path)]
        )
        if result.returncode != 0:
            raise ProofFailure(f"logrotate refused the rendered stanza: {result.stderr}")
        time.sleep(2)

        rotated = Path(str(target) + ".1")
        if not rotated.exists():
            raise ProofFailure("rotation did not move the previous file aside")
        _expect_contains(rotated, CANARY_BEFORE)

        # The three properties the negative controls each break.
        if not target.exists():
            raise ProofFailure("rotation did not recreate the file")
        _expect_ownership(target, contract)
        _log(socket, CANARY_AFTER)
        _expect_contains(target, CANARY_AFTER)
        if CANARY_AFTER in rotated.read_text(errors="replace"):
            raise ProofFailure(
                "the post-rotation message landed in the ROTATED file, so the writer was "
                "never told to reopen and is still holding the old descriptor"
            )

        # And the failure the host actually had: an action that suspended.
        stderr = b""
        if process.stderr is not None:
            os.set_blocking(process.stderr.fileno(), False)
            stderr = process.stderr.read() or b""
        suspensions = len(re.findall(rb"suspended", stderr))
        if suspensions:
            raise ProofFailure(f"rsyslog suspended an action {suspensions} time(s) during the run")
    finally:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            process.kill()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rendered", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    arguments = parser.parse_args(argv)

    rendered: Path = arguments.rendered
    work: Path = arguments.work
    stanza = (rendered / "host" / "logrotate.d" / "observability").read_text()

    print("positive control: the rendered contract")
    prove(rendered, work / "positive")
    print("  ok")

    # Each break is the removal of ONE declared property, and each one is a
    # thing somebody would plausibly leave out.
    controls: list[tuple[str, str, str]] = [
        (
            "create without an owner",
            "    create 0640 syslog adm",
            "    create 0640",
        ),
        (
            "create without a mode or an owner",
            "    create 0640 syslog adm",
            "    create",
        ),
        (
            "no postrotate reopen",
            "    postrotate\n        /usr/lib/rsyslog/rsyslog-rotate\n    endscript",
            "",
        ),
    ]
    failed = False
    for index, (name, old, new) in enumerate(controls):
        if old not in stanza:
            print(f"negative control {name!r}: the rendered stanza no longer contains {old!r}")
            print("  the control mutates nothing, so it would pass for the wrong reason")
            failed = True
            continue
        print(f"negative control: {name}")
        try:
            prove(rendered, work / f"negative{index}", stanza_text=stanza.replace(old, new, 1))
        except ProofFailure as error:
            print(f"  ok, refused: {error}")
        else:
            print("  THE PROOF PASSED WITH A BROKEN CONTRACT, so it is checking nothing")
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofFailure as failure:  # pragma: no cover - the positive control failing
        print(f"the rendered rotation contract does not hold: {failure}", file=sys.stderr)
        raise SystemExit(1) from failure
