"""``dotmac-observability`` — the adapter layer over the control-plane library.

Thin by rule: every command validates its inputs, calls one library function
and formats the result. No decision is made here that is not also available to
the promotion lane, because a rule that only the CLI enforces is a rule the
automation does not have.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .render import differences, render_control_plane, tree_digest, write_tree
from .validate import (
    Finding,
    InventoryError,
    load,
    scan_for_secret_material,
    semantic_findings,
)

__all__ = ["main"]

_DEFAULT_OUTPUT = "deploy/rendered"


def _report(findings: Sequence[Finding], *, heading: str) -> int:
    if not findings:
        return 0
    print(f"{heading}: {len(findings)} finding(s)", file=sys.stderr)
    for finding in findings:
        print(f"  {finding.render()}", file=sys.stderr)
    return 1


def _tracked_files(root: Path) -> tuple[Path, ...]:
    """Every file Git tracks under ``root``.

    Git's own index rather than a filesystem walk: the walk would have to
    reimplement ``.gitignore`` to avoid scanning a virtualenv, and a scanner
    that skips files for reasons nobody wrote down is how a real finding gets
    lost.
    """
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=True,
        text=True,
    )
    return tuple(root / name for name in result.stdout.split("\0") if name)


def _cmd_validate(root: Path) -> int:
    try:
        state = load(root)
    except InventoryError as error:
        return _report(error.findings, heading="inventory is not loadable")
    return _report(semantic_findings(state), heading="inventory is inconsistent")


def _cmd_render(root: Path, output: Path, *, check: bool) -> int:
    try:
        state = load(root)
    except InventoryError as error:
        return _report(error.findings, heading="inventory is not loadable")
    findings = semantic_findings(state)
    if findings:
        return _report(findings, heading="refusing to render an inconsistent inventory")

    tree = render_control_plane(state)
    if not check:
        write_tree(tree, output)
        print(f"rendered {len(tree)} file(s) into {output}  digest={tree_digest(tree)}")
        return 0

    drifted = differences(tree, output)
    if drifted:
        print(
            f"committed bytes under {output} disagree with a fresh render:",
            file=sys.stderr,
        )
        for path in drifted:
            print(f"  {path}", file=sys.stderr)
        print("  run `make render` and commit the result", file=sys.stderr)
        return 1
    print(f"render is byte-identical  digest={tree_digest(tree)}")
    return 0


def _cmd_secret_scan(root: Path) -> int:
    findings = scan_for_secret_material(root, _tracked_files(root))
    return _report(findings, heading="secret material in tracked files")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dotmac-observability", description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="repository root holding contracts/, inventory/ and routing/ (default: .)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("validate", help="schema and semantic gates over the inventory")

    render = commands.add_parser("render", help="render the control-plane configuration")
    render.add_argument(
        "--output", type=Path, default=None, help=f"default: <root>/{_DEFAULT_OUTPUT}"
    )
    render.add_argument(
        "--check",
        action="store_true",
        help="compare bytes against the committed render instead of writing",
    )

    commands.add_parser("secret-scan", help="refuse secret material in tracked files")

    arguments = parser.parse_args(argv)
    root: Path = arguments.root.resolve()

    if arguments.command == "validate":
        return _cmd_validate(root)
    if arguments.command == "render":
        output: Path = arguments.output if arguments.output is not None else root / _DEFAULT_OUTPUT
        return _cmd_render(root, output, check=bool(arguments.check))
    if arguments.command == "secret-scan":
        return _cmd_secret_scan(root)
    raise AssertionError(f"unreachable command {arguments.command!r}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
