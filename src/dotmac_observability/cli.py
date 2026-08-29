"""``dotmac-observability`` — the adapter layer over the control-plane library.

Thin by rule: every command validates its inputs, calls one library function
and formats the result. No decision is made here that is not also available to
the promotion lane, because a rule that only the CLI enforces is a rule the
automation does not have.

One command deliberately reads private material — ``render``, which cannot
produce a configuration without it — and one deliberately reports on it
without printing it: ``inventory-digest`` emits an identity a receipt or an
authorization can record, so an operator never has to open a private document
to cite it. ``validate`` accepts a private inventory and works without one, and
says which of the two it did, because "no findings" must not mean two different
things depending on an argument nobody can see in the output.
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
    apply_supersession,
    canonical_bytes,
    load,
    load_private_inventory,
    load_supersession_request,
    resolution_findings,
    resolve,
    scan_for_private_material,
    scan_for_secret_material,
    semantic_findings,
    supersede_findings,
    supersede_summary,
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


def _cmd_validate(root: Path, contracts: Path, private: Path | None) -> int:
    try:
        state = load(root, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="inventory is not loadable")
    findings = list(semantic_findings(state))
    if private is None:
        # Said out loud. Silence here would let a public-only run read exactly
        # like a resolved one, and the resolution gates are where a stale
        # binding or an unfalsifiable authentication claim is caught.
        print("public gates only — no private inventory supplied, resolution gates did not run")
    else:
        try:
            inventory = load_private_inventory(private, contracts=contracts)
        except InventoryError as error:
            return _report(
                findings + list(error.findings), heading="private inventory is not loadable"
            )
        findings += resolution_findings(state, inventory)
        print(
            f"resolved against {inventory.document} v{inventory.version} "
            f"sha256={inventory.digest}"
        )
    return _report(findings, heading="inventory is inconsistent")


def _cmd_inventory_digest(contracts: Path, private: Path, expect: str | None) -> int:
    """Print a private document's identity, never its contents.

    The whole point of the command: a receipt and a deployment plan both record
    document, version and digest, and an operator who has to open the file to
    read them off has opened a private document to fill in a public form.

    ``--expect`` turns it from a reporter into a gate, which is what makes a
    write worth trusting. Writing a document and then printing its digest
    proves the writer can hash what it just held in memory; reading the stored
    bytes BACK and comparing them against the digest you meant to store is the
    only version of that check which can fail on a truncated or partial write.
    """
    try:
        inventory = load_private_inventory(private, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="private inventory is not loadable")
    print(f"document {inventory.document}")
    print(f"version  {inventory.version}")
    print(f"sha256   {inventory.digest}")
    if expect is not None and inventory.digest != expect:
        print(
            f"  digest does not match the expected {expect}; the stored bytes are not "
            "the document that was meant to be written",
            file=sys.stderr,
        )
        return 1
    return 0


def _cmd_inventory_apply(contracts: Path, request_path: Path, previous: Path, output: Path) -> int:
    """Apply a reviewed retirement request to a stored private inventory.

    The whole point of a committed request: the change is reviewed on protected
    main in logical vocabulary, and this step is mechanical. Nothing here
    accepts a target name from a command line or a workflow input, because a
    name typed at run time is an unreviewed change to the environment.
    """
    import json

    try:
        request = load_supersession_request(request_path, contracts=contracts)
        before = load_private_inventory(previous, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="cannot apply the supersession request")

    with previous.open("rb") as handle:
        stored = json.load(handle)
    document, findings = apply_supersession(request, before, stored)
    if findings:
        return _report(findings, heading="refusing to apply the supersession request")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_bytes(document))
    try:
        after = load_private_inventory(output, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="the produced document is not valid")

    # Verified by the same gate an operator would run by hand, rather than
    # trusted because this function produced it.
    unsafe = supersede_findings(before, after, expect_previous_digest=before.digest)
    if unsafe:
        return _report(unsafe, heading="the produced document is not a safe supersession")
    print(supersede_summary(before, after).render())
    return 0


def _cmd_inventory_supersede(
    contracts: Path, previous: Path, following: Path, expect_previous: str
) -> int:
    """Prove one private document legitimately replaces a NAMED earlier version."""
    try:
        before = load_private_inventory(previous, contracts=contracts)
        after = load_private_inventory(following, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="a private inventory is not loadable")

    findings = supersede_findings(before, after, expect_previous_digest=expect_previous)
    if findings:
        return _report(findings, heading="refusing an unsafe supersession")
    # Logical names and counts only. A reviewer needs to see WHAT moved; the
    # values it moved to are the material this whole split exists to withhold.
    print(supersede_summary(before, after).render())
    return 0


def _cmd_render(root: Path, contracts: Path, output: Path, private: Path, *, check: bool) -> int:
    try:
        state = load(root, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="inventory is not loadable")
    findings = semantic_findings(state)
    if findings:
        return _report(findings, heading="refusing to render an inconsistent inventory")
    try:
        inventory = load_private_inventory(private, contracts=contracts)
        resolution = resolve(state, inventory)
    except InventoryError as error:
        return _report(error.findings, heading="refusing to render an unresolved inventory")

    tree = render_control_plane(state, resolution)
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


def _cmd_private_scan(root: Path) -> int:
    findings = scan_for_private_material(root, _tracked_files(root))
    return _report(findings, heading="private material in tracked files")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dotmac-observability", description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="root holding inventory/ and routing/ (default: .)",
    )
    parser.add_argument(
        "--contracts",
        type=Path,
        default=None,
        help=(
            "directory holding the *.schema.json contracts (default: <root>/contracts). "
            "Separable so a fixture tree is validated against the REAL contracts rather "
            "than a copy \u2014 a fixture carrying its own copy proves the copy, and the two "
            "drift the first time a schema changes."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate_command = commands.add_parser(
        "validate", help="schema and semantic gates over the inventory"
    )
    validate_command.add_argument(
        "--private-inventory",
        type=Path,
        default=None,
        help="an ObserverInventoryV1 document; adds the resolution gates (ADR-0004)",
    )

    render = commands.add_parser("render", help="render the control-plane configuration")
    render.add_argument(
        "--output", type=Path, default=None, help=f"default: <root>/{_DEFAULT_OUTPUT}"
    )
    render.add_argument(
        "--private-inventory",
        type=Path,
        required=True,
        help="an ObserverInventoryV1 document supplying every endpoint and credential binding",
    )
    render.add_argument(
        "--check",
        action="store_true",
        help="compare bytes against the committed render instead of writing",
    )

    digest = commands.add_parser(
        "inventory-digest", help="print a private document's identity, never its contents"
    )
    digest.add_argument("private_inventory", type=Path)
    digest.add_argument(
        "--expect",
        default=None,
        help="fail unless the document hashes to this digest; use it to verify a read-back",
    )

    apply_request = commands.add_parser(
        "inventory-apply",
        help="apply a reviewed retirement request to a stored private inventory",
    )
    apply_request.add_argument("--request", type=Path, required=True)
    apply_request.add_argument("--previous", type=Path, required=True)
    apply_request.add_argument("--output", type=Path, required=True)

    supersede = commands.add_parser(
        "inventory-supersede",
        help="prove one private document legitimately replaces a named earlier version",
    )
    supersede.add_argument("--previous", type=Path, required=True)
    supersede.add_argument("--next", dest="following", type=Path, required=True)
    supersede.add_argument(
        "--expect-previous-sha256",
        required=True,
        help=(
            "the digest of the version being replaced. Required, not optional: overwriting "
            "whatever is stored is a lost update, and naming the version you believe you are "
            "replacing turns that into a refusal instead of a surprise."
        ),
    )

    commands.add_parser("secret-scan", help="refuse secret material in tracked files")
    commands.add_parser(
        "private-material-scan", help="refuse resolved material in tracked files (ADR-0004)"
    )

    arguments = parser.parse_args(argv)
    root: Path = arguments.root.resolve()
    contracts: Path = (
        arguments.contracts.resolve() if arguments.contracts is not None else root / "contracts"
    )

    if arguments.command == "validate":
        return _cmd_validate(root, contracts, arguments.private_inventory)
    if arguments.command == "render":
        output: Path = arguments.output if arguments.output is not None else root / _DEFAULT_OUTPUT
        return _cmd_render(
            root, contracts, output, arguments.private_inventory, check=bool(arguments.check)
        )
    if arguments.command == "inventory-digest":
        return _cmd_inventory_digest(contracts, arguments.private_inventory, arguments.expect)
    if arguments.command == "inventory-apply":
        return _cmd_inventory_apply(
            contracts, arguments.request, arguments.previous, arguments.output
        )
    if arguments.command == "inventory-supersede":
        return _cmd_inventory_supersede(
            contracts,
            arguments.previous,
            arguments.following,
            arguments.expect_previous_sha256,
        )
    if arguments.command == "secret-scan":
        return _cmd_secret_scan(root)
    if arguments.command == "private-material-scan":
        return _cmd_private_scan(root)
    raise AssertionError(f"unreachable command {arguments.command!r}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
