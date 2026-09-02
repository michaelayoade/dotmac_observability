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

from .drift import compare
from .live_verify import load_live_observation, render_verification, verify
from .receipt import load_receipt, receipt_findings
from .render import differences, render_control_plane, tree_digest, write_tree
from .validate import (
    ACCEPTED_SCHEMA_VERSION,
    CAPTURE_SCHEMA_VERSION,
    Finding,
    InventoryError,
    apply_supersession,
    canonical_bytes,
    classify_stored_inventory,
    load,
    load_capture_inventory,
    load_private_inventory,
    load_supersession_request,
    migrate_capture,
    migration_findings,
    resolution_findings,
    resolve,
    retirement_findings,
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


def _cmd_request_shape(contracts: Path, request_path: Path) -> int:
    """Print the storage shape a reviewed request confirms, and nothing else.

    The mutation workflow needs to know how the document is stored BEFORE it
    reads it, and it must not work that out for itself — a shape discovered at
    run time and acted on immediately is a decision nobody reviewed. Reading it
    from the request goes through the contract, so a malformed or absent
    declaration fails here rather than producing a shell variable that is
    silently empty.
    """
    try:
        request = load_supersession_request(request_path, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="cannot read the supersession request")
    print(request.storage_shape)
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


def _cmd_inventory_classify(stored: Path, expect: str | None) -> int:
    """Say which contract a stored document is written against, and stop.

    The step the supersession workflow did not have, and the reason its first
    real failure was 68 schema errors on a document that is not corrupt at all.
    Both mutation tools load the previous version through the ACCEPTED contract
    before doing anything else, so a store holding the pre-contract capture
    format fails in the least legible place available — after the precondition
    guard has passed, in a tool whose job is to print a digest.

    It reads exactly one field, ``schema_version``, and prints exactly one
    line. No key name, no length, no value: a classifier that described the
    document would be the leak the whole workflow is built to avoid.

    Exit codes are the interface. 0 for the accepted contract, 2 for the
    capture format, 3 for anything else — so a workflow can branch on the
    answer without parsing prose, and an unrecognised third shape is
    distinguishable from a known-old one rather than being sorted into
    whichever it happens to resemble.
    """
    import json

    if not stored.is_file():
        print(f"no such document: {stored}", file=sys.stderr)
        return 1
    try:
        with stored.open("rb") as handle:
            document = json.load(handle)
    except json.JSONDecodeError as error:
        print(f"the stored document is not valid JSON ({error.msg})", file=sys.stderr)
        return 1
    if not isinstance(document, dict):
        print("the stored document is not a JSON object", file=sys.stderr)
        return 1
    declared = classify_stored_inventory(document)
    print(f"format {declared}")
    if expect is not None and declared != expect:
        # CONFIRMATION, not discovery — the same rule the storage shape already
        # follows. The reviewed request declares which contract the stored
        # version is in; a store that disagrees is a change nobody reviewed, so
        # this refuses instead of adapting to it.
        print(
            f"  the reviewed request declares {expect!r} and the store holds {declared!r}; "
            "refusing rather than adapting to a change nobody reviewed",
            file=sys.stderr,
        )
        return 4
    if declared == ACCEPTED_SCHEMA_VERSION:
        return 0
    if declared == CAPTURE_SCHEMA_VERSION:
        print(
            "  the store holds the PRE-CONTRACT capture format. It is not corrupt and it is "
            "not a retirement problem: bringing it to the accepted contract needs a "
            "`migrate-capture` request and `inventory-migrate`, and must happen before any "
            "retirement. See docs/runbooks/migrate-the-capture-format.md",
            file=sys.stderr,
        )
        return 2
    print(
        "  the stored document declares a schema_version this repository does not know. "
        "Refusing to sort it into whichever known format it resembles: the two are migrated "
        "by different code and being wrong about which one is holding a production estate",
        file=sys.stderr,
    )
    return 3


def _cmd_inventory_migrate(
    root: Path,
    contracts: Path,
    request_path: Path,
    stored: Path,
    host_binding: Path,
    output: Path,
) -> int:
    """Rewrite a capture-format document into the accepted contract.

    Every value in the result comes from ``stored`` except the host binding,
    which the capture format does not hold and which arrives as a FILE — from a
    configured private source on the runner, never from public Git and never
    from a workflow input, which is the distinction AGENTS.md rule 21 draws and
    the reason this is provisioning without disclosure.

    The federation split is taken from the PUBLIC inventory and cross-checked
    against the request. Both, not either: the request is what a reviewer read,
    and the public inventory is what the renderer will look in.
    """
    import json

    try:
        request = load_supersession_request(request_path, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="cannot read the migration request")
    if request.kind != "migrate-capture":
        print(
            f"this command applies a migrate-capture request; the request is {request.kind!r}",
            file=sys.stderr,
        )
        return 1
    try:
        state = load(root, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="inventory is not loadable")
    try:
        capture = load_capture_inventory(stored, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="the stored document is not a readable capture")

    with host_binding.open("rb") as handle:
        binding = json.load(handle)
    if not isinstance(binding, dict):
        print("the host binding file is not a JSON object", file=sys.stderr)
        return 1

    produced, findings = migrate_capture(
        capture,
        request,
        binding,
        (federation.target_id for federation in state.federations),
    )
    if findings:
        return _report(findings, heading="refusing to migrate")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_bytes(produced))
    try:
        after = load_private_inventory(output, contracts=contracts)
    except InventoryError as error:
        return _report(error.findings, heading="the migrated document is not valid")

    unsafe = migration_findings(capture, after, expect_previous_digest=request.previous_digest)
    if unsafe:
        return _report(unsafe, heading="the migrated document is not a safe supersession")
    resolution = resolution_findings(state, after)
    if resolution:
        return _report(resolution, heading="the migrated document does not resolve")
    # Counts and logical names only, exactly as a retirement summary prints.
    print(
        f"migrated {capture.version} -> {after.version}: "
        f"{len(after.targets)} target(s), {len(after.federations)} federation(s), "
        f"{len(after.receivers)} receiver(s), {len(after.source_sets)} source set(s)"
    )
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
    # Over the RENDERED bytes, and before anything is written. A retired
    # product reappearing in any surface the bundle produces stops the render
    # rather than being noticed by whoever reads the diff.
    retired = retirement_findings(state, tree)
    if retired:
        return _report(retired, heading="refusing to render a retired product's monitoring")
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


def _cmd_verify(
    root: Path,
    contracts: Path,
    private: Path,
    observation: Path,
    baseline: Path | None,
    previous_digest: str | None,
    *,
    first_promotion: bool,
) -> int:
    """Report the six conditions against one read-back, and the verdict.

    The verdict is printed even when it is the bad one, and all six rows are
    printed even when five passed: a report listing only failures cannot be
    told from a report of a run that checked less.
    """
    try:
        state = load(root, contracts=contracts)
        inventory = load_private_inventory(private, contracts=contracts)
        resolution = resolve(state, inventory)
        live = load_live_observation(observation, contracts=contracts)
        recorded = (
            None if baseline is None else load_live_observation(baseline, contracts=contracts)
        )
    except InventoryError as error:
        return _report(error.findings, heading="refusing to verify an unloadable input")

    verification = verify(
        state,
        resolution,
        render_control_plane(state, resolution),
        live,
        baseline=recorded,
        previous_digest=previous_digest,
        first_promotion=first_promotion,
    )
    print(render_verification(verification))
    return 0 if not verification.findings else 1


def _cmd_receipt_check(contracts: Path, path: Path, *, first_promotion: bool) -> int:
    findings = receipt_findings(
        load_receipt(path),
        contracts=contracts,
        location=path.name,
        first_promotion=first_promotion,
    )
    if findings:
        return _report(findings, heading="the receipt claims more than it records")
    print(f"{path.name} is internally consistent")
    return 0


def _cmd_drift(
    root: Path, contracts: Path, private: Path, observation: Path | None, receipt: Path | None
) -> int:
    """Compare the three artifacts, and say plainly which were not supplied.

    Exits non-zero when any artifact is missing as well as when any pair
    disagrees. Two artifacts agreeing is an incomplete result, not a clean one,
    and a zero exit is how "incomplete" becomes "clean" in somebody's job log.
    """
    try:
        state = load(root, contracts=contracts)
        inventory = load_private_inventory(private, contracts=contracts)
        resolution = resolve(state, inventory)
        live = (
            None if observation is None else load_live_observation(observation, contracts=contracts)
        )
    except InventoryError as error:
        return _report(error.findings, heading="refusing to compare an unloadable input")

    report = compare(
        tree=render_control_plane(state, resolution),
        live=live,
        receipt=None if receipt is None else load_receipt(receipt),
    )
    if report.clean:
        print("desired, live and receipt agree")
        return 0
    return _report(report.findings, heading="drift")


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

    classify = commands.add_parser(
        "inventory-classify",
        help="say which contract a stored private document is written against, and stop",
    )
    classify.add_argument("stored", type=Path)
    classify.add_argument(
        "--expect",
        default=None,
        help=(
            "fail unless the stored document declares this contract. Turns the classifier "
            "from a reporter into a gate, which is what a mutation workflow needs before it "
            "loads anything."
        ),
    )

    migrate = commands.add_parser(
        "inventory-migrate",
        help="rewrite a capture-format document into the accepted contract",
    )
    migrate.add_argument("--request", type=Path, required=True)
    migrate.add_argument("--stored", type=Path, required=True)
    migrate.add_argument(
        "--host-binding",
        type=Path,
        required=True,
        help=(
            "a JSON object carrying target_id, identity and ssh_alias. The accepted contract "
            "requires all three and the capture format holds none of them, so they arrive as a "
            "file from a configured private source \u2014 never through this repository and never "
            "through a workflow input, both of which are readable."
        ),
    )
    migrate.add_argument("--output", type=Path, required=True)

    shape = commands.add_parser(
        "request-shape",
        help="print the storage shape a reviewed supersession request confirms",
    )
    shape.add_argument("--request", type=Path, required=True)

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

    verify_command = commands.add_parser(
        "verify", help="report the six production conditions against one read-back"
    )
    verify_command.add_argument("--private-inventory", type=Path, required=True)
    verify_command.add_argument(
        "--observation",
        type=Path,
        required=True,
        help="an observability-live-observation.v1 document",
    )
    verify_command.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help=(
            "the read-back taken BEFORE the promotion. Without it the ingestion delta cannot "
            "be computed and condition 3 is reported unmet \u2014 never assumed to be zero."
        ),
    )
    verify_command.add_argument(
        "--previous-digest",
        default=None,
        help="the tree digest the previous release was accepted with, for condition 6",
    )
    verify_command.add_argument("--first-promotion", action="store_true")

    receipt_command = commands.add_parser(
        "receipt-check", help="refuse a receipt that claims more than it records"
    )
    receipt_command.add_argument("receipt", type=Path)
    receipt_command.add_argument("--first-promotion", action="store_true")

    drift_command = commands.add_parser(
        "drift", help="compare desired state, live state and the last accepted receipt"
    )
    drift_command.add_argument("--private-inventory", type=Path, required=True)
    drift_command.add_argument("--observation", type=Path, default=None)
    drift_command.add_argument("--receipt", type=Path, default=None)

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
    if arguments.command == "inventory-classify":
        return _cmd_inventory_classify(arguments.stored, arguments.expect)
    if arguments.command == "inventory-migrate":
        return _cmd_inventory_migrate(
            root,
            contracts,
            arguments.request,
            arguments.stored,
            arguments.host_binding,
            arguments.output,
        )
    if arguments.command == "request-shape":
        return _cmd_request_shape(contracts, arguments.request)
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
    if arguments.command == "verify":
        return _cmd_verify(
            root,
            contracts,
            arguments.private_inventory,
            arguments.observation,
            arguments.baseline,
            arguments.previous_digest,
            first_promotion=bool(arguments.first_promotion),
        )
    if arguments.command == "receipt-check":
        return _cmd_receipt_check(
            contracts, arguments.receipt, first_promotion=bool(arguments.first_promotion)
        )
    if arguments.command == "drift":
        return _cmd_drift(
            root, contracts, arguments.private_inventory, arguments.observation, arguments.receipt
        )
    if arguments.command == "secret-scan":
        return _cmd_secret_scan(root)
    if arguments.command == "private-material-scan":
        return _cmd_private_scan(root)
    raise AssertionError(f"unreachable command {arguments.command!r}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
