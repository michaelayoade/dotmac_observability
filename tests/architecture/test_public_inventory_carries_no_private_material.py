"""AGENTS.md rule 18 — public Git carries the logical description only.

Rule 1 asks whether a value is a SECRET. This asks the second question a public
repository forces and rule 1 was never meant to answer: whether a non-secret
fact is still something to publish. A production endpoint, an internal
hostname, a port and a credential custody path are each non-secret. Together
they are a map of the estate, drawn by the people who know it best and kept
current by a gate that fails when it drifts.

Both of this repository's real disclosures were of that second kind, and
neither was in an inventory file: PR #4 removed a rehearsal host address from
`ARCHITECTURE.md` and `SECURITY.md`, and PR #6 removed a credential basename
from prose that a previous sweep had passed as clean. The structural half of
rule 18 — closed contracts that refuse a private field outright — could not
have caught either. This scan is aimed at exactly that gap.
"""

from __future__ import annotations

import json
import subprocess

from dotmac_observability.validate import PRIVATE_SCAN_EXCLUSIONS, scan_for_private_material
from tests.conftest import REFERENCE_PRIVATE, REPO_ROOT


def _tracked():
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
        text=True,
    )
    return [REPO_ROOT / name for name in result.stdout.split("\0") if name]


def test_git_actually_tracks_something():
    # Without this, an empty index would make the scan below pass by scanning
    # nothing — the classic vacuous green.
    assert len(_tracked()) > 20


def test_no_tracked_file_carries_private_material():
    findings = scan_for_private_material(REPO_ROOT, _tracked())
    assert not findings, "\n".join(finding.render() for finding in findings)


def test_the_exclusion_list_is_exactly_the_detector_and_its_proof():
    """Asserted exactly, not as a subset, and deliberately SHORT.

    The obvious third entry would be the synthetic private inventory, and it is
    absent on purpose. That document is safe because of a property of its
    CONTENT — `.invalid` hosts and a reserved `secret/fixture/` prefix, both
    checked below — not because of where it sits. Excluding it by path would
    mean a real store path pasted into that file went unnoticed, which is a
    worse arrangement than the one it would be protecting.
    """
    assert PRIVATE_SCAN_EXCLUSIONS == (
        "src/dotmac_observability/validate.py",
        "tests/mutations/test_private_material_detector_bites.py",
    )
    for relative in PRIVATE_SCAN_EXCLUSIONS:
        assert (REPO_ROOT / relative).is_file(), f"{relative} is excluded but does not exist"


def test_the_synthetic_private_inventory_resolves_nothing_real():
    """The enforceable premise behind a tracked instance of a private type.

    ADR-0004 keeps documents of this shape out of Git. This one is here because
    CI has to exercise the join, and it is safe for two reasons a test can
    check rather than two a reader has to trust.
    """
    document = json.loads(REFERENCE_PRIVATE.read_text(encoding="utf-8"))

    endpoints = [
        endpoint for binding in document["targets"] for endpoint in binding["endpoints"]
    ] + [binding["endpoint"] for binding in document["federations"]]
    assert endpoints, "no endpoints examined; the fixture shape has drifted"
    for endpoint in endpoints:
        host = endpoint.rsplit(":", 1)[0]
        # RFC 6761 reserves `.invalid` as permanently unresolvable, so these
        # names cannot become real by accident or by somebody registering them.
        assert host.endswith(".invalid"), f"{endpoint} is not an unresolvable .invalid name"

    paths = [
        binding["credential"]["openbao_path"]
        for group in ("targets", "federations", "receivers")
        for binding in document[group]
        if binding.get("credential") is not None
    ]
    assert paths, "no store paths examined; the fixture shape has drifted"
    for path in paths:
        # A reserved prefix naming no real store namespace. The detector exempts
        # the PREFIX rather than this file, so a real path here is still caught —
        # proved by `test_the_reserved_prefix_is_what_makes_the_fixture_safe` in
        # `tests/mutations/`, which is where a planted shape can live.
        assert path.startswith("secret/fixture/"), f"{path} is not under the reserved prefix"
