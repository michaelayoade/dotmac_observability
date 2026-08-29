"""AGENTS.md rule 1 — no secret VALUE is ever committed.

The scan runs over Git's index rather than a filesystem walk, so it sees
exactly what a push would publish, and cannot be quieted by a `.gitignore`
entry added in the same change.
"""

from __future__ import annotations

import re
import subprocess

from dotmac_observability.validate import SECRET_SCAN_EXCLUSIONS, scan_for_secret_material
from tests.conftest import REPO_ROOT


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


def test_no_tracked_file_carries_secret_material():
    findings = scan_for_secret_material(REPO_ROOT, _tracked())
    assert not findings, "\n".join(finding.render() for finding in findings)


def test_the_exclusion_list_is_exactly_the_detector_and_its_proof():
    # An exclusion states an ENFORCEABLE premise (rule 15). The premise for
    # these two is that they must contain the shapes being detected or the
    # detector has no sensitivity proof. No third file can claim that premise,
    # so the list is asserted exactly rather than as a subset.
    assert SECRET_SCAN_EXCLUSIONS == (
        "src/dotmac_observability/validate.py",
        "tests/mutations/test_secret_detector_bites.py",
    )
    for relative in SECRET_SCAN_EXCLUSIONS:
        assert (REPO_ROOT / relative).is_file(), f"{relative} is excluded but does not exist"


_ASSIGNMENT = re.compile(r"^\s*openbao_path\s*=\s*(.+)$")


def test_no_public_inventory_document_carries_a_store_path():
    """The ADR-0004 inversion, stated as the assertion it became.

    This check used to REQUIRE every committed `openbao_path` to start with
    `secret/`, on the premise that a store path is safe to commit and only a
    pasted value would look different. ADR-0004 reverses the premise: a store
    path describes credential custody layout, so the key does not belong in a
    public document at all.

    Two things make this non-vacuous rather than a check over an empty set.
    The contracts refuse the key STRUCTURALLY, so a reader might reasonably ask
    what this adds — the answer is that it covers documents no schema reads,
    which is where both of this repository's real disclosures happened. And the
    detector's own sensitivity lives in `tests/mutations/`, where a planted
    path must be found.
    """
    for path in _tracked():
        if path.suffix != ".toml":
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        if not relative.startswith(("inventory/", "routing/", "tests/fixtures/")):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            assert _ASSIGNMENT.match(line) is None, (
                f"{relative}:{number} assigns openbao_path in a PUBLIC document; a store path "
                "is private material and belongs in the private inventory (ADR-0004)"
            )
