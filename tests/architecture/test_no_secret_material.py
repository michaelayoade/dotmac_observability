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


def test_every_committed_credential_reference_is_a_pointer_not_a_value():
    # Inventory only. The contracts mention `openbao_path` as a key NAME, which
    # is not an assignment and carries no value to check.
    checked = 0
    for path in _tracked():
        if path.suffix != ".toml":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            assigned = _ASSIGNMENT.match(line)
            if assigned is None:
                continue
            checked += 1
            # A pointer names a location in the store. Anything else here means
            # someone pasted the material where the path belongs.
            assert assigned.group(1).startswith(
                '"secret/'
            ), f"{path}:{number} openbao_path is not a secret/ store path"
    assert checked > 0, "no openbao_path assignment was examined; the matcher has drifted"
