"""Sensitivity proof for the private-material detector (rules 15 and 18).

`test_no_tracked_file_carries_private_material` passes on a clean repository.
It would also pass if the detector had no patterns at all, if an edit had
broken its regexes, or if the file walk silently skipped everything. Each test
below plants one shape and requires it to be found.

This file is one of the two paths in `PRIVATE_SCAN_EXCLUSIONS`, precisely
because it must contain the shapes being detected.

Every planted value is fabricated, and the care taken over that is the point
rather than pedantry: a sensitivity proof for a disclosure detector is the one
file most likely to disclose something.

The addresses are from the ranges RFC 5737 and RFC 3849 reserve for
documentation, so neither is or can become a real Dotmac address. The hostname
uses a real domain with a label that names nothing — the pattern matches on the
domain, so a fabricated label exercises it exactly as well as a real host would
and discloses nothing. The store path is real-SHAPED and points at no namespace
in use.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dotmac_observability.validate import scan_for_private_material

PLANTED = {
    "PRIVATE-ADDRESS": "endpoint = 198.51.100.14:9090\n",
    "PRIVATE-ADDRESS-V6": "endpoint = [2001:db8:1234::1]:9090\n",
    "PRIVATE-HOSTNAME": "the evaluator answers on no-such-host.dotmac.io\n",
    "PRIVATE-STORE-PATH": 'openbao_path = "secret/dotmac/observability/erp-scrape"\n',
}


@pytest.mark.parametrize(("code", "planted"), sorted(PLANTED.items()))
def test_the_detector_finds_planted_private_material(tmp_path: Path, code: str, planted: str):
    target = tmp_path / "docs" / "planted.md"
    target.parent.mkdir()
    target.write_text(planted)
    findings = scan_for_private_material(tmp_path, [target])
    assert [finding.code for finding in findings] == [code]
    assert findings[0].location.endswith(":1")


def test_the_detector_stays_quiet_on_the_shapes_this_repository_commits(tmp_path: Path):
    """The other half of sensitivity, and the one that keeps a detector alive.

    A detector that flags everything acquires an allowlist, the allowlist grows
    with every legitimate document, and the endpoint is a check that detects
    nothing while still appearing in `make check`. Each line below is something
    this repository genuinely commits, and none of them may trip it.
    """
    target = tmp_path / "clean.md"
    target.write_text(
        # The evaluators' own loopback posture, published deliberately.
        'listen = "127.0.0.1:9090"\n'
        # The wildcard bind inside a container. Names no host.
        "--web.listen-address=0.0.0.0:9090\n"
        # The schema namespace. A bare domain with no leading label, which is
        # why the hostname pattern requires one.
        '"$id": "https://dotmac.io/schemas/observability/target.v2.json"\n'
        # The reserved fixture prefix.
        '"openbao_path": "secret/fixture/erp-scrape"\n'
        # Synthetic endpoints, permanently unresolvable.
        '  - "erp-worker-1.invalid:443"\n'
        # Digests and revisions. This is the corpus that makes an entropy-based
        # detector unusable here, and it must stay quiet under a shape-based one.
        'digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"\n'
        "control_plane_revision = 6002885f0a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
        # A telegram chat id: a long negative integer with no dots or colons.
        "chat_id: -1000000000001\n"
        # Durations and version numbers, which a careless address pattern eats.
        'scrape_interval = "30s"\nversion = "3.11.3"\n'
    )
    assert scan_for_private_material(tmp_path, [target]) == ()


def test_an_excluded_path_is_skipped_but_only_that_path(tmp_path: Path):
    excluded = tmp_path / "src" / "dotmac_observability" / "validate.py"
    excluded.parent.mkdir(parents=True)
    excluded.write_text(PLANTED["PRIVATE-HOSTNAME"])
    other = tmp_path / "src" / "dotmac_observability" / "render.py"
    other.write_text(PLANTED["PRIVATE-HOSTNAME"])
    findings = scan_for_private_material(tmp_path, [excluded, other])
    assert [finding.location for finding in findings] == ["src/dotmac_observability/render.py:1"]


def test_the_two_detectors_answer_different_questions(tmp_path: Path):
    """Rule 1 and rule 18 are not the same check with a wider net.

    A store path is not a secret and the secret scanner is right to ignore it;
    an address is not a secret either. Keeping the two separate is what stops
    the second question being answered by widening the first detector until it
    flags legitimate content and gets an allowlist.
    """
    from dotmac_observability.validate import scan_for_secret_material

    target = tmp_path / "docs" / "note.md"
    target.parent.mkdir()
    target.write_text(PLANTED["PRIVATE-ADDRESS"])
    assert scan_for_secret_material(tmp_path, [target]) == ()
    assert scan_for_private_material(tmp_path, [target]) != ()


def test_the_reserved_prefix_is_what_makes_the_fixture_safe(tmp_path: Path):
    """The synthetic private inventory is exempt by PREFIX, not by path.

    `tests/fixtures/reference/private/inventory.json` is a tracked instance of a
    document type ADR-0004 keeps out of Git. It is safe because every store path
    in it is under `secret/fixture/`, a reserved namespace that names nothing
    real — and the detector exempts that prefix rather than exempting the file.

    The two designs are indistinguishable while the fixture is clean, which is
    why this test exists. Taking the real fixture's content, swapping one prefix
    for a real-shaped namespace, and requiring a finding is the only thing that
    tells them apart: had the file been exempted by path, this would pass
    silently while the file could hold anything at all.

    Written into `tmp_path`, and living in THIS file, for the same reason: a
    planted shape belongs where the scanner is allowed to find it.
    """
    fixture = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "reference"
        / "private"
        / "inventory.json"
    )
    original = fixture.read_text(encoding="utf-8")
    assert "secret/fixture/" in original, "the fixture no longer uses the reserved prefix"

    planted = original.replace("secret/fixture/", "secret/dotmac/observability/", 1)
    target = tmp_path / "private" / "inventory.json"
    target.parent.mkdir()
    target.write_text(planted, encoding="utf-8")

    findings = scan_for_private_material(tmp_path, [target])
    assert [finding.code for finding in findings] == ["PRIVATE-STORE-PATH"]

    # And the unmodified fixture, scanned the same way, must stay clean — or the
    # assertion above would be satisfied by a detector that flags every private
    # document regardless of what is in it.
    clean = tmp_path / "clean" / "inventory.json"
    clean.parent.mkdir()
    clean.write_text(original, encoding="utf-8")
    assert scan_for_private_material(tmp_path, [clean]) == ()
