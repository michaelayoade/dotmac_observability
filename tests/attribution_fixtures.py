"""Synthetic inputs for the attribution battery. NOTHING here resolves.

Every host is `.invalid` (RFC 2606), which is unresolvable by construction, and
no IPv4 or IPv6 literal appears anywhere in this battery at all. That is a
STRONGER choice than the RFC 5737 documentation range the design asked for, and
it is made deliberately: this repository's private-material detector refuses
every non-loopback IPv4 literal in a tracked file with no documentation-range
carve-out (`_PRIVATE_PATTERNS["ADDRESS"]` in `validate.py`), so a `192.0.2.x`
fixture would need a third entry in `PRIVATE_SCAN_EXCLUSIONS` -- a list
`tests/architecture/test_public_inventory_carries_no_private_material.py`
asserts EXACTLY, on the premise that only the detector and its own proof may
contain the shapes it detects. A fixture is neither. Using names the detector
has no reason to look at keeps the premise true and needs no exemption.

The passwords here are short and obviously synthetic for a second reason: the
secret detector's ASSIGNED-CREDENTIAL pattern fires on sixteen or more
credential-shaped characters after a `password`-ish key, and a fixture that
trips a repository gate gets the gate weakened rather than the fixture fixed.
"""

from __future__ import annotations

from collections.abc import Mapping

from dotmac_observability.attribution import DECLARED_FAMILIES, FamilyScan

# An unresolvable host, a synthetic user and a synthetic password. The password
# is a real component of the DSN because the parser must be shown poisoning and
# DROPPING one; it is nine characters and names nothing.
CONSUMER_DSN = "postgresql://obsuser:pw-fixture@erp-db.invalid:5432/erpdb"
BARE_DSN = "postgresql://erp-db.invalid/erpdb"

DIGEST_A = "sha256:" + "1a" * 32
DIGEST_B = "sha256:" + "2b" * 32
DIGEST_C = "sha256:" + "3c" * 32
DIGEST_D = "sha256:" + "4d" * 32
DIGEST_E = "sha256:" + "5e" * 32


def clean_scans(**overrides: FamilyScan) -> dict[str, FamilyScan]:
    """One complete, successful, empty scan per declared family.

    Complete rather than partial on purpose: a test about ONE family's defect
    should not be able to pass because a different family was also wrong.
    """
    scans = {
        name: FamilyScan(family=name, attempted=True, completed=True, errors=(), found=0)
        for name in DECLARED_FAMILIES
    }
    scans.update(overrides)
    return scans


def observation(**overrides: object) -> dict[str, object]:
    """The private-side input a projection is given. Public fields only here."""
    observed: dict[str, object] = {
        "target_id": "erp-production",
        "observation_digest": DIGEST_A,
        "collector_artifact_digest": DIGEST_B,
        "authorization_digest": DIGEST_C,
        "challenge_digest": DIGEST_D,
        "authority_ref": "control:decision/7f2c",
        "host_identity_digest": DIGEST_E,
        "observed_at": "2026-09-05T09:00:00Z",
        "consumers_attributed": 3,
        "consumers_unattributed": 1,
    }
    observed.update(overrides)
    return observed


# The envelope is a plain mapping so it can be serialized without a converter.
# These two accessors exist only so a test can index into it without every
# assertion carrying a cast; they assert the container's TYPE, which is itself
# worth checking -- a projection that returned a string here would satisfy a
# `len()` assertion.


def coverage_of(envelope: Mapping[str, object]) -> list[dict[str, object]]:
    entries = envelope["coverage"]
    assert isinstance(entries, list), "coverage is not a list"
    return entries


def counts_of(envelope: Mapping[str, object]) -> dict[str, int]:
    counts = envelope["counts"]
    assert isinstance(counts, dict), "counts is not a mapping"
    return counts
