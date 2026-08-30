"""Superseding a private inventory is compare-and-set, never an overwrite.

The failure this guards is quiet and expensive, and it is the one that
prompted the capability. Two operators read stored version 1, each edits it,
each writes version 2. The second write wins. The change the first one made —
a decommissioned product's target removed, say — is silently back in the
environment, and nothing anywhere records that it ever left. The next
promotion resolves it, renders it, and scrapes a host that no longer exists.

A digest printed after a write cannot catch that: it proves the writer can
hash what it is holding. Naming the version you believe you are replacing, and
reading the stored bytes back afterwards, are the two halves that can.

Everything here works on copies in `tmp_path`. Nothing writes a second private
document into the repository, because the tracked one is safe for reasons
specific to its content and a second file would need the same argument made
again.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dotmac_observability.validate import (
    load_private_inventory,
    supersede_findings,
    supersede_summary,
)
from tests.conftest import CONTRACTS, REFERENCE_PRIVATE


def _write(path: Path, document: dict[str, object]) -> Path:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def versions(tmp_path: Path):
    """A v1 copy of the fixture, and a v2 that retires one target.

    Shaped after the real change this capability exists for: the CRM scrape
    target and its credential binding leave together, because the credential
    file backing that binding was shredded on the host.
    """
    original = json.loads(REFERENCE_PRIVATE.read_text(encoding="utf-8"))
    following = json.loads(json.dumps(original))
    following["version"] = 2
    following["targets"] = [
        target for target in following["targets"] if target["target_id"] != "erp-production"
    ]
    return (
        load_private_inventory(_write(tmp_path / "v1.json", original), contracts=CONTRACTS),
        load_private_inventory(_write(tmp_path / "v2.json", following), contracts=CONTRACTS),
        original,
        following,
    )


def _codes(previous, following, expect) -> set[str]:
    return {
        finding.code
        for finding in supersede_findings(previous, following, expect_previous_digest=expect)
    }


def test_a_legitimate_supersession_is_accepted(versions):
    previous, following, _, _ = versions
    assert _codes(previous, following, previous.digest) == set()


def test_naming_the_wrong_previous_digest_is_refused(versions):
    previous, following, _, _ = versions
    # The compare-and-set half. An operator who read a different version, or
    # read nothing at all, cannot name this digest, so the write stops here
    # instead of landing on top of somebody else's change.
    assert "SUPERSEDE-PREVIOUS-DIGEST" in _codes(previous, following, "0" * 64)


def test_a_skipped_or_reused_version_is_refused(tmp_path, versions):
    previous, _, original, following_doc = versions
    for version in (1, 3):
        skewed = json.loads(json.dumps(following_doc))
        skewed["version"] = version
        following = load_private_inventory(
            _write(tmp_path / f"v{version}-skew.json", skewed), contracts=CONTRACTS
        )
        assert "SUPERSEDE-VERSION" in _codes(previous, following, previous.digest), version


def test_a_renamed_document_is_not_a_new_version(tmp_path, versions):
    previous, _, _, following_doc = versions
    renamed = json.loads(json.dumps(following_doc))
    renamed["document"] = "reference-private-inventory-new"
    following = load_private_inventory(
        _write(tmp_path / "renamed.json", renamed), contracts=CONTRACTS
    )
    # Every receipt naming the old document becomes unresolvable, which is a
    # different and worse failure than a rejected write.
    assert "SUPERSEDE-DOCUMENT" in _codes(previous, following, previous.digest)


def test_changing_environment_mid_succession_is_refused(tmp_path, versions):
    previous, _, _, following_doc = versions
    moved = json.loads(json.dumps(following_doc))
    moved["environment"] = "production"
    following = load_private_inventory(_write(tmp_path / "moved.json", moved), contracts=CONTRACTS)
    assert "SUPERSEDE-ENVIRONMENT" in _codes(previous, following, previous.digest)


def test_a_version_bump_that_changes_nothing_is_refused(tmp_path, versions):
    previous, _, original, _ = versions
    unchanged = json.loads(json.dumps(original))
    unchanged["version"] = 2
    following = load_private_inventory(
        _write(tmp_path / "unchanged.json", unchanged), contracts=CONTRACTS
    )
    # Two receipts would name different versions of an environment that never
    # moved, and a reader comparing them would go looking for a change that
    # does not exist.
    assert "SUPERSEDE-NO-CHANGE" in _codes(previous, following, previous.digest)


def test_a_reformat_alone_is_not_a_change(tmp_path, versions):
    """The other half of NO-CHANGE, and the reason it is safe to enforce.

    The digest is taken over the canonical form, so re-indenting the stored
    document does not read as a change. Without this, an operator who
    pretty-printed the file would be told they had superseded something.
    """
    previous, _, original, _ = versions
    reformatted = json.loads(json.dumps(original))
    reformatted["version"] = 2
    path = tmp_path / "reformatted.json"
    path.write_text(json.dumps(reformatted, indent=8, sort_keys=False), encoding="utf-8")
    following = load_private_inventory(path, contracts=CONTRACTS)
    assert "SUPERSEDE-NO-CHANGE" in _codes(previous, following, previous.digest)


def test_the_summary_names_logical_identities_and_never_resolved_values(versions):
    previous, following, original, _ = versions
    summary = supersede_summary(previous, following)

    assert summary.targets_removed == ("erp-production",)
    assert summary.targets_added == ()
    assert summary.credentials_before == 4
    assert summary.credentials_after == 3

    rendered = summary.render()
    assert "erp-production" in rendered

    # The load-bearing assertion. Every resolved value in the fixture must be
    # absent from a summary an operator will paste into a ticket.
    resolved = [endpoint for binding in original["targets"] for endpoint in binding["endpoints"]]
    resolved += [binding["endpoint"] for binding in original["federations"]]
    for group in ("targets", "federations", "receivers"):
        for binding in original[group]:
            credential = binding.get("credential")
            if credential is not None:
                resolved += [credential["openbao_path"], credential["file_name"]]
            if binding.get("destination") is not None:
                resolved.append(binding["destination"])
    assert resolved, "no resolved values collected; the fixture shape has drifted"
    for value in resolved:
        assert value not in rendered, f"the change summary leaked {value!r}"


def test_the_leak_assertion_would_notice_a_leak(versions):
    """Sensitivity proof for the assertion above.

    A loop over values that never appear passes whether or not the summary is
    careful. Rendering a value that IS private and requiring the same check to
    fail is what separates a working guard from a vacuous one.
    """
    previous, following, original, _ = versions
    leaked = supersede_summary(previous, following).render()
    leaked += "\n  endpoint: " + original["targets"][0]["endpoints"][0]
    assert any(
        endpoint in leaked for binding in original["targets"] for endpoint in binding["endpoints"]
    )


def test_a_truncated_document_is_a_finding_and_not_a_traceback(tmp_path: Path):
    """The read-back path's expected failure must be reportable.

    A supersession writes the document and then re-reads the STORED bytes,
    precisely so a truncated or partial write is caught. If that surfaces as a
    `JSONDecodeError` traceback, the one failure the check exists to detect is
    the one it reports worst, and an operator following the runbook is left
    with a stack trace instead of an instruction.

    Found by running the runbook's own negative case rather than by review.
    """
    from dotmac_observability.validate import InventoryError

    complete = REFERENCE_PRIVATE.read_text(encoding="utf-8")
    truncated = tmp_path / "truncated.json"
    truncated.write_text(complete[:200], encoding="utf-8")

    with pytest.raises(InventoryError) as raised:
        load_private_inventory(truncated, contracts=CONTRACTS)
    assert [finding.code for finding in raised.value.findings] == ["MALFORMED"]
    # The message has to name the read-back case, because that is the context
    # an operator will be in when they see it.
    assert "incomplete" in raised.value.findings[0].message
