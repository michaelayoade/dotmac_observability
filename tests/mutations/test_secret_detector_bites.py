"""Sensitivity proof for the secret scanner (AGENTS.md rules 1 and 15).

`test_no_tracked_file_carries_secret_material` passes on a clean repository.
It would also pass if the scanner had no patterns at all, if its regexes had
been broken by an edit, or if the file walk silently skipped everything. Each
test below plants one shape and requires the scanner to find it.

This file is one of the two paths in `SECRET_SCAN_EXCLUSIONS`, precisely
because it must contain the shapes being detected.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dotmac_observability.validate import scan_for_secret_material

# Fabricated, structurally valid, and matched to no real system.
PLANTED = {
    "SECRET-TELEGRAM-BOT-TOKEN": "bot_token = 1234567890:AAF-abcdefghijklmnopqrstuvwxyz01234\n",
    "SECRET-SLACK-WEBHOOK": "url = https://hooks.slack.com/services/T0000/B0000/xxxxxxxxxxxx\n",
    "SECRET-AWS-ACCESS-KEY": "key = AKIAIOSFODNN7EXAMPLE\n",
    "SECRET-PEM-PRIVATE-KEY": "-----BEGIN RSA PRIVATE KEY-----\n",
    "SECRET-ASSIGNED-CREDENTIAL": 'password = "hunter2-hunter2-hunter2"\n',
}


@pytest.mark.parametrize(("code", "planted"), sorted(PLANTED.items()))
def test_the_detector_finds_a_planted_secret(tmp_path: Path, code: str, planted: str):
    target = tmp_path / "inventory" / "planted.toml"
    target.parent.mkdir(parents=True)
    target.write_text(planted)
    findings = scan_for_secret_material(tmp_path, [target])
    assert [finding.code for finding in findings] == [code]
    assert findings[0].location.endswith(":1")


def test_the_detector_stays_quiet_on_the_shapes_this_repository_commits(tmp_path: Path):
    # The other half of sensitivity: a detector that flags everything gets an
    # allowlist bolted on until it flags nothing. These five lines are what
    # legitimate inventory looks like, and none of them may trip it.
    target = tmp_path / "clean.toml"
    target.write_text(
        'credential_ref = "telegram-oncall"\n'
        'target_id = "erp-production"\n'
        'bearer_token_file = "/etc/prometheus/secrets/erp-scrape.token"\n'
        'rules_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"\n'
        'image_digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"\n'
    )
    assert scan_for_secret_material(tmp_path, [target]) == ()


def test_an_excluded_path_is_skipped_but_only_that_path(tmp_path: Path):
    excluded = tmp_path / "src" / "dotmac_observability" / "validate.py"
    excluded.parent.mkdir(parents=True)
    excluded.write_text(PLANTED["SECRET-AWS-ACCESS-KEY"])
    other = tmp_path / "src" / "dotmac_observability" / "render.py"
    other.write_text(PLANTED["SECRET-AWS-ACCESS-KEY"])
    findings = scan_for_secret_material(tmp_path, [excluded, other])
    assert [finding.location for finding in findings] == ["src/dotmac_observability/render.py:1"]
