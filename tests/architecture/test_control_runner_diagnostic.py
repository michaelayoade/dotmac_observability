"""Runner workflows fail before queueing and prove repository containment."""

from __future__ import annotations

import json
import re
from pathlib import Path

from scripts import require_runner
from scripts import verify_runner_token_boundary as boundary

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/control-runner-diagnostic.yml"
OWN = "michaelayoade/dotmac_observability"
FOREIGN = "michaelayoade/dotmac_starter_mt"
RUNNER = "control-runner-observability"
LABEL = "dotmac-observability-control"


def _jobs() -> dict[str, str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    starts = [
        (match.group(1), match.start())
        for match in re.finditer(r"^  ([a-z][a-z0-9-]*):\s*$", text, re.MULTILINE)
    ]
    return {
        name: text[start : starts[index + 1][1] if index + 1 < len(starts) else len(text)]
        for index, (name, start) in enumerate(starts)
    }


def _runner_response(*, labels: list[str] | None = None) -> bytes:
    return json.dumps(
        {
            "runners": [
                {
                    "name": RUNNER,
                    "status": "online",
                    "busy": False,
                    "labels": [
                        {"name": label}
                        for label in labels or ["self-hosted", "dotmac-control-runner", LABEL]
                    ],
                }
            ]
        }
    ).encode()


def test_diagnostic_is_dispatch_only_and_main_only() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    triggers = text[: text.index("jobs:")]
    assert "workflow_dispatch:" in triggers
    for forbidden in ("pull_request", "pull_request_target", "push:", "schedule:"):
        assert forbidden not in triggers
    assert text.count("if: github.ref == 'refs/heads/main'") == 2


def test_self_hosted_job_has_exact_label_and_no_secret_or_action() -> None:
    body = _jobs()["diagnostic"]
    assert f"runs-on: [self-hosted, dotmac-control-runner, {LABEL}]" in body
    assert "secrets." not in body
    assert "uses:" not in body
    assert RUNNER in body


def test_token_exists_only_in_the_hosted_boundary_job() -> None:
    body = _jobs()["token-boundary"]
    assert "runs-on: ubuntu-latest" in body
    assert "RUNNER_QUERY_TOKEN" in body
    assert OWN in body
    assert FOREIGN in body


def test_boundary_refuses_anything_but_own_200_foreign_403(monkeypatch) -> None:
    response = _runner_response()

    def request(repository: str, token: str) -> tuple[int, bytes]:
        assert token == "opaque-test-value"
        return (200, response) if repository == OWN else (403, b"")

    monkeypatch.setenv("RUNNER_QUERY_TOKEN", "opaque-test-value")
    monkeypatch.setattr(boundary, "_request", request)
    argv = [
        "--own-repository",
        OWN,
        "--foreign-repository",
        FOREIGN,
        "--runner-name",
        RUNNER,
        "--label",
        "self-hosted",
        "--label",
        "dotmac-control-runner",
        "--label",
        LABEL,
    ]
    assert boundary.main(argv) == 0
    monkeypatch.setattr(boundary, "_request", lambda repository, token: (200, response))
    assert boundary.main(argv) == 3


def test_preflight_requires_the_repository_specific_label(monkeypatch) -> None:
    monkeypatch.setenv("RUNNER_QUERY_TOKEN", "opaque-test-value")
    monkeypatch.setattr(
        require_runner, "_query", lambda repository, token: (200, _runner_response())
    )
    argv = [
        "--repository",
        OWN,
        "--label",
        "self-hosted",
        "--label",
        "dotmac-control-runner",
        "--label",
        LABEL,
    ]
    assert require_runner.main(argv) == 0
    monkeypatch.setattr(
        require_runner,
        "_query",
        lambda repository, token: (
            200,
            _runner_response(labels=["self-hosted", "dotmac-control-runner"]),
        ),
    )
    assert require_runner.main(argv) == require_runner.EXIT_REFUSED
