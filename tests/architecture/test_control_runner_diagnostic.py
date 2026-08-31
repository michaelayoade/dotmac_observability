"""The query token stays hosted before a no-repository-secret runner job."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from scripts import require_runner
from scripts import verify_runner_token_boundary as boundary

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/control-runner-diagnostic.yml"
OWN = "michaelayoade/dotmac_observability"
FOREIGN = "michaelayoade/dotmac_starter_mt"
RUNNER = "control-runner-observability"
LABEL = "dotmac-observability-control"
REQUIRED_LABELS = (
    "self-hosted",
    "Linux",
    "X64",
    "dotmac-control-runner",
    LABEL,
)


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


def test_diagnostic_is_dispatch_only_and_main_only() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    triggers = text[: text.index("jobs:")]
    assert "workflow_dispatch:" in triggers
    for forbidden in ("pull_request", "pull_request_target", "push:", "schedule:"):
        assert forbidden not in triggers
    assert text.count("if: github.ref == 'refs/heads/main'") == 2


def test_self_hosted_job_has_exact_labels_and_no_injected_secret_or_action() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "permissions: {}" in text[: text.index("jobs:")]
    body = _jobs()["diagnostic"]
    assert f"runs-on: [{', '.join(REQUIRED_LABELS)}]" in body
    assert "secrets." not in body
    assert "uses:" not in body
    assert RUNNER in body
    for assertion in (
        'test "${RUNNER_OS}" = "Linux"',
        'test "${RUNNER_ARCH}" = "X64"',
        'test "$(id -u)" = "1003"',
        'test "$(id -un)" = "ghrun-observability"',
        '"ghrun-observability,ghrunners"',
        'test -n "${RUNNER_QUERY_TOKEN+x}"',
        "test -S /var/run/docker.sock",
    ):
        assert assertion in body


def test_query_secret_is_injected_only_in_the_hosted_boundary_job() -> None:
    jobs = _jobs()
    body = jobs["token-boundary"]
    assert "runs-on: ubuntu-latest" in body
    assert "permissions:\n      contents: read" in body
    assert "${{ secrets.RUNNER_QUERY_TOKEN }}" in body
    assert OWN in body
    assert FOREIGN in body
    for label in REQUIRED_LABELS:
        assert f"--label {label}" in body
    assert "persist-credentials: false" in body
    diagnostic = jobs["diagnostic"]
    assert "env:" not in diagnostic
    assert "secrets.RUNNER_QUERY_TOKEN" not in diagnostic


def _runner(
    *, status: str = "online", labels: tuple[str, ...] = REQUIRED_LABELS
) -> dict[str, object]:
    return {
        "name": RUNNER,
        "status": status,
        "busy": False,
        "labels": [{"name": label} for label in labels],
    }


def _runner_response(*, runner: dict[str, object] | None = None) -> bytes:
    return json.dumps({"runners": [runner or _runner()]}).encode()


def _argv() -> list[str]:
    argv = [
        "--own-repository",
        OWN,
        "--foreign-repository",
        FOREIGN,
        "--runner-name",
        RUNNER,
    ]
    for label in REQUIRED_LABELS:
        argv.extend(("--label", label))
    return argv


def _install_request(
    monkeypatch,
    *,
    own_status: int = 200,
    foreign_status: int = 403,
    runner: dict[str, object] | None = None,
) -> None:
    response = _runner_response(runner=runner)

    def request(repository: str, token: str) -> tuple[int, bytes]:
        assert token == "opaque-test-value"
        if repository == OWN:
            return own_status, response
        assert repository == FOREIGN
        return foreign_status, b""

    monkeypatch.setenv("RUNNER_QUERY_TOKEN", "opaque-test-value")
    monkeypatch.setattr(boundary, "_request", request)


def test_boundary_accepts_only_own_200_foreign_403(monkeypatch) -> None:
    _install_request(monkeypatch)
    assert boundary.main(_argv()) == 0


@pytest.mark.parametrize(
    ("own_status", "foreign_status"),
    ((403, 403), (200, 404), (200, 401), (200, 200)),
)
def test_boundary_refuses_every_other_status_pair(
    monkeypatch, own_status: int, foreign_status: int
) -> None:
    _install_request(monkeypatch, own_status=own_status, foreign_status=foreign_status)
    assert boundary.main(_argv()) == 3


def test_boundary_refuses_an_offline_runner(monkeypatch) -> None:
    _install_request(monkeypatch, runner=_runner(status="offline"))
    assert boundary.main(_argv()) == 3


def test_boundary_refuses_a_runner_missing_one_required_label(monkeypatch) -> None:
    _install_request(monkeypatch, runner=_runner(labels=REQUIRED_LABELS[:-1]))
    assert boundary.main(_argv()) == 3


def test_preflight_requires_the_repository_specific_label(monkeypatch) -> None:
    monkeypatch.setenv("RUNNER_QUERY_TOKEN", "opaque-test-value")
    monkeypatch.setattr(
        require_runner, "_query", lambda repository, token: (200, _runner_response())
    )
    argv = ["--repository", OWN]
    for label in REQUIRED_LABELS:
        argv.extend(("--label", label))
    assert require_runner.main(argv) == 0
    monkeypatch.setattr(
        require_runner,
        "_query",
        lambda repository, token: (
            200,
            _runner_response(runner=_runner(labels=REQUIRED_LABELS[:-1])),
        ),
    )
    assert require_runner.main(argv) == require_runner.EXIT_REFUSED
