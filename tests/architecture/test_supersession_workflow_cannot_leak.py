"""The supersession workflow must not be able to publish the private inventory.

Content tests prove the CLI does not leak. They say nothing about the workflow
that runs it, and a workflow is the easier place to get this wrong: one
`upload-artifact` step added later to help diagnose a failure would publish the
document while every content test stayed green. The failure path is where this
normally happens, because the handler that gathers context to explain a failure
is the handler that ships the thing.

So the guard is structural and it reads the workflow's own text. Two
independent properties, because either alone can be defeated:

* **Nothing that publishes.** No artifact upload, no job summary, no debug
  tracing, no remote shell.
* **Nowhere to publish FROM.** The document exists only under `$RUNNER_TEMP`
  and never in the checkout, so an upload rooted at the workspace could not
  reach it even if one were added.

Comments are stripped before the executable scan. The workflow discusses `set
-x` and destroy endpoints in prose precisely to explain why it does not use
them, and a guard that could not tell the two apart would force the file to
stop explaining itself.
"""

from __future__ import annotations

import re

import pytest

from tests.conftest import REPO_ROOT

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "private-inventory-supersede.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")


def _executable(text: str) -> str:
    """The workflow with comment lines and trailing comments removed."""
    kept: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        kept.append(line.split(" #", 1)[0])
    return "\n".join(kept)


EXECUTABLE = _executable(TEXT)


def test_the_workflow_exists_and_the_stripper_kept_the_code():
    # Without this, a renamed file or an over-eager stripper would make every
    # assertion below pass over an empty string.
    assert WORKFLOW.is_file()
    assert "inventory-apply" in EXECUTABLE
    assert "curl" in EXECUTABLE
    assert len(EXECUTABLE.splitlines()) > 80


def test_the_stripper_removes_prose_but_not_code():
    """Sensitivity proof for the stripper itself.

    The workflow deliberately mentions `set -x` in a comment explaining why it
    is absent. If the stripper stopped working, that comment would be read as
    code and the tracing check below would fail for the wrong reason — or, far
    worse, a real `set -x` would be excused as prose.
    """
    assert "set -x" in TEXT, "the workflow no longer explains why it avoids tracing"
    assert "set -x" not in EXECUTABLE
    sample = _executable("run: echo hello  # set -x\n# set -x\nrun: set -e\n")
    assert "set -x" not in sample
    assert "set -e" in sample


@pytest.mark.parametrize(
    "forbidden",
    [
        "upload-artifact",
        "download-artifact",
        "GITHUB_STEP_SUMMARY",
        "ACTIONS_STEP_DEBUG",
        "ACTIONS_RUNNER_DEBUG",
        "tmate",
        "continue-on-error",
    ],
)
def test_the_workflow_carries_nothing_that_publishes(forbidden: str):
    # Checked against the WHOLE file, comments included. There is no legitimate
    # reason for this workflow to name any of them, so a mention is a change
    # worth failing on rather than a discussion worth allowing.
    assert forbidden not in TEXT, (
        f"{forbidden!r} appears in the supersession workflow. The private inventory must "
        "never leave the runner; if this is genuinely needed, it needs a reviewed change to "
        "this guard first (AGENTS.md rule 21, ADR-0004)"
    )


@pytest.mark.parametrize("forbidden", ["set -x", "/destroy", "/metadata", "bash -x"])
def test_the_executable_workflow_neither_traces_nor_destroys(forbidden: str):
    # Executable lines only. `.data.metadata.version` is a legitimate KV read
    # and lives in the code; a `/metadata` ENDPOINT call would delete version
    # history, which is the evidence every receipt depends on.
    assert forbidden not in EXECUTABLE, (
        f"{forbidden!r} appears in an executable line. Tracing echoes the document into the "
        "log, and a destroy or metadata-delete endpoint removes the superseded version that "
        "AGENTS.md rule 21 requires be retained"
    )


def test_the_document_lives_only_under_runner_temp():
    """Nowhere to publish from, which is the half that survives a careless edit.

    Every path the private document is written to must be under `$RUNNER_TEMP`.
    An artifact upload is rooted at the workspace by default, so a document that
    is never in the workspace cannot be collected by one.
    """
    assigned = re.findall(r'work="([^"]+)"', EXECUTABLE)
    assert assigned, "no working directory assignment found; the matcher has drifted"
    for value in set(assigned):
        assert value.startswith("${RUNNER_TEMP}"), (
            f"the working directory {value!r} is not under $RUNNER_TEMP; a document in the "
            "checkout can be collected by any artifact step added later"
        )
    # And the workspace is never named as a destination for it.
    assert "GITHUB_WORKSPACE" not in EXECUTABLE


def test_only_the_shred_step_runs_on_failure():
    """A failure handler is how this class of workflow leaks.

    Exactly one `always()` step, and it must be the one that deletes the working
    copies. Any other always-run step is a candidate context-gatherer.
    """
    assert EXECUTABLE.count("if: always()") == 1
    tail = EXECUTABLE[EXECUTABLE.index("if: always()") :]
    assert "rm -rf" in tail, "the always() step is not the one that shreds the working copies"


def test_it_runs_only_by_dispatch_and_only_from_protected_main():
    assert "workflow_dispatch:" in EXECUTABLE
    for trigger in ("  push:", "  pull_request:", "  schedule:"):
        assert trigger not in EXECUTABLE, (
            f"{trigger.strip()} would run this without a human choosing to, and its whole "
            "safety argument rests on a reviewed request applied deliberately"
        )
    # `workflow_dispatch` lets a caller pick any ref that carries the workflow,
    # so without this a branch could supply both the workflow and the request it
    # applies — the review gate bypassed by choosing a dropdown value.
    assert "if: github.ref == 'refs/heads/main'" in EXECUTABLE


def test_it_asks_for_no_write_permission():
    assert "permissions:" in EXECUTABLE
    assert "contents: read" in EXECUTABLE
    assert (
        "write"
        not in re.sub(
            r"--data-binary|write\.json|written\.json|Write the next version", "", EXECUTABLE
        ).split("jobs:")[0]
    ), "the workflow requests a write permission it does not need"


def test_the_request_path_cannot_escape_the_repository():
    # The one caller-supplied value. A path input that accepts `/etc/...` or
    # `../` reaches outside the reviewed corpus, which would let a dispatch
    # apply something nobody merged.
    assert "*..*" in EXECUTABLE
    assert "case " in EXECUTABLE


def test_it_refuses_to_run_before_the_public_inventory_exists():
    """Both directions or neither.

    Superseding the private half while unable to compare it with the public
    half is the one-way check this repository refuses everywhere else: it passes
    while leaving orphans on the side nobody looked at.
    """
    assert "inventory/control-plane.toml" in EXECUTABLE


# ── Sensitivity: the guard must fail on the edits it exists to catch ─────────
#
# Every assertion above passes on a clean file, and would also pass if the
# checks were misspelled, if the parametrize list were empty, or if the
# stripper deleted everything. Each case below plants one realistic regression
# and requires the corresponding check to refuse it.


def _would_publish(text: str) -> bool:
    return any(
        token in text
        for token in (
            "upload-artifact",
            "download-artifact",
            "GITHUB_STEP_SUMMARY",
            "ACTIONS_STEP_DEBUG",
            "ACTIONS_RUNNER_DEBUG",
            "tmate",
            "continue-on-error",
        )
    )


def test_planting_an_artifact_upload_is_caught():
    # The exact edit the guard exists for: a debug artifact added to diagnose a
    # failing run, which would publish the private inventory.
    planted = TEXT + (
        "\n      - name: Debug\n"
        "        if: failure()\n"
        "        uses: actions/upload-artifact@v4\n"
        "        with:\n"
        "          path: ${RUNNER_TEMP}/inventory\n"
    )
    assert _would_publish(planted)
    assert not _would_publish(TEXT)


def test_planting_shell_tracing_is_caught():
    planted = _executable(TEXT + "\n        run: |\n          set -x\n          curl ...\n")
    assert "set -x" in planted
    assert "set -x" not in EXECUTABLE


def test_planting_a_destroy_endpoint_is_caught():
    planted = _executable(
        TEXT + '\n        run: curl -X POST "${BAO_ADDR}/v1/${BAO_MOUNT}/destroy/x"\n'
    )
    assert "/destroy" in planted
    assert "/destroy" not in EXECUTABLE


def test_moving_the_document_into_the_workspace_is_caught():
    planted = _executable(TEXT.replace('work="${RUNNER_TEMP}/inventory"', 'work="./inventory"'))
    assigned = re.findall(r'work="([^"]+)"', planted)
    assert assigned, "the mutation changed nothing; the search string has drifted"
    assert not all(value.startswith("${RUNNER_TEMP}") for value in assigned)


def test_adding_a_second_always_step_is_caught():
    planted = _executable(
        TEXT + "\n      - name: Collect context\n        if: always()\n        run: env\n"
    )
    assert planted.count("if: always()") == 2
    assert EXECUTABLE.count("if: always()") == 1


def test_removing_the_protected_main_guard_is_caught():
    planted = _executable(TEXT.replace("if: github.ref == 'refs/heads/main'", ""))
    assert "if: github.ref == 'refs/heads/main'" not in planted
    assert "if: github.ref == 'refs/heads/main'" in EXECUTABLE


def test_adding_a_push_trigger_is_caught():
    planted = _executable(
        TEXT.replace("on:\n  workflow_dispatch:", "on:\n  push:\n  workflow_dispatch:")
    )
    assert "  push:" in planted
    assert "  push:" not in EXECUTABLE
