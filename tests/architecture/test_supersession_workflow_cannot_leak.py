"""The private-inventory workflows must not leak, over-reach, or run anywhere.

Content tests prove the CLI does not leak. They say nothing about the workflows
that run it, and a workflow is the easier place to get this wrong: one
`upload-artifact` step added later to help diagnose a failure would publish the
document while every content test stayed green. The failure path is where this
normally happens, because the handler that gathers context to explain a failure
is the handler that ships the thing.

So the guard is structural and reads the workflows' own text. Four families of
property, each of which was a real defect in an earlier draft:

* **Nothing that publishes**, and **nowhere to publish from** — the document
  lives only under `$RUNNER_TEMP`, so an upload rooted at the checkout could
  not reach it even if one were added.
* **Nowhere to run but the named runner.** OpenBao's listener sits behind an
  inventory-derived allowlist with a terminal DROP on both address families;
  a hosted runner arrives from a dynamic range, and reopening the allowlist to
  reach one would undo the containment to serve a convenience.
* **No credential above the step that needs it.** A job-level `env` hands the
  production token to checkout, the setup actions and every dependency
  `poetry install` executes.
* **A reader that cannot write, and a writer that cannot list.** One identity
  able to do both is the thing to eliminate.

Comments are stripped before the executable scan. The workflows discuss `set
-x` and destroy endpoints in prose precisely to explain why they avoid them,
and `.data.metadata.version` is a legitimate KV read while a `/metadata`
endpoint call would delete the version history rule 21 requires be retained. A
guard that could not tell those apart would force the files to stop explaining
themselves.
"""

from __future__ import annotations

import re

import pytest

from tests.conftest import REPO_ROOT

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SUPERSEDE = WORKFLOWS / "private-inventory-supersede.yml"
DISCOVER = WORKFLOWS / "private-inventory-discover.yml"
BOTH = (SUPERSEDE, DISCOVER)

READER_SECRET = "OPENBAO_INVENTORY_READER_TOKEN"
WRITER_SECRET = "OPENBAO_INVENTORY_WRITER_TOKEN"


def _executable(text: str) -> str:
    """The workflow with comment lines and trailing comments removed."""
    kept: list[str] = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        kept.append(line.split(" #", 1)[0])
    return "\n".join(kept)


def _text(path):
    return path.read_text(encoding="utf-8")


def _code(path):
    return _executable(_text(path))


# ── The corpus is real ──────────────────────────────────────────────────────


def test_both_workflows_exist_and_the_stripper_kept_the_code():
    for path in BOTH:
        assert path.is_file(), f"{path.name} is missing"
        code = _code(path)
        assert "curl" in code and "RUNNER_TEMP" in code
        assert len(code.splitlines()) > 40


def test_the_stripper_removes_prose_but_not_code():
    """Sensitivity proof for the stripper itself.

    The workflows deliberately mention `set -x` in comments explaining why it
    is absent. If the stripper stopped working, that prose would be read as
    code — or, far worse, a real `set -x` would be excused as prose.
    """
    assert "set -x" in _text(SUPERSEDE), "the workflow no longer explains why it avoids tracing"
    assert "set -x" not in _code(SUPERSEDE)
    sample = _executable("run: echo hi  # set -x\n# set -x\nrun: set -e\n")
    assert "set -x" not in sample and "set -e" in sample


# ── Nothing that publishes ──────────────────────────────────────────────────

_PUBLISHERS = (
    "upload-artifact",
    "download-artifact",
    "GITHUB_STEP_SUMMARY",
    "ACTIONS_STEP_DEBUG",
    "ACTIONS_RUNNER_DEBUG",
    "tmate",
    "continue-on-error",
)


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
@pytest.mark.parametrize("forbidden", _PUBLISHERS)
def test_no_workflow_carries_anything_that_publishes(path, forbidden: str):
    # The WHOLE file, comments included: there is no legitimate reason for
    # either workflow to name any of these, so a mention is a change worth
    # failing on rather than a discussion worth allowing.
    assert forbidden not in _text(path), (
        f"{forbidden!r} appears in {path.name}. The private inventory must never leave the "
        "runner; if this is genuinely needed it takes a reviewed change to this guard first"
    )


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
@pytest.mark.parametrize("forbidden", ["set -x", "bash -x", "/destroy", "/metadata"])
def test_no_workflow_traces_or_destroys(path, forbidden: str):
    # Executable lines only. `.data.metadata.version` is a legitimate KV read;
    # a `/metadata` ENDPOINT call would delete the version history that every
    # receipt naming a superseded version depends on.
    assert forbidden not in _code(path), f"{forbidden!r} appears in executable {path.name}"


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_the_document_lives_only_under_runner_temp(path):
    assigned = re.findall(r'work="([^"]+)"', _code(path))
    assert assigned, f"{path.name}: no working directory found; the matcher has drifted"
    for value in set(assigned):
        assert value.startswith("${RUNNER_TEMP}"), (
            f"{path.name}: working directory {value!r} is not under $RUNNER_TEMP; a document "
            "in the checkout can be collected by any artifact step added later"
        )
    assert "GITHUB_WORKSPACE" not in _code(path)


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_only_the_shred_step_runs_on_failure(path):
    code = _code(path)
    assert code.count("if: always()") == 1, f"{path.name} has more than one always() step"
    assert (
        "rm -rf" in code[code.index("if: always()") :]
    ), f"{path.name}'s always() step is not the one that shreds the working copies"


# ── Nowhere to run but the named runner ─────────────────────────────────────


# The named dedicated fixed-egress runner. A LITERAL label pair, not a
# repository variable: a variable can be repointed at a hosted runner without
# touching either workflow or this guard, and with no matching runner
# registered a literal leaves the job QUEUED rather than silently rerouted.
RUNNER = "[self-hosted, dotmac-control-runner]"

_HOSTED = ("ubuntu-latest", "ubuntu-22", "ubuntu-24", "windows-", "macos-", "-latest")


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_neither_workflow_runs_on_a_hosted_runner(path):
    runs_on = re.findall(r"^\s*runs-on:\s*(.+)$", _code(path), re.MULTILINE)
    assert len(runs_on) == 1, f"{path.name} declares {len(runs_on)} runs-on"
    declared = runs_on[0].strip()
    assert declared == RUNNER, (
        f"{path.name} pins its runner to {declared!r}, not {RUNNER}. OpenBao is contained "
        "behind an allowlist with a terminal DROP; a hosted runner arrives from a dynamic "
        "range, and widening the allowlist to reach one would undo the containment"
    )
    for hosted in _HOSTED:
        assert hosted not in declared


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_the_runner_is_not_indirected_through_a_variable(path):
    """A literal, so there is nothing to repoint.

    `runs-on: ${{ vars.X }}` reads well and is worse here: the variable can be
    changed to a hosted label in repository settings, which touches neither
    workflow nor this guard, and the change would not appear in any diff.
    """
    runs_on = re.findall(r"^\s*runs-on:\s*(.+)$", _code(path), re.MULTILINE)[0]
    assert "vars." not in runs_on and "${{" not in runs_on


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_no_workflow_needs_the_runner_to_be_reachable(path):
    """The runner polls OUTBOUND and is never reached. Michael's ruling.

    Inbound SSH stays closed and no dstnat is added, so a workflow that needed
    to be called back would be a design error rather than a missing firewall
    rule. The temptation arrives disguised as plumbing — a callback, a webhook,
    a health endpoint — and each would put a listener on a host chosen
    precisely for having none.

    `services:` and `ports:` are how a job opens one in practice, so they are
    the shapes refused here.
    """
    code = _code(path)
    for forbidden in ("services:", "ports:", "--publish", "-p 0.0.0.0"):
        assert forbidden not in code, (
            f"{path.name} contains {forbidden!r}, which opens a listener on the runner. It "
            "polls outbound and is never reached; if a workflow appears to need inbound "
            "reachability, the workflow is wrong"
        )


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_no_workflow_hardcodes_an_address(path):
    """Neither the store's address nor the runner's may be written down here.

    Both are resolved material under ADR-0004 and both arrive from
    configuration: the store's from a secret, the runner's from nowhere at all
    — a self-hosted runner is selected by LABEL, and its egress address is a
    property of the network rather than an input to a job.

    The repository-wide private-material scanner already refuses an address in
    any tracked file. This is narrower and worth having anyway, because the
    plausible mistake is specific: pinning a workflow to the host it is
    "supposed" to run on by writing the address into a comment or a check, at
    which point the address is published and the pin is decorative.
    """
    text = _text(path)
    v4 = re.findall(r"(?<![\w.])(?!127\.)(?!0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text)
    # A prefix LENGTH is policy rather than an address — the runbook has to be
    # able to say "an exact /32, never the /22" — so only a full address is
    # refused here.
    assert not v4, f"{path.name} hardcodes address(es) {sorted(set(v4))}"


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_each_workflow_also_refuses_a_hosted_runner_at_run_time(path):
    # Belt and braces with `runs-on`: a repository variable can be repointed
    # without touching the file, and the containment argument depends on where
    # this actually executes.
    assert "RUNNER_ENVIRONMENT:-" in _code(path)


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_each_workflow_runs_only_by_dispatch_from_protected_main(path):
    code = _code(path)
    assert "workflow_dispatch:" in code
    for trigger in ("  push:", "  pull_request:", "  schedule:"):
        assert trigger not in code, f"{path.name}: {trigger.strip()} would run this unbidden"
    assert "if: github.ref == 'refs/heads/main'" in code


# ── No credential above the step that needs it ──────────────────────────────


@pytest.mark.parametrize("path", BOTH, ids=lambda p: p.name)
def test_no_workflow_declares_a_job_level_env(path):
    """A job-level `env` is inherited by every step, including third-party ones.

    Job properties sit at four spaces and step properties at eight, so the
    indentation distinguishes them without parsing YAML.
    """
    job_level = re.findall(r"^    env:\s*$", _code(path), re.MULTILINE)
    assert not job_level, (
        f"{path.name} declares a job-level env. checkout, the setup actions and everything "
        "`poetry install` executes would inherit whatever it holds"
    )
    assert re.search(
        r"^        env:\s*$", _code(path), re.MULTILINE
    ), f"{path.name} declares no step-level env at all; the matcher has drifted"


def test_the_writer_credential_appears_only_after_the_tool_is_verified():
    code = _code(SUPERSEDE)
    assert "poetry check --lock" in code, "the tool verification step is gone"
    verified_at = code.index("poetry check --lock")
    first_use = code.index(WRITER_SECRET)
    assert verified_at < first_use, (
        "the writer credential is introduced before the tool is verified; verification is "
        "what earns the token, so it cannot come after it"
    )


def test_every_step_touching_the_store_names_its_credential_explicitly():
    # Each mutation step carries its own env block rather than inheriting one,
    # so removing a step cannot silently widen another's reach.
    code = _code(SUPERSEDE)
    assert (
        code.count(WRITER_SECRET) == 3
    ), "expected the writer credential in exactly the read, write and read-back steps"


# ── A reader that cannot write, a writer that cannot list ───────────────────


def test_the_two_workflows_use_different_identities():
    assert READER_SECRET in _code(DISCOVER)
    assert WRITER_SECRET not in _code(DISCOVER), (
        "discovery names the writer credential. Discovery needs no write capability at all, "
        "and an identity that can do both is the thing to eliminate"
    )
    assert WRITER_SECRET in _code(SUPERSEDE)
    assert READER_SECRET not in _code(SUPERSEDE)


def test_discovery_cannot_mutate():
    code = _code(DISCOVER)
    for forbidden in ("-X POST", "-X PUT", "-X DELETE", '"cas"', "cas:"):
        assert forbidden not in code, (
            f"discovery contains {forbidden!r}. It reports and stops; the token it uses "
            "cannot write, and the file must not pretend otherwise"
        )
    assert "inventory-apply" not in code


# ── The reviewed request, not a runtime discovery ───────────────────────────


def test_the_mutation_confirms_the_shape_rather_than_discovering_it():
    code = _code(SUPERSEDE)
    assert "request-shape" in code, "the shape no longer comes from the reviewed request"
    assert "the store disagrees" in code, "no refusal on a shape mismatch"
    # The giveaway of the old design: branching on what the store looks like
    # instead of on what the request declared.
    assert "if jq -e " not in code.replace("jq -e --arg", ""), (
        "the mutation is branching on the store's shape again; it must branch on the "
        "reviewed request and refuse when the store disagrees"
    )


def test_the_request_path_cannot_escape_the_repository():
    assert "*..*" in _code(SUPERSEDE)


def test_it_refuses_to_run_before_the_public_inventory_exists():
    assert "inventory/control-plane.toml" in _code(SUPERSEDE)


# ── Sensitivity: the guard must fail on the edits it exists to catch ────────


def test_planting_an_artifact_upload_is_caught():
    planted = _text(SUPERSEDE) + (
        "\n      - name: Debug\n        if: failure()\n"
        "        uses: actions/upload-artifact@v4\n"
    )
    assert any(token in planted for token in _PUBLISHERS)
    assert not any(token in _text(SUPERSEDE) for token in _PUBLISHERS)


def test_planting_an_inbound_listener_is_caught():
    # The plausible version: a "health endpoint" so something can check on the
    # run. Harmless-looking, and it needs the runner to be reachable.
    planted = _executable(
        _text(SUPERSEDE) + "\n      - name: Health\n        ports:\n          - 8080:8080\n"
    )
    assert "ports:" in planted
    assert "ports:" not in _code(SUPERSEDE)


def test_planting_the_runner_address_is_caught():
    # The specific plausible mistake: pinning the workflow to "the right host"
    # by writing its address into a check, which publishes the address and
    # leaves the pin decorative.
    # Built at run time rather than written as a literal. The repository-wide
    # scanner reads THIS file too, and it is not in PRIVATE_SCAN_EXCLUSIONS —
    # correctly, because that list's premise is "the detector and its proof",
    # and this is the proof for a different detector. Assembling the address
    # keeps the exclusion list at exactly two entries instead of widening it
    # past its stated premise for a test's convenience.
    address = ".".join(("198", "51", "100", "7"))
    planted = _text(SUPERSEDE).replace(
        "RUNNER_ENVIRONMENT:-", f'RUNNER_IP:-}}" = "{address}" ] || exit 1; [ "${{X:-'
    )
    pattern = r"(?<![\w.])(?!127\.)(?!0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
    assert re.findall(pattern, planted)
    assert not re.findall(pattern, _text(SUPERSEDE))


def test_planting_a_hosted_runner_is_caught():
    planted = _executable(_text(SUPERSEDE).replace(RUNNER, "ubuntu-latest"))
    found = re.findall(r"^\s*runs-on:\s*(.+)$", planted, re.MULTILINE)
    assert found and found[0].strip() != RUNNER


def test_indirecting_the_runner_through_a_variable_is_caught():
    # The subtler regression: still not hosted, but now repointable in
    # repository settings without a diff anyone would review.
    planted = _executable(_text(SUPERSEDE).replace(RUNNER, "${{ vars.RUNNER }}"))
    found = re.findall(r"^\s*runs-on:\s*(.+)$", planted, re.MULTILINE)[0]
    assert "vars." in found
    assert "vars." not in re.findall(r"^\s*runs-on:\s*(.+)$", _code(SUPERSEDE), re.MULTILINE)[0]


def test_planting_a_job_level_env_is_caught():
    planted = _executable(
        _text(SUPERSEDE).replace(
            "    environment: private-inventory",
            "    environment: private-inventory\n    env:\n      BAO_TOKEN: x",
        )
    )
    assert re.findall(r"^    env:\s*$", planted, re.MULTILINE)
    assert not re.findall(r"^    env:\s*$", _code(SUPERSEDE), re.MULTILINE)


def test_giving_discovery_the_writer_credential_is_caught():
    planted = _executable(_text(DISCOVER).replace(READER_SECRET, WRITER_SECRET))
    assert WRITER_SECRET in planted
    assert WRITER_SECRET not in _code(DISCOVER)


def test_planting_shell_tracing_is_caught():
    planted = _executable(_text(SUPERSEDE) + "\n        run: |\n          set -x\n")
    assert "set -x" in planted and "set -x" not in _code(SUPERSEDE)


def test_planting_a_destroy_endpoint_is_caught():
    planted = _executable(_text(SUPERSEDE) + '\n        run: curl "${BAO_ADDR}/v1/x/destroy/y"\n')
    assert "/destroy" in planted and "/destroy" not in _code(SUPERSEDE)


def test_moving_the_document_into_the_workspace_is_caught():
    planted = _executable(
        _text(SUPERSEDE).replace('work="${RUNNER_TEMP}/inventory"', 'work="./inv"')
    )
    assigned = re.findall(r'work="([^"]+)"', planted)
    assert assigned, "the mutation changed nothing; the search string has drifted"
    assert not all(value.startswith("${RUNNER_TEMP}") for value in assigned)


def test_adding_a_second_always_step_is_caught():
    planted = _executable(_text(SUPERSEDE) + "\n      - if: always()\n        run: env\n")
    assert planted.count("if: always()") == 2
    assert _code(SUPERSEDE).count("if: always()") == 1


def test_removing_the_protected_main_guard_is_caught():
    planted = _executable(_text(SUPERSEDE).replace("if: github.ref == 'refs/heads/main'", ""))
    assert "if: github.ref == 'refs/heads/main'" not in planted


def test_adding_a_push_trigger_is_caught():
    planted = _executable(
        _text(SUPERSEDE).replace("on:\n  workflow_dispatch:", "on:\n  push:\n  workflow_dispatch:")
    )
    assert "  push:" in planted and "  push:" not in _code(SUPERSEDE)


# ── The host binding a migration needs (ADR-0008) ───────────────────────────
#
# A migration is the one change that carries a resolved value the store does
# not already hold: the accepted contract requires `host.identity` and
# `host.ssh_alias`, and the capture format has no `host` key at all. It arrives
# as a repository SECRET — neither public Git nor a CI input, which is the
# distinction rule 21 draws — and the properties below are what keep that true.

HOST_BINDING_SECRET = "OBSERVABILITY_HOST_BINDING"


def test_the_host_binding_is_a_secret_and_never_a_dispatch_input():
    """An input is echoed into the run's own record; a secret is not.

    `workflow_dispatch` inputs appear in the run summary, in the API and in
    `github.event.inputs` for every later step. A host identity typed into one
    is published to everybody who can read the run.
    """
    text = _text(SUPERSEDE)
    assert HOST_BINDING_SECRET in text
    inputs = text[text.index("    inputs:") : text.index("permissions:")]
    for forbidden in ("identity", "ssh_alias", "host_binding", HOST_BINDING_SECRET):
        assert forbidden not in inputs, (
            f"{forbidden!r} appears among the dispatch inputs. Dispatch inputs are recorded "
            "with the run; the host binding is a secret for exactly that reason"
        )


def test_the_host_binding_is_injected_into_exactly_one_step():
    """The INJECTION is counted, not every mention of the name.

    The step also names the secret in the message it prints when the secret is
    unset, which is the one place naming it is useful — an operator reading
    "not configured" needs to know what to configure. What must stay singular
    is `secrets.<name>`, which is the expression that actually puts the value
    into an environment.
    """
    code = _code(SUPERSEDE)
    assert code.count(f"secrets.{HOST_BINDING_SECRET}") == 1, (
        "the host binding is injected into more than one step. Like the writer credential it "
        "lives only where it is used; a second injection is a second place it can be read from"
    )


def test_the_host_binding_is_shredded_in_its_own_step_and_not_only_at_the_end():
    """Shredded twice, and the first one is the one that matters.

    The `always()` step removes the whole working directory, which covers the
    failure path. But the host binding is needed for one command and the job
    continues afterwards — writing to the store, reading back, resolving — so
    leaving it on disk for the rest of the run widens its exposure for no
    reason at all.
    """
    code = _code(SUPERSEDE)
    apply_step = code[code.index(HOST_BINDING_SECRET) :]
    apply_step = apply_step[: apply_step.index("      - name:")]
    assert (
        "shred -u" in apply_step or "rm -f" in apply_step
    ), "the host binding file survives the step that used it"


def test_the_host_binding_lands_under_runner_temp_with_a_restrictive_umask():
    code = _code(SUPERSEDE)
    assert 'printf \'%s\' "${HOST_BINDING}" > "$work/host.json"' in code
    assert "umask 077" in code


def test_planting_the_host_binding_as_a_dispatch_input_is_caught():
    planted = _text(SUPERSEDE).replace(
        "      request:\n", "      host_binding:\n        type: string\n      request:\n"
    )
    inputs = planted[planted.index("    inputs:") : planted.index("permissions:")]
    assert "host_binding" in inputs
    original = _text(SUPERSEDE)
    assert (
        "host_binding"
        not in original[original.index("    inputs:") : original.index("permissions:")]
    )


# ── Classification before loading ───────────────────────────────────────────


def test_the_store_is_classified_before_anything_loads_it():
    """The step whose absence produced 68 schema errors in a digest tool.

    `inventory-digest` and `inventory-apply` both load the previous version
    through the ACCEPTED contract as their first act. On a store holding the
    pre-contract capture format that fails with a schema error list which reads
    as corruption — after the precondition guard has passed, because the guard
    only checks that public inventory exists.
    """
    code = _code(SUPERSEDE)
    assert "inventory-classify" in code, "the stored format is not classified before loading"
    assert code.index("inventory-classify") < code.index("inventory-digest"), (
        "the digest tool runs before the classifier, which is the ordering that produced the "
        "illegible failure in the first place"
    )
    assert "--expect" in code, "the classifier is reporting rather than gating"


def test_the_declared_previous_format_comes_from_the_reviewed_request():
    code = _code(SUPERSEDE)
    assert "previous_format" in code
    assert "load_supersession_request" in code, (
        "the kind and format are being read by something other than the contract's own parser; "
        "a second reader of the same document drifts from the contract"
    )


def test_a_migration_and_a_retirement_take_different_tools():
    code = _code(SUPERSEDE)
    assert "inventory-migrate" in code and "inventory-apply" in code
    assert (
        'if [ "${KIND}" = "migrate-capture" ]; then' in code
    ), "the branch is not on the reviewed request's kind"
