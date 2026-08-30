"""The CI matrix equals `make check`, and the rotation proof cannot go vacuous.

`.github/workflows/ci.yml` says in a comment that its matrix "must equal `make
check`'s prerequisites EXACTLY", and names the failure it is guarding against:
the Starter shipped a matrix naming a subset, and formatting plus committed
assets then went unenforced on every pull request while `make check` still
passed on a developer's machine.

That was a stated review discipline with nothing enforcing it, which AGENTS.md
rule 15 says to either enforce or record as unmonitored. This enforces it.

The second half guards the rotation proof, which is the only check in this
repository that runs real external programs. Its value is entirely in its
NEGATIVE controls — three deliberately broken stanzas that must each fail — and
those controls locate themselves in the rendered stanza by exact string. A
renderer change that reworded the stanza would make every control mutate
nothing, every "failure" stop happening, and the job report success while
proving that a broken contract is fine.
"""

from __future__ import annotations

import re

from tests.conftest import REPO_ROOT

# Parsed with regexes rather than a YAML library, deliberately. This
# repository's single runtime dependency is `jsonschema`, and its CI installs
# nothing else; pulling in a parser so a guard can read a workflow would add a
# dependency to the whole project for one test. The shapes read below are two
# flat lists, which is well within what a regex can read correctly, and each
# matcher carries an assertion that it found something — a matcher that has
# drifted fails rather than silently comparing two empty lists.

CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPO_ROOT / "Makefile"
PROOF = REPO_ROOT / "scripts" / "rotation_proof.py"


def _check_prerequisites() -> list[str]:
    """`check:`'s prerequisites, following backslash continuations.

    Continuation-aware because the target currently spans two lines, and a
    matcher that read only the first would compare the matrix against a
    truncated set — passing while the drift it exists to catch went unseen.
    """
    text = MAKEFILE.read_text(encoding="utf-8")
    marker = "\ncheck:"
    assert marker in text, "the Makefile has no `check:` target; the matcher has drifted"
    lines: list[str] = []
    for line in text[text.index(marker) + 1 :].splitlines():
        lines.append(line)
        if not line.rstrip().endswith("\\"):
            break
    joined = " ".join(lines).replace("\\", " ")
    joined = re.sub(r"##.*", "", joined).replace("check:", "", 1)
    return joined.split()


def _matrix_targets() -> list[str]:
    text = CI.read_text(encoding="utf-8")
    block = re.search(r"^\s+target:\n((?:\s+- \S+\n)+)", text, re.MULTILINE)
    assert block, "the quality matrix's target list was not found; the matcher has drifted"
    return re.findall(r"- (\S+)", block.group(1))


def test_the_makefile_and_the_matrix_were_both_read():
    """Sensitivity: both sides of the comparison are non-empty and plausible."""
    prerequisites = _check_prerequisites()
    targets = _matrix_targets()
    assert len(prerequisites) >= 5, prerequisites
    assert len(targets) >= 5, targets
    assert "test" in prerequisites and "test" in targets


def test_the_quality_matrix_equals_make_checks_prerequisites():
    prerequisites = _check_prerequisites()
    targets = _matrix_targets()
    assert targets == prerequisites, (
        "the CI matrix and `make check` have drifted. A matrix naming a SUBSET is the "
        "documented past failure: the gate keeps passing locally while nothing enforces it on "
        f"a pull request.\n  make check: {prerequisites}\n  matrix:     {targets}"
    )


# ── the rotation proof ──────────────────────────────────────────────────────


def test_ci_runs_the_rotation_proof():
    text = CI.read_text(encoding="utf-8")
    assert "\n  rotation-proof:\n" in text
    job = text[text.index("\n  rotation-proof:\n") :]
    job = job[: job.index("\n  schemas:\n")]
    assert "scripts/rotation_proof.py" in job
    for tool in ("rsyslog", "logrotate"):
        assert tool in job, f"the job does not install {tool}, so it proves nothing about it"


def test_the_rotation_proof_never_touches_the_real_log_tree():
    """It runs as root, so what it may touch is asserted rather than trusted.

    `/var/log` legitimately appears in the script as a SEARCH string — the
    rendered artefacts name it, and the proof rewrites those paths to point at
    an isolated tree. What must never appear is `/var/log` as the ARGUMENT to a
    filesystem call, which is the difference between rewriting a path and
    opening one.
    """
    source = PROOF.read_text(encoding="utf-8")
    calls = re.compile(
        r"\b(open|touch|chmod|chown|mkdir|write_text|write_bytes|unlink|rmtree|copy2)\s*\("
        r"[^)]*/var/"
    )
    offenders = [line.strip() for line in source.splitlines() if calls.search(line)]
    assert not offenders, f"the proof performs filesystem calls on a real path: {offenders}"
    # It must not install, start or signal anything the host owns either. The
    # tokens are matched only as QUOTED LITERALS, for the same reason /var/log
    # is matched only as a call argument: the script's own prose explains why it
    # avoids these paths, and a guard that could not tell an explanation from a
    # use would force the file to stop explaining itself — the rule the
    # workflow-leak guard already settled by stripping comments.
    for forbidden in ("systemctl", "/etc/rsyslog", "/etc/logrotate"):
        for quote in ('"', "'"):
            assert (
                f"{quote}{forbidden}" not in source
            ), f"the proof names {forbidden!r} as a literal, so it touches host state"


def test_each_stanza_editing_control_actually_mutates_the_rendered_stanza():
    """The proof's proof, for the controls that edit the stanza.

    A control that locates itself by exact string mutates nothing once the
    renderer rewords that string, its deliberate failure stops happening, and
    the job reports that a broken contract is fine. The script checks this at
    run time too; this fails in the fast suite instead of only in the job that
    needs a runner with rsyslog.
    """
    from dotmac_observability.render import LOGROTATE_CONFIG, render_control_plane
    from dotmac_observability.validate import load
    from tests.conftest import CONTRACTS, REFERENCE, resolved

    stanza = dict(render_control_plane(load(REFERENCE, contracts=CONTRACTS), resolved(REFERENCE)))[
        LOGROTATE_CONFIG
    ]
    source = PROOF.read_text(encoding="utf-8")
    controls = re.findall(r'\("(    (?:create|postrotate)[^"]*)", ""\)', source)
    assert controls, "no stanza-editing control was found; the matcher has drifted"
    for control in controls:
        needle = control.encode().decode("unicode_escape")
        assert needle in stanza, (
            f"a negative control searches for {needle!r}, which the rendered stanza no longer "
            "contains. The control would mutate nothing and the proof would pass on a broken "
            "contract"
        )


def test_every_sabotage_the_controls_name_is_one_the_proof_implements():
    """The environment controls are strings, so a typo would silently do nothing.

    `no-tmpfiles`, `wrong-owner` and `wrong-mode` reach `_prepare` as plain
    values. A misspelled one falls through to the correct branch, the control
    then passes, and the run reports a broken contract as fine — which is
    exactly what the first two controls did before they were replaced, for a
    different reason.
    """
    source = PROOF.read_text(encoding="utf-8")
    named = set(re.findall(r'^\s+"(no-tmpfiles|wrong-owner|wrong-mode)",$', source, re.MULTILINE))
    handled = set(re.findall(r'sabotage == "([a-z-]+)"', source))
    assert named, "no environment control was found; the matcher has drifted"
    assert named == handled, (
        f"the controls name {sorted(named)} and _prepare handles {sorted(handled)}; a name "
        "with no branch falls through to the correct behaviour and passes"
    )
