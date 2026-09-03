"""Every `procedure_ref` in the ingestion contract resolves to a tracked file.

An alert annotation that names a procedure is read at one moment: the moment
somebody is acting on the alert. A path that does not resolve is discovered
then, and it is the same failure as untested prose — worse, because it looks
like the procedure exists and somebody spends the first minutes of an incident
hunting for it.

`docs/runbooks/README.md` states the rule this guard enforces the other half
of: a runbook lands in the same change as the capability it describes, never
before. So a `procedure_ref` either names a written runbook, or it names the
register that says the procedure is owed and what it must answer. What it may
never name is a file that is not there.
"""

from __future__ import annotations

import tomllib

from tests.conftest import REFERENCE, REPO_ROOT

DOCUMENTS = (
    REPO_ROOT / "inventory" / "ingestion.toml",
    REFERENCE / "inventory" / "ingestion.toml",
)


def _procedure_refs(document: dict[str, object]) -> list[str]:
    refs: list[str] = []
    deadman = document["deadman"]
    assert isinstance(deadman, dict)
    signals = deadman["signals"]
    assert isinstance(signals, list)
    for signal in signals:
        assert isinstance(signal, dict)
        sensitivity = signal["sensitivity"]
        assert isinstance(sensitivity, dict)
        refs.append(str(sensitivity["procedure_ref"]))
    projection = document["projection"]
    assert isinstance(projection, dict)
    rebuild = projection["rebuild"]
    assert isinstance(rebuild, dict)
    refs.append(str(rebuild["procedure_ref"]))
    return refs


def test_the_reader_found_something_to_check():
    """Sensitivity proof for the reader itself.

    A parser that has drifted returns an empty list, and a loop over an empty
    list passes every assertion below without looking at anything.
    """
    for path in DOCUMENTS:
        with path.open("rb") as handle:
            refs = _procedure_refs(tomllib.load(handle))
        assert len(refs) >= 3, f"{path} yielded {refs}, which is too few to be the whole set"


def test_every_procedure_reference_resolves_to_a_tracked_file():
    for path in DOCUMENTS:
        with path.open("rb") as handle:
            refs = _procedure_refs(tomllib.load(handle))
        for ref in refs:
            target = REPO_ROOT / ref
            assert target.is_file(), (
                f"{path.relative_to(REPO_ROOT)} names {ref!r}, which is not a tracked file. "
                "An alert annotation naming a procedure is read during an incident, and a "
                "path that does not resolve costs the first minutes of one"
            )
