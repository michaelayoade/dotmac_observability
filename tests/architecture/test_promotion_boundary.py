"""The promotion executor decides; it does not reach.

Two boundaries are asserted here, and both are the kind that erode by one
convenient exception at a time.

**No host I/O in this repository.** The mechanics of reaching a host belong to
`dotmac-deployment-foundation` (see the ownership table in
`docs/ARCHITECTURE.md`). A control plane that grew its own SSH transport, HTTP
client or `subprocess` call would be a second answer to how a release reaches a
host, and the second answer is the one that never gets the fixes. The check is
over IMPORTS rather than over behaviour, because an import is what a reviewer
can see and a network call three layers down is not.

**The state machine here is the state machine documented.** `STATES` and the
`PromotionFacility` methods are compared against the table in
`docs/ARCHITECTURE.md`. A stage added to one and not the other is a promotion
that skips a step nobody notices is missing.
"""

from __future__ import annotations

import ast
import re

import pytest

from dotmac_observability.promote import STATES
from tests.conftest import REPO_ROOT

SRC = REPO_ROOT / "src" / "dotmac_observability"
ARCHITECTURE = (REPO_ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")

# Modules that decide and compare. Named individually rather than globbed, so a
# NEW module is not silently covered by a rule nobody considered for it — and
# so a reader can see that the list is the promotion lane.
DECIDING_MODULES = ("live_verify.py", "receipt.py", "drift.py", "promote.py")

# Anything that could reach a host, a socket or another process. `json`,
# `hashlib` and `pathlib` are absent from this list deliberately: reading a
# document the caller names is not reaching anything.
FORBIDDEN_IMPORTS = frozenset(
    {
        "asyncio",
        "ftplib",
        "http",
        "httpx",
        "multiprocessing",
        "paramiko",
        "requests",
        "shutil",
        "socket",
        "ssl",
        "subprocess",
        "telnetlib",
        "urllib",
    }
)


def _imported_names(source: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_the_deciding_modules_all_exist():
    """Sensitivity: a scan over a list of missing files passes for the wrong reason."""
    missing = [name for name in DECIDING_MODULES if not (SRC / name).is_file()]
    assert not missing, f"the promotion lane names modules that do not exist: {missing}"


@pytest.mark.parametrize("name", DECIDING_MODULES)
def test_a_deciding_module_reaches_nothing(name):
    imported = _imported_names((SRC / name).read_text(encoding="utf-8"))
    reaching = sorted(imported & FORBIDDEN_IMPORTS)
    assert not reaching, (
        f"{name} imports {reaching}. Host effects belong to the promotion facility "
        "(`promote.PromotionFacility`), which this repository declares and does not "
        "implement — see docs/ARCHITECTURE.md's ownership table."
    )


def test_the_detector_would_catch_a_transport_import():
    """The scan above runs over a clean corpus, so it needs a planted positive."""
    planted = "import subprocess\nfrom urllib import request\n"
    assert _imported_names(planted) & FORBIDDEN_IMPORTS == {"subprocess", "urllib"}


# ── The state machine is the documented one ─────────────────────────────────


def _documented_states() -> list[str]:
    """The state names from the table in `docs/ARCHITECTURE.md` §"Promotion".

    Bounded at the next heading rather than read to the end of the file, so a
    later section growing a table of its own cannot silently extend the list
    this comparison is made against.
    """
    start = ARCHITECTURE.index("\n## Promotion")
    rest = ARCHITECTURE[start + 1 :]
    end = rest.index("\n## ", 1)
    rows = re.findall(r"^\| `([A-Z]+)` \|", rest[:end], re.MULTILINE)
    assert rows, "the promotion state table was not found; the matcher has drifted"
    return rows


def test_the_executor_walks_exactly_the_documented_states():
    assert list(STATES) == _documented_states()


def test_the_facility_declares_a_method_for_every_state_it_completes():
    """Every state has a host effect behind it, plus the rollback that undoes them.

    `VERIFIED` is completed by `observe` and `ACCEPTED` by `accept`, so the
    mapping is not name-for-name; what this asserts is that the Protocol has
    not grown a method with no state or lost one that had a state.
    """
    methods = _protocol_methods()
    assert methods == {
        "fetch",
        "check_configuration",
        "rehearse",
        "stage",
        "reload",
        "observe",
        "rollback",
        "accept",
    }


def test_the_repository_implements_no_promotion_facility():
    """The Protocol is declared here and implemented elsewhere, by design.

    A concrete implementation appearing in `src/` is the moment this repository
    becomes a deployment tool as well as a control plane, so it fails here
    rather than in a review. Test doubles are exempt: they live under `tests/`
    and reach nothing.
    """
    offenders: list[str] = []
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {
                base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
                for base in node.bases
            }
            if "PromotionFacility" in bases:
                offenders.append(f"{path.name}:{node.name}")
    assert not offenders, (
        f"{offenders} implement the promotion facility inside this repository. The mechanics "
        "belong to `dotmac-deployment-foundation`."
    )


def _protocol_methods() -> set[str]:
    """The Protocol's declared methods, read from the source.

    Read from the AST rather than with `dir()`, because a Protocol class also
    carries whatever the typing machinery of the running interpreter puts on
    it, and a set comparison against that is a test that fails on a Python
    upgrade for a reason unrelated to its subject.
    """
    tree = ast.parse((SRC / "promote.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PromotionFacility":
            return {
                item.name
                for item in node.body
                if isinstance(item, ast.FunctionDef) and not item.name.startswith("_")
            }
    raise AssertionError("PromotionFacility was not found in promote.py")
