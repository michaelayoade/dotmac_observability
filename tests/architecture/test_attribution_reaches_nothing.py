"""The attribution lane decides and parses. It does not reach.

`tests/architecture/test_promotion_boundary.py` asserts this for the promotion
modules and names them individually, "so a NEW module is not silently covered
by a rule nobody considered for it". These two modules have now been considered
for it, and they are held to the same rule here rather than appended to that
list -- because they need one narrow exemption that the promotion lane does not,
and burying an exemption inside a list that has none would weaken a guard that
is currently absolute.

**The exemption, with its premise stated.** `urllib.parse` is permitted; every
other part of `urllib` is not. The premise is that `urlsplit` is string
parsing, which reaches nothing -- the same reason `json` and `pathlib` are
absent from the promotion lane's forbidden list ("reading a document the caller
names is not reaching anything"). `urllib.request` IS a transport and is
refused, so the exemption is checked at submodule granularity rather than taken
on trust.

Hand-rolling a DSN splitter to avoid the import was considered and rejected.
The parse decides which values get poisoned; a subtle mis-parse there means a
host or a user is never poisoned and the vault cannot refuse it. Trading a
battle-tested parser for a tidier import list would move risk from a guard that
a reviewer can read into code that a reviewer cannot.
"""

from __future__ import annotations

import ast
import re

import pytest

from tests.conftest import REPO_ROOT

SRC = REPO_ROOT / "src" / "dotmac_observability"

# Named individually, matching the promotion lane's convention and for the same
# stated reason: a new module joins by decision, never by glob.
ATTRIBUTION_MODULES = ("attribution.py", "attribution_enumerators.py")

FORBIDDEN_IMPORTS = frozenset(
    {
        "asyncio",
        "ftplib",
        "http",
        "httpx",
        "multiprocessing",
        "paramiko",
        "requests",
        "socket",
        "ssl",
        "subprocess",
        "telnetlib",
        "urllib",
    }
)

# The single exemption, spelled as the FULL dotted name it permits. `urllib`
# stays forbidden; `urllib.parse` is the one member allowed through.
PERMITTED_SUBMODULES = frozenset({"urllib.parse"})


def _imports(source: str) -> set[str]:
    """Every imported name, as its full dotted path.

    Full paths rather than top-level packages, because the whole exemption
    below turns on the difference between `urllib.parse` and `urllib.request`.
    Function-level imports are included -- `ast.walk` descends into function
    bodies -- which matters because a module that wanted to hide a transport
    would put the import inside the function that uses it.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            # The MEMBER, not the bare module. `from urllib import request`
            # records `urllib.request` rather than `urllib`, which is the
            # difference the exemption below turns on -- recording the bare
            # module would make that import indistinguishable from
            # `from urllib import parse` and force the exemption to be
            # package-wide, which is exactly the hole it must not be.
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _permitted(name: str) -> bool:
    return any(
        name == allowed or name.startswith(f"{allowed}.") for allowed in PERMITTED_SUBMODULES
    )


def _reaching(names: set[str]) -> set[str]:
    return {
        name for name in names if name.split(".")[0] in FORBIDDEN_IMPORTS and not _permitted(name)
    }


def test_the_attribution_modules_all_exist():
    """Sensitivity: a scan over a list of missing files passes for nothing."""
    missing = [name for name in ATTRIBUTION_MODULES if not (SRC / name).is_file()]
    assert not missing, f"the attribution lane names modules that do not exist: {missing}"


@pytest.mark.parametrize("name", ATTRIBUTION_MODULES)
def test_an_attribution_module_reaches_nothing(name):
    reaching = sorted(_reaching(_imports((SRC / name).read_text(encoding="utf-8"))))
    assert not reaching, (
        f"{name} imports {reaching}. Reading a host belongs to whatever implements "
        "`attribution_enumerators.HostSource`, a Protocol this repository DECLARES and "
        "does not implement -- the same split as `promote.PromotionFacility`."
    )


def test_the_detector_would_catch_a_transport_import():
    """A scan over a clean corpus proves nothing about itself."""
    planted = "import subprocess\nfrom urllib import request\nimport httpx\n"
    assert _reaching(_imports(planted)) == {"subprocess", "urllib.request", "httpx"}
    # And a bare `import urllib`, which cannot be narrowed and so fails closed.
    assert _reaching(_imports("import urllib\n")) == {"urllib"}


def test_the_exemption_is_submodule_precise_and_not_a_package_hole():
    """The near-miss that would make the exemption worthless.

    Permitting `urllib` wholesale would let `urllib.request` -- an HTTP client
    -- in under a premise written about string parsing. So the permitted set is
    asserted to admit exactly one member and to refuse its sibling.
    """
    assert {"urllib.parse"} == PERMITTED_SUBMODULES
    assert _reaching({"urllib.parse"}) == set()
    assert _reaching({"urllib.request"}) == {"urllib.request"}
    assert _reaching({"urllib"}) == {"urllib"}


def test_the_exemption_is_actually_used_or_it_should_be_deleted():
    """An exemption covering nothing has stopped describing anything.

    Same discipline as `test_the_module_allowed_to_name_a_host_is_the_detector
    _and_uses_it`: if the parse moves elsewhere, the permission is removed
    rather than left lying around for the next module to find.
    """
    used = {
        allowed
        for name in ATTRIBUTION_MODULES
        for imported in _imports((SRC / name).read_text(encoding="utf-8"))
        for allowed in PERMITTED_SUBMODULES
        if imported == allowed or imported.startswith(f"{allowed}.")
    }
    assert used == PERMITTED_SUBMODULES, (
        "an exemption is granted that nothing uses; delete it rather than leaving it to "
        "cover a module that does not need it"
    )


def test_the_seam_is_declared_and_not_implemented_here():
    """No concrete host source ships in this repository.

    A class in `src/` implementing all four seam methods would be the second
    answer to how a host is touched, and the second answer is the one that
    never gets the fixes. Checked structurally rather than by naming the
    classes that do not exist.
    """
    seam = {"exists", "list_dir", "read_text", "run"}
    offenders: list[str] = []
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            methods = {
                item.name
                for item in node.body
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
            }
            bases = {base.id for base in node.bases if isinstance(base, ast.Name)}
            if seam <= methods and "Protocol" not in bases:
                offenders.append(f"{path.name}:{node.name}")
    assert not offenders, (
        f"{offenders} implements the host seam. `HostSource` is declared here and "
        "implemented by whoever owns reaching a host (docs/ARCHITECTURE.md, Ownership)."
    )


def test_that_seam_detector_would_notice_an_implementation():
    """Planted positive for the check above, which otherwise scans a clean tree."""
    planted = ast.parse(
        "class RealHost:\n"
        "    def exists(self, p): ...\n"
        "    def list_dir(self, d): ...\n"
        "    def read_text(self, p): ...\n"
        "    def run(self, a): ...\n"
    )
    node = next(n for n in ast.walk(planted) if isinstance(n, ast.ClassDef))
    methods = {i.name for i in node.body if isinstance(i, ast.FunctionDef)}
    assert {"exists", "list_dir", "read_text", "run"} <= methods
    assert not {b.id for b in node.bases if isinstance(b, ast.Name)}


# ── Failures are values, not classes (ruling 1) ─────────────────────────────
#
# The seam's failure half must survive an artifact boundary. It did not: a
# `HostSource` implementation lives in another distribution, so an `isinstance`
# check against a class defined here is always False and its failure mode is
# silent -- the exception falls through to the catch-all and is misclassified.
# The concrete consequence was a clean host with no `/etc/cron.d` reporting a
# parse error on `cron`.
#
# These checks are static and structural because the behavioural proofs live in
# `tests/mutations/test_attribution_seam_is_structural.py`. The pair is
# deliberate: the battery proves the current code classifies correctly, and
# these prove the SHAPE that made it wrong cannot come back.

_NOMINAL_MATCH = re.compile(r"isinstance\s*\(\s*(?:error|exc|exception)\b")
_SOURCE_EXCEPT = re.compile(r"except\s+\(?\s*Source[A-Za-z]*")


def test_no_attribution_module_matches_an_exception_by_class():
    for name in ATTRIBUTION_MODULES:
        text = (SRC / name).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            assert not _NOMINAL_MATCH.search(line), (
                f"{name}:{number} matches an exception by CLASS. A `HostSource` lives in "
                "another artifact, so its exceptions are different classes and this check is "
                "always False -- silently. Read the `error_class` attribute instead."
            )
            assert not _SOURCE_EXCEPT.search(line), (
                f"{name}:{number} catches a Source* exception by name. Same reason: a "
                "foreign `SourceMissing` is a different class, so a clean host with no "
                "/etc/cron.d was classified `parse`."
            )


def test_that_detector_would_catch_both_shapes():
    """Planted positives. Both scans above run over a clean corpus."""
    assert _NOMINAL_MATCH.search("    if isinstance(error, SourceError):")
    assert _NOMINAL_MATCH.search("        if isinstance(exc, Foo):")
    assert _SOURCE_EXCEPT.search("    except SourceMissing:")
    assert _SOURCE_EXCEPT.search("    except (SourceDenied, SourceTimeout):")
    # Near-misses that must NOT trip it: classifying a VALUE, and catching the
    # broad boundary exception the ruling requires.
    assert not _NOMINAL_MATCH.search("    if isinstance(code, str) and code in CLASSES:")
    assert not _SOURCE_EXCEPT.search("    except Exception as error:")


def test_the_seam_boundary_never_catches_baseexception():
    """`Exception`, never `BaseException`, at every `HostSource` call site.

    A `KeyboardInterrupt` or `SystemExit` is not a source failure. Swallowing
    one at the boundary files a document reporting a failure on every family
    the walk had not yet reached -- a complete-looking census produced by
    someone pressing Ctrl-C.

    Scoped to the enumerators. `attribution.run_guarded` still catches
    `BaseException` and must: it is a CONTAINMENT boundary whose job is to stop
    a traceback reaching stderr, not a classification boundary that decides
    what a document says.
    """
    text = (SRC / "attribution_enumerators.py").read_text(encoding="utf-8")
    offenders = [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if "except BaseException" in line and not line.lstrip().startswith("#")
    ]
    assert not offenders, f"attribution_enumerators.py catches BaseException at {offenders}"


def test_the_containment_boundary_still_catches_baseexception():
    """The other half, so the check above cannot be satisfied by deleting it.

    If `run_guarded` were narrowed to `Exception`, a `KeyboardInterrupt` raised
    mid-parse would unwind through frames holding the DSN and the default
    handler would print them.
    """
    text = (SRC / "attribution.py").read_text(encoding="utf-8")
    assert "except BaseException as exc:" in text, (
        "the process-level containment boundary was narrowed; a cancelled run now prints a "
        "traceback carrying the parsed DSN"
    )
