"""Shared locations. Nothing here constructs state — fixtures are paths only.

A test that needs a *modified* inventory copies the reference tree into a
tmp_path and edits the copy. Mutating a shared in-memory object would make the
guard tests order-dependent, and an order-dependent guard test is exactly the
kind that passes forever while the guard rots.

The one helper that does build something, :func:`resolved`, exists because
since ADR-0004 a render needs BOTH halves of the input and spelling the join
out in every test would bury what each test is actually about.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from dotmac_observability.model import Resolution
from dotmac_observability.validate import load, load_private_inventory, resolve

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = REPO_ROOT / "contracts"
REFERENCE = REPO_ROOT / "tests" / "fixtures" / "reference"
REFERENCE_RENDERED = REFERENCE / "rendered"
# A tracked instance of a document type ADR-0004 keeps out of Git, safe because
# every host in it is `.invalid` and every store path is under the reserved
# `secret/fixture/` prefix — both asserted, not asserted-by-comment. See
# `tests/fixtures/reference/private/README.md`.
REFERENCE_PRIVATE = REFERENCE / "private" / "inventory.json"


@pytest.fixture
def reference_copy(tmp_path: Path) -> Path:
    """A writable copy of the reference inventory, without its expected render."""
    destination = tmp_path / "reference"
    shutil.copytree(REFERENCE, destination)
    shutil.rmtree(destination / "rendered")
    return destination


def private_path(root: Path) -> Path:
    """The private inventory inside a reference tree, original or copied."""
    return root / "private" / "inventory.json"


def resolved(root: Path) -> Resolution:
    """Join a reference tree to its own private inventory.

    Raises through :func:`~dotmac_observability.validate.resolve`, so a test
    that calls this on a deliberately broken copy gets the resolution findings
    rather than a half-built object.
    """
    return resolve(
        load(root, contracts=CONTRACTS),
        load_private_inventory(private_path(root), contracts=CONTRACTS),
    )


def edit(path: Path, old: str, new: str) -> None:
    """Replace ``old`` with ``new`` in ``path``, asserting ``old`` was there.

    The assertion is the point. A mutation test whose search string has drifted
    silently mutates nothing and then passes because the guard it was meant to
    provoke stayed quiet — which is indistinguishable from the guard working.
    """
    text = path.read_text()
    assert old in text, f"{path.name} no longer contains the text this mutation edits"
    path.write_text(text.replace(old, new, 1))
