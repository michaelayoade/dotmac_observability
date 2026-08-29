"""Shared locations. Nothing here constructs state — fixtures are paths only.

A test that needs a *modified* inventory copies the reference tree into a
tmp_path and edits the copy. Mutating a shared in-memory object would make the
guard tests order-dependent, and an order-dependent guard test is exactly the
kind that passes forever while the guard rots.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = REPO_ROOT / "contracts"
REFERENCE = REPO_ROOT / "tests" / "fixtures" / "reference"
REFERENCE_RENDERED = REFERENCE / "rendered"


@pytest.fixture
def reference_copy(tmp_path: Path) -> Path:
    """A writable copy of the reference inventory, without its expected render."""
    destination = tmp_path / "reference"
    shutil.copytree(REFERENCE, destination)
    shutil.rmtree(destination / "rendered")
    return destination


def edit(path: Path, old: str, new: str) -> None:
    """Replace ``old`` with ``new`` in ``path``, asserting ``old`` was there.

    The assertion is the point. A mutation test whose search string has drifted
    silently mutates nothing and then passes because the guard it was meant to
    provoke stayed quiet — which is indistinguishable from the guard working.
    """
    text = path.read_text()
    assert old in text, f"{path.name} no longer contains the text this mutation edits"
    path.write_text(text.replace(old, new, 1))
