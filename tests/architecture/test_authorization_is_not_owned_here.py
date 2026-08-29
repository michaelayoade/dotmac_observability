"""AGENTS.md rule 20 — this repository is an ADOPTER, not a second control plane.

`dotmac-deployment-control` owns deployment intent, plan freezing, approval
policy and the approval decision. This repository consumes an approved plan and
records which one it executed. The line is easy to cross by accident: a
promotion lane naturally wants to say "authorized by", and one schema field is
all it takes to become a second answer to who may deploy.

Two distinct things are asserted here, and they fail for different reasons.

**Ownership.** No contract may DEFINE approval or signature semantics. A
`$defs` entry describing what an approval is belongs to the owner; a `$ref`
into a reference of one is consumption and is fine.

**Self-attestation.** No contract may carry an approver NAME. Michael's ruling:
`approved_by = "a name"` is self-attested documentation, not authorization —
nothing verifies it, the person named is never notified, and it produces an
approval record that looks checkable and is not. The owning module agrees in
its own schema: `dotmac-deployment-control` records
`approval_policy_code`, `approval_policy_version` and `approval_decision_ref`,
and no name column anywhere.
"""

from __future__ import annotations

import json

import pytest

from tests.conftest import CONTRACTS, REPO_ROOT

CONTRACT_FILES = sorted(CONTRACTS.glob("*.schema.json"))

# Field names that assert a human approved something in this repository's own
# voice. `approval_decision_ref` is deliberately NOT here: it is an opaque
# pointer into the system that took the decision, which is the shape this rule
# exists to require rather than forbid.
_SELF_ATTESTED = frozenset(
    {
        "approved_by",
        "approver",
        "authorized_by",
        "signed_by",
        "reviewed_by",
        "sign_off",
        "signoff",
    }
)

# A contract that DEFINES one of these owns approval semantics. Referencing an
# approved plan is consumption; defining what an approval is, is ownership.
_OWNERSHIP_DEFS = frozenset({"authorization", "approval", "signature", "attestation"})


def test_there_are_contracts_to_check():
    # Without this the two scans below pass over an empty set, which is the
    # vacuous green rule 15 exists to refuse.
    assert len(CONTRACT_FILES) >= 5


def test_no_contract_defines_approval_or_signature_semantics():
    for path in CONTRACT_FILES:
        schema = json.loads(path.read_text(encoding="utf-8"))
        defined = {name.lower() for name in schema.get("$defs", {})}
        overlap = defined & _OWNERSHIP_DEFS
        assert not overlap, (
            f"{path.name} defines {sorted(overlap)}. Deployment authorization belongs to "
            "`dotmac-deployment-control`; consume an approved plan by reference instead "
            "(AGENTS.md rule 20)"
        )


@pytest.mark.parametrize("path", CONTRACT_FILES, ids=lambda p: p.name)
def test_no_contract_carries_a_self_attested_approver(path):
    found: list[str] = []

    def walk(node: object, where: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() in _SELF_ATTESTED:
                    found.append(f"{where}/{key}")
                walk(value, f"{where}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}/{index}")

    walk(json.loads(path.read_text(encoding="utf-8")), path.name)
    assert not found, (
        f"{path.name} carries self-attested approver field(s) {found}. A name in a tracked "
        "file is verified by nothing and notifies nobody; record an approval_decision_ref "
        "resolvable in the deployment control plane, or leave the approval to the "
        "protected-branch merge (AGENTS.md rule 20)"
    )


def test_the_detector_would_catch_a_self_attested_approver():
    """Sensitivity proof. A scan over a clean corpus proves nothing on its own.

    The publication block is the exact place this field was removed from, so it
    is the right place to plant it back: if the walk ever stops descending into
    `$defs`, this fails while the parametrized scan above stays green.
    """
    schema = json.loads((CONTRACTS / "target.schema.json").read_text(encoding="utf-8"))
    publication = schema["$defs"]["publication"]
    assert "approved_by" not in publication["properties"], "the real contract regressed"

    planted = json.loads(json.dumps(schema))
    planted["$defs"]["publication"]["properties"]["approved_by"] = {"type": "string"}

    found: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() in _SELF_ATTESTED:
                    found.append(key)
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(planted)
    assert found == ["approved_by"]


def test_the_publication_exception_keeps_its_rationale():
    """Removing the approver must not quietly remove the review.

    The rationale is the half a reviewer can actually act on, and it is what
    stops the exception being available by omission. Dropping both fields
    together would have looked like tidying and would have deleted the gate.
    """
    schema = json.loads((CONTRACTS / "target.schema.json").read_text(encoding="utf-8"))
    publication = schema["$defs"]["publication"]
    assert set(publication["required"]) == {"endpoints", "rationale"}
    assert publication["properties"]["rationale"]["minLength"] >= 40


def test_the_repository_states_the_boundary_where_a_reader_will_look():
    agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "dotmac-deployment-control" in agents, (
        "rule 20 must NAME the owner. A boundary rule that does not say who owns the other "
        "side leaves a reader with nowhere to go"
    )
