"""Structural invariants: AGENTS.md rule 14 and the contract surface.

Static checks only. Nothing here starts a service or reads a host — the point
is that a reviewer can trust the repository's shape without running it.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib

import jsonschema
import pytest

from dotmac_observability.render import (
    ALERTMANAGER_CONFIG,
    COMPOSE_FILE,
    EXPOSURE_IPV4,
    EXPOSURE_IPV6,
    GRAFANA_ALERTING,
    GRAFANA_DASHBOARDS,
    GRAFANA_DATASOURCES,
    GRAFANA_PLUGINS,
    INGESTION_RULES,
    LOGROTATE_CONFIG,
    LOKI_CONFIG,
    META_RULES,
    PROMETHEUS_CONFIG,
    PROMTAIL_CONFIG,
    RSYSLOG_CONFIG,
    TIMEZONE_FILE,
    TMPFILES_CONFIG,
    render_control_plane,
)
from dotmac_observability.validate import load
from tests.conftest import CONTRACTS, REFERENCE, REPO_ROOT, resolved

SRC = REPO_ROOT / "src" / "dotmac_observability"
CONTRACT_FILES = sorted(CONTRACTS.glob("*.schema.json"))


def test_the_declared_contracts_are_all_present():
    names = {path.name for path in CONTRACT_FILES}
    assert names == {
        "control-plane.schema.json",
        "target.schema.json",
        "bundle-lock.schema.json",
        "routing.schema.json",
        "promotion-receipt.schema.json",
        # Live state as an ARTIFACT rather than a habit of reading APIs in the
        # right order. Rule 12 names three independently comparable artifacts;
        # two of them were contracts and the third was a procedure, which
        # cannot be compared later, attached to a ticket or replayed.
        "live-observation.schema.json",
        # Both public schemas whose every INSTANCE is private (ADR-0004). A
        # shape discloses nothing; publishing it is what lets a reviewer
        # disagree with the split.
        "private-inventory.schema.json",
        "supersession-request.schema.json",
        # The bundle (ADR-0008): everything deployed that is not a target, a
        # route or a receiver. Public and topology-free like the rest.
        "bundle.schema.json",
        # The PRE-CONTRACT capture format, written down so a document already
        # stored in it can be read and migrated rather than hand-edited. Not a
        # second private-inventory contract: nothing new may be written against
        # it, and the only tool that reads it produces an accepted-contract
        # document.
        "private-inventory-capture.schema.json",
        # The ingestion boundary (ADR-0011): what the one fleet shipper may put
        # into this control plane and what is refused. Public and topology-free
        # like the rest — it carries a vocabulary and a policy, never an
        # address, a store path or a credential basename.
        "telemetry-ingestion.schema.json",
        # Postgres consumer attribution, as the SAME public/private split every
        # other pair here keeps (ADR-0004). The envelope is committable: logical
        # target id, derived coverage verdicts, counts, and three digests naming
        # three different authorities -- and no property a resolved host, port,
        # user, database, launch path or credential pointer could be typed into.
        # The observation is the private half; its shape is published so a
        # reviewer can disagree with the split, and its every INSTANCE stays out
        # of Git.
        "postgres-consumer-attribution-envelope.schema.json",
        "postgres-consumer-attribution-observation.schema.json",
        # v2 of both, which exists because v1 could not be extended. An
        # optional field would make one version name two shapes; a required one
        # would change what an already-stored document's digest means. v2
        # requires BOTH `collector_artifact_digest` and `source_artifact_digest`
        # -- the coverage claim depends on two artifacts, this collector and the
        # separately released `HostSource` implementation that decides which
        # failures are reported as `missing`, and naming only one leaves the
        # half that can turn a denial into an absence unidentified. v1 is
        # retained and not deprecated: it stays readable historical evidence,
        # and it cannot discharge the rotation interlock.
        "postgres-consumer-attribution-envelope-v2.schema.json",
        "postgres-consumer-attribution-observation-v2.schema.json",
    }
    # `consumer-attribution-authorization.schema.json` and
    # `attribution-challenge.schema.json` are deliberately ABSENT, and for two
    # DIFFERENT reasons that must not be collapsed into one. Permission to
    # inspect a target is `ConsumerAttributionAuthorizationV1`, owned by
    # `dotmac-deployment-control`. The nonce, freshness, target binding and
    # output-signature semantics are `AttributionChallengeV1`, owned by the
    # observation authority. A single request document here would let whoever
    # granted access also define what counts as proof of the result; two
    # issuers, two documents, neither able to close the loop alone. This
    # repository consumes both by digest and defines neither (rule 20).
    #
    # `deployment-authorization.schema.json` is deliberately ABSENT. Defining
    # one here would make an adopter into a second deployment control plane;
    # `dotmac-deployment-control` owns approval, and this repository consumes an
    # approved plan by reference (AGENTS.md rule 20, ADR-0006 §7).


@pytest.mark.parametrize("path", CONTRACT_FILES, ids=lambda p: p.name)
def test_each_contract_is_a_valid_2020_12_schema(path):
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    # A contract without these is a shape nobody can cite in a review.
    for key in ("$schema", "$id", "title", "description"):
        assert key in schema, f"{path.name} has no {key}"
    assert schema["$schema"].endswith("2020-12/schema")


@pytest.mark.parametrize("path", CONTRACT_FILES, ids=lambda p: p.name)
def test_each_contract_closes_its_objects(path):
    """An open object accepts a typo as an unread extra key.

    The commonest way a control plane silently loses a setting is a
    misspelling that validates. Every object in a contract must therefore
    either forbid extra properties or be a branch wrapper that delegates to one
    that does.
    """
    schema = json.loads(path.read_text(encoding="utf-8"))
    open_objects: list[str] = []

    def walk(node: object, where: str) -> None:
        if isinstance(node, dict):
            if (
                node.get("type") == "object"
                and "properties" in node
                and node.get("additionalProperties") is not False
            ):
                open_objects.append(where)
            for key, value in node.items():
                walk(value, f"{where}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}/{index}")

    for key in ("$defs", "properties"):
        walk(schema.get(key, {}), key)
    # The two discriminated documents keep an open top-level `properties` block
    # so `kind` can be read before a branch is chosen; the branches themselves
    # are closed, which is where the typo would land.
    assert open_objects == [], f"{path.name} has open objects at {open_objects}"


@pytest.mark.parametrize("path", sorted(SRC.glob("*.py")), ids=lambda p: p.name)
def test_every_module_explains_itself(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstring = ast.get_docstring(tree)
    assert docstring, f"{path.name} has no module docstring"
    assert len(docstring) > 120, f"{path.name}'s docstring says too little to be worth reading"


# The detector cannot detect a hostname it is forbidden to spell. Same premise
# as `SECRET_SCAN_EXCLUSIONS` and `PRIVATE_SCAN_EXCLUSIONS`, and asserted as an
# exact single name rather than a set so a second module cannot quietly join it.
_MAY_NAME_A_HOST = "validate.py"


def test_no_source_file_hardcodes_a_host():
    """Rule 14. Container-side paths are declared constants; hosts are not.

    A literal address in the renderer would be invisible in the inventory and
    would survive every environment, which is how a staging config reaches
    production pointing at the wrong evaluator.
    """
    address = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    # The one permitted literal, with an enforceable premise: 0.0.0.0 is not a
    # host, it is the wildcard bind INSIDE the container. What the outside world
    # can reach is decided by the compose `ports` knob, which is overridable and
    # defaults to the inventory's declared loopback address.
    permitted = {"0.0.0.0"}
    checked = 0
    for path in sorted(SRC.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        found = set(address.findall(text)) - permitted
        assert not found, f"{path.name} contains literal IP address(es) {sorted(found)}"
        if path.name == _MAY_NAME_A_HOST:
            continue
        checked += 1
        assert "dotmac.io" not in text, f"{path.name} names a real Dotmac host"
    assert checked > 1, "the hostname assertion ran over too few modules to mean anything"


def test_the_module_allowed_to_name_a_host_is_the_detector_and_uses_it():
    """The exemption above states an enforceable premise, so it is enforced.

    `validate.py` may name the domain because the private-material detector
    matches on it, and a detector forbidden to spell the shape it looks for
    detects nothing. That premise is only true while the name is IN a pattern —
    if it ever appears as a plain literal instead, the exemption has stopped
    describing anything and this fails.
    """
    text = (SRC / _MAY_NAME_A_HOST).read_text(encoding="utf-8")
    assert "dotmac.io" in text, (
        "the detector no longer names the domain; delete the exemption rather "
        "than leaving it to cover a module that does not need it"
    )
    assert "\\.dotmac\\.io" in text, (
        "the domain appears outside a regex; the exemption's premise is that "
        "this module is the DETECTOR, not that it may mention hosts"
    )


def test_every_makefile_value_is_an_overridable_knob():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assignments = re.findall(r"^([A-Z_][A-Z0-9_]*)\s*(\?=|:=|=)\s", makefile, re.MULTILINE)
    assert assignments, "no Makefile variables found; the matcher has drifted"
    for name, operator in assignments:
        assert operator == "?=", f"Makefile {name} uses {operator}; rule 14 requires ?="


def test_every_rendered_compose_variable_carries_a_default_or_refuses():
    rendered = dict(
        render_control_plane(load(REFERENCE, contracts=CONTRACTS), resolved(REFERENCE))
    )[COMPOSE_FILE]
    variables = re.findall(r"\$\{([^}]*)\}", rendered)
    assert variables, "the compose file declares no knobs; the matcher has drifted"
    for variable in variables:
        # `:-` supplies a documented default; `:?` refuses to start without a
        # value. A bare ${VAR} silently becomes the empty string, which for a
        # mount source means the container starts with nothing mounted.
        assert (
            ":-" in variable or ":?" in variable
        ), f"${{{variable}}} has neither a default nor a refusal"


def test_the_renderer_produces_exactly_its_declared_files():
    produced = {
        path
        for path, _ in render_control_plane(
            load(REFERENCE, contracts=CONTRACTS), resolved(REFERENCE)
        )
    }
    assert produced == {
        PROMETHEUS_CONFIG,
        META_RULES,
        INGESTION_RULES,
        ALERTMANAGER_CONFIG,
        LOKI_CONFIG,
        PROMTAIL_CONFIG,
        GRAFANA_DATASOURCES,
        GRAFANA_DASHBOARDS,
        GRAFANA_PLUGINS,
        GRAFANA_ALERTING,
        RSYSLOG_CONFIG,
        LOGROTATE_CONFIG,
        TMPFILES_CONFIG,
        TIMEZONE_FILE,
        EXPOSURE_IPV4,
        EXPOSURE_IPV6,
        COMPOSE_FILE,
    }


def test_the_build_tool_is_pinned_exactly():
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["poetry"]["requires-poetry"] == "2.4.1"
    # Not published: nothing pins this repository, so a version here is a
    # deployment label. Saying so in the metadata stops a release lane adopting it.
    assert project["tool"]["poetry"]["classifiers"] == ["Private :: Do Not Upload"]


def test_governance_is_pinned_by_exact_commit():
    profile = json.loads(
        (REPO_ROOT / ".dotmac" / "standards-profile.json").read_text(encoding="utf-8")
    )
    model = profile["governance_model"]
    assert model["kind"] == "pinned"
    assert re.fullmatch(r"[0-9a-f]{40}", model["revision"]), "governance revision is not a full SHA"
    workflow = (REPO_ROOT / ".github" / "workflows" / "engineering-standards.yml").read_text(
        encoding="utf-8"
    )
    # Rule 16: the workflow must EXECUTE the same accepted revision the profile
    # declares. A profile pin nobody runs is documentation.
    assert model["revision"] in workflow


def test_the_host_and_container_secret_directories_stay_distinct():
    """A comment is not a guard, so the distinction gets one.

    The host directory is a configurable mount SOURCE; the container paths are
    renderer constants and mount TARGETS. Spelling the default host path as one
    of the container paths is legal, renders correctly, and invites the next
    operator to create the directory in the wrong filesystem — which presents
    as a receiver that never delivers.
    """
    from dotmac_observability.render import _ALERTMANAGER_SECRETS, _PROMETHEUS_SECRETS
    from dotmac_observability.validate import DEFAULT_SECRETS_DIR

    container = {_PROMETHEUS_SECRETS, _ALERTMANAGER_SECRETS}
    assert len(container) == 2, "the two evaluators must read from distinct container paths"
    assert DEFAULT_SECRETS_DIR not in container


@pytest.mark.parametrize("path", CONTRACT_FILES, ids=lambda p: p.name)
def test_every_internal_reference_in_a_contract_resolves(path):
    """A dangling `$ref` is invisible to `check_schema` and fatal at validation.

    `jsonschema.Draft202012Validator.check_schema` — which CI's `schemas` job
    runs, and which is the only structural check these files had — does NOT
    resolve references. A `$ref` pointing at a `$defs` entry that does not exist
    passes it cleanly and then raises `PointerToNowhere` the first time a real
    document is validated against that branch.

    This is not hypothetical: adding a `kind` discriminator to the supersession
    request introduced exactly that, the schema job would have stayed green, and
    the failure surfaced only because a test happened to exercise the new branch.
    A branch nobody exercised would have shipped.
    """
    schema = json.loads(path.read_text(encoding="utf-8"))
    defined = set(schema.get("$defs", {}))

    def walk(node, where):
        if isinstance(node, dict):
            reference = node.get("$ref")
            if isinstance(reference, str):
                assert reference.startswith("#/$defs/"), (
                    f"{path.name}{where}: only internal $defs references are used here, "
                    f"and {reference!r} is not one"
                )
                name = reference.removeprefix("#/$defs/")
                assert name in defined, (
                    f"{path.name}{where}: $ref points at {reference!r}, which this contract "
                    f"does not define. check_schema does not catch this"
                )
            for key, value in node.items():
                walk(value, f"{where}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}/{index}")

    walk(schema, "")
