"""Sensitivity proofs for the bundle's gates (AGENTS.md rule 15).

`test_the_reference_bundle_raises_no_findings` passes on a clean bundle. It
would also pass if `_bundle_findings` returned an empty list unconditionally,
if a mutation's search string had drifted so nothing was edited, or if the
gate's condition had been written inverted — which one of them was, and which
is why this file exists rather than being implied by the unit tests.

Each case below plants one break and requires the named code. `edit` asserts
its search string was present, so a mutation that stopped mutating fails here
rather than passing quietly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dotmac_observability.render import EXPOSURE_IPV6, render_control_plane
from dotmac_observability.validate import load, semantic_findings
from tests.conftest import CONTRACTS, REFERENCE, edit, resolved

BUNDLE = ("inventory", "bundle.toml")

# The loopback surface a mutation edits, spelled once. Written out rather than
# matched loosely because `edit` asserts its search string was present: a
# mutation whose anchor has drifted must fail here, not quietly change nothing
# and then pass because the gate it was meant to provoke stayed silent.
_LOOPBACK_SURFACE = (
    'exposure = "loopback"\n'
    "  authenticated = false\n"
    "\n"
    "  [[exposure.surfaces]]\n"
    '  name = "alertmanager"'
)

BREAKS: tuple[tuple[str, str, str, str], ...] = (
    (
        "ROSTER-INCOMPLETE",
        "a service the bundle deploys but nobody owns",
        'name = "grafana"\nkind = "service"\nowner = "observability-control-plane"\nport = 3000',
        'name = "grafana-x"\nkind = "service"\nowner = "observability-control-plane"\nport = 3000',
    ),
    (
        "DATASOURCE-UNROSTERED",
        "a datasource whose URL could only be rendered by inventing an address",
        'name = "logs"\n  kind = "loki"\n  service = "loki"',
        'name = "logs"\n  kind = "loki"\n  service = "nowhere"',
    ),
    (
        "SURFACE-UNDECLARED-SOURCE",
        "an allow_from naming a set that does not exist",
        'allow_from = "management"',
        'allow_from = "nobody"',
    ),
    (
        "SURFACE-SOURCE-IGNORED",
        "a loopback surface naming a source it will never be reached from",
        _LOOPBACK_SURFACE,
        _LOOPBACK_SURFACE.replace(
            'exposure = "loopback"',
            'exposure = "loopback"\n  allow_from = "management"',
            1,
        ),
    ),
    (
        "LISTEN-NOT-LOOPBACK",
        "a runtime binding a resolved address instead of loopback",
        'listen = "127.0.0.1:3100"',
        'listen = "0.0.0.0:3100"',
    ),
    (
        "SYSLOG-PATH-DUPLICATE",
        "two facilities writing one file with independently declared ownership",
        'path = "/var/log/mail.err"',
        'path = "/var/log/mail.log"',
    ),
)


@pytest.mark.parametrize(
    ("code", "why", "old", "new"), BREAKS, ids=[case[0].lower() for case in BREAKS]
)
def test_the_bundle_gate_bites(reference_copy: Path, code: str, why: str, old: str, new: str):
    edit(reference_copy.joinpath(*BUNDLE), old, new)
    found = {
        finding.code for finding in semantic_findings(load(reference_copy, contracts=CONTRACTS))
    }
    assert code in found, f"the gate for {why} did not fire"


def test_a_clean_bundle_produces_none_of_those_codes():
    """The other half of a sensitivity proof.

    Without it, a gate that fired on EVERYTHING would satisfy every case above
    and the suite would report a detector that cannot discriminate as working.
    """
    found = {finding.code for finding in semantic_findings(load(REFERENCE, contracts=CONTRACTS))}
    assert found.isdisjoint({case[0] for case in BREAKS})


def test_the_ipv6_chain_derivation_cannot_be_overridden_from_the_inventory(reference_copy: Path):
    """The dead-rule class, proved unreachable rather than merely absent.

    A test asserting `DOCKER-USER not in ipv6.rules` on the reference bundle
    passes if the renderer emits no IPv6 rules at all. This one changes the
    inventory in the way an author would if they wanted the rule in the other
    chain — there is no field for it — and then checks that IPv6 rules ARE
    emitted and are still on INPUT.
    """
    edit(
        reference_copy.joinpath(*BUNDLE),
        'name = "prometheus"\n  kind = "container_published"',
        'name = "prometheus"\n  kind = "container_published"',
    )
    tree = dict(
        render_control_plane(load(reference_copy, contracts=CONTRACTS), resolved(reference_copy))
    )
    ipv6 = tree[EXPOSURE_IPV6]
    assert (
        ipv6.count("-A INPUT") >= 3
    ), "no IPv6 rules were emitted, so the assertion below is vacuous"
    assert "DOCKER-USER" not in ipv6
