"""Sensitivity proof for containment. A guard over a clean tree proves nothing.

Every assertion in `test_attribution_projection.py` about material NOT reaching
a payload is satisfied trivially by two useless implementations: a vault holding
nothing, and a projection returning nothing. This file plants the defect each
guard is aimed at and requires a refusal, then plants a near-miss and requires
the guard to stay quiet -- because a containment check that refuses correct
input gets switched off long before it catches anything.

No IPv4 or IPv6 literal appears anywhere in this battery; see
`tests/attribution_fixtures.py` for why that is a stronger choice here than a
documentation range, and why it needs no exemption from this repository's own
private-material detector.
"""

from __future__ import annotations

import io
import sys

import pytest

from dotmac_observability.attribution import (
    ENVELOPE_FIELDS,
    LeakRefusal,
    RedactionVault,
    parse_dsn,
    project_envelope,
    run_guarded,
    safe_error,
)
from tests.attribution_fixtures import (
    CONSUMER_DSN,
    clean_scans,
    counts_of,
    coverage_of,
    observation,
)

# ── The vacuous-green guards. These two are the point of the file. ──────────


def test_the_vault_is_not_vacuous():
    """An EMPTY vault makes every `assert_clean` in the battery pass.

    That is the shape of the false green this whole design is exposed to: the
    containment tests would stay green forever while `parse_dsn` quietly
    stopped poisoning anything, because "no poisoned value was found in the
    payload" and "there were no poisoned values" are the same sentence to an
    assertion. So the vault is required to be NON-EMPTY after a parse, with the
    specific components named, and an empty vault is required to be unable to
    refuse anything at all.
    """
    empty = RedactionVault()
    assert len(empty) == 0
    # Proof of the vacuity, stated rather than assumed: an empty vault passes a
    # payload that is nothing but the DSN.
    empty.assert_clean({"leak": CONSUMER_DSN})

    vault = RedactionVault()
    parse_dsn(CONSUMER_DSN, target_id="erp-production", vault=vault)
    assert len(vault) >= 4, (
        "the parser stopped poisoning; every containment assertion in this battery "
        "would now pass over an empty set"
    )
    for component in (CONSUMER_DSN, "pw-fixture", "erp-db.invalid", "obsuser", "erpdb"):
        assert vault.contains(component), f"{component} was parsed and not poisoned"
    with pytest.raises(LeakRefusal):
        vault.assert_clean({"leak": CONSUMER_DSN})


def test_the_envelope_still_carries_what_a_gate_needs():
    """A projection returning `{}` satisfies EVERY containment assertion.

    It leaks nothing because it says nothing, and it is useless: a fleet gate
    reading these envelopes cannot tell an unscanned host from a clean one, an
    attributed consumer from an unowned one, or which authority the observation
    ran under. Containment that has eaten the payload is not containment.
    """
    envelope = project_envelope(observation(), clean_scans(), vault=RedactionVault())
    assert envelope, "the projection returned nothing"
    assert set(envelope) == set(ENVELOPE_FIELDS)
    for field in ENVELOPE_FIELDS:
        assert envelope[field] not in (None, "", [], {}), f"{field} is present but empty"
    # The three things a gate actually acts on, checked as VALUES rather than
    # as presence: coverage it can compare host to host, counts it can threshold
    # on, and the references it resolves upstream.
    assert len(coverage_of(envelope)) == counts_of(envelope)["families_declared"]
    assert counts_of(envelope)["consumers_unattributed"] == 1
    assert counts_of(envelope)["consumers_attributed"] == 3
    assert envelope["authority_ref"] == "control:decision/7f2c"
    assert envelope["target_id"] == "erp-production"


# ── Planted leaks, one per route out of the process ─────────────────────────


@pytest.mark.parametrize("field", ["target_id", "authority_ref", "observation_digest"])
def test_a_dsn_planted_in_any_public_field_aborts_the_projection(field):
    """One plant per field, because containment must not be field-specific.

    A projection that scanned only the fields somebody remembered would pass a
    single-field test and leak through the tenth.
    """
    vault = RedactionVault()
    parse_dsn(CONSUMER_DSN, target_id="erp-production", vault=vault)
    with pytest.raises(LeakRefusal):
        project_envelope(observation(**{field: CONSUMER_DSN}), clean_scans(), vault=vault)


def test_a_host_embedded_in_a_longer_string_is_still_caught():
    """The near-miss an equality check would pass, planted.

    The real disclosure was a host inside an error sentence, not a field whose
    whole value was the host.
    """
    vault = RedactionVault()
    parse_dsn(CONSUMER_DSN, target_id="erp-production", vault=vault)
    with pytest.raises(LeakRefusal):
        vault.assert_clean({"note": "scrape of erp-db.invalid timed out after 10s"})


def test_a_value_that_merely_resembles_poisoned_material_is_not_refused():
    """The other half of sensitivity: the guard must stay quiet on clean input.

    `erp-production` is the LOGICAL target id, published deliberately, and it
    shares a prefix with the poisoned host. A guard that refused it would refuse
    every correct envelope.
    """
    vault = RedactionVault()
    parse_dsn(CONSUMER_DSN, target_id="erp-production", vault=vault)
    vault.assert_clean(
        {
            "target_id": "erp-production",
            "environment": "production",
            "note": "erp-db is the logical name; erp-database.invalid is a different host",
        }
    )


def test_a_short_component_is_still_poisoned():
    """A minimum length would be a silent allowlist.

    A two-character password is a password. The tempting optimization here is
    to skip short values because they cause false positives, and the cost of
    that optimization is that the shortest secrets stop being protected.
    """
    vault = RedactionVault()
    vault.poison("qz")
    with pytest.raises(LeakRefusal):
        vault.assert_clean({"note": "qz"})


# ── The error path ──────────────────────────────────────────────────────────


def test_the_v1_error_formatter_would_have_leaked_and_safe_error_does_not():
    """The defect, spelled out, so its absence is evidence rather than habit.

    `"{}: {}".format(type(e).__name__, e)` is what the first design used. Below
    it is constructed explicitly, shown to carry the DSN, and contrasted with
    `safe_error` on the same exception.
    """
    error = ConnectionError(f"could not connect to {CONSUMER_DSN}")
    v1_formatting = f"{type(error).__name__}: {error}"
    assert CONSUMER_DSN in v1_formatting, "the planted defect no longer leaks; the plant is stale"
    assert CONSUMER_DSN not in safe_error(error)
    assert safe_error(error) == "ConnectionError"


def test_a_chained_exception_does_not_smuggle_the_value_through_the_cause():
    """`raise ... from None`, planted as its own case.

    Without it the original exception is attached as `__cause__`, and the
    default handler prints "The above exception was the direct cause of" plus
    the original message -- which is the DSN.
    """
    vault = RedactionVault()
    with pytest.raises(ValueError) as raised:
        parse_dsn(
            "postgresql://obsuser:pw-fixture@erp-db.invalid:notaport/erpdb",
            target_id="erp-production",
            vault=vault,
        )
    assert raised.value.__cause__ is None, "the original exception is still attached"
    assert "erp-db.invalid" not in str(raised.value)


def test_the_guarded_entry_point_suppresses_the_traceback_body():
    """`sys.tracebacklimit = 0`, checked by its effect rather than its value.

    A traceback prints the SOURCE LINE of each frame. A collector's frames
    contain the parse of the DSN, so a frame listing is a disclosure even when
    every exception message is clean.
    """
    previous = getattr(sys, "tracebacklimit", None)
    stderr, sys.stderr = sys.stderr, io.StringIO()
    try:

        def boom() -> int:
            secret = CONSUMER_DSN
            raise RuntimeError(secret[:0] or "opaque")

        run_guarded(boom)
        written = sys.stderr.getvalue()
        limit = sys.tracebacklimit
    finally:
        sys.stderr = stderr
        if previous is None:
            if hasattr(sys, "tracebacklimit"):
                del sys.tracebacklimit
        else:
            sys.tracebacklimit = previous

    assert limit == 0
    assert "Traceback" not in written
    assert "secret = CONSUMER_DSN" not in written
    assert written.strip() == "attribution: refused (RuntimeError)"
