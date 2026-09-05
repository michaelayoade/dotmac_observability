"""The public envelope has no private field to fill, and refuses one it grows.

Two halves of AGENTS.md rule 18, and the repository already runs both against
its other contracts: the STRUCTURAL half closes every object so a resolved
endpoint has nowhere to be typed, and the SCAN catches material written into a
document no schema reads. This file adds a third, which the other contracts do
not need and this one does: the material here is parsed at runtime from live
hosts, so containment has to hold over VALUES a collector produces, not only
over fields a schema declares.

The projection is therefore default-deny on field names. A collector that grows
a `db_host` next quarter does not get to publish it by having been written
after this module; it raises `UnclassifiedField` and somebody decides.
"""

from __future__ import annotations

import copy
import io
import pickle
import sys

import pytest

from dotmac_observability.attribution import (
    ATTRIBUTION_SCHEMA_VERSION,
    CLASSIFIED_FIELDS,
    DECLARED_FAMILIES,
    ENVELOPE_FIELDS,
    FamilyScan,
    LeakRefusal,
    RedactionVault,
    Target,
    UnclassifiedField,
    Verdict,
    parse_dsn,
    project_envelope,
    run_guarded,
    safe_error,
    verify_request,
)
from tests.attribution_fixtures import (
    BARE_DSN,
    CONSUMER_DSN,
    DIGEST_C,
    DIGEST_D,
    clean_scans,
    counts_of,
    coverage_of,
    observation,
)

_PRIVATE_NAMES = (
    "db_host",
    "db_port",
    "db_user",
    "db_name",
    "dsn",
    "password",
    "launch_path",
    "secret_pointers",
    "env_var_names",
)


def _project(**overrides: object) -> dict[str, object]:
    return project_envelope(observation(**overrides), clean_scans(), vault=RedactionVault())


# ── The envelope is what a gate can act on ──────────────────────────────────


def test_the_envelope_carries_exactly_its_declared_fields():
    envelope = _project()
    assert set(envelope) == set(ENVELOPE_FIELDS)
    assert envelope["schema_version"] == ATTRIBUTION_SCHEMA_VERSION


def test_the_envelope_has_no_private_field_at_all():
    """Not "is empty" -- ABSENT. A key that exists is a key somebody fills."""
    envelope = _project()
    for name in _PRIVATE_NAMES:
        assert name not in envelope
    assert name not in ENVELOPE_FIELDS


def test_private_input_is_accepted_and_dropped_rather_than_refused():
    """A collector should not have to pre-filter; the projection is the filter.

    Requiring the collector to hand over only public fields would put the
    containment decision in the component that has the material, which is the
    component least able to be audited.
    """
    envelope = project_envelope(
        observation(db_host="erp-db.invalid", db_port=5432, launch_path="/etc/cron.d/erp"),
        clean_scans(),
        vault=RedactionVault(),
    )
    assert set(envelope) == set(ENVELOPE_FIELDS)
    assert "erp-db.invalid" not in repr(envelope)


def test_an_unclassified_new_field_is_refused_rather_than_passed_through():
    """Tomorrow's field cannot leak by default.

    This is the failure that actually happens: a collector grows a field, the
    projection copies what it does not recognize, and the field turns out to be
    a connection string. Default-deny means the new field stops a run and gets
    a decision instead of a commit.
    """
    with pytest.raises(UnclassifiedField) as raised:
        project_envelope(
            observation(replica_endpoint="erp-db.invalid:5432"),
            clean_scans(),
            vault=RedactionVault(),
        )
    assert "replica_endpoint" in str(raised.value)
    # The refusal names the FIELD and not its value -- an exception message is
    # the one string guaranteed to be printed somewhere.
    assert "erp-db.invalid" not in str(raised.value)


# ── Coverage completeness ───────────────────────────────────────────────────


def test_a_missing_family_is_refused_rather_than_omitted():
    partial = clean_scans()
    del partial["anacron"]
    with pytest.raises(ValueError, match="anacron"):
        project_envelope(observation(), partial, vault=RedactionVault())


def test_an_undeclared_family_is_refused():
    extra = clean_scans()
    extra["kubernetes_cronjob"] = FamilyScan(
        family="kubernetes_cronjob", attempted=True, completed=True
    )
    with pytest.raises(ValueError, match="kubernetes_cronjob"):
        project_envelope(observation(), extra, vault=RedactionVault())


def test_coverage_is_ordered_and_complete_so_two_hosts_compare():
    envelope = _project()
    assert [entry["family"] for entry in coverage_of(envelope)] == list(DECLARED_FAMILIES)


def test_the_counts_agree_with_the_coverage_they_summarize():
    scans = clean_scans(
        cron=FamilyScan(family="cron", attempted=True, completed=True, found=2),
        at=FamilyScan(family="at", attempted=False, completed=False),
    )
    envelope = project_envelope(observation(), scans, vault=RedactionVault())
    counts = counts_of(envelope)
    assert counts["families_declared"] == len(DECLARED_FAMILIES)
    assert counts["families_scanned"] == 1
    assert counts["families_unknown"] == 1
    assert counts["families_absent"] == len(DECLARED_FAMILIES) - 2
    verdicts = [entry["verdict"] for entry in coverage_of(envelope)]
    assert verdicts.count(Verdict.UNKNOWN.value) == counts["families_unknown"]


# ── The three references, three authorities ─────────────────────────────────


@pytest.mark.parametrize("missing", ["authorization_digest", "challenge_digest", "authority_ref"])
def test_each_reference_is_required_because_none_implies_the_others(missing):
    """Permission and challenge are issued by DIFFERENT authorities.

    `ConsumerAttributionAuthorizationV1` (deployment control) says you may look
    at this host. `AttributionChallengeV1` (the observation authority) supplies
    the nonce and says what counts as proof of the answer. One document holding
    both would let whoever granted permission also define what the result means,
    which is the loop this split exists to keep open. So neither reference can
    stand in for the other and neither is optional.
    """
    arguments = {
        "authorization_digest": DIGEST_C,
        "challenge_digest": DIGEST_D,
        "authority_ref": "control:decision/7f2c",
    }
    arguments[missing] = ""
    with pytest.raises(ValueError, match=missing):
        verify_request(**arguments)


def test_verify_request_records_and_does_not_adjudicate():
    """It returns what it was given. It does not verify a signature or approve.

    Anything stronger would need the upstream shapes, and knowing them here
    means defining them here -- which is how an adopter becomes a second
    authorization authority (rule 20).
    """
    recorded = verify_request(
        authorization_digest=DIGEST_C,
        challenge_digest=DIGEST_D,
        authority_ref="control:decision/7f2c",
    )
    assert recorded == {
        "authorization_digest": DIGEST_C,
        "challenge_digest": DIGEST_D,
        "authority_ref": "control:decision/7f2c",
    }


def test_the_two_digests_stay_distinct_in_the_envelope():
    """Reaching for the near-miss reference is how a wrong binding ships green.

    If the projection ever wrote one digest into both fields, every assertion
    that merely checks "a digest is present" would still pass while the
    envelope claimed a challenge it never received.
    """
    envelope = _project()
    assert envelope["authorization_digest"] != envelope["challenge_digest"]
    assert envelope["authorization_digest"] == DIGEST_C
    assert envelope["challenge_digest"] == DIGEST_D


# ── Containment ─────────────────────────────────────────────────────────────


def test_the_target_type_has_no_password_field_to_begin_with():
    """Not "the password is cleared" -- there is nowhere to put one.

    A field that can hold a secret eventually holds one, and then `repr`,
    `dataclasses.asdict` and every traceback frame carry it.
    """
    assert not hasattr(Target(target_id="erp-production"), "password")
    assert "password" not in Target.__dataclass_fields__


def test_parsing_a_dsn_poisons_it_and_returns_no_password():
    vault = RedactionVault()
    target = parse_dsn(CONSUMER_DSN, target_id="erp-production", vault=vault)
    assert target.target_id == "erp-production"
    assert vault.contains("pw-fixture"), "the password was not poisoned"
    assert vault.contains(CONSUMER_DSN), "the raw DSN was not poisoned"
    assert vault.contains("erp-db.invalid")
    # The parsed host exists on the object so it can be digested, and is kept
    # out of `repr` because `repr` is what a debugger, a log and pytest print.
    assert "erp-db.invalid" not in repr(target)
    assert "obsuser" not in repr(target)


def test_a_bare_dsn_still_parses_and_still_poisons():
    vault = RedactionVault()
    parse_dsn(BARE_DSN, target_id="erp-production", vault=vault)
    assert vault.contains("erp-db.invalid")


def test_the_vault_prints_a_count_and_never_its_contents():
    vault = RedactionVault()
    vault.poison(CONSUMER_DSN)
    assert repr(vault) == "<RedactionVault 1 poisoned value(s)>"
    assert CONSUMER_DSN not in repr(vault)
    assert CONSUMER_DSN not in str(vault)
    assert CONSUMER_DSN not in f"{vault}"


def test_the_vault_refuses_to_be_serialized():
    """A vault reaching a pickle, a receipt or a `json.dumps` hook is the leak.

    Raising in `__reduce__` and `__getstate__` closes both routes at once, and
    an exception at the moment of serialization is a far better outcome than a
    file that quietly contains every parsed DSN on the host.
    """
    vault = RedactionVault()
    vault.poison(CONSUMER_DSN)
    with pytest.raises(LeakRefusal):
        pickle.dumps(vault)
    with pytest.raises(LeakRefusal):
        copy.deepcopy(vault)


def test_assert_clean_matches_a_substring_not_an_equal_value():
    """The leak that happened was a DSN EMBEDDED in a longer sentence.

    An equality check passes that cleanly, which is precisely why this one is a
    substring scan: containment has to survive the value being interpolated.
    """
    vault = RedactionVault()
    vault.poison("erp-db.invalid")
    vault.assert_clean({"target_id": "erp-production"})
    with pytest.raises(LeakRefusal):
        vault.assert_clean({"note": "connection to erp-db.invalid refused"})


def test_a_poisoned_key_is_caught_as_well_as_a_poisoned_value():
    """A dict keyed by hostname discloses the hostname just as loudly."""
    vault = RedactionVault()
    vault.poison("erp-db.invalid")
    with pytest.raises(LeakRefusal):
        vault.assert_clean({"erp-db.invalid": 1})


def test_the_refusal_names_the_path_and_never_the_value():
    vault = RedactionVault()
    vault.poison("erp-db.invalid")
    with pytest.raises(LeakRefusal) as raised:
        vault.assert_clean({"note": "erp-db.invalid"})
    assert "erp-db.invalid" not in str(raised.value)
    assert "/note" in str(raised.value)


def test_the_projection_aborts_when_a_poisoned_value_reaches_a_public_field():
    """It aborts. It does not redact and continue.

    Redacting means the payload was built from material that should never have
    reached the builder, and a redactor only has to miss one spelling.
    """
    vault = RedactionVault()
    vault.poison("erp-production")
    with pytest.raises(LeakRefusal):
        project_envelope(observation(), clean_scans(), vault=vault)


# ── The error path, which is the path nobody tests ──────────────────────────


def test_an_exception_reduces_to_a_type_name():
    """The v1 defect, named: `"{}: {}".format(type(e).__name__, e)`.

    `str(exc)` on a libpq or URL failure quotes the thing it failed on, so the
    leak arrived through the error formatter. There is deliberately no argument
    to `safe_error` that re-enables detail.
    """
    error = ValueError(f"could not connect to {CONSUMER_DSN}")
    assert safe_error(error) == "ValueError"
    assert CONSUMER_DSN not in safe_error(error)
    assert "erp-db.invalid" not in safe_error(error)


def test_a_failure_mid_parse_carries_the_type_and_not_the_value():
    vault = RedactionVault()
    with pytest.raises(ValueError) as raised:
        parse_dsn(
            "postgresql://obsuser:pw-fixture@erp-db.invalid:notaport/erpdb",
            target_id="erp-production",
            vault=vault,
        )
    message = str(raised.value)
    assert "erp-db.invalid" not in message
    assert "pw-fixture" not in message
    assert "ValueError" in message


def test_the_entry_point_prints_a_type_name_and_suppresses_the_traceback():
    """A traceback prints SOURCE LINES and every chained frame's message.

    So no `except` inside the module is sufficient on its own: an unhandled
    failure mid-parse writes the DSN to stderr regardless. `BaseException` is
    deliberate -- a `KeyboardInterrupt` unwinds through frames holding the DSN
    just as a `ValueError` does.
    """
    previous_limit = getattr(sys, "tracebacklimit", None)
    stderr, sys.stderr = sys.stderr, io.StringIO()
    try:

        def boom() -> int:
            raise RuntimeError(f"failed against {CONSUMER_DSN}")

        code = run_guarded(boom)
        written = sys.stderr.getvalue()
    finally:
        sys.stderr = stderr
        if previous_limit is None:
            if hasattr(sys, "tracebacklimit"):
                del sys.tracebacklimit
        else:
            sys.tracebacklimit = previous_limit

    assert code == 1
    assert "RuntimeError" in written
    assert CONSUMER_DSN not in written
    assert "pw-fixture" not in written


def test_every_classified_field_is_decided_one_way_or_the_other():
    """No field sits in the table undecided, and the private ones outnumber none.

    A classification table with only public entries would pass every test above
    while providing no evidence that anybody thought about the private side.
    """
    assert set(CLASSIFIED_FIELDS) >= set(_PRIVATE_NAMES)
    assert all(isinstance(value, bool) for value in CLASSIFIED_FIELDS.values())
    assert not any(CLASSIFIED_FIELDS[name] for name in _PRIVATE_NAMES)
    assert {name for name, public in CLASSIFIED_FIELDS.items() if public} <= set(
        ENVELOPE_FIELDS
    ) | {
        "consumers_attributed",
        "consumers_unattributed",
    }
