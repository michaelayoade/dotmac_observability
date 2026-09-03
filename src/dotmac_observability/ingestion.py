"""The ingestion boundary: what is accepted, what is refused, and what is unmeasured.

The decision authority for ``observability-telemetry-ingestion.v1``. Everything
else — the loader's gates, the rendered alerts, the tests — is a caller. It
performs no I/O and holds no state, for the same reason
:mod:`~dotmac_observability.live_verify` does: a classifier that reached a
network could not be exercised against planted material in a unit test, and
planted material is the only evidence a rejection rule still bites.

Three ideas carry the module.

**Rejection is by RULE, not by outcome.** :func:`classify` runs the declared
rejection rules before the accepted vocabulary, and reports WHICH rule refused
a record. That ordering is not a preference. A planted probe usually carries an
attribute this contract does not accept anyway, so a classifier that checked
the vocabulary first would refuse every probe for the wrong reason and every
rejection rule would appear to bite while doing nothing at all. The gate in
:mod:`~dotmac_observability.validate` compares the rule NAME, so a rule that
has stopped matching fails even though the probe is still refused.

**A negative suite needs a positive control.** A classifier that refuses
everything satisfies every rejection probe ever written, and nothing about the
refusals distinguishes it from a correct one. The contract therefore carries
``accepted_control`` records that must be ACCEPTED, checked in the same pass.

**Dropped and never sent are different facts.** :data:`UNMEASURED` is a verdict,
not a missing value. A counter that has never been written and a counter
standing at zero are the same number and opposite news, and the only way to
keep them apart is to give the first one its own name — here, in the rendered
alerts, and in the read-back.

Planted material is BUILT rather than written down. Nothing in this file, and
nothing in the contract, contains a string that looks like a credential; the
shapes are assembled from repeated characters at call time. A repository that
had to commit realistic secret-shaped strings in order to prove it refuses
secret-shaped strings would be defeating its own scanner to do it, and this one
has already published a credential basename once (PR #6).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from .model import AcceptedAttribute, Ingestion, RejectionRule

__all__ = [
    "ACCEPTED",
    "PLANTED_SHAPES",
    "REJECTED",
    "UNMEASURED",
    "VALUE_SHAPE_NAMES",
    "RebuildComparison",
    "Verdict",
    "classify",
    "compare_rebuild",
    "duration_seconds",
    "integrity_state",
    "planted_value",
]

ACCEPTED: Final = "accepted"
REJECTED: Final = "rejected"

#: The verdict for a fact that was never observed, distinct from every fact that
#: was. Spelled the way the Knowledge health surface spells it, deliberately: a
#: fleet that uses two words for "nobody looked" ends up reading one of them as
#: "fine".
UNMEASURED: Final = "UNMEASURED"

# Synthetic material, assembled rather than committed. Every value is
# structurally what its name says and cryptographically worthless: the repeated
# characters are the point, because a probe that carried entropy would be
# indistinguishable from a leak in every scanner this repository runs.
_FILLER: Final = "A"
_HEX_FILLER: Final = "0"


def planted_value(shape: str) -> str:
    """Materialise one named synthetic shape.

    Raises :class:`KeyError` for an unknown shape rather than returning a
    placeholder. A probe naming a shape the classifier does not know is a probe
    that would otherwise be run against an empty string and pass by refusing
    nothing.
    """
    return PLANTED_SHAPES[shape]


PLANTED_SHAPES: Final[Mapping[str, str]] = {
    "bearer": "Bearer " + _FILLER * 40,
    "basic": "Basic " + _FILLER * 32,
    "cookie": "sid=" + _FILLER * 32 + "; Path=/; HttpOnly",
    "api_key": "sk-" + _FILLER * 32,
    "session_id": _FILLER * 48,
    # Assembled across a concatenation so the armoured header never appears as a
    # literal on any line: the secret scanner reads lines, and a file that
    # tripped it would have to be added to the exclusion list, which is how a
    # detector acquires the blind spot that eventually matters.
    "pem_private_key": "-----BEGIN " + "PRIVATE KEY-----\n" + _FILLER * 64,
    "json_body": '{"note": "' + _FILLER * 24 + '"}',
    "query_string": "?q=" + _FILLER * 8 + "&sid=" + _FILLER * 32,
    "clean_short_text": "control",
    "log_level": "info",
    # IPv6, for two reasons that both matter. Rule 14's detector refuses a
    # literal IPv4 address in any source file and an exemption here would
    # widen its blind spot to buy a test fixture; and the family this fleet
    # keeps getting wrong is the one nobody exercises, so the positive
    # control runs down the path that produced seven dead firewall rules.
    "loopback_address": "::1",
    "hex32": _HEX_FILLER * 31 + "1",
    "hex16": _HEX_FILLER * 15 + "1",
    "uuid": "00000000-0000-4000-8000-000000000001",
}

# Value shapes a `value_shape` rejection rule may name. Named forms rather than
# regular expressions typed into a TOML document, for the reason the contract
# gives: a pattern in a data file is code that no reviewer reads as code.
_BEARER = re.compile(r"^(?:Bearer|Basic|Digest)\s+\S+", re.IGNORECASE)
_COOKIE_PAIR = re.compile(r"^[A-Za-z0-9_.-]+=[^;]{8,}(?:;|$)")
_API_KEY = re.compile(r"^(?:sk|pk|key|tok)[-_][A-Za-z0-9._-]{16,}$", re.IGNORECASE)
_PEM = re.compile(r"-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}")
_LONG_OPAQUE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")
_QUERY_STRING = re.compile(r"^\?|(?:^|&)[A-Za-z0-9_.-]+=[^&]*&")
_JSON_DOCUMENT = re.compile(r"^\s*[{\[]")

_VALUE_SHAPES: Final[Mapping[str, re.Pattern[str]]] = {
    "authorization_credential": _BEARER,
    "cookie_pair": _COOKIE_PAIR,
    "api_key": _API_KEY,
    "pem_private_key": _PEM,
    "long_opaque_token": _LONG_OPAQUE,
    "query_string": _QUERY_STRING,
    "json_document": _JSON_DOCUMENT,
}

#: The shapes a `value_shape` rejection rule may name. Published so the loader
#: can refuse a rule naming one this module does not implement, rather than
#: letting the rule sit in the contract matching nothing: an inert rule and a
#: rule with nothing to catch produce identical evidence.
VALUE_SHAPE_NAMES: Final[frozenset[str]] = frozenset(_VALUE_SHAPES)

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_INTEGER = re.compile(r"^[0-9]{1,9}$")


_DURATION_UNITS: Final[Mapping[str, float]] = {
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
    "y": 31536000.0,
}


def duration_seconds(value: str) -> float:
    """A declared duration in seconds, so two of them can be compared.

    One implementation, imported by both the loader and the renderer. Two
    spellings of this would be two answers to "is the projection kept longer
    than its source", and the answer that reached the rendered alert would be
    whichever module the caller happened to be in.

    The contract's pattern already guarantees the shape, so this parses rather
    than validates; a value that reached here unvalidated raises rather than
    returning zero, because zero compares as "no retention at all" and passes
    every upper-bound check there is.
    """
    for unit in ("ms", "s", "m", "h", "d", "w", "y"):
        head = value[: -len(unit)]
        if value.endswith(unit) and head.isdigit():
            return int(head) * _DURATION_UNITS[unit]
    raise ValueError(f"not a declared duration: {value!r}")


@dataclass(frozen=True, slots=True)
class Verdict:
    """One record's fate, and the reason for it.

    ``rule`` names the DECLARED rejection rule that refused the record, or one
    of the two built-in refusals below. A caller that only reads ``outcome``
    cannot tell a rule that is working from a rule that has been superseded by
    the vocabulary check, which is the failure this field exists to prevent.
    """

    outcome: str
    rule: str | None = None
    attribute: str | None = None
    reason: str = ""


#: A record carrying an attribute the contract does not accept. Built in rather
#: than declared, because it is the closure of the vocabulary rather than a
#: policy about any particular field.
_UNKNOWN_ATTRIBUTE: Final = "attribute-not-accepted"
#: An accepted attribute whose value fails its own declared validation. The
#: contract's central claim is that a field accepted and never validated is a
#: field nobody owns; this is where the validation is actually applied.
_INVALID_VALUE: Final = "attribute-value-invalid"


def _matches(rule: RejectionRule, name: str, value: str) -> bool:
    if rule.kind == "attribute_name":
        return name.lower() == rule.match.lower()
    if rule.kind == "attribute_prefix":
        return name.lower().startswith(rule.match.lower())
    pattern = _VALUE_SHAPES.get(rule.match)
    if pattern is None:
        # A rule naming a shape this module does not implement must never be
        # silently inert: an unmatched rule is a rule that refuses nothing, and
        # the loader's gate would then be checking a probe against a rule that
        # cannot fire. The loader refuses such a rule outright
        # (`REJECTION-UNKNOWN-SHAPE`); returning False here is the belt to that
        # brace and is unreachable through a validated document.
        return False
    return bool(pattern.search(value))


def _shape_ok(shape: str, value: str) -> bool:
    if shape == "ip_address":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True
    if shape == "hex32":
        return bool(_HEX32.match(value))
    if shape == "hex16":
        return bool(_HEX16.match(value))
    if shape == "uuid":
        return bool(_UUID.match(value))
    if shape == "printable_short":
        return len(value) <= 256 and value.isprintable()
    if shape == "duration_ms":
        return bool(_INTEGER.match(value))
    if shape == "http_status":
        return bool(_INTEGER.match(value)) and 100 <= int(value) <= 599
    return False


def _structurally_safe(attribute: AcceptedAttribute | None, value: str) -> bool:
    """Whether a value is a known structural form on an accepted attribute.

    True only when the attribute is accepted for this signal, its declared
    validation is a strict shape, and the value satisfies that shape. Anything
    else — an unaccepted field, an ``opaque`` or ``enum`` validation, a value
    that fails its own shape — is not exempt from the value-shape rules.
    """
    if attribute is None or attribute.validation.kind != "shape":
        return False
    shape = attribute.validation.shape
    return shape is not None and _shape_ok(shape, value)


def classify(policy: Ingestion, signal: str, attributes: Sequence[tuple[str, str]]) -> Verdict:
    """Decide one record, and say which rule decided it.

    The order is the contract's, and it is the half most easily got wrong:

    1. **Declared rejection rules**, over every attribute the record carries.
    2. **The accepted vocabulary**, which closes everything not named.
    3. **Each accepted attribute's own validation.**

    Running the vocabulary first would be simpler and would make every planted
    probe pass, because a probe plants a field this contract does not accept.
    Every rejection rule would then look like it was working while none of them
    ran, and the day a sender started shipping a cookie under an ACCEPTED
    attribute name is the day the difference would have mattered.
    """
    accepted = {
        attribute.name: attribute for attribute in policy.attributes if signal in attribute.signals
    }
    for name, value in attributes:
        attribute = accepted.get(name)
        for rule in policy.rejected:
            if rule.kind == "value_shape" and _structurally_safe(attribute, value):
                # A value-shape rule is a HEURISTIC over unstructured material.
                # An accepted attribute whose declared validation is a strict
                # structural shape, and whose value satisfies it, is not
                # unstructured, and applying the heuristic anyway refuses real
                # traffic: a UUID request id is thirty-six characters of hex and
                # dashes and matches an opaque-token rule exactly. The positive
                # control found that, which is the argument for having one.
                #
                # Name and prefix rules are NOT exempted. Those say a field must
                # not arrive at all, and a well-formed value in a forbidden
                # field is still a forbidden field.
                continue
            if _matches(rule, name, value):
                return Verdict(
                    REJECTED,
                    rule=rule.name,
                    attribute=name,
                    reason=f"refused by {rule.name}: {rule.kind} {rule.match!r}",
                )
    for name, value in attributes:
        attribute = accepted.get(name)
        if attribute is None:
            return Verdict(
                REJECTED,
                rule=_UNKNOWN_ATTRIBUTE,
                attribute=name,
                reason=(
                    f"{name!r} is not in the accepted vocabulary for {signal}; an open "
                    "vocabulary at the ingestion boundary is how a store acquires a field "
                    "nobody chose"
                ),
            )
        validation = attribute.validation
        if validation.kind == "enum":
            if value not in validation.values:
                return Verdict(
                    REJECTED,
                    rule=_INVALID_VALUE,
                    attribute=name,
                    reason=f"{value!r} is not one of the declared values for {name!r}",
                )
        elif validation.kind == "shape" and (
            validation.shape is None or not _shape_ok(validation.shape, value)
        ):
            return Verdict(
                REJECTED,
                rule=_INVALID_VALUE,
                attribute=name,
                reason=f"value does not match the declared shape for {name!r}",
            )
    return Verdict(ACCEPTED)


def integrity_state(counter: str, value: int | None, baseline: int | None) -> str:
    """``UNMEASURED``, ``GROWING`` or ``STABLE`` for one integrity counter.

    ``value`` is ``None`` when the counter has never been observed — the series
    does not exist, because nothing has ever been dropped and nothing has ever
    been shipped, and those two are not the same fact. Reading ``None`` as zero
    is the single most common way an ingestion dashboard reports a dead
    pipeline as a clean one, and it is why this function exists rather than a
    subtraction at each call site.

    ``baseline`` is ``None`` for the same reason: a delta against a baseline
    that was never recorded is not zero, it is unmeasured (AGENTS.md rule 30 —
    the assertion is that the counter does not GROW from a recorded baseline,
    and an unrecorded baseline makes the assertion unmakeable rather than
    satisfied).
    """
    if value is None or baseline is None:
        return UNMEASURED
    if value < baseline:
        # A counter that went backwards was reset underneath the baseline. The
        # delta is meaningless, not zero: the interval between the reset and now
        # is unobserved, and reporting STABLE would claim the interval was
        # clean.
        return UNMEASURED
    return "GROWING" if value > baseline else "STABLE"


@dataclass(frozen=True, slots=True)
class RebuildComparison:
    """The result of rebuilding the audit projection and comparing it.

    ``verdict`` is one of ``UNMEASURED``, ``MATCHED`` or ``DIVERGED``, and
    ``UNMEASURED`` is not an error case. A rebuild that read nothing from either
    side agrees perfectly with itself, and a comparison that cannot fail is not
    a comparison — the same reason the live-observation contract refuses an
    empty tree read-back rather than passing it as "nothing differs".
    """

    verdict: str
    missing: tuple[str, ...] = ()
    extra: tuple[str, ...] = ()
    differing: tuple[str, ...] = ()


def compare_rebuild(
    source: Mapping[str, str] | None,
    projection: Mapping[str, str] | None,
) -> RebuildComparison:
    """Compare a rebuilt projection against the authoritative audit rows.

    Both arguments map an audit event id to a digest over that row's canonical
    content. The digest is what makes the comparison about CONTENT rather than
    about volume: two sets of the same size agree on a count and can disagree
    about every row in them.

    ``None`` on either side means that side could not be read, which is
    reported as ``UNMEASURED`` rather than as agreement. So is a pair of empty
    inputs, which is the shape a rebuild takes when it failed to connect: it
    produces an exact match, against nothing, in a function whose whole purpose
    is to be able to disagree.

    **Which half exists.** This function is complete and exercised. What does
    not exist is the reader that fills its two arguments: producing ``source``
    means reading audit rows out of each application's own database, which is
    the application's boundary and not this repository's, and producing
    ``projection`` means reading back from a projection this control plane does
    not yet host. Until both readers exist the projection's declared verdict is
    ``UNMEASURED``, and the contract refuses any other value while
    ``last_rebuilt`` is null.
    """
    if source is None or projection is None:
        return RebuildComparison(UNMEASURED)
    if not source and not projection:
        return RebuildComparison(UNMEASURED)
    missing = tuple(sorted(key for key in source if key not in projection))
    extra = tuple(sorted(key for key in projection if key not in source))
    differing = tuple(
        sorted(key for key, digest in source.items() if projection.get(key, digest) != digest)
    )
    if missing or extra or differing:
        return RebuildComparison("DIVERGED", missing, extra, differing)
    return RebuildComparison("MATCHED")
