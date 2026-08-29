"""A deterministic YAML emitter.

AGENTS.md rule 13 requires that the same inputs produce the same BYTES on any
machine. A general YAML library cannot promise that across versions: quoting
style, key ordering, line width and flow/block choices are all implementation
details that have changed under us before, and a rendered-bytes gate that
fails because a library minor version moved teaches everyone to stop trusting
the gate.

So this module emits the small, closed subset of YAML the control plane
actually needs — nested mappings, sequences, and scalars — with every choice
fixed here in the open:

* two-space indent, block style throughout, no flow collections except the
  empty ones (``{}`` and ``[]``, which have no block spelling);
* insertion order preserved and never sorted, so the caller owns ordering and
  a reviewer sees the order they wrote;
* one quoting rule, applied identically everywhere (see :func:`_scalar`);
* a trailing newline and no trailing whitespace.

The real oracle for correctness is ``promtool check config`` and ``amtool
check-config`` in CI. This module's job is to be *stable*, not clever.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import TypeAlias, TypeGuard

__all__ = ["emit"]

YamlScalar: TypeAlias = str | int | bool | None
YamlValue: TypeAlias = "YamlScalar | Sequence[YamlValue] | Mapping[str, YamlValue]"

_INDENT = "  "

# A scalar is emitted plain only when it cannot be mistaken for anything else:
# an identifier-shaped string that YAML will not read as a number, a boolean,
# a null, a date or a tag. Everything else — anything with a colon, a slash, a
# space, a leading digit, a leading sigil — is double-quoted. The rule is
# deliberately conservative and uniform: "sometimes quoted" is a diff nobody
# can review, and an unquoted `15s` today becomes an unquoted `1e5` tomorrow.
_PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_RESERVED = frozenset(
    {
        "true",
        "false",
        "null",
        "yes",
        "no",
        "on",
        "off",
        "y",
        "n",
        "True",
        "False",
        "Null",
        "Yes",
        "No",
        "On",
        "Off",
        "Y",
        "N",
        "TRUE",
        "FALSE",
        "NULL",
        "YES",
        "NO",
        "ON",
        "OFF",
        "~",
    }
)
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _looks_numeric(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _quote(value: str) -> str:
    out = []
    for char in value:
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif ord(char) < 0x20:
            out.append(f"\\x{ord(char):02x}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def _scalar(value: YamlScalar) -> str:
    if value is None:
        return "null"
    # bool before int: bool IS an int in Python, and `isinstance(True, int)`
    # would render `true` as `1`, which Prometheus reads as a number.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if _PLAIN.match(value) and value not in _RESERVED and not _looks_numeric(value):
        return value
    return _quote(value)


# A TypeGuard rather than a plain bool: it lets the callers below pass the
# narrowed value to `_scalar` without an ignore comment, which keeps the two
# genuine ignores this module might one day need distinguishable from noise.
def _is_scalar(value: YamlValue) -> TypeGuard[YamlScalar]:
    return value is None or isinstance(value, str | int | bool)


def _emit_mapping(node: Mapping[str, YamlValue], depth: int, out: list[str]) -> None:
    pad = _INDENT * depth
    for key, value in node.items():
        label = f"{pad}{_scalar(key)}:"
        if _is_scalar(value):
            out.append(f"{label} {_scalar(value)}")
        elif isinstance(value, Mapping):
            if not value:
                out.append(f"{label} {{}}")
            else:
                out.append(label)
                _emit_mapping(value, depth + 1, out)
        elif isinstance(value, Sequence):
            if not value:
                out.append(f"{label} []")
            else:
                out.append(label)
                _emit_sequence(value, depth + 1, out)
        else:  # pragma: no cover - the type alias forbids it
            raise TypeError(f"unsupported YAML value at {key!r}: {type(value)!r}")


def _emit_sequence(node: Sequence[YamlValue], depth: int, out: list[str]) -> None:
    pad = _INDENT * depth
    for item in node:
        if _is_scalar(item):
            out.append(f"{pad}- {_scalar(item)}")
        elif isinstance(item, Mapping):
            if not item:
                out.append(f"{pad}- {{}}")
                continue
            # The first key rides the dash so the block reads as one record;
            # the rest align under it at the same depth.
            nested: list[str] = []
            _emit_mapping(item, depth + 1, nested)
            first = nested[0].lstrip()
            out.append(f"{pad}- {first}")
            out.extend(nested[1:])
        elif isinstance(item, Sequence):
            if not item:
                out.append(f"{pad}- []")
                continue
            nested = []
            _emit_sequence(item, depth + 1, nested)
            first = nested[0].lstrip()
            out.append(f"{pad}- {first}")
            out.extend(nested[1:])
        else:  # pragma: no cover - the type alias forbids it
            raise TypeError(f"unsupported YAML item: {type(item)!r}")


def emit(document: Mapping[str, YamlValue], *, header: Sequence[str] = ()) -> str:
    """Render ``document`` as block YAML, ending in exactly one newline.

    ``header`` lines are emitted as ``#`` comments before the body. Rendered
    files are committed and read by humans, so every one of them says where it
    came from and that hand-editing it is pointless.
    """
    out: list[str] = [f"# {line}".rstrip() for line in header]
    _emit_mapping(document, 0, out)
    return "\n".join(out) + "\n"
