"""Strict JSON helpers shared by the VulnSight result models.

Everything here works on plain JSON data (dictionaries, lists, strings,
numbers, booleans and ``None``). Nothing executes or imports scanned code, and
nothing uses pickle.
"""

import json
import math
from enum import Enum
from typing import Any, TypeVar

from vulnsight.scanner.taint_model import (
    MAX_TRACE_STEPS,
    Neutralization,
    SourceKind,
    TaintLabel,
    TaintOrigin,
    TraceKind,
    TraceStep,
)

E = TypeVar("E", bound=Enum)


class SchemaError(ValueError):
    """Raised when data does not follow the VulnSight JSON schema."""


def dumps_canonical(data: Any) -> str:
    """Serialize JSON data deterministically.

    Keys are sorted, output is indented and ASCII-only, and NaN or infinity are
    rejected. The result is identical on every platform and Python run.
    """

    return json.dumps(
        data,
        sort_keys=True,
        indent=2,
        ensure_ascii=True,
        allow_nan=False,
    )


def _reject_constant(name: str):
    raise SchemaError(f"invalid JSON constant: {name}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object, rejecting a key that appears more than once."""

    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise SchemaError(f"invalid JSON: duplicate key {key!r}")

        result[key] = value

    return result


def loads_strict(text: str) -> Any:
    """Parse JSON text, rejecting NaN, Infinity, duplicate keys and bad input."""

    if not isinstance(text, str):
        raise SchemaError("JSON input must be a string")

    try:
        return json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except SchemaError:
        # Raised by our own hooks (duplicate keys, NaN, Infinity): keep as is.
        raise
    except ValueError as error:
        # JSONDecodeError is a ValueError, and so is the error Python raises
        # for an integer longer than its configured digit limit.
        raise SchemaError(f"invalid JSON: {error}") from error
    except RecursionError as error:
        raise SchemaError("invalid JSON: nesting is too deep") from error


class Reader:
    """Typed, path-aware access to one JSON object.

    Every read marks its key as used. ``finish()`` rejects keys nobody read, so
    unknown keys are errors instead of being silently ignored.
    """

    def __init__(self, data: Any, path: str):
        if not isinstance(data, dict):
            raise SchemaError(f"{path}: expected an object")

        for key in data:
            if not isinstance(key, str):
                raise SchemaError(f"{path}: object keys must be strings")

        self._data = data
        self.path = path
        self._used: set[str] = set()

    def _fetch(self, key: str) -> Any:
        if key not in self._data:
            raise SchemaError(f"{self.path}.{key}: missing required key")

        self._used.add(key)

        return self._data[key]

    def _is_null(self, key: str) -> bool:
        """Report whether a key is present and null (a missing key is not)."""

        if key in self._data and self._data[key] is None:
            self._used.add(key)

            return True

        return False

    def _fail(self, key: str, expected: str):
        raise SchemaError(f"{self.path}.{key}: expected {expected}")

    def text(self, key: str) -> str:
        value = self._fetch(key)

        if not isinstance(value, str):
            self._fail(key, "a string")

        return value

    def optional_text(self, key: str) -> str | None:
        value = self._fetch(key)

        if value is not None and not isinstance(value, str):
            self._fail(key, "a string or null")

        return value

    def integer(self, key: str) -> int:
        value = self._fetch(key)

        if isinstance(value, bool) or not isinstance(value, int):
            self._fail(key, "an integer")

        return value

    def optional_integer(self, key: str) -> int | None:
        value = self._fetch(key)

        if value is None:
            return None

        if isinstance(value, bool) or not isinstance(value, int):
            self._fail(key, "an integer or null")

        return value

    def number(self, key: str) -> float:
        value = self._fetch(key)

        if isinstance(value, bool) or not isinstance(value, int | float):
            self._fail(key, "a number")

        try:
            number = float(value)
        except OverflowError:
            # An integer too large for a float is not a finite number.
            self._fail(key, "a finite number")

        if not math.isfinite(number):
            self._fail(key, "a finite number")

        return number

    def optional_number(self, key: str) -> float | None:
        if self._is_null(key):
            return None

        return self.number(key)

    def enum(self, key: str, enum_type: type[E]) -> E:
        value = self.text(key)

        try:
            return enum_type(value)
        except ValueError:
            allowed = ", ".join(sorted(member.value for member in enum_type))
            raise SchemaError(
                f"{self.path}.{key}: {value!r} is not one of: {allowed}"
            ) from None

    def optional_enum(self, key: str, enum_type: type[E]) -> E | None:
        if self._is_null(key):
            return None

        return self.enum(key, enum_type)

    def array(self, key: str) -> list:
        value = self._fetch(key)

        if not isinstance(value, list):
            self._fail(key, "an array")

        return value

    def strings(self, key: str) -> tuple[str, ...]:
        items = self.array(key)

        for index, item in enumerate(items):
            if not isinstance(item, str):
                raise SchemaError(f"{self.path}.{key}[{index}]: expected a string")

        return tuple(items)

    def object(self, key: str) -> "Reader":
        return Reader(self._fetch(key), f"{self.path}.{key}")

    def optional_object(self, key: str) -> "Reader | None":
        if self._is_null(key):
            return None

        return self.object(key)

    def objects(self, key: str) -> list["Reader"]:
        return [
            Reader(item, f"{self.path}.{key}[{index}]")
            for index, item in enumerate(self.array(key))
        ]

    def mapping(self, key: str) -> dict[str, Any]:
        """Return a nested object as a plain dictionary."""

        value = self._fetch(key)

        if not isinstance(value, dict):
            self._fail(key, "an object")

        return value

    def finish(self):
        unknown = sorted(set(self._data) - self._used)

        if unknown:
            raise SchemaError(f"{self.path}: unknown keys: {', '.join(unknown)}")


# ---------------------------------------------------------------
# Taint-model codecs
# ---------------------------------------------------------------


def _build(path: str, factory, *args, **kwargs):
    """Call a model constructor, turning its ValueError into a SchemaError."""

    try:
        return factory(*args, **kwargs)
    except (ValueError, TypeError) as error:
        raise SchemaError(f"{path}: {error}") from error


def origin_to_dict(origin: TaintOrigin) -> dict[str, Any]:
    return {
        "origin_id": origin.origin_id,
        "kind": origin.kind.value,
        "line": origin.line,
        "col": origin.col,
    }


def origin_from_reader(reader: Reader) -> TaintOrigin:
    origin = _build(
        reader.path,
        TaintOrigin,
        origin_id=reader.text("origin_id"),
        kind=reader.enum("kind", SourceKind),
        line=reader.integer("line"),
        col=reader.integer("col"),
    )
    reader.finish()

    return origin


def step_to_dict(step: TraceStep) -> dict[str, Any]:
    return {
        "kind": step.kind.value,
        "line": step.line,
        "col": step.col,
        "text": step.text,
    }


def step_from_reader(reader: Reader) -> TraceStep:
    text = reader.text("text")
    step = _build(
        reader.path,
        TraceStep,
        kind=reader.enum("kind", TraceKind),
        line=reader.integer("line"),
        col=reader.integer("col"),
        text=text,
    )
    reader.finish()

    if step.text != text:
        # TraceStep shortens long text; refuse to change data silently.
        raise SchemaError(f"{reader.path}.text: text is longer than the model allows")

    return step


def _neutralization_key(item: Neutralization):
    return (item.cwe, tuple(sorted(item.platforms)), item.via)


def neutralization_to_dict(item: Neutralization) -> dict[str, Any]:
    return {
        "cwe": item.cwe,
        "platforms": sorted(item.platforms),
        "via": item.via,
    }


def neutralization_from_reader(reader: Reader) -> Neutralization:
    platforms = reader.strings("platforms")

    if len(set(platforms)) != len(platforms):
        raise SchemaError(f"{reader.path}.platforms: duplicate platforms")

    item = _build(
        reader.path,
        Neutralization,
        cwe=reader.text("cwe"),
        platforms=frozenset(platforms),
        via=reader.text("via"),
    )
    reader.finish()

    return item


def label_to_dict(label: TaintLabel) -> dict[str, Any]:
    return {
        "origin": origin_to_dict(label.origin),
        "trace": [step_to_dict(step) for step in label.trace],
        "neutralizations": [
            neutralization_to_dict(item)
            for item in sorted(label.neutralizations, key=_neutralization_key)
        ],
    }


def label_from_reader(reader: Reader) -> TaintLabel:
    origin = origin_from_reader(reader.object("origin"))
    trace_readers = reader.objects("trace")

    if len(trace_readers) > MAX_TRACE_STEPS:
        # TaintLabel would shorten the trace; refuse to change data silently.
        raise SchemaError(f"{reader.path}.trace: more than {MAX_TRACE_STEPS} steps")

    trace = tuple(step_from_reader(item) for item in trace_readers)
    neutralizations = [
        neutralization_from_reader(item) for item in reader.objects("neutralizations")
    ]

    if len(set(neutralizations)) != len(neutralizations):
        raise SchemaError(f"{reader.path}.neutralizations: duplicate entries")

    label = _build(
        reader.path,
        TaintLabel,
        origin=origin,
        trace=trace,
        neutralizations=frozenset(neutralizations),
    )
    reader.finish()

    return label
