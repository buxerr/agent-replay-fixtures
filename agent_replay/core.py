from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = 1
MAX_EVENTS = 10_000
MAX_KIND_LENGTH = 256

_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_KNOWN_TOKENS = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,})\b"
)
_SECRET_FIELD_SUFFIXES = (
    "apikey",
    "authorization",
    "password",
    "secret",
    "accesstoken",
    "refreshtoken",
    "idtoken",
)


class ReplayError(Exception):
    """Base error for invalid or unavailable replay fixtures."""


class FixtureNotFound(ReplayError):
    """No fixture matches the redacted request."""


class FixtureIntegrityError(ReplayError):
    """A fixture is malformed, oversized, or has an invalid digest."""


class FixtureConflict(ReplayError):
    """A different trace was already recorded for the same request."""


class TraceMismatch(ReplayError):
    """The next recorded event does not match the caller's expectation."""


class TraceExhausted(ReplayError):
    """The trace has no remaining events."""


class SecretRedactor:
    """Redacts common credential fields and token strings before hashing or writing."""

    def __init__(self, extra_fields: Iterable[str] = ()) -> None:
        self._extra_fields = {self._normalize_field(field) for field in extra_fields}

    @staticmethod
    def _normalize_field(field: str) -> str:
        if not isinstance(field, str):
            raise TypeError("secret field names must be strings")
        return re.sub(r"[^a-z0-9]", "", field.casefold())

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise TypeError("JSON object keys must be strings")
                normalized_key = self._normalize_field(key)
                if self._is_secret_field(normalized_key):
                    result[key] = "[REDACTED]"
                else:
                    result[key] = self.redact(nested)
            return result
        if isinstance(value, (list, tuple)):
            return [self.redact(item) for item in value]
        if isinstance(value, str):
            return _KNOWN_TOKENS.sub("[REDACTED]", _BEARER.sub("[REDACTED]", value))
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        raise TypeError("values must be finite JSON-compatible data")

    def _is_secret_field(self, normalized_key: str) -> bool:
        if normalized_key in self._extra_fields or normalized_key == "token":
            return True
        return any(normalized_key.endswith(suffix) for suffix in _SECRET_FIELD_SUFFIXES)


def _canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise TypeError("value cannot be encoded as deterministic JSON") from error
    return text.encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _validate_events(events: Iterable[Mapping[str, Any]], redactor: SecretRedactor) -> list[dict[str, Any]]:
    if isinstance(events, (str, bytes, dict)):
        raise TypeError("events must be an iterable of event objects")
    result: list[dict[str, Any]] = []
    for event in events:
        if len(result) >= MAX_EVENTS:
            raise ValueError("trace exceeds the event-count limit")
        if not isinstance(event, Mapping):
            raise TypeError("each event must be a mapping")
        if set(event) != {"kind", "payload"}:
            raise ValueError("each event must contain exactly kind and payload")
        kind = event["kind"]
        if not isinstance(kind, str) or not kind or len(kind) > MAX_KIND_LENGTH:
            raise ValueError("event kind must be a non-empty string of at most 256 characters")
        result.append({"kind": kind, "payload": redactor.redact(event["payload"])})
    return result


def _load_fixture(path: Path, expected_request_hash: str, max_fixture_bytes: int) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise FixtureNotFound("fixture file is unavailable") from error
    if size > max_fixture_bytes:
        raise FixtureIntegrityError("fixture exceeds the configured size limit")
    try:
        raw = path.read_bytes()
        if len(raw) > max_fixture_bytes:
            raise FixtureIntegrityError("fixture exceeds the configured size limit")
        envelope = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except FixtureIntegrityError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise FixtureIntegrityError("fixture JSON is malformed") from error
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "sha256"}:
        raise FixtureIntegrityError("fixture envelope has an invalid shape")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "request_sha256", "events"}:
        raise FixtureIntegrityError("fixture payload has an invalid shape")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != SCHEMA_VERSION:
        raise FixtureIntegrityError("fixture schema version is unsupported")
    request_hash = payload["request_sha256"]
    if not isinstance(request_hash, str) or not hmac.compare_digest(request_hash, expected_request_hash):
        raise FixtureIntegrityError("fixture does not match the requested input")
    try:
        actual_hash = _digest(payload)
    except (TypeError, ValueError, RecursionError) as error:
        raise FixtureIntegrityError("fixture payload is not deterministic JSON") from error
    stored_hash = envelope["sha256"]
    if not isinstance(stored_hash, str) or not hmac.compare_digest(stored_hash, actual_hash):
        raise FixtureIntegrityError("fixture digest verification failed")
    events = payload["events"]
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise FixtureIntegrityError("fixture event list is invalid")
    for event in events:
        if (
            not isinstance(event, dict)
            or set(event) != {"kind", "payload"}
            or not isinstance(event["kind"], str)
            or not event["kind"]
            or len(event["kind"]) > MAX_KIND_LENGTH
        ):
            raise FixtureIntegrityError("fixture contains an invalid event")
    return payload


class TraceRecorder:
    """Writes redacted, immutable JSON fixtures without making network calls."""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        redactor: SecretRedactor | None = None,
        max_fixture_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if max_fixture_bytes <= 0:
            raise ValueError("max_fixture_bytes must be positive")
        self.directory = Path(directory)
        self.redactor = redactor or SecretRedactor()
        self.max_fixture_bytes = max_fixture_bytes

    def record(self, request: Any, events: Iterable[Mapping[str, Any]]) -> Path:
        normalized_request = self.redactor.redact(request)
        request_hash = _digest(normalized_request)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "request_sha256": request_hash,
            "events": _validate_events(events, self.redactor),
        }
        envelope = {"payload": payload, "sha256": _digest(payload)}
        raw = _canonical_bytes(envelope)
        if len(raw) > self.max_fixture_bytes:
            raise ValueError("fixture exceeds the configured size limit")

        self.directory.mkdir(parents=True, exist_ok=True)
        target = self.directory / (request_hash + ".json")
        lock_path = self.directory / (request_hash + ".lock")
        file_descriptor, temporary_name = tempfile.mkstemp(prefix=".fixture-", suffix=".tmp", dir=self.directory)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(file_descriptor, "wb") as temporary:
                temporary.write(raw)
                temporary.flush()
                os.fsync(temporary.fileno())
            try:
                lock_path.mkdir()
            except FileExistsError:
                if target.is_file():
                    existing = _load_fixture(target, request_hash, self.max_fixture_bytes)
                    if _canonical_bytes({"payload": existing, "sha256": _digest(existing)}) == raw:
                        return target
                    raise FixtureConflict("a different trace is already stored for this request")
                raise FixtureConflict("another recorder is writing this request fixture")
            try:
                if target.exists():
                    existing = _load_fixture(target, request_hash, self.max_fixture_bytes)
                    if _canonical_bytes({"payload": existing, "sha256": _digest(existing)}) != raw:
                        raise FixtureConflict("a different trace is already stored for this request")
                else:
                    os.replace(temporary_path, target)
            finally:
                lock_path.rmdir()
            return target
        finally:
            temporary_path.unlink(missing_ok=True)


class ReplaySession:
    """Consumes one fixture in order; mismatches never advance the cursor."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = copy.deepcopy(events)
        self._position = 0

    @property
    def remaining(self) -> int:
        return len(self._events) - self._position

    def next_event(self, expected_kind: str | None = None) -> dict[str, Any]:
        if self._position >= len(self._events):
            raise TraceExhausted("trace has no remaining events")
        event = self._events[self._position]
        if expected_kind is not None and event["kind"] != expected_kind:
            raise TraceMismatch("expected event kind " + expected_kind + ", got " + event["kind"])
        self._position += 1
        return copy.deepcopy(event)

    def assert_exhausted(self) -> None:
        if self.remaining:
            raise TraceMismatch("trace has " + str(self.remaining) + " unconsumed event(s)")


class ReplayTransport:
    """Offline-only transport: a missing fixture raises and never falls back to a provider."""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        redactor: SecretRedactor | None = None,
        max_fixture_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if max_fixture_bytes <= 0:
            raise ValueError("max_fixture_bytes must be positive")
        self.directory = Path(directory)
        self.redactor = redactor or SecretRedactor()
        self.max_fixture_bytes = max_fixture_bytes

    def open(self, request: Any) -> ReplaySession:
        request_hash = _digest(self.redactor.redact(request))
        fixture_path = self.directory / (request_hash + ".json")
        if not fixture_path.is_file():
            raise FixtureNotFound("no fixture matches request sha256 " + request_hash)
        payload = _load_fixture(fixture_path, request_hash, self.max_fixture_bytes)
        return ReplaySession(payload["events"])
