from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_replay import (
    FixtureConflict,
    FixtureIntegrityError,
    FixtureNotFound,
    ReplayTransport,
    SecretRedactor,
    TraceExhausted,
    TraceMismatch,
    TraceRecorder,
)

FAKE_API_KEY = "sk-" + "example-" + "a" * 24
FAKE_SECOND_API_KEY = "sk-" + "example-" + "b" * 24
FAKE_GITHUB_TOKEN = "gh" + "p_" + "c" * 36


class ReplayFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        self.request = {
            "model": "example-model",
            "headers": {"Authorization": "Bearer request-header-secret"},
            "api_key": FAKE_API_KEY,
            "input": [{"role": "user", "content": "hello"}],
        }
        self.events = [
            {"kind": "model.response", "payload": {"text": "answer", "usage": {"token_count": 3}}},
            {"kind": "tool.call", "payload": {"name": "lookup", "arguments": {"query": "x"}}},
            {"kind": "tool.result", "payload": {"access_token": "hidden", "result": "ok"}},
        ]

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_redacts_before_persisting_and_replays_in_order(self) -> None:
        fixture = TraceRecorder(self.directory).record(self.request, self.events)
        raw = fixture.read_text(encoding="utf-8")
        self.assertNotIn("request-header-secret", raw)
        self.assertNotIn(FAKE_API_KEY, raw)
        self.assertNotIn('"access_token":"hidden"', raw)
        self.assertIn('"token_count":3', raw)

        replay_request = dict(self.request)
        replay_request["api_key"] = FAKE_SECOND_API_KEY
        session = ReplayTransport(self.directory).open(replay_request)
        self.assertEqual(session.next_event("model.response")["payload"]["text"], "answer")
        self.assertEqual(session.next_event("tool.call")["payload"]["name"], "lookup")
        self.assertEqual(session.next_event("tool.result")["payload"]["access_token"], "[REDACTED]")
        session.assert_exhausted()

    def test_inline_tokens_and_custom_secret_fields_are_redacted(self) -> None:
        redactor = SecretRedactor(extra_fields={"customer_code"})
        result = redactor.redact({
            "message": "use Bearer abc.def-123 and " + FAKE_GITHUB_TOKEN,
            "customer_code": "private",
            "token_count": 42,
        })
        self.assertEqual(result["message"], "use [REDACTED] and [REDACTED]")
        self.assertEqual(result["customer_code"], "[REDACTED]")
        self.assertEqual(result["token_count"], 42)

    def test_missing_fixture_fails_closed(self) -> None:
        with self.assertRaises(FixtureNotFound):
            ReplayTransport(self.directory).open(self.request)

    def test_network_is_never_used_during_replay(self) -> None:
        TraceRecorder(self.directory).record(self.request, self.events)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network access attempted")):
            session = ReplayTransport(self.directory).open(self.request)
            self.assertEqual(session.next_event()["kind"], "model.response")

    def test_event_mismatch_does_not_advance_cursor(self) -> None:
        TraceRecorder(self.directory).record(self.request, self.events)
        session = ReplayTransport(self.directory).open(self.request)
        with self.assertRaises(TraceMismatch):
            session.next_event("tool.call")
        self.assertEqual(session.remaining, 3)
        self.assertEqual(session.next_event()["kind"], "model.response")

    def test_trace_exhaustion_and_unconsumed_event_errors(self) -> None:
        TraceRecorder(self.directory).record(self.request, self.events[:1])
        session = ReplayTransport(self.directory).open(self.request)
        with self.assertRaises(TraceMismatch):
            session.assert_exhausted()
        session.next_event()
        session.assert_exhausted()
        with self.assertRaises(TraceExhausted):
            session.next_event()

    def test_different_trace_for_same_request_is_not_silently_overwritten(self) -> None:
        recorder = TraceRecorder(self.directory)
        path = recorder.record(self.request, self.events)
        original = path.read_bytes()
        with self.assertRaises(FixtureConflict):
            recorder.record(self.request, [{"kind": "model.response", "payload": {"text": "new"}}])
        self.assertEqual(path.read_bytes(), original)

    def test_fixture_digest_detects_edits(self) -> None:
        path = TraceRecorder(self.directory).record(self.request, self.events)
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["payload"]["events"][0]["payload"]["text"] = "edited"
        path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(FixtureIntegrityError):
            ReplayTransport(self.directory).open(self.request)

    def test_non_finite_fixture_values_fail_as_integrity_errors(self) -> None:
        path = TraceRecorder(self.directory).record(self.request, self.events)
        path.write_text(path.read_text(encoding="utf-8").replace('"answer"', "NaN"), encoding="utf-8")
        with self.assertRaises(FixtureIntegrityError):
            ReplayTransport(self.directory).open(self.request)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        path = TraceRecorder(self.directory).record(self.request, self.events)
        path.write_text('{"payload":{},"payload":{},"sha256":"x"}', encoding="utf-8")
        with self.assertRaises(FixtureIntegrityError):
            ReplayTransport(self.directory).open(self.request)

    def test_limits_and_non_json_values_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TraceRecorder(self.directory, max_fixture_bytes=1).record(self.request, self.events)
        with self.assertRaises(TypeError):
            TraceRecorder(self.directory).record({"bad": float("nan")}, [])
        with self.assertRaises(ValueError):
            TraceRecorder(self.directory).record(self.request, [{"kind": "bad", "payload": {}}] * 10_001)


if __name__ == "__main__":
    unittest.main()
