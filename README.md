# Agent Replay Fixtures

Record normalized model and tool-boundary events as local JSON fixtures, redact common credentials before writing, and replay traces without contacting a provider. A missing fixture raises an error; replay has no live-call fallback.

## Install

Install the package with pip install . from this directory. It uses only the Python standard library and supports Python 3.11 or newer.

## Record and replay

TraceRecorder.record(request, events) stores an immutable fixture addressed by the SHA-256 of the redacted request. Each event has exactly two fields: kind and payload. Typical kinds include model.request, model.response, tool.call, tool.result, and stream.chunk.

ReplayTransport.open(request) returns a ReplaySession. Consume events in order with next_event(), optionally checking the expected kind, and call assert_exhausted() at the end of a test. Event mismatches do not advance the trace.

The recorder redacts credential-shaped object fields, common bearer strings, and recognizable provider tokens before both request hashing and persistence. Configure additional secret field names with SecretRedactor(extra_fields={...}). Inspect fixtures before committing them; custom credentials can use formats the default rules do not recognize.

## Test

Run python -m unittest discover -s tests -v.

## Scope

This package provides storage, redaction, integrity checks, and deterministic replay primitives. SDK adapters, provider-specific stream normalization, fixture curation, and encrypted fixture storage are not included yet. Never use production traces as fixtures without reviewing the redacted output.

MIT licensed. See LICENSE.
