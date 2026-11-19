# Python LLM Agent Record/Replay Test Fixtures

Run deterministic, offline regression tests for LLM agents and tool-using applications. This Python library records normalized model and tool-boundary events as local JSON fixtures, redacts common credentials before storage, and replays a trace without contacting a provider. A missing fixture raises an error; there is no live-call fallback.

## Install from source

Requires Python 3.11 or newer. Clone the repository and install the local package:

```sh
git clone https://github.com/buxerr/agent-replay-fixtures.git
cd agent-replay-fixtures
python -m pip install .
```

## Record and replay a trace

Each event has a `kind` and `payload`. Common kinds include `model.request`, `model.response`, `tool.call`, `tool.result`, and `stream.chunk`.

```python
from agent_replay import ReplayTransport, TraceRecorder

request = {"model": "example", "messages": [{"role": "user", "content": "Hi"}]}
events = [{"kind": "model.response", "payload": {"text": "Hello"}}]

fixtures = "tests/fixtures"
TraceRecorder(fixtures).record(request, events)

session = ReplayTransport(fixtures).open(request)
response = session.next_event("model.response")
assert response["payload"]["text"] == "Hello"
session.assert_exhausted()
```

`TraceRecorder.record` writes an immutable fixture addressed by the SHA-256 of the redacted request. `ReplayTransport.open` matches that request and returns a `ReplaySession`. An event-kind mismatch does not advance the trace.

## Redaction and fixture safety

The default redactor recognizes credential-shaped object fields, common bearer strings, and several provider token formats. Add field names with `SecretRedactor(extra_fields={"customer_secret"})`. Review generated fixtures before committing them: custom credentials may use formats the default rules do not recognize, and redaction is not encryption.

Run the unit suite with `python -m unittest discover -s tests -v`.

## Scope and limitations

The package provides fixture storage, redaction, integrity checks, and deterministic replay primitives. It does not include SDK adapters, provider-specific stream normalization, fixture curation, or encrypted fixture storage. Connect it to the model and tool boundaries in your own test harness.

## License

MIT. See [LICENSE](LICENSE).
