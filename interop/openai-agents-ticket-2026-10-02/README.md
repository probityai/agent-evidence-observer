# OpenAI Agents SDK trace and protected ticket reference

This installable reference uses OpenAI Agents SDK **0.23.1**: actual `Runner`,
`ModelResponse`, `function_tool`, native agent/task/turn/function/generation spans,
and an application-owned `TracingProcessor`. A scripted native `Model` supplies
fixed synthetic calls. No provider API request, credential or model inference is
used. The protected target is Observer's existing signed HTTP/SQLite ticket
service, built from the separately selected source commit
`71ac0b2126473316655184235000647a6dd0f5cf`.

The complete six-case plan freezes before execution. Permit commits revision 1;
revocation and changed arguments are refused with unchanged revision 0; a tool
failure before HTTP leaves revision 0. A tool failure after committed HTTP and
`MaxTurnsExceeded` after a committed tool both retain revision 1, while task status
stays **error** or **incomplete**. Task completion is distinct from dispatch
permission and authenticated effect completion. All nine scripted model calls,
six tool invocations and 36 native span lifecycles must remain represented.

## Install and execute

Choose an immutable adapter source revision. This builds ordinary wheels from Git;
it is not a PyPI release. Python 3.13 is tested. Runtime dependencies and producer
SDK are selected by hashes in `requirements.lock`.

```sh
# Run from this profile in your selected adapter checkout.
python -m venv .producer-env
.producer-env/bin/python -m pip install --require-hashes -r requirements.lock
git worktree add --detach selected-observer 71ac0b2126473316655184235000647a6dd0f5cf
.producer-env/bin/python -m pip wheel --no-deps --no-build-isolation selected-observer . --wheel-dir selected-wheels
.producer-env/bin/python verify_wheels.py selected-wheels --selection source-selection.json
.producer-env/bin/python -m pip install --no-deps selected-wheels/*.whl
.producer-env/bin/probity-openai-run /tmp/new-openai-packet --source-revision "$(git rev-parse HEAD)"
```

The command refuses an existing packet. Private signing keys and SQLite databases
stay in a temporary directory; the retained packet contains public grants, signed
receipts, original HTTP bytes, installed sources/license, the before-run plan,
original SDK callback exports, task errors, and bounded wall/process CPU counters.
A 90-second serial execution budget permits six attempts and at most nine model
calls. SDK usage is zero by construction; these counters measure integration
execution, not language model tokens or quality.

## Register the processor

For an application, install the producer extra and register **before any trace or
agent run**. Compatibility is bounded to SDK 0.23.1 and this tested reference.

```python
from agents import set_trace_processors
from probity_openai.processor import LocalTraceProcessor

collector = LocalTraceProcessor()  # payload capture is off by default
set_trace_processors([collector])  # replaces the default OpenAI exporter
# Run your application's actual Agents SDK workflow here.
collector.force_flush()
collector.shutdown()              # idempotent; closes further capture
capture = collector.snapshot()
```

The export destination is the application-owned in-memory snapshot. There is no
network exporter, background queue or callback logging. Callbacks are serialized
with a lock. `force_flush` marks synchronous capture completion; `shutdown` flushes
and closes. Metadata mode retains identifiers, parent relationships, native times
and span types only. It omits workflow/model/operation names, inputs, outputs,
custom data, errors and user metadata. `capture_payloads=True` retains detached
native exports and can include sensitive inputs, outputs or errors. Only finite,
public synthetic fixtures opt in in this reference. It does not sanitize another
processor, previous buffers, framework logs or other application channels.

Replacing processors is essential: `add_trace_processor` would preserve the
default OpenAI exporter. Serialization and closed-processor failures increment a
fixed counter without retaining error payloads. The SDK can continue executing
when a processor fails; publication must refuse that incomplete capture. This
profile's reader requires zero capture failures, explicit flush and shutdown,
complete trace/span parentage and chronology, and every declared attempt.

## Install the separate reader and select host policy

```sh
python -m venv .reader-env
.reader-env/bin/python -m pip install --require-hashes -r requirements-reader.lock
.reader-env/bin/python -m pip install --no-deps selected-wheels/*.whl
.reader-env/bin/python -c "import importlib.util; assert importlib.util.find_spec('agents') is None and importlib.util.find_spec('openai') is None"
.reader-env/bin/probity-openai-read /tmp/new-openai-packet --pins-file /path/to/host-selected-policy.json
```

The reader requires a separately supplied pins file: exact plan, source-manifest
and artifact-manifest SHA-256 values, profile and UTC consumer reference time.
The producer emits a demonstration pins file. Copying it is author-operated
replay, not an independent host selection. A host must select its own policy and
reader wheel hashes outside the candidate packet, run the reader as a gate, and
publish only on verified status and the full six-attempt population. An upgrade
selects new adapter source bytes and wheel hashes, builds into a new directory,
then replays retained packets before changing the host's selection. The protected
Observer baseline stays separately pinned; this reference creates no release tag.

The reader imports neither SDK nor OpenAI client and makes no network request.
It authenticates signed native effects separately from SDK trace records. Trace
records and source hashes remain same-operator provenance; they do not prove
independent effect custody. The profile's admission decision applies to this
bounded synthetic integration population, not arbitrary application traces.

## Reproduce compatibility and refusal controls

```sh
.producer-env/bin/python -m pytest tests -q
.producer-env/bin/ruff check --select E,F,I,C901 --config 'lint.mccabe.max-complexity=5' src tests verify_wheels.py
```

The tests run the installed real SDK, check opt-in/default capture and callback
failures, retain failure after committed effects and incomplete tasks, and reject
omitted model/tool/span records, reordered/misparented traces, changed native
read-back, wrong scope/budgets, boolean numeric substitutions and unclosed capture
**after** artifact digest reselection. CI rebuilds source-proven standard wheels,
executes a new six-case packet outside the source directory, and reproduces its
report with a separate SDK-free reader. Original artifacts expire after 90 days;
retained capsules and exact run IDs must be recorded separately.

## Ownership and outside use

Probity maintains this reference through
[Observer issues](https://github.com/probityai/agent-evidence-observer/issues).
Compatibility changes require source selections, native runs and semantic refusal
checks. No outside acceptance, recurring host use or independent custody is
established by this author-operated reference.

The SDK's [current contribution policy](https://github.com/openai/openai-agents-python/blob/81f0ccf20c6e24063b9da36fa37f2bdb6a43d8d3/CONTRIBUTING.md)
restricts upstream PRs to collaborators. Tracing listing eligibility additionally
requires a released installable integration and independently verifiable continued
SDK use by an unaffiliated project, with an issue before any listing change. This
owned implementation is executable; directory inclusion remains a separate goal.
