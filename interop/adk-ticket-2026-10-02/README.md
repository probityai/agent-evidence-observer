# Native Google ADK plugin and protected ticket reference

This additive reference executes installed **Google ADK 2.11.0** `App`, `Runner`,
`BaseLlm`, `FunctionTool`, `BasePlugin` and `ReflectAndRetryToolPlugin`. A scripted
native model supplies fixed public synthetic calls; it performs no inference or
remote provider request. The protected HTTP/SQLite target is separately selected
Observer source `4a50e61471355611121a578f3a4c22daa931d419`.

The before-run plan declares twelve attempts, at most 25 model calls and 18 tool
invocations, and a 120-second serial execution budget. It covers permit,
revocation, changed arguments, errors before dispatch and after committed effect,
handled retries and exhausted retries with the collector first or last,
typed MCP `isError:true` tool returns with the collector first or last, and caller
closure after committed effect. MCP 2.2.0 supplies an actual typed result; no MCP
client/server transport is executed. Original tool records are retained **before**
any plugin can replace a response or consume a callback.

## Callback order and completion

Native plugin callbacks short-circuit when an earlier plugin returns a value.
Placing ReflectAndRetry before the collector can therefore hide original
`on_tool_error` or `after_tool` data. This reference retains those omissions as
actual coverage differences. Original tool results/errors, subsequent handled
reflection responses, native events, yielded events and retained session history
remain separate. The reader reconstructs the exact callback population for each
selected order rather than inventing callbacks that were never observed.

Unhandled errors retain notification-only agent/run error callbacks and lack
`after_run`. In SDK 2.11.0, early caller closure can still execute `after_run`.
That callback does not make the task complete: the closure case remains
**incomplete** with native revision 1. A terminal failure after committed HTTP
also keeps authenticated revision 1. Native effect completion, task completion,
handled errors and consumer publication admission have distinct meanings.
Native event timestamps may tie; retained sequence and event/invocation identities
supply ordering. Token usage remains absent, as reported by the scripted model.

## Install selected wheels and execute

Select an immutable adapter checkout. These are ordinary wheels built from
published Git source, not a registry release. Python 3.13 is tested; dependency
hashes are selected in `requirements.lock`.

```sh
# Run from this profile within the selected adapter checkout.
python -m venv .producer-env
.producer-env/bin/python -m pip install --require-hashes -r requirements.lock
git worktree add --detach selected-observer 4a50e61471355611121a578f3a4c22daa931d419
.producer-env/bin/python -m pip wheel --no-deps --no-build-isolation selected-observer . --wheel-dir selected-wheels
.producer-env/bin/python verify_wheels.py selected-wheels --selection source-selection.json
.producer-env/bin/python -m pip install --no-deps selected-wheels/*.whl
.producer-env/bin/probity-adk-run /tmp/new-adk-packet --source-revision "$(git rev-parse HEAD)"
```

The command refuses an existing packet. Private keys and SQLite databases stay in
a temporary directory. Public grants, signed receipts, original HTTP bytes,
installed source/license, the complete plan, original native JSON bytes and fields,
raw tool records, ordered callbacks, model requests/responses, full yielded/session
events, task errors and wall/process CPU counters are retained. Source hashes
select provenance; they do not prove independently witnessed execution.

## External plugin registration

```python
from google.adk.apps.app import App
from probity_adk.plugin import CapturePlugin

capture = CapturePlugin()  # payload capture is off by default
app = App(name="your_app", root_agent=your_agent, plugins=[capture])
# Give app to your real Runner and execute your application's workflow.
# Runner.close() closes plugins; snapshot is local application-owned data.
records = capture.snapshot()
```

The export destination is a local in-memory snapshot. There is no callback network
exporter or logging. Registration does not remove other application plugins or
telemetry exporters; this finite reference configures no exporter and uses no
provider credentials. Metadata mode retains callback phase, invocation identifier
and sequence only, without serializing payloads. `capture_payloads=True` retains
detached original native fields and can contain sensitive inputs, outputs or
errors; only the public synthetic fixture opts in here. It does not sanitize SDK
logs, other plugins or other application channels.

Capture is serialized by a lock and bounded to 512 callbacks and one MiB per
payload. Serialization, size and closed-capture failures are counted without
retaining exception text. Close is idempotent. A closed capture is not a task
success marker. Publication refuses nonzero capture failures or missing declared
coverage. The plugin never replaces framework return values.

## Install a framework-free reader and host gate

```sh
python -m venv .reader-env
.reader-env/bin/python -m pip install --require-hashes -r requirements-reader.lock
.reader-env/bin/python -m pip install --no-deps selected-wheels/*.whl
.reader-env/bin/python -c "import importlib.util; assert importlib.util.find_spec('google') is None and importlib.util.find_spec('mcp') is None"
.reader-env/bin/probity-adk-read /tmp/new-adk-packet --pins-file /path/to/host-policy.json
.reader-env/bin/probity-adk-gate /tmp/new-adk-packet --reader "$PWD/.reader-env/bin/probity-adk-read" --policy /path/to/host-policy.json --policy-sha256 HOST_SELECTED_SHA256 --output /tmp/new-host-receipt
```

A host selects its reader source/wheel hashes and exact plan, source-manifest,
artifact-manifest and historical UTC reference-time policy **outside** the
candidate packet. The gate authenticates policy bytes, freezes them into a new
host receipt directory outside the packet, launches the separately installed
reader without a shell, retains original child stdout/stderr and admits only a
successful complete twelve-attempt reference population. A candidate cannot choose
its own policy through this interface. It cannot change an existing receipt.

Producer-emitted demonstration pins copied by author CI remain author-operated
replay. They are not independent host policy selection or recurring adoption. An
upgrade selects new source bytes and wheel hashes, rebuilds into a new directory
and replays retained packets before updating the host's selection. The protected
Observer source stays separately pinned. No release tag is created.

The reader imports neither ADK, genai nor MCP and performs no network request.
It verifies original native JSON against decoded fields, full event/session joins,
fixed model/tool scripts and SDK schemas, plugin order/coverage, native request
scope, signed effect/read-back joins, task errors and typed resource bounds.
Admission applies to this bounded reference population, not arbitrary traces or
universal production containment.

## Verify and maintain

```sh
.producer-env/bin/python -m pytest tests -q
.producer-env/bin/ruff check --select E,F,I,C901 --config 'lint.mccabe.max-complexity=5' src tests verify_wheels.py
```

Controls execute the real SDK, retain first/last retry differences, admit valid
tied native timestamps, and refuse omitted/reordered/rebound model/tool/event/
session/callback records, coerced errors/incomplete outcomes, changed typed MCP
errors, altered effect receipts, boolean counters, wrong budgets/source/policy
and unclosed/failed capture after digest reselection. CI proves wheel source bytes,
executes a fresh native packet outside checkout, reconstructs it with a separate
SDK-free reader and runs the installed host gate.

Probity maintains this external plugin through
[Observer issues](https://github.com/probityai/agent-evidence-observer/issues).
Compatibility changes require updated source selections, native runs and semantic
refusal controls. The SDK primary source was refreshed at
`6bbef14ffa3beadfb812cc57bf83e1eb68800152`; upstream changes require Google CLA and
review. Existing analytics issue 7112 has assigned owners, and notification issue
5044 is closed with callbacks present. This reference takes over neither issue.
No upstream pitch or new public comment is required for this owned plugin.

Outside producer acceptance, continued host use, registry release and independent
effect custody remain separate goals. The synthetic service and captured history
are same-operator; signed evidence retains PEER scope. No model-quality, real MCP
transport, blind comparison, process-restart or power-loss claim is made.
