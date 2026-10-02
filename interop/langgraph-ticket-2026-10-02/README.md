# LangGraph native protected-ticket reference

This additive profile connects **real LangGraph 1.0.10** public checkpoint and
interrupt/resume APIs to Observer's existing AAE-protected HTTP ticket service.
It is a finite, deterministic Probity-operated integration candidate. There is
no model inference, provider call, LangGraph adoption, external operator result,
quality benchmark, independent custody, caller authentication or general
exactly-once guarantee. The native AAE mandate is still unsigned.

## Six declared attempts

| Attempt | Real framework behavior | Required effect result |
|---|---|---|
| `permit` | One dispatch node completes | Signed completion, separate GET, one matching native SQLite row |
| `deny` | Native AAE DENY reaches HTTP gate | HTTP 409, initial signed state unchanged, no local row |
| `altered-argument` | Graph sends changed content with selected original request/grant | HTTP 409, initial signed state unchanged |
| `interrupt-before` | Native `interrupt` before dispatch, `Command(resume=True)` resumes | No first-boundary HTTP call; one permitted call on resume |
| `resume-after-effect` | Native `interrupt` after committed dispatch; resume re-executes node | Two admitted HTTP calls, identical retained signed response/readback, revision one |
| `pending-intent` | Host fault after durable intent but before effect | HTTP 409, signed pending intent, revision zero; effect incomplete |

The resume-after-effect case does **not** prove that arbitrary tools are safe to
replay. Its cached-return behavior comes from this exact service's fresh grant
check and retained completed state. The checkpoint store is `InMemorySaver` in
one process; process restart, durable LangGraph checkpoint recovery and actual
host failures remain unexercised. The pending-intent case does not automatically
replay. It preserves the original service behavior rather than infer a success.

## Run and consume

Use Python 3.13 in a fresh environment from the repository root:

```sh
python -m venv .venv-lg
.venv-lg/bin/python -m pip install --require-hashes --only-binary=:all: -r interop/langgraph-ticket-2026-10-02/requirements.lock --report lg-install-report.json
.venv-lg/bin/python -m pip install --no-deps -e .
cd interop/langgraph-ticket-2026-10-02
../../.venv-lg/bin/python -m pytest -q tests
../../.venv-lg/bin/python lg_run.py fresh-run --source-revision "$(git rev-parse HEAD)"
cp fresh-run/consumer-pins.json /tmp/langgraph-selected-pins.json
../../.venv-lg/bin/python lg_reader.py fresh-run --pins-file /tmp/langgraph-selected-pins.json
```

`fresh-run` must not exist. Install, execution and reader errors fail CI; no
import skip, success fallback or reused recorded result is used. Every action is
loopback-only with one SQLite file per selected attempt. Dependency versions and
per-platform wheel hashes are locked; CI retains pip's fresh installation report.
The lock intentionally includes test/lint dependencies used by this profile.
The base Observer source installation is the selected checkout, with `--no-deps`.

The reader runs without LangGraph execution, network requests or native-store
access. It consumes original public `StateSnapshot`/`PregelTask`/`Interrupt`
projections from `get_state` and `get_state_history`, and literal bounded canonical
HTTP request/response bytes. It checks the complete declared population, checkpoint
parent chain, ordered steps, aware checkpoint times inside the selected pre-run
and consumer-evaluation interval, graph channels, native task results, interrupt identity,
resume boundary, selected arguments and every HTTP-to-graph result join. It
recomputes the native AAE decision and verifies the selected signed authority,
service receipt and separate native readback using existing Observer readers.

The pre-run selection and consumer evaluation clocks retain fractional seconds
to bound native checkpoints precisely; signed grants and service reference times
retain their existing whole-second profile. Grant verification projects the aware
evaluation instant to UTC whole seconds, preserving its signed whole-second
half-open validity window. The reader does not round checkpoint
times or widen the selected interval.

The three selected pins are plan SHA-256, artifact-manifest SHA-256 and an aware
consumer evaluation time. A consumer must approve these separately and select its
service/issuer policy before admitting a result. The convenient author-generated
`consumer-pins.json`, or a copy of it outside the packet, does **not** create
independent selection or custody. Replacing the plan and every selected consumer
pin can replace the local trust root. This profile does not resist its own trusted
operator fabricating a complete history.

## Retained evidence and budgets

- Pre-run exact plan, input/configuration, authority grant, native mandate and
  distinct public issuer/service keys; private keys are never written.
- Adapter/base source bytes and their pre-run hash manifest; installed dependency
  versions and hashes of distribution files (excluding bytecode).
- All six original public native checkpoint histories and invocation boundaries,
  including original interrupted snapshots before resume.
- Every literal HTTP request/response, distinct GET readback and final GET;
  SQLite stores retained for inspection, but not trusted by the offline reader.
- Elapsed nanoseconds per attempt; zero input/output tokens because no provider
  runs. Peak memory is `null`/unmeasured, not a zero measurement.
- One node, recursion limit four, six attempts, HTTP 5-second timeout and 64 KiB
  response cap, reader 8 MiB/file cap, CI 15 minutes and runner 180 seconds.
- Original controls and a fresh CI output artifact, retained 90 days.

`recorded-report.json` is a local factual result, not CI execution. Fresh remote
CI must pass before any claim of remote reproduction. The tests include real
native executions, semantic mutations with reselected artifact hashes, property
controls, original population/pin checks, and an import/network guard for the
reader. They follow `TestLangGraphPacket.TestPassingCases/TestFailingCases`.

LangGraph API references: [interrupt/resume](https://docs.langchain.com/oss/python/langgraph/interrupts),
[checkpoint history](https://docs.langchain.com/oss/python/langgraph/persistence).
Both external instructions are used only to select the native API behavior;
installed code/version hashes govern this retained execution. No framework files
or upstream fixtures are vendored in the source profile.
