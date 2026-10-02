# Durable LangGraph restart controls

The additive `probity-langgraph-durable-restart-v0` profile runs real LangGraph
1.0.10 and its native `langgraph-checkpoint-sqlite` 3.1.1 `SqliteSaver` in separate
OS processes. The original six-case in-memory profile, its retained packets and
source lock keep their original scope. This runner selects a new plan before any
worker starts and retains its own sources, dependencies, checkpoints and HTTP bytes.

| Attempt | Exit and recovery | Protected ticket result |
|---|---|---|
| `restart-before` | Native interrupt before dispatch; flush capture and `os._exit(73)`; new process reopens checkpoint and resumes | One admitted dispatch, revision one |
| `restart-after` | Native interrupt after committed dispatch; hard exit; new process resumes and re-executes node | Two HTTP calls, same signed completion/readback, revision one |
| `crash-after-effect` | `os._exit(74)` inside dispatch after committed HTTP response, before node return or interrupt | New process invokes `None` from durable pending task; two calls, revision one |
| `restart-pending` | Protected service faults after durable intent; graph interrupts and hard exits; fault removed before restart | Two refused calls, signed pending state remains at revision zero |
| `missing-checkpoint` | Hard exit before dispatch; checkpoint database removed before fresh worker starts | Recovery wrapper refuses missing state; zero calls, revision zero |
| `wrong-thread` | Hard exit before dispatch; next worker selects an absent thread | Recovery wrapper refuses missing state; zero calls, revision zero |

The graph uses `durability="sync"`, SQLite `synchronous=FULL`, one node and
recursion limit four. Workers retain their PID and the parent retains actual exit
codes and elapsed nanoseconds. An `os._exit` does not run Python cleanup. The hard
exit inside dispatch makes the effect/checkpoint gap executable: the protected
service's existing completed-receipt cache closes this specific replay gap.
These results do not establish arbitrary tool idempotence or general exactly-once
execution. Pending intent remains incomplete even when graph recovery completes.

The protected target remains in the parent process with its durable SQLite store.
Target-process restart, machine power loss, storage corruption, distributed
failover, caller/mandate authentication and independent effect custody are not
exercised. Keys, store, clock and retention remain under the same Probity operator.
The negative recovery wrapper refuses an absent checkpoint before invoking the
graph; this is wrapper policy, not a claim that LangGraph inherently rejects a
new thread. No model/provider runs occur, and tokens are zero by construction.

Install the hash-pinned `requirements-restart.lock` and this exact Observer source
checkout using the original README instructions. From this profile directory:

```sh
../../.venv-lg/bin/python -m pytest -q tests
../../.venv-lg/bin/python durable_run.py fresh-durable-run --source-revision "$(git rev-parse HEAD)"
cp fresh-durable-run/consumer-pins.json /tmp/langgraph-durable-selected-pins.json
../../.venv-lg/bin/python durable_reader.py fresh-durable-run --pins-file /tmp/langgraph-durable-selected-pins.json
```

The output must not exist. Each worker has a 30-second timeout, each HTTP request
has a 5-second timeout and 64 KiB response limit, and the offline reader caps each
file at 8 MiB. CI bounds the full fresh packet at 180 seconds and retains artifacts
for 90 days. Installation/worker/reader errors fail rather than skip a case.

The offline reader imports no LangGraph and accesses no network or SQLite store.
It checks the exact plan/source/dependency population; native history, parent
links, steps and precise checkpoint time bounds; original interrupt-to-HTTP joins;
exact checkpoint reopened by the next process; distinct process identities and
exit codes; every literal HTTP byte/graph result join; replayed native mandate,
signed grant, completed receipt and signed pending/refusal state. Mutation tests
reselect artifact hashes to test these semantics beyond digest matching.

The parent snapshots SQLite with its backup API after each hard exit, retaining a
consistent `before-restart.sqlite` including committed WAL content. The reader
uses public native snapshots and signed target readbacks, never trusts the database
files or deserializes framework checkpoints. Worker JSON and databases are retained
for inspection; the selected artifact manifest authenticates the aggregate original
attempt files that the offline reader actually consumes.

The author-generated pins remain local selection. A consumer must separately
approve its plan/artifact pins, reference time, key and issuer policy. A fully
fabricated history by the trusted operator remains outside this profile's scope.
`durable-recorded-report.json` records local execution, not remote CI or adoption.
An outside operator/host gate still requires actual acceptance and operation.

The complete original clean Python 3.13.15 packet is retained in
[`durable-fixture.zip`](durable-fixture.zip); [`durable-provenance.json`](durable-provenance.json)
binds its digest, exact implementation commit, selected consumer pins and measured
control counts. The report also replayed successfully in a separate environment
containing Observer and its cryptography/AAE dependencies without LangGraph.
Extract this selected archive to a new directory and pass the separately selected
pins to `durable_reader.py` for offline reproduction. The saved evaluation time
reconstructs that historical validity window; admitting a result now requires
separately selected current authority and policy. The archive is evidence of this
finite local run; fresh workflow outputs remain separate.
