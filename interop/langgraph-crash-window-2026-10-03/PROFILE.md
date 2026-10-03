# Effect/checkpoint crash window with target restart

This additive four-case profile covers a gap between the delivered durable and
joint restart profiles. Durable v0 exits inside the node after an HTTP commit
but keeps the target in the parent process. Joint v1 restarts both processes
after the first worker has persisted an interrupt checkpoint. Their original
case populations, retained results, readers and selections remain unchanged.

Here the first real LangGraph 1.0.10 / SqliteSaver 3.1.1 worker durably captures
the committed HTTP response and pending native task, then calls `os._exit(74)`
inside the dispatch node before returning or creating a completion checkpoint.
The parent stops and reaps the protected target, retains a consistent native
checkpoint backup, and starts a new target process from the same committed
SQLite store and externally retained signed head. A distinct worker reopens
the unfinished task and checks newly supplied host recovery authority first.

| Case | Current recovery authority | Result |
|---|---|---|
| `valid-after` | Valid at integer host clock100 | Invoke `None` to replay the native pending task; cached signed HTTP receipt is byte-identical, revision remains one and a completed graph result is released |
| `revoked-after` | Revoked at clock100 | No native invocation or recovery HTTP call; authenticated prior effect remains present |
| `expired-after` | Exclusive expiry boundary200 | No native invocation or recovery HTTP call; prior effect remains present |
| `rollback-after` | Clock99 below durable high-water100 | No native invocation or recovery HTTP call; prior effect remains present |

The complete population is four attempts, eight graph workers and eight target
processes. All four have authenticated earlier revision-one effects; one result
is released and three recovery actions refuse. A verified report permits this
bounded evidence to be published. It does not admit the refused recovery actions.
There are five physical POST calls: four first calls and one valid recovery
replay. That replay returns the same signed completion rather than creating a
new effect; all recovery effect deltas are zero. This is distinct from a recovery
path that returns a retained completion without making another physical POST.
The selected target's existing receipt cache handles this particular replay.
This does not establish arbitrary tool idempotence, general exactly-once,
distributed failover, power-loss durability, production containment or independent
operator/key/store/clock/retention custody. `witnessScope` remains `PEER` and every
original `doesNotAssert` entry remains. Models, providers and tokens are zero.

The reader opens original SQLite snapshots read-only and checks native public
checkpoint IDs, parent links and integer steps against the stored checkpoint
rows and durable authority high-water/denial anchors. It does not deserialize
native binary checkpoint payloads, import LangGraph, invoke a target or use the
network. Literal worker/target commands, PIDs, exits, streams, HTTP bytes,
signed store receipts, before-recovery and final databases and selected source
and dependency records are retained. Local OS and filesystem custody remain
trusted; concurrent host-file replacement and revocation after the authority
check remain outside this boundary.
Before any packet or SQLite read, a bounded walk requires regular files and
refuses every link or special member, including selected FIFOs. Limits are 512
files, 1,024 entries, depth 12, 64 MiB total and 16 MiB per member. The regular-file
reader uses nonblocking/no-follow opens. Native workers must finish within the
declared 30-second budget; malformed or deeply nested metadata has a stable refusal.
Packet JSON is limited to 64 nested levels and 16,384 values independently of
the interpreter's recursion setting. Native checkpoint metadata is at most
1 KiB and has exactly the selected `source`, integer `step` and empty `parents`
fields. These additive restrictions preserve the original readers.

Install the hash-selected native requirements from
`../joint-recovery-2026-10-02/requirements.lock` and this exact Observer checkout.
Run `python -m pytest -q tests` here, then
`python crash_run.py fresh-run --source-revision <exact-commit>`.
For separate offline consumption, build and normally install the Observer,
joint reader0.0.2 and this reader0.0.1 wheels with the joint reader's hash-selected
reader dependencies. Select the plan/artifact pins outside the packet and run
`<reader-venv>/bin/python -I -B <reader-venv>/bin/probity-read-langgraph-crash-window fresh-run --pins-file <outside-selected-pins>`.
The explicit `-B` prevents Python from rewriting installed bytecode caches;
`-I` ignores environment-based bytecode settings. The consumer compares the
entire selected installation before and after reader execution.
The maintained workflow performs this framework-free installed replay and requires
its canonical report to equal the native runner's report. Installation or execution
errors fail the job; cases are never skipped. Same-operator CI, an installable
reader and its fresh receipts do not establish outside acceptance or recurring use.
