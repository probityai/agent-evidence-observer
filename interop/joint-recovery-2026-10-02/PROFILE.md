# Selected joint native recovery profile

This profile joins the previously separate native worker recovery and protected
target restart exercises. It imports the merged `authority_worker.gate` and
`TicketStore` implementations. It does not alter their backend or any earlier
result, fixture, source pin, installed reader or profile identifier.

The frozen population contains 19 cases, 40 fresh native graph workers and 38
actual HTTP target processes. The first graph worker reaches a native interrupt,
synchronously persists its SQLite checkpoint and exits through `os._exit(73)`.
The first target then exits. Its replacement opens the existing native store
against an externally retained signed history head. The host supplies a new
authority/grant/key/store/clock selection only after those processes exit. A new
worker reopens the native `SqliteSaver` state and checks that selection before
calling LangGraph resume or releasing a cached completion.

| Selected cases | Executable boundary |
| --- | --- |
| valid before/after | New dispatch or authenticated cached completion after both process exits |
| revoked before/after | Durable target revocation and recovery denial; authentic earlier completion remains retained |
| expired before/after | Exact integer expiry boundary; current host permission ends without erasing prior state |
| rollback before/after | Recovery integer clock below durable high-water refuses |
| sticky before/after | Third fresh worker supplies an old equal-clock permit after denial and is refused |
| grant expiry after | Signed grant expires at the exact selected UTC boundary; worker sends no recovery HTTP request |
| grant mismatch / issuer mismatch after | Current grant digest or issuer policy differs; result release is refused |
| target key / missing store / store rollback after | Actual target startup refuses changed signing identity, absent native state or state predating retained history |
| pending intent / transaction after | Actual target hard exits at code 74/75; native graph checkpoint survives; pending work refuses automatic replay, then host explicitly marks it incomplete |
| concurrent before | Eight actual overlapping HTTP callers after target restart produce completed and pending-refusal responses; resumed graph observes the single native revision |

Each denied grant/key/store selection is also recorded in the merged durable
clock denial anchor. A correct old permit at the same clock cannot clear it;
an explicitly later valid host selection can. Native SQLite snapshots retain
the final high-water mark, denial flag, graph checkpoint population, service
history, exact ticket bytes and committed receipt. The reader opens them with
SQLite immutable read-only mode. Raw worker, parent process, current selection,
HTTP and target records are joined to their attempt projections. Exact argv
binds the phase, endpoint, case, native database, output and current-policy path;
the parent-captured PID must match its worker, with distinct PIDs across the run.

The signed grant's UTC clock and the recovery integer clock are separate declared
host selections. This deterministic fixture clock does not claim trusted wall
time or an outside time authority. The grants, service keys, filesystem and
host selections belong to the same operator. Bearer authority does not prove
remote caller identity. Native checkpoint captures are selected byte evidence,
not independently signed records from another operator.

The offline reader authenticates historical signed effects using their historical
reference time. That authentication does not grant current dispatch authority.
An installed publication gate can publish a complete report containing refusals;
it cannot admit an invalid action or release a denied result. No power-loss,
general exactly-once, remote-identity, independent-custody or production-containment
claim is made. No model/provider call is used.
Owned child processes use an explicit credential-free variable allowlist with
provider tracing disabled; their selected environment is retained in receipts.

## Reproduce and consume

From this directory, use an isolated Python 3.12 or 3.13 environment:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --no-deps -e ../..
python -m ruff check joint_*.py joint_host_gate.py tests
python -m ruff check --select C901 --config 'lint.mccabe.max-complexity=5' joint_*.py joint_host_gate.py tests
python -m pytest -q
python joint_run.py /outside-git/original --source-revision "$(git rev-parse HEAD)"
```

The caller must separately select the source revision, plan/artifact bytes,
evaluation time, reader executable and publication policy. A packet cannot
select its own trust pins. The workflow demonstrates a same-team host selection
in a separate installed environment without LangGraph. Its wheel and install
receipts are retained alongside the full native original. The outside-packet
policy selects the whole installed environment's file population and hashes,
package versions, launch scripts, bytecode, extension modules, metadata and
`.pth` injection surfaces, plus the resolved interpreter bytes. The native host
gate recomputes that closure before launching the reader; a changed verifier
module refuses even when its launcher bytes are unchanged. The reader emits
canonical JSON bytes, and the publication gate checks every finite case's
disposition as well as aggregate counters. The host OS and Python standard
library remain local custody assumptions. Independent custody,
maintainer acceptance and a recurring outside gate remain separate outcomes.

The tests execute a fresh complete native population, then explicitly reselect
mutated bytes to exercise semantic refusals rather than merely detect changed
hashes. Hypothesis checks clock transitions; nested passing/failing test classes
check native process identities, current selections, checkpoint recovery, exact
HTTP bytes, signed effects, pending work and host publication boundaries.

The exact source commit precedes the original run. Later result/archive commits
remain separate from that source pin. Original stdout/stderr, native SQLite,
retained source, install metadata and host reader receipts stay outside Git and
in the authenticated original archive. Git contains only the bounded report and
provenance/index. Workflow artifact retention is 90 days; it is not permanent
custody, and the program archive receipt supplies the durable original identity.
