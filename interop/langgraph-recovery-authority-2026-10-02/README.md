# Recovery authority across native worker exits

This additive profile runs eight real LangGraph 1.0.10 / SqliteSaver 3.1.1 cases.
Each first worker exits with code73 after a synchronous native checkpoint. A
second OS process reopens that SQLite checkpoint and reads the host's current
recovery authority before invoking the interrupted graph. The selected transitions
are valid, revoked, exact-boundary expiry and clock rollback, each before dispatch
and after a protected HTTP ticket commit.

Recovery authority is a separate host-selected JSON policy binding the literal
request and signed grant. It is not a replacement grant or an authenticated
external issuer. This fixture uses a declared deterministic integer host clock:
initial100, expiry200, selected expiry200 and rollback99. It exercises the
boundary without waiting or pretending these are independent clock observations.
A SQLite `BEGIN IMMEDIATE` serializes comparison/update of the action's durable
clock high-water mark. Every well-typed, action-bound observation raises that
mark even when revocation or expiry denies recovery; a later replay of an older
permit therefore refuses. A denied-at-high-water marker also prevents an
equal-clock old permit from resurrecting revoked recovery authority. A strictly
later explicit host permit can restore recovery; equal-clock repeated valid
permits remain allowed. Missing recovery anchors fail closed. Revocation, expiry
and rollback refuse before recovery dispatch or release of a cached native graph
result. An earlier signed revision-one commit remains present and is reported
separately from the recovery refusal. A valid after-effect recovery sends the
same request; the selected service returns the unchanged completion receipt.

Run with explicit source and selections:

```sh
python -m pip install --require-hashes --only-binary=:all: -r ../langgraph-ticket-2026-10-02/requirements-restart.lock
python -m pip install --no-deps -e ../..
python -m pip check
python -m pytest -q tests
python authority_run.py fresh-run --source-revision "$(git rev-parse HEAD)" > fresh-report.json
cp fresh-run/consumer-pins.json /tmp/authority-selected-pins.json
python authority_reader.py fresh-run --pins-file /tmp/authority-selected-pins.json > reader-report.json
```

The reader uses Observer cryptographic verification and standard-library files;
it does not import LangGraph, open SQLite or use the network. Select the literal
plan, artifact manifest and host policy digests outside the submitted packet.
Keep these selected pins under the consuming host's control. Successful report
verification means this complete selected eight-case population met its declared
recovery/effect contract; the six refusal cases are expected. It does not admit
a refused recovery action. `freshRecoveryDispatches` and
`retainedNativeRevision` are separate outputs for host publication or execution
policy. A host must choose its own authoritative clock/revocation source and
maintain that source and its selected pins before actual deployment.

Every worker command, exit, stdout/stderr, authority read, native public snapshot,
HTTP literal byte sequence, signed readback, checkpoint database and source /
installed dependency manifest is retained. Output directories are exclusive;
previous runs are not overwritten. The workflow uploads the complete packet and
separate reader result, including failure receipts. Its gate fails on a reader
refusal; downstream publication can depend on that job with ordinary `needs`.
Original v0 and durable profiles, installed-reader CLI/pins and archived packets
are unchanged. This separate source profile is not silently installed into the
existing reader package.

The protected target remains in one parent process. This demonstrates selected
worker restart and recovery policy checks, not target restart, arbitrary graph
recovery, power-loss durability, distributed exactly-once operation, outside
acceptance, recurring outside adoption or independent key/store/clock custody.
`witnessScope` remains `PEER`; all original signed `doesNotAssert` entries remain.
Revocation after a check or concurrent replacement of the host authority file
is outside this selected boundary; the target's signed grant checks remain
separate. Existing commit evidence does not authorize a further action.
