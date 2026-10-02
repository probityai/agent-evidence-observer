# Consumer publication gate

Install the dedicated readers from a reviewed immutable Observer checkout using
[the wheel builder](../framework-consumer-2026-10-02/README.md). Keep the reader
environment separate from the producing agent environment. The gate below runs
one installed reader and requires its complete selected report before publication.
It preserves failed tasks, denied effects, errors and incomplete outcomes.

Keep both the host policy and native pins outside the packet. Review and commit
those bytes with the host workflow. The policy digest is supplied separately by
that workflow; the gate freezes the selected pins before launching the child.

```json
{
  "schema": "probity-framework-host-gate-v1",
  "reader": "langgraph",
  "profile": "probity-langgraph-aae-ticket-v0",
  "plannedAttempts": 6,
  "pinsSha256": "REVIEWED_RAW_NATIVE_PINS_SHA256"
}
```

For the original Pydantic profile, select `reader: pydantic`,
`profile: probity-pydantic-ai-ticket-v0` and `plannedAttempts: 5`. A later native
profile or population requires a new reviewed policy. These are packet integrity
decisions, not authority to dispatch a new effect.

```sh
python selected-observer/interop/consumer-host-2026-10-02/framework_gate.py \
  --packet evidence/langgraph/packet \
  --pins policy/framework/langgraph-pins.json \
  --policy policy/framework/langgraph-gate.json \
  --policy-sha256 REVIEWED_RAW_HOST_POLICY_SHA256 \
  --reader-bin "$PWD/.reader-env/bin" \
  --output "$PWD/receipts/new-langgraph-gate"
```

The output parent must exist and the receipt directory must be new. Retain the
whole directory on success and refusal. It includes selected inputs, command,
child exit/timeout, stdout/stderr, admitted report and gate decision. A timeout,
nonzero child, malformed/ambiguous report, wrong profile/denominator, changed
selection or existing output exits nonzero. Publication must depend on this job;
do not use `continue-on-error` or publish from an `always()` step.

The [host workflow](HOST-WORKFLOW.yml) is a concrete embedding template. Replace
its explicit digest placeholder with reviewed host policy bytes. Copy the reviewed
`framework_gate.py` to host `.ci/framework_gate.py` and commit it with that policy.
The template pins the already merged reader/builder source independently; select
a reviewed immutable revision for each code surface; install reports and build
records remain attached. No automatic schedule or external workflow is installed
by this example. The host chooses its actual recurring publication trigger.

## Installation and upgrades

Use Python 3.13.15 and the committed hash-selected reader/build dependency lock.
For historical0.0.1 readers, use the immutable `5b5b6328bf70fef0fa17e86e62c6163c5943b13f` source checkout with the original builder, as shown in the reader instructions. For current durable support, use the separate0.0.2 builder and its new frozen contract. Each builder checks selected source hashes and produces standard wheels. Normal
installation uses `pip install --no-index --no-deps reader-wheels/*.whl`, followed
by `pip check`. Do not install the original Pydantic producer package into this
reader environment: it shares a Python namespace with the dedicated reader.

To upgrade, retain the old environment and original packet. Review the new
immutable checkout, source contract, dependencies, profile semantics and expected
population. Build/install into a fresh candidate environment. Run the original
valid packet and the refusal controls with each environment's Python:

```sh
.reader-env/bin/python -m pytest -q \
  selected-observer/interop/framework-consumer-2026-10-02/test_installed_readers.py \
  selected-observer/interop/consumer-host-2026-10-02/test_framework_gate.py \
  --junitxml=receipts/upgrade-reader-controls.xml
```

Capture `pip freeze`, `pip check`, the pip installation report, wheel build record
and JUnit output in both environments. Re-run the selected host gate against the
same original packet with a fresh output for each. Review any report changes,
then commit the new reader commit and policy together. Same version strings do
not establish source identity; green tests do not establish outside adoption.
An expanded new producer packet is a separately selected population, not a silent
replacement for historical records.

The A2A/Inspect installed consumer uses its own selection schema, Python 3.12 and
receipt-producing command in [NATIVE-CONSUMER-CI](../../docs/NATIVE-CONSUMER-CI.md).
This framework gate does not relabel those profiles or consume the native
Inspect-to-ticket effect join. Consumer selection, actual producer execution,
producer review, recurring host use and independent effect custody remain
separate observations.

## Explicit durable profile selection

Install the [additive0.0.2 wheel](../framework-consumer-2026-10-02/DURABLE-INSTALL-2026-10-02.md)
before selecting the durable profile. The v1 schema retains its original two
reader enums. The separately reviewed v2 schema selects only this exact new
reader/profile/population:

```json
{
  "schema": "probity-framework-host-gate-v2",
  "reader": "langgraph-durable",
  "profile": "probity-langgraph-durable-restart-v0",
  "plannedAttempts": 6,
  "pinsSha256": "REVIEWED_RAW_DURABLE_PINS_SHA256"
}
```

Use the same gate command with the durable packet and separately reviewed durable
policy/pins outside it. The wrapper launches `probity-langgraph-durable-read` using
its frozen pin copy. A v1 policy cannot silently select that command, and v2 refuses
historical reader enums, a different profile or an altered denominator before any
child launch. Historical packets and policies continue to use v1 and the original
commands. The admitted report retains committed-effect recovery, pending intent
and missing-state refusal outcomes without changing their scope ceilings.

The [durable host template](DURABLE-HOST-WORKFLOW.yml) pins the reviewed additive
reader/gate source at `55c3921cf299407176f2121083c7f39aff12165f`. Copy the gate
from that revision into the host and commit it with its v2 policy and selected
native pins. Both templates keep publication dependent on successful admission;
they are owned embedding examples, without an outside installation or commitment.
