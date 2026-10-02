# Installed model report gate

This additive Linux/Python3.12+ reader verifies the original operational CPU task
profile without loading model weights, llama.cpp or Inspect. A separate host
policy decides whether its verified report meets the host's selected quality and
resource limits. All eight family/cap rows stay separate. Model comparison rows
also include their model identity; no score pooling is permitted.

Build `probity-model-task-reader`0.0.1 from the exact reviewed source contract,
then normally install its wheel into a clean environment:

```sh
python build_reader.py /path/to/observer /new/reader-wheels
python -m venv /new/consumer
/new/consumer/bin/python -m pip install --no-index --no-deps /new/reader-wheels/*.whl
/new/consumer/bin/python -m pip check
export PATH=/new/consumer/bin:$PATH
probity-model-publication-gate /native/packet /new/receipts \
  --pins-file /reviewed/native-pins.json --policy-file /reviewed/policy.json \
  --policy-sha256 REVIEWED_RAW_POLICY_SHA256 --timeout-seconds 60
```

Build tools are setuptools84.0.0/wheel0.48.0, selected by the adjacent framework
reader lock. The reader distribution itself has no dependencies. The source
contract binds every packaged Python byte. Before executing reader code, the
installed command compares the bundled module's SHA256 with the host selection;
it executes only the selected retained source bytes. The host must review and pin
the complete source revision/wheel as well as the source/policy/input selections.
A source digest alone does not independently vet arbitrary code.

The externally reviewed raw policy selects native pins, reader source, profile,
complete denominator, every quality row and five resource limits. Policy, pins
and receipts must be outside the producer packet. Each row declares exact planned
count, minimum typed-exact correct and minimum JSON-format-valid count. Resource
limits bound native elapsed time, returned prompt/completion tokens, **summed
whole-process CPU deltas during returned calls**, and process lifetime peak RSS.
They do not measure total preparation/build CPU, total process CPU outside those
calls, a task's memory allocation or deployment authority. The selected native
profile additionally enforces its frozen runtime/token budget.

The gate freezes reviewed policy and pins before launching the installed reader.
It retains launch, exact stdout/stderr, child exit/timeout, verified report and the
separate policy decision in a fresh directory. A changed packet/source/profile,
missing population, malformed report, changed raw policy/pins, nonzero child or
timeout holds publication. Gate exit0 allows publication only when evidence and
all selected score/resource limits pass; exit1 retains refusals. Existing output
cannot be overwritten. A host publisher depends on this success as illustrated
in `HOST-WORKFLOW.yml`; replace its final placeholder with the real reviewed host
command and record the maintained host revision/job/pin.

The retained native fixture is the complete147-file original run from
[run37044646302](https://github.com/probityai/agent-evidence-observer/actions/runs/37044646302),
including native library source-selection bytes; it omits the original archive's
model weights and preparation payload. `fixture-provenance.json` binds every
selected member to the full original archive. This derivative archive is a replay
fixture, not a fresh model run. It records48 scored calls, **0/48 typed-exact** and
2/48 format-valid. The explicit `evidence-policy.json` admits those complete
failed-task results with zero quality minima. `quality-policy.json` requires one
correct target in each of eight rows and refuses all eight while evidence remains
verified. Both are disclosed same-team example policies, not accepted outside
consumer selections. `run_host_example.py NEW_DIRECTORY` executes and retains
both installed CLI decisions.

A normal upgrade requires a reviewed new distribution version, source contract,
wheel digest and separately selected policy. Keep the original profile/pins and
its replay controls. New model/protocol/population profiles need their own reader
source selection and policy rows; version0.0.1 reads only the original48 profile.
No outside recurring host, producer acceptance, model deployment decision,
protected effect or independent custody is established by this owned workflow.
