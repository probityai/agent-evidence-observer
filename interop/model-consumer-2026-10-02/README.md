# Installed model report gate

This additive Linux/Python3.12+ reader verifies the original operational CPU task
profile without loading model weights, llama.cpp or Inspect. A separate host
policy decides whether its verified report meets the host's selected quality and
resource limits. All eight family/cap rows stay separate. Model comparison rows
also include their model identity; no score pooling is permitted.

Build `probity-model-task-reader` 0.0.3 from the exact reviewed source contract,
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
source selection and policy rows; version0.0.1 reads only the original48 profile; version0.0.2 preserves that source
and adds the explicitly selected comparison96 reader.
No outside recurring host, producer acceptance, model deployment decision,
protected effect or independent custody is established by this owned workflow.

## Executed normal upgrade

The workflow builds the exact public0.0.1 source at
`3a5efd16d242dc9044fc7492278a524c5c08a0cc`, installs it normally into two
clean environments and upgrades the candidate with `pip install --upgrade` of
the reviewed0.0.2 wheel. Version0.0.1 admits the original48 packet and refuses
the new comparison reader selection before execution. Version0.0.2 admits both
complete selected evidence records. The original module/pins and exact report
bytes remain unchanged; the same `probity-model-task-read` CLI remains available.

The new `comparison-run.zip` retains every native packet member from authenticated
[run37053301748](https://github.com/probityai/agent-evidence-observer/actions/runs/37053301748);
its provenance preserves the original native source/model selections. This is
offline original replay, not new inference. The96 scored attempts remain
16 separate model/family/cap rows:135M typed-exact0/48 and360M8/48, with
format-valid2/48 and42/48 respectively. The explicitly disclosed comparison
quality policy requires at least one correct target in each360M family/cap row;
both grounded-abstention rows refuse at0/6, while evidence stays verified.
The135M baseline stays visible with explicit zero minima; no pooled score is used.

`run_upgrade_example.py NEW_DIRECTORY --baseline-python BASELINE_PYTHON
--candidate-python CANDIDATE_PYTHON` retains actual versions, commands, child
statuses, exact original report, comparison admission, quality holds and native
mutation refusal. The candidate gate also refuses receipt output under the native
packet before creating any directory or modifying retained producer bytes.
The normal upgrade is same-team owned verification; it supplies no outside host
acceptance, recurring adoption, deployment or dispatch authority.

## Normal schema-control reader upgrade

Version 0.0.3 adds the separately frozen `probity-local-cpu-format-control-v1`
reader. The original 48 and comparison 96 modules and report bytes remain exact.
Normal installed 0.0.2 refuses the new source and policy; 0.0.3 supports its
192 attempts and 32 distinct model/cap/decoder/family rows. Neither model runtime
nor framework libraries are installed in the reader environment.

The new profile requires policy schema `probity-model-publication-policy-v2`,
explicit decoder/model identities and `minSchemaValid` for every selected row.
Other profiles retain policy v1. Counts include unsupported outcomes; any
unsupported, error, incomplete or unknown-start result holds publication.
JSON validity, exact schema/type validity and semantic correctness remain separate.
The gate requires correct <= schemaValid <= formatValid <= planned; resource
limits retain their declared returned-call CPU and process lifetime RSS scope.

The authentic retained run has all 96 schema outputs valid but weak semantic
results. The example quality policy selects 6/6 valid schemas for every schema
row and at least 3/6 correct in each 360M schema family/cap. It holds exactly two
policy-decision rows (1/6 each), despite valid evidence and schemas. Unconstrained
and 135M zero semantic minima are explicit; all rows and outcomes remain retained.
These are same-team example host policies selected after inference and frozen
before consumer replay, not preregistered model-success criteria or accepted
outside policy. The source experiment's syntax-only constraints and declared
budgets are separate preregistered selections.

`run_format_upgrade_example.py` retains actual installed versions, framework
absence, baseline refusal, exact prior report bytes, selected semantic holds and
native mutation refusal. `format-run.zip` contains all 463 compact-original run
members byte-exact; provenance binds the authenticated provider artifact. Pins
copied from that artifact are explicit same-team examples, held outside the
producer packet before reader launch. No new inference is performed in this
consumer replay; capability and installation do not establish external adoption.
