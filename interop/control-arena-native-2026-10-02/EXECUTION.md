# Execution and native grammar

The exact host source is `7c0ebaa21c9d59d146c0eafcf7d6938734e8e430` in the
qualified `astrogilda/control-arena` fork. The upstream example uses a genuine
`Setting`, `get_control_task`, `control_solver`, honest policy, the default react
scaffold, MockLLM and native echo/typed submission tools. Alpha and beta at epochs
1 and 2 are the whole declared population. Each executes two model calls and two
tool calls. The scripted workload measures native execution, not model quality;
echo has no external target effect. Upstream acceptance remains an owner decision.

## Select and install before candidate execution

The consumer selects an exact reviewed Observer source commit, host source,
Inspect version, literal population, permitted observation window and wheel
bytes before importing candidate host code. `run_selected_host.py` checks clean
Git identity, reviewed wheel SHA256 and installed module SHA256, version and
absence of Inspect/ControlArena from the isolated reader environment. It writes
`selection-before-execution.json` before launching the native host. Inherited
provider credential variables are removed without displaying their values.

The reader distribution is `probity-control-arena-reader==0.0.1`, with no runtime
dependencies. Build backend versions are fixed in `pyproject.toml`. The reviewed
wheel SHA256 is
`223431565ea536f5f5e601f10462933310fb30abf6f39d88b779b3d25ed82eaa`
(8807 bytes). Its module SHA256 is
`1ae62c85b18f7b50a28a615d5ddcf9d4ea2b4a7455728656ea40c614b57e1c02`.
Build with `SOURCE_DATE_EPOCH=946684800`; the runner refuses a wheel that differs.
An intentional reader/source upgrade requires review and new maintained pins.

After the native run, the consumer capture stage hashes both selected local file
representations itself and requires the producer capture receipt to agree. Only
the resulting digest is added to the already selected source/population/time
policy. Candidate JSON never selects the reader, expected population or window.
The host and consumer own the output paths and retention/access settings.

Reproduce the exact workflow locally from a clean reviewed Observer checkout:

```bash
git clone https://github.com/astrogilda/control-arena /tmp/selected-native-host
git -C /tmp/selected-native-host checkout --detach 7c0ebaa21c9d59d146c0eafcf7d6938734e8e430
(cd /tmp/selected-native-host && uv sync --dev --frozen)
SOURCE_DATE_EPOCH=946684800 uv build --wheel --out-dir /tmp/reader-wheels interop/control-arena-native-2026-10-02
uv venv /tmp/selected-reader
uv pip install --python /tmp/selected-reader/bin/python --no-deps /tmp/reader-wheels/*.whl
python interop/control-arena-native-2026-10-02/run_selected_host.py \
  --reader-root "$PWD" --reader-source-commit "$(git rev-parse HEAD)" \
  --reader-python /tmp/selected-reader/bin/python \
  --wheel /tmp/reader-wheels/probity_control_arena_reader-0.0.1-py3-none-any.whl \
  --host-root /tmp/selected-native-host --host-python /tmp/selected-native-host/.venv/bin/python \
  --host-origin https://github.com/astrogilda/control-arena \
  --backend asyncio --output-dir /tmp/selected-native-result
```

Select the reviewed source SHA outside the candidate in a maintained job. The
local `git rev-parse` illustration assumes the checkout is already selected and
trusted. Repeat with `--backend trio` and a new output directory. The runner
retains every executed command's full output, exit status and output digest.

For existing captures, `select_policy.py` opens no candidate log. Supply an
explicit digest from a trusted capture stage, exact full host commit, origin,
Inspect version and outside time interval. Its four expected identities are
compiled in this profile. Invoke the installed consumer with:

```bash
/path/to/selected-reader/bin/python -I -m probity_control_arena_reader \
  --log /path/to/control-arena.json --policy /path/to/selected-policy.json
```

Zero exit publishes under that policy; nonzero exit holds. Overall native
`success` alone does not establish complete samples or a successful publication.

## Bounded joins and timing

The reader binds exact bytes, clean reported source and Inspect version; native
task/dataset/plan/scaffold metadata; the complete four sample/epoch population;
two model/two tool observations per sample; and the exact system/user/assistant/
tool message sequence, final model output, StepCounter and submitted answer.
It refuses sample errors, limits, solver errors, invalidation or incomplete runs.

Native spans must have the declared six begin/end signatures, unique IDs, known
active parents and complete closure. If a span end includes name/type/parent
fields they must match its begin. Children and events must remain within their
own span. Model/tool actions must interleave model → echo → model → submit,
finish after their start, and precede the next action's start. The sample and
ordinary spans must lie inside the native evaluation interval and the selected
outside observation window.

Two actual grammar details are preserved: sample initialization may complete
just before `sample.started_at`, and native tool events use their enclosing
solver span rather than their nested tool span. The initial span is bounded by
the evaluation, its own timestamps and the sample start. Inspect 0.3.257 records
evaluation completion at whole-second precision, so its final recorded second
is included. This precision allowance does not loosen the separately selected
outside observation window or model/tool/sample/span causality.

The 56 installed-reader controls operate on each backend's actual host export.
Mutation controls reselect digests to exercise semantics, not just byte mismatch:
changed/omitted/duplicate samples and events; errors and limits; unsupported
plans/versions/sources; incomplete spans; broken output/message/tool/store joins;
reversed completion/start; impossible model/tool ordering; unknown parents;
inconsistent span ends; and sample/event/span containment. Hypothesis checks
native omissions. No raw log fixture is committed.
Bootstrap mutants also prove a changed installed module cannot execute before
byte mismatch refusal, and a changed wheel cannot start the reader process.

The workflow is a maintained consumer demonstration, with separate asyncio/trio
jobs and native export controls. CI execution, upstream acceptance, producer
adoption and independent custody are distinct records. Retained Git/clock/log
self-reports and CI artifacts remain PEER evidence. The `doesNotAssert` list is
preserved in every publication report.
