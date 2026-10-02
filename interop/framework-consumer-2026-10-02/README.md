# Installed framework readers

These dedicated wheels reconstruct the retained LangGraph and Pydantic AI native
packets without installing either agent framework. The builder checks every selected
source byte against `FRAMEWORK-CONSUMER-CONTRACT-2026-10-02.json` before creating
standard wheels. The commands require a separately selected pins file.

```sh
python -m venv .reader-env
.reader-env/bin/python -m pip install --require-hashes -r interop/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock
git fetch origin 5b5b6328bf70fef0fa17e86e62c6163c5943b13f
git worktree add --detach selected-reader-source 5b5b6328bf70fef0fa17e86e62c6163c5943b13f
PATH="$PWD/.reader-env/bin:$PATH" bash interop/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-BUILD-2026-10-02.sh "$PWD/selected-reader-source" "$PWD/reader-wheels"
.reader-env/bin/python -m pip install --no-deps reader-wheels/*.whl
```

`probity-langgraph-read PACKET --pins-file POLICY` reconstructs six retained
checkpoint/interrupt/resume cases. `probity-pydantic-read PACKET --pins-file POLICY`
reconstructs five typed-tool/retry/error cases. Both retain the native report's
per-case outcomes and ceilings. The host workflow template requires an exact
profile, verified status and complete denominator before publication.

The fixture ZIPs are the original successful Ubuntu artifacts, authenticated before
extraction. LangGraph comes from [run 37003859466](https://github.com/probityai/agent-evidence-observer/actions/runs/37003859466)
and Pydantic from [run 37003617436](https://github.com/probityai/agent-evidence-observer/actions/runs/37003617436).
Their SHA-256 values are selected in `test_installed_readers.py`. The tests replay
the full original packets through installed commands, require explicit pins, and
refuse semantic substitutions even after an adversary reselects artifact hashes.

```sh
.reader-env/bin/python -m pip install pytest==8.4.2
.reader-env/bin/python -m pytest -q interop/framework-consumer-2026-10-02/test_installed_readers.py
```

This replays existing native executions. It does not make a new model or framework
call. Fixture pins copied by Probity are local test selections; a host must select
its own policy. In-memory LangGraph checkpoints do not establish process-restart
durability. Synthetic ticket effects, same-operator custody and scripted Pydantic
FunctionModel provenance remain explicit in each report. Host CI adoption and
independent effect custody require separate records. No release tag is created.

The historical0.0.1 builder now uses the explicit baseline `5b5b6328bf70fef0fa17e86e62c6163c5943b13f`, whose files match the frozen contract. The contract's recorded34550 provenance label predates two Pydantic reader byte corrections; it is retained as historical metadata, not used as a valid build selection. Native LangGraph producer changes also require the historical source checkout. The [additive durable reader upgrade](DURABLE-INSTALL-2026-10-02.md) installs0.0.2 with separate explicit commands and a new complete source/metadata selection.
