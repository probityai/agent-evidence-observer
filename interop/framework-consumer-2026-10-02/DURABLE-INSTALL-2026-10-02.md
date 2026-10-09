# Install the additive durable LangGraph reader

The standard `probity-langgraph-ticket-reader`0.0.2 wheel preserves the original
`probity-langgraph-read` command, CLI bytes and historical reader. It adds the
explicit `probity-langgraph-durable-read` command for the separately selected
`probity-langgraph-durable-restart-v0` profile. Each command refuses the other's
packet. Profile selection comes from the reviewed command/host policy, never from
an untrusted packet's own profile field.

The new `FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json` selects35 literal files,
including every packaged Observer/LangGraph source, both CLI wrappers, wheel
metadata, dependency lock and builder. The builder verifies these selected bytes
before producing normal wheels. It copies only offline readers, with no graph
runner/worker, SQLite checkpoint package, LangGraph or Pydantic AI dependency.
Original contracts, source pins and packet ZIPs remain intact.

Use a reviewed immutable checkout and the same hash-selected reader/build
requirements as the original package:

Start in checkout `55c3921cf299407176f2121083c7f39aff12165f`. All35 selected
source and packaging files match there. The recorded `observer_base_commit`
predates three packaging additions; it is provenance, not the complete build
selection. This frozen replay does not qualify the current Observer package.

```sh
set -eu
python -m venv .durable-reader-env
.durable-reader-env/bin/python -m pip install --require-hashes --only-binary=:all: -r interop/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock
PATH="$PWD/.durable-reader-env/bin:$PATH" bash interop/framework-consumer-2026-10-02/FRAMEWORK-DURABLE-CONSUMER-BUILD-2026-10-02.sh "$PWD" "$PWD/durable-reader-wheels"
.durable-reader-env/bin/python -m pip install --no-index --no-deps --upgrade durable-reader-wheels/*.whl
.durable-reader-env/bin/python -m pip check
.durable-reader-env/bin/probity-langgraph-durable-read SELECTED_PACKET --pins-file SEPARATELY_REVIEWED_PINS
```

The selected plan/artifact digests and historical evaluation time remain mandatory.
No command automatically accepts the producer's convenience pin file. A historical
read reconstructs the selected validity window; it does not authorize a new effect
or establish current authority. Keep source selection, packet/pin policy and any
host gate policy under the host's review and retain every per-case disposition.

The publication wrapper's original `probity-framework-host-gate-v1` retains only
its historical `langgraph` and `pydantic` reader enums. Durable operation explicitly
selects new schema `probity-framework-host-gate-v2`, reader `langgraph-durable`,
profile `probity-langgraph-durable-restart-v0` and exactly six attempts. It freezes
separately supplied pin bytes before starting the installed child. The reader and
gate keep pending intent incomplete and missing-state controls refused; admitting
the complete bounded record does not turn these individual outcomes into success.
See [the host gate](../consumer-host-2026-10-02/README.md) and its durable template.

The upgrade workflow actually builds/installs0.0.1 from immutable baseline
`5b5b6328bf70fef0fa17e86e62c6163c5943b13f`, runs32 original installed/gate controls,
checks that the durable command is absent and the historical command refuses a
durable packet, then normally upgrades the same environment to0.0.2. It runs the
original populations again along with the new durable/profile/source-selection
refusals. The original contract's34550 provenance label predates two Pydantic
reader-byte corrections; afce also does not match those later selected bytes.
The frozen historical contract is retained, and the explicit baseline matches its
entire source population. The new additive builder avoids depending on native
producer bytes that are not packaged into an offline wheel.

`fixtures/langgraph-durable.zip` retains the exact successful Ubuntu artifact from
[run37045346741](https://github.com/probityai/agent-evidence-observer/actions/runs/37045346741),
artifact11244118332, SHA256
`53226e9a77526c67c759e582b9f40b4512fff78ca64fad99bc99d2e5a4d97ed8`.
Tests authenticate that ZIP before replay, require explicit pins and refuse
reselected mutations of process identity, hard exit, checkpoint joins, arguments,
pending effects and absent-state recovery. Separate controls refuse changed source,
CLI, metadata or dependency bytes before any wheel is built. The reader environment
has no agent frameworks; byte verification uses the installed distributions' files.

This is an installation/upgrade and publication-gate capability over retained
native runs. It adds no new graph/model executions, outside producer acceptance,
recurring host adoption, independent custody, target-process restart, machine
power-loss or general exactly-once claim. No release tag or external workflow is
installed. Review the complete old/new valid and refusal populations before a host
replaces a previously selected reader, then commit code selection and policy together.
