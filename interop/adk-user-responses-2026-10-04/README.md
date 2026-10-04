# ADK user-response routing

This installed reference selects Google ADK source
[`86a47f6974bae349a5c9ea15a74a4b450614ae42`](https://github.com/google/adk-python/commit/86a47f6974bae349a5c9ea15a74a4b450614ae42).
Shangjie Chen's routing fix makes a user FunctionResponse reach the issuing
sub-agent even when resumability is disabled. A later plain message returns
to the root. Google owns that fix and its original tests.

Three finite cases exercise native confirmation granted, confirmation denied
and a long-running tool completed by the host. The real Runner, LlmAgent,
FunctionTool and LongRunningFunctionTool execute a fixed public model script.
There are no provider requests or model-quality evaluations. This new pin
leaves the October 2 ticket and October 3 comparison pins and populations intact.

| evidence | retained original | scope |
| --- | --- | --- |
| native routing | each yielded event, session, supplied response and model request | response agent and exact issuing call |
| callbacks | unchanged existing CapturePlugin snapshots, in callback order | callbacks actually delivered to this registered plugin |
| authority | literal broker scope and prior signed commitment | this author-operated file-writing authority |
| effect | signed Observer history, two distinct keys and current file bytes | one native approved write; one separate host LRO completion; zero denied writes |
| publication | a separate installed reader, exact policy pin and repeated output | admission of these three finite cases |

The LRO tool body starts work and returns None. The same host operator writes
its completion through the broker before supplying the user response. That
completion is kept separate from a native tool-body effect. Keys, producer,
target, witness and reader remain author-operated PEER work. A successful
confirmation route does not establish an independent operator or outside
consumer adoption.

## Run installed copies

The [workflow](../../.github/workflows/adk-user-responses.yml) shows the ordinary
wheel builds, hash-locked dependencies and separate producer and reader installs.
It replaces the release SDK with a normal install from the exact source checkout,
then checks all 778 installed SDK Python Git blobs before importing it. The
reader environment has no ADK distribution. Python, dependency installation,
site initialization and the host remain trusted.

```sh
python -I -B bootstrap.py \
  --producer /absolute/producer/bin/python \
  --reader /absolute/reader/bin/python \
  --wheels /absolute/selected-wheels \
  --sdk /absolute/adk-at-86a47f6 \
  --output /absolute/new-run
```

The launcher saves the plan before native imports, retains every subprocess
stdout, stderr and exit status, saves the complete selected SDK Python source
and wheels, then invokes the installed offline reader twice. Byte-identical
decisions are required before a publication receipt is written. The host policy
selects raw outputs after execution; it does not claim pre-run external custody.

```sh
ADK_RESPONSES_PACKET=/absolute/new-run/packet \
  /absolute/reader/bin/python -I -B test_controls.py -v
```

Semantic mutations are checked after their byte hashes are reselected. Wrong
call IDs, root-routed responses, trapped later text, missing callbacks, denial
mislabelled as a tool body, changed file bytes and host completion mislabelled
as native execution are refused. Failed CLI reads remove stale passing output.

The reference reuses the existing
[`CapturePlugin`](../adk-ticket-2026-10-02/src/probity_adk/plugin.py) unchanged.
Its callback position and finite capture limits remain part of the contract.
The native-model example follows Google's retained MockModel and Runner tests;
the fixed script is a local author control. The prospective eight-task
implementation-owned study remains not started.
