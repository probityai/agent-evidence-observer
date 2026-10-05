# Install Observer and choose a native reader

Observer is source-only. The root distribution is `agent-evidence-observer` 0.0.1,
with Python 3.12 or later and Apache-2.0 terms. A version string does not select
the source: install an immutable revision or a wheel whose bytes you reviewed.
The profile distributions below are separate source install units, not registry releases.

## Try the installed broker

With Python 3.12 and [uv](https://docs.astral.sh/uv/):

```sh
uv venv observer-env --python python3.12
uv pip install --python observer-env/bin/python 'agent-evidence-observer @ git+https://github.com/probityai/agent-evidence-observer.git@f68c8538639aea1515ea357a85a20739004e66fd'
observer-env/bin/agent-evidence-observer demo sample-run
observer-env/bin/agent-evidence-observer verify sample-run
```

The demo prints `{"noDetectedGap": "true", "retryReplayed": "true", "status": "verified", "witnessScope": "PEER"}`.
Verification prints `{"noDetectedGap": "true", "status": "verified", "witnessScope": "PEER"}`.
Use a new, empty output directory. The demo's keys and witness share one local operator.
Its coverage applies to brokered file writes and checked snapshots.

Keep a separate source checkout if the selected profile needs scripts:

```sh
git clone https://github.com/probityai/agent-evidence-observer.git observer-source
git -C observer-source checkout f68c8538639aea1515ea357a85a20739004e66fd
observer-env/bin/agent-evidence-read-native --source-checkout "$PWD/observer-source" --describe-sources inspect-execution
```

This command prints `installed_sources` and `reader_sources` hash maps for review.
It neither reads a native packet nor accepts those hashes as policy.
Select packet hashes, reader hashes and keys through the consumer's accepted process.

## What the root wheel contains

| Task | Installed entry point | Other selected inputs |
| --- | --- | --- |
| Record and verify brokered writes | `agent-evidence-observer` | A new local run, or a retained packet and consumer-pinned keys |
| Apply consumer policy to a broker packet | `agent-evidence-admit` | [Admission policy and retained state](https://github.com/probityai/agent-evidence-observer/blob/main/docs/CONSUMER-ADMISSION.md) |
| Read bounded Inspect execution or A2A SDK packets | `agent-evidence-read-native` | A matching immutable checkout and a separately selected manifest; [consumer CI guide](https://github.com/probityai/agent-evidence-observer/blob/main/docs/NATIVE-CONSUMER-CI.md) |
| Read Atomic native delegation tests | `agent-evidence-read-atomic` | Selected native test packet and manifest; [Atomic guide](https://github.com/probityai/agent-evidence-observer/blob/main/docs/ATOMIC-NATIVE-READER.md). No separate source checkout |
| Demonstrate and read a witnessed run selection | `python -I -m probity_observer.selection_profile` | [Opening, closing, operator and witness pins](https://github.com/probityai/agent-evidence-observer/blob/main/docs/WITNESSED-RUN-SELECTION.md) |

The root wheel contains `probity_observer` modules and the Apache license.
It does not contain the `interop/` scripts, profile wheels, native frameworks,
model weights, retained experiment packets or selected consumer policies.
The `inspect` extra supplies the historical Inspect 0.3.273 dependency, not every profile.
The `aae` extra supplies the existing canonicalization dependency.

## Separately installed native profiles

Each link gives its own source pins, dependencies, commands, retained inputs and limits.
Use its install instructions and workflow. Some profiles need a root wheel installed first;
others have their own dependency or source-selection contract.
Do not replace their frozen input pins with a newer framework or main revision.

The dedicated [LangGraph and Pydantic readers](https://github.com/probityai/agent-evidence-observer/blob/main/interop/framework-consumer-2026-10-02/README.md)
have a source-checked wheel builder and an explicit durable-reader upgrade.
They are not installed by the root package or by a framework producer's manifest.
The accepted [Inspect consumer guide](https://github.com/probityai/agent-evidence-observer/blob/main/interop/inspect-current-host-2026-10-03/README.md)
selects its own reader unit and Python 3.12 runtime.

The following source manifests declare separate distributions. A module/script
entry point means the manifest declares no console command; use its guide.

| Profile source | Distribution | Python constraint | Declared console commands |
| --- | --- | --- | --- |
| [a2a-history-boundary-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/a2a-history-boundary-2026-10-02/README.md) | `probity-a2a-history-reader` | `>=3.12` | `probity-read-a2a-history` |
| [a2a-native-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/a2a-native-2026-10-02/README.md) | `probity-a2a-native-reference` | `>=3.12` | Module/script entry points; follow the profile guide |
| [adk-a2a-failed-task-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/adk-a2a-failed-task-2026-10-03/README.md) | `probity-adk-failure-reference` | `>=3.12` | `probity-adk-failure-produce`, `probity-adk-failure-read` |
| [adk-nested-compaction-2026-10-04](https://github.com/probityai/agent-evidence-observer/blob/main/interop/adk-nested-compaction-2026-10-04/README.md) | `probity-adk-nested-compaction` | `>=3.12` | Module/script entry points; follow the profile guide |
| [adk-ticket-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/adk-ticket-2026-10-02/README.md) | `probity-adk-reference` | `>=3.13` | `probity-adk-run`, `probity-adk-read`, `probity-adk-gate` |
| [adk-user-responses-2026-10-04](https://github.com/probityai/agent-evidence-observer/blob/main/interop/adk-user-responses-2026-10-04/README.md) | `probity-adk-user-responses` | `>=3.12` | `probity-adk-responses-produce`, `probity-adk-responses-read` |
| [ag2-push-authority-2026-10-04](https://github.com/probityai/agent-evidence-observer/blob/main/interop/ag2-push-authority-2026-10-04/README.md) | `probity-ag2-push-authority` | `>=3.12` | Module/script entry points; follow the profile guide |
| [authority-unreachable-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/authority-unreachable-2026-10-03/README.md) | `agent-evidence-authority-reference` | `>=3.12` | Module/script entry points; follow the profile guide |
| [control-arena-native-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/control-arena-native-2026-10-02/README.md) | `probity-control-arena-reader` | `>=3.11` | `probity-read-control-arena` |
| [crewai-job-fences-2026-10-04](https://github.com/probityai/agent-evidence-observer/blob/main/interop/crewai-job-fences-2026-10-04/README.md) | `probity-crewai-job-fences` | `>=3.12` | Module/script entry points; follow the profile guide |
| [evaluation-contract-2026-10-01](https://github.com/probityai/agent-evidence-observer/blob/main/interop/evaluation-contract-2026-10-01/README.md) | `probity-evaluation-contract-reference` | `>=3.11` | Module/script entry points; follow the profile guide |
| [haystack-native-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/haystack-native-2026-10-03/README.md) | `probity-haystack-reference` | `>=3.12` | `agent-evidence-read-haystack` |
| [inspect-current-host-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/inspect-current-host-2026-10-03/README.md) | `probity-inspect-current-reader` | `>=3.12,<3.13` | `probity-inspect-current` |
| [joint-recovery-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/joint-recovery-2026-10-02/README.md) | `probity-joint-recovery-reader` | `>=3.12` | `probity-read-joint-recovery`, `probity-gate-joint-recovery` |
| [langgraph-crash-window-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/langgraph-crash-window-2026-10-03/PROFILE.md) | `probity-langgraph-crash-window-reader` | `>=3.12` | `probity-read-langgraph-crash-window` |
| [local-model-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/local-model-2026-10-02/README.md) | `probity-local-model-reference` | `>=3.11` | Module/script entry points; follow the profile guide |
| [local-model-boundary-tasks-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/local-model-boundary-tasks-2026-10-02/README.md) | `probity-local-cpu-boundary-tasks` | `>=3.11` | Module/script entry points; follow the profile guide |
| [local-model-comparison-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/local-model-comparison-2026-10-02/README.md) | `probity-local-cpu-model-comparison` | `>=3.11` | Module/script entry points; follow the profile guide |
| [local-model-format-control-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/local-model-format-control-2026-10-02/README.md) | `probity-local-cpu-format-control` | `>=3.11` | Module/script entry points; follow the profile guide |
| [local-model-tasks-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/local-model-tasks-2026-10-02/README.md) | `probity-local-cpu-task-matrix` | `>=3.11` | Module/script entry points; follow the profile guide |
| [local-model-vocabulary-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/local-model-vocabulary-2026-10-02/README.md) | `probity-local-cpu-vocabulary` | `>=3.11` | Module/script entry points; follow the profile guide |
| [openai-agents-ticket-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/openai-agents-ticket-2026-10-02/README.md) | `probity-openai-agents-reference` | `>=3.13` | `probity-openai-run`, `probity-openai-read` |
| [pydantic-ai-native-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/pydantic-ai-native-2026-10-02/README.md) | `probity-pydantic-reference` | `>=3.12` | `probity-pydantic-run`, `probity-pydantic-read` |
| [pydantic-recovery-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/pydantic-recovery-2026-10-03/README.md) | `probity-pydantic-recovery-reader` | `>=3.12` | `probity-read-pydantic-recovery` |
| [smolagents-native-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/smolagents-native-2026-10-03/README.md) | `probity-smolagents-reference` | `>=3.12` | `probity-smolagents-produce`, `probity-smolagents-read` |
| [target-recovery-2026-10-02](https://github.com/probityai/agent-evidence-observer/blob/main/interop/target-recovery-2026-10-02/README.md) | `probity-target-recovery-reader` | `>=3.12` | `probity-read-target-recovery` |
| [witness-operator-2026-10-03](https://github.com/probityai/agent-evidence-observer/blob/main/interop/witness-operator-2026-10-03/README.md) | `probity-witness-operator-reference` | `>=3.12` | `agent-evidence-witness` |

## Source workflows and refusal

Profiles without a separate package manifest remain source workflows. Start with
[the interop index](https://github.com/probityai/agent-evidence-observer/tree/main/interop)
and the corresponding maintained workflow. This includes native LangGraph tickets,
recovery authority, ExecSurface state, the five-tier launcher and bounded consumer gates.
The local-model profiles need their selected model/source bytes and preparation budgets;
a root install does not download a model or perform inference.

A native reader checks its supported retained contract. It does not accept an arbitrary
framework trace. Keep task errors, missing records and unsupported start states in the result.
Select new reader and source hashes after a reviewed upgrade; changing package metadata
also changes a native consumer's selected `pyproject.toml` digest.

Unsupported Python fails installation. A missing source checkout or native packet fails
before a valid receipt. A changed selection digest, mismatched source or changed retained
artifact causes refusal. Retain stdout, stderr and the refusal receipt when the reader
creates one. Native readers return nonzero on refusal; do not ignore that exit in a gate.

Witnessed run selection establishes consistency of one supplied anchored history.
It does not establish unique selection across other histories, real-time precedence,
execution truth or independent custody. First-party fixture execution, an offline replay
and a maintained outside gate are separate results.
