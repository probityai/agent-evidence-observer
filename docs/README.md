# Find an example for your question

Observer helps you keep an agent's decision, its recorded events, and its actual
effect separate. Start with the situation you need to understand. Each worked
example explains the outcome before linking to commands and exact evidence.

## Follow a practical case

These examples use controlled local effects and selected framework runs:

| Your question | Worked example |
| --- | --- |
| A refund reply was lost. Does retrying record it twice? | [Approved refund retries](APS-REFUND-RETRIES.md) |
| A job's output was refused. Had its body already changed a file? | [CrewAI job decisions and file effects](CREWAI-JOB-FENCES.md) |
| Nested agents shortened their history. Which sessions and callbacks were captured? | [ADK history and nested calls](ADK-NESTED-COMPACTION.md) |
| The dispatched request changed after approval. Does permission still apply? | [REMORA cases and protected file writes](REMORA-EFFECT-BRIDGE.md) |
| A server changed a tool after its grade. Does the saved definition still match? | [Tool grades and retained local effects](TOOL-MANIFEST-EFFECT.md) |
| An evaluation failed. Did its tool still update the target? | [Inspect scores, authority, and effects](INSPECT-AUTHORITY-EFFECT.md) |

A verified record answers a specific question under selected inputs. Read each
example's evidence boundary before applying the result elsewhere. Separate
installations do not establish separate operators, and a local file or row does
not establish a remote provider's effect.

## Start with the core tools

Use [Running the demo](RUNNING.md) for a first recorded write and retry.
The [component tour](OVERVIEW.md) explains how the broker, ticket service,
history, and readers fit together. [Installation and profile selection](INSTALLATION.md)
helps you choose the package or source profile for your task.

## For developers and agents

The worked examples link to `docs/reference/` for their exact source pins,
commands, fields, refusal controls, and retained artifacts. Each profile's
protocol and workflow remain the authority for reproducing that profile.
Keep those references with the example when you review or automate it.

The [ADK full-suite source reference](reference/ADK-FULL-TOX-SOURCE.md) separates
the recorded upstream correction from the native consumer's original SDK pin.

For implementation contracts, see the [design and trust boundary](DESIGN.md),
[protected dispatch](PROTECTED-DISPATCH.md), and [consumer admission](CONSUMER-ADMISSION.md).
