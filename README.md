# Agent Evidence Observer (prototype)

Record brokered agent writes and check selected native framework reports offline.

Use it in agent harnesses and evaluation pipelines that need replayable action records or a consumer gate for retained reports.

## Quick start

No release is published yet, so pin a commit. Python 3.12 or later and
[`uv`](https://docs.astral.sh/uv/) are needed:

```sh
git clone https://github.com/probityai/agent-evidence-observer && cd agent-evidence-observer
git checkout f68c8538639aea1515ea357a85a20739004e66fd
uv venv .venv --python python3.12 && uv pip install --python .venv/bin/python .
.venv/bin/agent-evidence-observer demo ./sample-run
.venv/bin/agent-evidence-observer verify ./sample-run
```

The two commands print:

```text
{"noDetectedGap": "true", "retryReplayed": "true", "status": "verified", "witnessScope": "PEER"}
{"noDetectedGap": "true", "status": "verified", "witnessScope": "PEER"}
```

`sample-run/` now holds the signed packet, the history, the public keys and the file tree. The demo
writes a file, retries it, and the retry returns the first effect. `noDetectedGap` means the broker's
file-tree snapshots found no change it did not make. It does not mean every agent effect was seen.

## Status

Version 0.0.1, unreleased. Every record says `witnessScope: PEER`: the witness key runs on the same
host under the same operator, so the records show what this broker saw, not what an independent
observer saw. Linux runs can launch a fixed workload under bubblewrap with only the broker's socket
exposed. Running an unmodified agent that way, and a separately operated witness, are the next steps.

## Documentation

Start with [worked examples](docs/README.md) to follow a practical question,
then open its technical reference for commands and exact evidence.

| page | read it for |
| --- | --- |
| [Component tour](https://github.com/probityai/agent-evidence-observer/blob/main/docs/OVERVIEW.md) | every part of the prototype in one paragraph each, with links: ticket service, replay, evaluation history, A2A, AAE, protected dispatch |
| <a name="run-the-demo"></a>[Running the demo](https://github.com/probityai/agent-evidence-observer/blob/main/docs/RUNNING.md) | the full install with tests, and what each output field means |
| <a name="claim-and-trust-boundary"></a><a name="tests-and-remaining-gaps"></a><a name="linux-boundary-gate"></a><a name="consumer-admission"></a><a name="roadmap"></a>[Design, trust boundary and roadmap](https://github.com/probityai/agent-evidence-observer/blob/main/docs/DESIGN.md) | what each mechanism checks and does not establish, the Linux boundary gate, recovery, consumer admission, and the roadmap |
| [Isolated producer](https://github.com/probityai/agent-evidence-observer/blob/main/docs/ISOLATED-PRODUCER.md) | the acceptance criteria for running an unmodified agent behind the broker |
| [Witness ledger](https://github.com/probityai/agent-evidence-observer/blob/main/docs/WITNESS-LEDGER.md) | signed begin and terminal receipts, and how a reader checks them |
| [Installation and profile selection](https://github.com/probityai/agent-evidence-observer/blob/main/docs/INSTALLATION.md) | choose the root wheel, a separate profile wheel or a selected source reader; runtime requirements and installed examples |
| [Atomic native reader](https://github.com/probityai/agent-evidence-observer/blob/main/docs/ATOMIC-NATIVE-READER.md) | install an offline reader for selected native delegation runs and their refusal controls |
| [Witnessed run selection](https://github.com/probityai/agent-evidence-observer/blob/main/docs/WITNESSED-RUN-SELECTION.md) | check a selected run against consumer-retained opening and closing checkpoints |
| [Approved refund retries](https://github.com/probityai/agent-evidence-observer/blob/main/docs/APS-REFUND-RETRIES.md) | run the APS approval and local SQLite example, then check retries and refusals with a separately installed reader |

## License

Apache License 2.0; see [LICENSE](https://github.com/probityai/agent-evidence-observer/blob/main/LICENSE).
