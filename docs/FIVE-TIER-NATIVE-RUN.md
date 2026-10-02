# One local run across five tiers

The launcher runs the pinned Inspect reasoning profile, the Inspect execution profile for tools/agents/workloads, and the native A2A SDK profile in separate processes. Inspect uses controlled local mock outputs; the A2A server performs deterministic arithmetic. These are executable native contract examples, not model-quality benchmarks.

```sh
python -m pip install -e '.[test,inspect,aae]'
python -m pip install -e 'interop/a2a-native-2026-10-02[test]'
python examples/five_tier_demo.py ./five-tier-run
```

Use a fresh output directory. `launch-plan.json` declares three profile launches covering five tiers and pins each launch script before execution. Each profile separately writes its native declaration before its own attempts; the parent declaration accounts for launches, not a new combined attempt population. The native logs, common records, runtime/source pins and consumer receipts remain under each profile's `native/` directory. The wrapper retains the exact command, stdout/stderr and launch outcome. It does not assign an aggregate score.

The parent requires a zero child exit, a newly created bounded JSON receipt and the selected profile's receipt shape. A missing or stale report, malformed report, child refusal or timeout makes the overall launch incomplete and returns a nonzero exit. A child failure does not erase its partial native directory or prevent the other declared launches from being attempted. On a launcher timeout, the local child process group is terminated. Failure-control tests exercise actual child processes, including a zero-exit command that produces no report and a zero-exit child whose report says refused.

`complete` in the parent report means all three profile launches produced their expected receipts. Individual task failures, native harness errors, incomplete responses and unknown starts remain in the child records; they do not become successful attempts. The native profile readers reconstruct those records from selected original bytes. The launch wrapper is orchestration accounting, not a substitute for those readers or an independent custody claim.

Resources stay scoped to each native profile: Inspect's normalized sample duration represents the precision of its native timing field; owned-tool timings and the A2A client duration have their own measured intervals. Unknown token and memory measures remain unknown. The file workload's read-back and the deterministic SDK exchange do not establish independently observed effects or production containment. A real-model evaluation and a separately controlled operator run remain separate executions with their own budget, keys, policy and retained inputs.
