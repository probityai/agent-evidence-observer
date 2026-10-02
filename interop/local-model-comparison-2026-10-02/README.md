# Preregistered paired CPU model comparison

The original 24 authored tasks, targets, typed JSON rubric, system message and generation settings remain unchanged. Both selected SmolLM2 models use Q4_K_M quantization and output caps 24/96. The protocol freezes all 96 calls, a SHA-ranked task order, and four rotated model/cap positions per task. Each of the four pairs occupies each position six times. Native prompt state resets before each call; no LlamaCache or warmup calls are selected.

[Actual run 37053301748](https://github.com/probityai/agent-evidence-observer/actions/runs/37053301748) executed source `b7db63c319d53b0cb27638a229f966d477a2bbd5` after remotely published amended protocol `6d6b205cc1c544968573381b72fbbe33c9ec4b3e`. The original 48-call run remains unchanged. All 96 new attempts started, returned and were scored; error, incomplete and unknown-start counts are zero.

| Selected model | Output cap | Extraction | Arithmetic | Policy | Abstention | Format-valid |
| --- | --- | --- | --- | --- | --- | --- |
| 135M Q4_K_M | 24 | 0/6 | 0/6 | 0/6 | 0/6 | 1/24 |
| 135M Q4_K_M | 96 | 0/6 | 0/6 | 0/6 | 0/6 | 1/24 |
| 360M Q4_K_M | 24 | 2/6 | 1/6 | 1/6 | 0/6 | 21/24 |
| 360M Q4_K_M | 96 | 2/6 | 1/6 | 1/6 | 0/6 | 21/24 |

Cells are strict typed-exact target passes. The selected larger model produces more valid JSON but still fails most decision/abstention tasks. All original text and native resource counts remain in the [report](results/paired-cpu-37053301748.json) and [original native ZIP](results/paired-cpu-native-37053301748.zip). No answer repairs, adaptive selection or inference reruns were made after seeing outputs.

Runtime took 50.885084703 s; serial call measurements total 50.041492533 s and whole-process CPU deltas total 98.295793573 s. Whole-process lifetime peak RSS is 535,884 KiB across both engines, not a per-model allocation. Native returned counts are 5,656 prompt and 2,539 completion tokens. Sixteen separate model/cap/family rows retain quality and resources. The selected fresh preparation downloaded 472,221,945 response-body bytes in 5.345179384 s inside the original 512 MiB/180 s envelope. Selected category caps (384 MiB models, 64 MiB source, 1 MiB metadata, 63 MiB dependencies) were published before transfers.

Initial preparation run 37052641046 selected nine wheels and valid payloads but failed at build metadata because the pathspec transitive dependency was omitted. No inference began; all 96 positions remain unknown-start for that preparation attempt. The published amendment adds the exact 31,191-byte pathspec 0.12.1 wheel before first inference. Models, tasks, order, rubric and all aggregate budgets stay unchanged. The original preparation archive/failure remains separately retained; corrected preparation is not a retry of a model response.

To replay without an inference framework, extract the ZIP into a fresh directory and run:

```sh
python task_matrix.py packet --verify --pins-file independently-selected-pins.json
```

[Acquisition](results/acquisition-37053301748.json) binds provider ZIP digest, original runner, protocol, retained pins and exposure. A host must select these hashes independently of an adjacent producer pins file. A complete scoped report permits evidence publication; quality acceptance is a separate host policy. Preparation reconstruction validates retained selection/accounting/source receipts; weights and source wheels live in the full preparation archive. It does not independently witness transfers, loading, inference or custody.

Ordinary PR/main checks run 63 offline rubric/selection/serial/denominator/transfer/refusal controls. The actual workflow runs only on explicit manual selection or `run/local-model-comparison-v1`; merging does not redownload models or infer on main.

Balanced position and prompt-state controls address the previous fixed configuration order. OS page cache, CPU interference, engine construction/load, shared lifetime RSS and this small author-written population remain scoped limitations. These are descriptive paired results, not a representative benchmark, parameter-count causal estimate, real protected effect or outside adoption. Same-team review does not establish independent host/key/store/clock/retention custody.
