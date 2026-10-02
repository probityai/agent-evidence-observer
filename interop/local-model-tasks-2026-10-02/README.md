# Frozen operational CPU microtasks

This new protocol selects 24 author-written tasks across structured extraction, arithmetic, policy decisions and grounded abstention, each under two output caps (24 and 96 tokens): 48 planned attempts. It keeps the original twelve-question Inspect baseline unchanged. These tasks measure this small operational population; they are not a representative benchmark or real effect admission.

`protocol.json` freezes every input, target, typed JSON rubric, ordering, model revision, runtime and resource boundary before implementation execution. The same selected SmolLM2-135M Q4_K_M weights, two decode/two prefill threads and 512 MiB new-download envelope apply. Preparation, build and inference retain finite deadlines. No paid provider or GPU requests are authorized. The cumulative token caps include all returned native responses; errors and unknown-start attempts remain visible.

The runner will retain original llama.cpp requests/responses, durable call-start/return/error markers, source/model provenance and resource measures, then a separately invoked reader will reconstruct all 48 outcomes from explicitly selected hashes. Report publication requires complete valid retained evidence; quality stays a separate per-family/per-configuration result. A model refusal, malformed JSON, wrong answer or execution failure will not disappear or cause a retry. Peak RSS is a process lifetime high-water mark.

The first commit containing this protocol is the preregistration checkpoint. Record its exact SHA in every execution declaration and verify the protocol bytes from that commit before loading weights. Later implementation fixes require a separate run and all previous outcomes remain retained. No independent operator, protected effects, custody or host adoption is established.

## Run and select bytes

Use the existing `../local-model-2026-10-02/prepare_local_model.py` and selected dependency lock to download and source-build exactly the old pinned runtime. Its preparation checks enforce the unchanged 512 MiB envelope; installation uses retained hashes and no index. The dedicated `local-model-task-matrix.yml` workflow records preparation/build failures and uploads artifacts even when execution fails. It runs only by manual dispatch or the explicit `run/local-model-task-matrix-v1` branch; ordinary CI runs the offline reader controls.

```bash
timeout --signal=TERM --kill-after=5s 595s python task_matrix.py ./run --weights ../model.gguf --provenance ../provenance.json --protocol-commit 5cfd69b8315a2e4cd8dacbbf5de40db71ce8658c
python task_matrix.py ./run --verify --pins-file ./separately-selected-pins.json
python -m pytest tests -q
```

The runner verifies the frozen protocol at the selected git commit before importing/loading the runtime. The packet retains the complete selected backend source, libraries, distribution metadata, license, model cards, preparation receipts, native responses and preflight token counts. Reusing adjacent producer pins is convenient for replay, but a publication gate must choose the hashes independently. The reader is framework-free and needs only Python's standard library; it refuses altered sources, populations, timestamps, prompts, token/resource counts and protocol changes. It never calls the model.

A pre-runtime failure produces a retained terminal error and all 48 unknown-start outcomes. A killed process retains completed start/return markers; without a terminal capsule it cannot pass publication. Whole-process peak RSS and CPU are explicitly scoped. Prompt and output subtotals cover returned responses, while token use in native errors remains unknown. The two output-cap configurations and four families remain eight separate quality rows; format compliance and typed target correctness are separate counts.
