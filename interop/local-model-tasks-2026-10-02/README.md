# Frozen operational CPU microtasks

This new protocol selects 24 author-written tasks across structured extraction, arithmetic, policy decisions and grounded abstention, each under two output caps (24 and 96 tokens): 48 planned attempts. It keeps the original twelve-question Inspect baseline unchanged. These tasks measure this small operational population; they are not a representative benchmark or real effect admission.

`protocol.json` freezes every input, target, typed JSON rubric, ordering, model revision, runtime and resource boundary before implementation execution. The same selected SmolLM2-135M Q4_K_M weights, two decode/two prefill threads and 512 MiB new-download envelope apply. Preparation, build and inference retain finite deadlines. No paid provider or GPU requests are authorized. The cumulative token caps include all returned native responses; errors and unknown-start attempts remain visible.

The runner will retain original llama.cpp requests/responses, durable call-start/return/error markers, source/model provenance and resource measures, then a separately invoked reader will reconstruct all 48 outcomes from explicitly selected hashes. Report publication requires complete valid retained evidence; quality stays a separate per-family/per-configuration result. A model refusal, malformed JSON, wrong answer or execution failure will not disappear or cause a retry. Peak RSS is a process lifetime high-water mark.

The first commit containing this protocol is the preregistration checkpoint. Record its exact SHA in every execution declaration and verify the protocol bytes from that commit before loading weights. Later changes to the execution path require a separate native run and all previous outcomes remain retained. Reader-only hardening may replay the selected original packet, with the executed source and audited reader source recorded separately. No independent operator, protected effects, custody or host adoption is established.

## Run and select bytes

Use the existing `../local-model-2026-10-02/prepare_local_model.py` and selected dependency lock to download and source-build exactly the old pinned runtime. Its preparation checks enforce the unchanged 512 MiB envelope; installation uses retained hashes and no index. The dedicated `local-model-task-matrix.yml` workflow records preparation/build failures and uploads artifacts even when execution fails. It runs only by manual dispatch or the explicit `run/local-model-task-matrix-v1` branch; ordinary CI runs the offline reader controls.

```bash
timeout --signal=TERM --kill-after=5s 595s python task_matrix.py ./run --weights ../model.gguf --provenance ../provenance.json --protocol-commit 5cfd69b8315a2e4cd8dacbbf5de40db71ce8658c
python task_matrix.py ./run --verify --pins-file ./separately-selected-pins.json
python -m pytest tests -q
```

The runner verifies the frozen protocol at the selected git commit before importing/loading the runtime. The packet retains the complete selected backend source, libraries, distribution metadata, license, model cards, preparation receipts, native responses and preflight token counts. Reusing adjacent producer pins is convenient for replay, but a publication gate must choose the hashes independently. The reader is framework-free and needs only Python's standard library; it refuses altered sources, populations, timestamps, prompts, token/resource counts and protocol changes. It never calls the model.

A pre-runtime failure produces a retained terminal error and all 48 unknown-start outcomes. A killed process retains completed start/return markers; without a terminal capsule it cannot pass publication. Whole-process peak RSS and CPU are explicitly scoped. Prompt and output subtotals cover returned responses, while token use in native errors remains unknown. The two output-cap configurations and four families remain eight separate quality rows; format compliance and typed target correctness are separate counts.


## Actual selected result

[Run37044646302](https://github.com/probityai/agent-evidence-observer/actions/runs/37044646302) executed commit `ab84161d09bb7bd696bba57717a418a95dd1d976`, after the protocol checkpoint was published. All 48 calls started, returned and were scored; no error, incomplete or unknown-start attempt occurred. Each of the eight family/configuration rows scored **0/6 typed-exact targets**. One extraction response per cap parsed as a JSON object; all other outputs failed the frozen JSON format rule. The original outputs remain visible in the [selected receipt](results/operational-cpu-37044646302.json). The longer cap did not produce a correct typed target in this population; this does not establish general inability, nor a representative quality estimate.

Preparation and source build passed their unchanged selected boundaries. Native responses retained 2,828 prompt and 1,840 completion tokens; elapsed run time was 16.723400890 seconds and whole-process lifetime peak RSS reached 200,488 KiB. Per-family/configuration call elapsed and whole-process CPU deltas remain separate in the receipt. Configuration-major order was fixed before execution, so cache/warmup and cap effects are not independently identified.

Artifact11244227462 retains the full original payload through December31,2026. Its 274,795,286-byte ZIP was downloaded and its SHA256 independently matched the provider: `f7e6abdb54f16c3f07777f83a7b68999b9a3f332bbf4f19d4eef5d3add0fcf29`. The selected original declaration, protocol, manifest and terminal hashes are in the receipt. Direct artifact transport initially returned HTTP403; the authenticated connector path recovered the original ZIP.

After native execution, same-team review identified missing serial-overlap and aggregate elapsed-time refusal controls. The reader now refuses overlapping successive calls, summed serial elapsed time exceeding the terminal envelope, and error markers with changed request/start fields. Thirty synthetic controls pass in ordinary PR/main CI. The hardened offline reader and a separately selected same-team reviewer replayed the original native packet and exactly reproduced its original report. The receipt records both source hashes; it does not relabel the native execution as having used the later hardened source. Future runs also upload a compact native-packet artifact and print the produced hash selections, preserving the full preparation artifact separately.
