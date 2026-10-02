# Native schema decoding versus unconstrained generation

The frozen protocol preserves the original 24 authored tasks, targets, typed JSON rubric, prompts, generation settings, selected 135M/360M Q4_K_M weights and 24/96 caps. Adding two decoders gives192 attempts. SHA-ranked task blocks rotate all eight model/cap/decoder pairs, placing each pair in each position three times. Prompt state resets before each call; no LlamaCache/warmup is selected.

[Actual run 37056945285](https://github.com/probityai/agent-evidence-observer/actions/runs/37056945285) executed source `75797cbb4fafc0669849357dd2275825b469c1f9` after remotely published protocol `108887b86df66e0d12a4db981a8aadd047f50b16`. Every 192 planned attempt started, returned and was scored; errors, incomplete, unknown-start and unsupported counts are zero. All 96 unconstrained output text bytes match the prior96 comparison originals. Original48/96 reports remain unchanged.

| Model | Cap | Decoder | Extraction | Arithmetic | Policy | Abstention | JSON-valid | Schema-valid |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| smol135-q4 | short24 | unconstrained | 0/6 | 0/6 | 0/6 | 0/6 | 1/24 | 0/24 |
| smol135-q4 | short24 | schema | 4/6 | 0/6 | 0/6 | 1/6 | 24/24 | 24/24 |
| smol135-q4 | long96 | unconstrained | 0/6 | 0/6 | 0/6 | 0/6 | 1/24 | 0/24 |
| smol135-q4 | long96 | schema | 4/6 | 0/6 | 0/6 | 1/6 | 24/24 | 24/24 |
| smol360-q4 | short24 | unconstrained | 2/6 | 1/6 | 1/6 | 0/6 | 21/24 | 10/24 |
| smol360-q4 | short24 | schema | 6/6 | 3/6 | 1/6 | 3/6 | 24/24 | 24/24 |
| smol360-q4 | long96 | unconstrained | 2/6 | 1/6 | 1/6 | 0/6 | 21/24 | 10/24 |
| smol360-q4 | long96 | schema | 6/6 | 3/6 | 1/6 | 3/6 | 24/24 | 24/24 |

Family cells are typed-exact target passes. All 96 constrained outputs meet both JSON/schema contracts; these format controls improve some extraction, arithmetic and abstention outcomes, while policy remains weak. Complete schema validity does not imply correct or safe decisions. All original text, failures, native measurements and 32 separate model/cap/decoder/family rows remain in the [report](results/format-cpu-37056945285.json) and [original native ZIP](results/format-cpu-native-37056945285.zip). No target change, response repair or inference rerun followed observed outputs.

The exact 0.3.16 pure Python compiler and 24 generated GBNF files were published before inference. Contracts contain requested keys and types, no target values, decision enums, constants or semantic patterns. Grounded presence/absence use the same broad nullable scalar contract. The frozen compiler imposes at most 16 decimal integer digits, one optional ASCII space and fixed required-key order; free values are within those restrictions. A pre-inference syntax-only patch excludes unescaped JSON control characters. This controlled decoder is a selected format intervention, not all possible schema engines or arbitrary JSON representations.

Runtime took 93.963267580 s, serial call measurements 92.899769500 s and whole-process CPU 177.947250784 s. Shared lifetime peak RSS is 554,152 KiB across both engines, not model allocations. Native counts are 11,312 prompt/3,495 completion tokens. Fresh selected preparation transferred 472,221,945 response-body bytes in 6.380860649 s inside its 512 MiB/180 s envelope; run 600 s,1 GiB shared RSS,192 calls and finite token maxima were selected before execution. The two prior comparison preparations plus this one total 1,416,634,644 bytes; including the earlier48-run preparation yields 1,694,784,417 bytes across four declared preparations. Each run has its own envelope; total history is not one512 MiB acquisition. Provider calls/dollars remain zero.

The [acquisition record](results/acquisition-37056945285.json) binds original ZIP digest, source, protocol, pins and exposure. Extract into a fresh packet directory and replay without an inference backend:

```sh
python task_matrix.py packet --verify --pins-file independently-selected-pins.json
```

A host must select hashes independently of adjacent producer pins. The reader separately scores JSON format, declared schema validity and typed-exact targets, retains every outcome, and refuses changed grammar/compiler/decoder/resource selections. Unsupported constraints retain explicit outcomes with original errors and never silently fall back. Complete evidence permits publishing a scoped report; host quality/resource acceptance is separate.

Ordinary CI runs 82 synthetic/native-fixture controls, including exact native replay and equality of all 96 unconstrained responses to prior originals. The actual workflow runs only on explicit manual selection or `run/local-model-format-control-v1`; merging does not download models or infer on main. Compact originals retain native sources, grammars, outputs and measurements; weights/source wheels remain in the full private preparation archive. Receipt reconstruction is not independent witnessing of transfers/loading/inference.

This finite authored population does not establish a representative benchmark, general causal model estimate, real protected effect, outside adoption or independent host/key/store/clock/retention custody. OS page cache, CPU interference, engine construction, grammar sampling and shared lifetime resources remain scoped limitations. Targets were already public; outputs/comparison were emitted together, without blind custody.
