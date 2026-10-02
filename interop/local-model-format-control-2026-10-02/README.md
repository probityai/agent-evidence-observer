# Frozen schema-format control experiment

The unchanged 24 authored tasks/rubrics run under two selected Q4_K_M models, output caps 24/96, and unconstrained versus schema decoding: 192 attempts. Every eight-pair task block rotates frozen model/cap/decoder positions; each pair occupies each position three times. Prompt state resets, and no LlamaCache or warmup is selected.

Schemas constrain requested JSON keys and declared syntax/types. They contain no target value constants/enums/patterns, arithmetic answers, policy decisions, supplied names or abstention outcomes. The exact 0.3.16 pure Python schema-to-GBNF compiler and generated grammar bytes are frozen before inference. One syntax-only patch excludes unescaped JSON control characters. Prompts remain unchanged. Strict JSON format, schema contract validity and typed-exact original targets are separately scored; no quality improvement is assumed.

The per-preparation 512 MiB envelope, 600 s run, shared 1 GiB peak RSS, finite 192-call/token maxima and zero provider calls/dollars are declared before execution. Prior preparation attempts and cumulative transfers remain separate, visible records. Unsupported constraints retain an explicit error/outcome and never fall back to unconstrained generation. This is not a benchmark, deployment, real protected effect or independent custody claim.
