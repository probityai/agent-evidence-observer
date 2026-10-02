# Preregistered authored boundary task expansion

This additive profile freezes 48 new authored case identities with 46 unique literal inputs: 16 typed-value extraction boundaries, 16 publish/admit/dispatch/recover policy decisions, and 16 grounded known/unknown distinctions. The positive controls publish-consent-a/checks-a and admit-expiry-a/signature-a repeat literal inputs across two paired contrasts. They count as declared case identities, not independent unique prompts. This population extends the earlier tasks without changing their historical scores. Selection is informed by the previously public format and semantic failures; this is a finite authored diagnostic study with public targets, without blind custody or a representative benchmark claim.

Compare the same selected actual SmolLM2 135M/360M Q4_K_M weights, caps 24/96 and unconstrained/schema decoders: 384 attempts. Each of the eight model/cap/decoder configurations appears in every position six times across 48 SHA-ranked task blocks. No cache, warmup, examples, response retries, repairs, task dropping or target/prompt retuning are selected. Cases, typed-exact targets, contracts, all 48 grammars and order are remotely preregistered before inference. Typed pairs include type/value boundaries; 16 policy/grounded pairs specify semantic contrasts. JSON format, schema validity and exact typed semantic correctness remain separate. Each family also reports eight planned pairs and pairs for which both answers are strictly correct; a correct positive answer alone does not close its negative foil. This grouping is frozen in source before inference.

Use the exact selected llama-cpp-python 0.3.16 compiler with the previously frozen raw-control-character syntax patch. Grammar contains keys and permitted types without target constants, enums or semantic patterns. Null versus string-null uses a shared nullable string contract; known and unknown cases share one broad scalar/nullable contract. The compiler permits at most 16 decimal integer digits, one optional ASCII space and fixed required-key order. These declared restrictions are part of this format intervention and do not represent every JSON/schema engine.

Each fresh preparation has a 512 MiB response-body budget (selected payloads 472221945 bytes), 180 s transfer and 335 s build limits. Runtime selects 600 s wall time, 600 whole-process CPU s, shared 1 GiB lifetime peak RSS, at most 384 calls, 196608 prompt tokens and 23040 completion tokens, with zero paid providers. CPU and RSS limits are checked at preflight and/or after returns and reconstructed offline; they are not independent telemetry or CPU/RSS hard kills. Wall timeout uses 595 s TERM plus 5 s KILL. Shared lifetime RSS is not per-model/task allocation. Process CPU includes all run initialization/inference threads; per-call CPU sums must fit the retained total. Late measured results are retained and held.

Previous four preparation attempts transferred 1694784417 response-body bytes in aggregate; current actual preparation costs and any failure will be added without resetting history. Each per-run limit is separate; aggregate cost is not one 512 MiB acquisition. Earlier 48/96/192-call reports remain unchanged. This profile does not execute protected effects, establish outside acceptance/recurring use, or provide independent effect custody.

[Actual run 37060702246](https://github.com/probityai/agent-evidence-observer/actions/runs/37060702246) completed at frozen source `6cfd28dc61aa0ae43be5da8382fe959c94235997`. All 384 planned calls started and were scored; error/incomplete/unknown-start/unsupported counts are zero. The original report, original native ZIP and acquisition record are retained in `results/`. Source and all targets/grammars remained unchanged after observing outputs.

| Model | Cap | Decoder | Typed values | Policy | Grounded | JSON-valid | Schema-valid | Both-correct pairs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| smol135-q4 | short24 | unconstrained | 0/16 | 0/16 | 0/16 | 0/48 | 0/48 | 0/24 |
| smol135-q4 | short24 | schema | 16/16 | 0/16 | 3/16 | 48/48 | 48/48 | 8/24 |
| smol135-q4 | long96 | unconstrained | 0/16 | 0/16 | 0/16 | 0/48 | 0/48 | 0/24 |
| smol135-q4 | long96 | schema | 16/16 | 0/16 | 3/16 | 48/48 | 48/48 | 8/24 |
| smol360-q4 | short24 | unconstrained | 0/16 | 0/16 | 1/16 | 34/48 | 10/48 | 0/24 |
| smol360-q4 | short24 | schema | 13/16 | 2/16 | 1/16 | 48/48 | 48/48 | 5/24 |
| smol360-q4 | long96 | unconstrained | 0/16 | 0/16 | 1/16 | 48/48 | 10/48 | 0/24 |
| smol360-q4 | long96 | schema | 13/16 | 2/16 | 1/16 | 48/48 | 48/48 | 5/24 |

All 192 constrained responses satisfy their schemas. Neither model closes any policy or grounded pair. The 135M model gets 16/16 typed values versus 13/16 for 360M at each cap; larger-model superiority is not supported by this selected diagnostic population. Constrained strict totals are 38/96 for 135M and32/96 for 360M; unconstrained totals are 0/96 and2/96. Complete format validity is distinct from semantic correctness. The 24 separate model/cap/decoder/family rows and all 192 paired-case denominators remain in the unchanged original report. No quality threshold was adjusted to admit these results.

Actual resources: 257.401173568s run wall,255.990321531s summed call wall,497.394631919s total process CPU including initialization,496.051239620s summed call CPU and567192KiB shared lifetime peak RSS. Native counts are 35280 prompt/7498 completion tokens. Preparation transferred 472221945 response-body bytes in 7.305208953s. Across all five preparations including earlier failure/successes, transferred body bytes total 2167006362; each envelope remains separate.

Replay the original packet with the reviewed stdlib reader and independently selected four pins:

```sh
python task_matrix.py packet --verify --pins-file independently-selected-pins.json
```

Ordinary CI runs 92 synthetic/native-fixture controls without inference. Actual CPU inference runs only on explicit manual selection or `run/local-model-boundary-tasks-v1`; merging does not download models or infer on main. Compact originals retain source, grammars, outputs and resource measurements; weights/preparation source/wheels remain in the complete private original. Reader reconstruction is not independent witnessing of transfers/loading/inference. Existing installed consumer 0.0.3 supports earlier profiles; this 384-call profile remains unsupported until an additive owner-reviewed upgrade.
