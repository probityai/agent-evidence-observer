# Nested ADK compaction, callbacks and effects: technical reference

Read the [worked example](../ADK-NESTED-COMPACTION.md) for the problem and outcome.
This reference retains the exact source, recorded checks, and evidence boundary.

The [runnable profile](../../interop/adk-nested-compaction-2026-10-04/README.md) qualifies ADK #7401 at `81c43680d6ebe0288b77a2e9ff746f696889c75d`. It keeps the existing [user-response route](../../interop/adk-user-responses-2026-10-04/README.md), pinned at `86a47f6974bae349a5c9ea15a74a4b450614ae42`, unchanged.

The native runner calls a middle AgentTool twice. Each middle call invokes a leaf AgentTool; each leaf reads a large public fixture three times and answers. Four cases retain token-based compaction, no config, window-only config and plugin exclusion as separate native paths. The model is an ordinary fixed BaseLlm implementation; no provider is contacted.

| Case | Agent model calls (root/middle/leaf) | Direct summary calls | Native body writes | Captured invocations | Nested publication |
| --- | --- | --- | --- | --- | --- |
| Token threshold | 3/4/8 | 9 | 6 | 5 | Finite covered reference |
| No config | 3/4/8 | 0 | 6 | 5 | Finite covered reference |
| Window only | 3/4/8 | 1 at parent | 6 | 5 | Finite covered reference |
| Token, plugins excluded | 3/4/8 | 9 | 6 | 1 at root | Hold for nested callback coverage |

The capture plugin records each actual invocation config before its run, including the original JSON bytes, native session identity and summarizer identity observation. The reader checks token/retention settings in both nesting levels, excludes parent window triggers from children, checks five separate sessions and preserves the parent's original trigger JSON. It checks that both leaf runs carry their own summary and that the second run starts with fresh history.

Each tool-body write binds its actual native function-call and invocation identities to a separately scoped Observer broker. Trusted keys and the broker commitment are saved before effects. The SDK-free reader verifies signed history, checkpoints, current files and each covered before-tool/after-tool/native-event join. All keys, fixture tools and storage have one author operator; the witness remains PEER.

Native before-model callback bytes and model-entry bytes stay separate. The reader admits only the pinned SDK's `adk_agent_name` label enrichment between those positions. The direct SDK summarizer bypasses these plugin model callbacks; its original model requests stay in a separate population. Root session history is also separate from child events. The trace covers these registered plugin positions, not every application event.

The shared plugin stays open through both middle and leaf calls, then the parent closes it once. Actual Verify at `e835ce2bd6a960e7a1cc2fa6522f16d55dce728a` reads an event-absence projection of that finite lifecycle twice per case. Three covered cases support absence of premature close. Plugin exclusion leaves nested coverage unknown and returns `not_established`. Host capture timestamps are projected to whole UTC seconds for Verify v1; they are not trusted timestamps.

Twenty reselected-input controls check config loss, window-trigger leakage, repeated-session/history leakage, callback sequence and failures, premature/double close, source-position joins, duplicate JSON, foreign effects, effect operator labels, signatures, unmediated files, coverage laundering and candidate publication. Verify separately checks a present close, unknown coverage and malformed duplicate input.

The first local probe and its text-None harness failure remain unchanged. A later packaged-producer attempt omitted a `hashlib` import after its first native write; that original is also retained before the normal repair. The passing result is a separate attempt. Publisher SDK source was never patched to make the fixture pass.

The 16-row native comparison remains separately pinned. The prospective eight-task implementation-owned run has not started. No model-quality, outside custody or consumer adoption result is claimed here.
