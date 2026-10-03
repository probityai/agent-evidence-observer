# Selected native contract

The immutable SDK source is huggingface/smolagents at c30b115286e000e98711fae5e85993547b73d826, version 1.27.0.dev0. The packaged selection enumerates every Python and prompt YAML file in that SDK Git tree. The producer authenticates the complete installed population before importing the SDK, refuses pre-existing package bytecode and retains the selected SDK, broker and profile bytes.

The native population is:

| Case | Model attempts | Custom tool forwards | Signed writes | Native state | Publication |
| --- | ---: | ---: | ---: | --- | --- |
| permit | 2 | 1 | 1 | success | RELEASE |
| wrong-content | 2 | 1 | 0 | success | WITHHOLD |
| error-before | 2 | 1 | 0 | success | WITHHOLD |
| error-after | 2 | 1 | 1 | success | WITHHOLD |
| max-steps | 2 | 1 | 1 | max_steps_error | WITHHOLD |
| model-error-after | 2 | 1 | 1 | raised | WITHHOLD |
| incomplete-after | 1 | 1 | 1 | incomplete | WITHHOLD |
| final-without-effect | 1 | 0 | 0 | success | WITHHOLD |

Total: 14 scripted model attempts, 7 custom tool forwards and 5 signed writes. There are 14 ActionStep callbacks and 6 FinalAnswerStep callbacks. Scripted replies exercise the actual ToolCallingAgent runtime; they invoke no model provider.

Native tool errors are handled by the SDK and can coexist with a final successful run. A model error escapes after a finalized ActionStep whose error field is empty. Max-step fallback performs another model attempt and returns a final answer while preserving the earlier write. The incomplete case closes the native stream immediately after the first finalized ActionStep. FinalAnswerStep is captured by its explicit callback and is absent from native action memory.

The reader authenticates the original artifact selection, host-selected issuer/observer/witness keys and exact request, complete retained source, actual forward bytes, signed writes, callback order, selected error classes and terminal state. A signed write is preserved in failure and incomplete cases. Release requires the complete permit contract, including the selected signed effect. A final answer alone is insufficient.

The host policy is explicitly selected outside the packet, with its SHA-256 supplied at the CLI. The framework-free reader uses its installed broker/profile source and packaged primary SDK hashes as source trust anchors. A rewritten source manifest cannot authorize different SDK bytes. Tests reselect changed native records to reach semantic checks beyond the original-artifact hash check.

The SDK's base dependency declaration omits PyYAML although agents.py imports it unconditionally; the runner selects PyYAML explicitly. Dependency packages, installation metadata and the interpreter remain trusted. Resolved dependency versions and hashes are retained and then checked in after initial native CI qualification. Action timing only establishes finalized native closure; no duration or performance claim is made.

Witness scope is PEER. This finite owned run does not establish provider inference, independent effect custody, producer acceptance or recurring outside adoption. Existing signed broker limits and doesNotAssert fields remain in force.

