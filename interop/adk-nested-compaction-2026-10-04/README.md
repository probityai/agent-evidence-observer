# ADK nested compaction and shared plugin lifecycle

Run the unchanged [ADK #7401 head](https://github.com/google/adk-python/pull/7401) through `root -> AgentTool(middle) -> AgentTool(leaf)`, twice. The full source pin is `81c43680d6ebe0288b77a2e9ff746f696889c75d`; all 778 installed publisher Python files must match before imports.

Four cases keep token compaction, no config, window-only config and `include_plugins=False` separate. Each executes six native tool-body writes. The installed SDK-free reader checks raw model and callback bytes, fresh repeated sessions, config propagation, parent config preservation, shared-plugin close and signed Observer writes.

The three covered cases can publish this finite reference. The no-plugin case keeps a nested callback coverage hold. Direct SDK summarizer requests are retained separately from plugin model callbacks. Verify consumes four lifecycle projections twice: three `supported`, one `not_established`.

The [workflow](../../.github/workflows/adk-nested-compaction.yml) builds ordinary wheels, installs the selected SDK normally, runs the producer once and the independent reader twice, then runs 20 semantic controls and the actual Verify CLI. It retains setup failures as well as native attempts.

This is author-operated PEER work with fixed public responses and same-host clocks. The older 16 rows and prospective eight-task study remain separate; that study has not started.
