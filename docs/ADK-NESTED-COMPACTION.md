# Check what survives when nested agents shorten their history

An agent can call another agent, which calls a third. Each has its own session
history. When the framework shortens that history, a useful check needs to follow
the actual sessions, summaries, and tool effects through all three levels.

This example runs that nested pattern in ADK with fixed model replies. It checks
what was recorded before and after each tool call, and whether the shared capture
plugin stayed open until the child calls finished.

## What the example shows

Four cases compare token-triggered summaries, no history-shortening configuration,
a window-only configuration, and a run that excludes plugins from child agents.
The recorded model calls, direct summary calls, and file writes remain separate.
A summary call does not imply that the ordinary model callbacks observed it.

Three cases have the selected nested callback coverage. The plugin-exclusion case
has only root coverage, so the reader cannot establish the same nested result.
Verify preserves that missing coverage as `not_established` when checking for a
premature plugin close.

## Run and inspect it

The [technical reference](reference/ADK-NESTED-COMPACTION.md) gives the exact ADK
source, measured counts, session and callback checks, source positions, and
refusal controls. It links the runnable profile and keeps the separate
user-response example distinct.

## What the result establishes

The runs use a fixed model implementation and local fixture files. One author
operates the keys and storage. The result covers the selected framework paths;
it does not measure model quality, all application events, or outside custody.
