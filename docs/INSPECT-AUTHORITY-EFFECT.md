# Keep an evaluation score separate from the tool's effect

An evaluation can fail after a tool has already changed its target. It can also
pass because a denied action was the expected behavior. The task score alone
cannot tell you whether the tool was permitted or what it changed.

This example connects Inspect's actual tool events to an authorization decision
and a local HTTP ticket service. It uses fixed mock replies, records the original
requests and responses, and checks the ticket's retained state.

## What the example shows

Six planned attempts preserve task completion, authorization, and effect as
separate results. They include a permitted update with a passing task, a permitted
update with a failing task, a denial, an interrupted pending effect, a model error
after an update, and an attempt that was never started.

The reader can verify a ticket update even when the later task fails. A durable
intent without completion remains incomplete. An unstarted attempt stays in the
selected population with its effect unknown.

## Run and inspect it

The [technical reference](reference/INSPECT-AUTHORITY-EFFECT.md) provides the exact
runtime, installation and reader commands, attempt matrix, retained HTTP and
framework records, and refusal controls. The reader checks these records offline;
it does not rerun Inspect or contact the ticket service.

## What the result establishes

One operator controls the service keys, store, and clock. The AAE mandate is
unsigned, and its decision does not authenticate an issuer. The selected grants
are checked at the historical evaluation and dispatch times. The result does not
establish current authorization, independent custody, or model quality.
