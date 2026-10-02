# Pydantic AI failure controls, October 2, 2026

The v1 reference adds exhausted retries and a tool exception after a committed
protected HTTP effect. It preserves the original five-case v0 reader and its
archived signed packets and policy pins. No release or host adoption is claimed.

The native population has seven cases. The exhausted case retains two typed
tool attempts raising `ModelRetry` under the declared one-retry budget. Native
Pydantic AI 1.68.0 emits one retry prompt and the second tool call, then raises
`UnexpectedModelBehavior` before appending another prompt. Its verbatim message
history, both wrapper traces and exact terminal exception are retained. The
separate signed GET remains at revision zero.

The committed-effect case performs a real POST through the existing protected
local HTTP service, retains the response and separate GET, then raises the
selected `RuntimeError` before a native tool return. The reader authenticates
the request, authority, HTTP bytes, receipt and signed readback. Execution is an
error and the retained effect is revision one; both facts survive reconstruction.
An operator must assess that committed effect before attempting recovery.

The profile suite passes 55 controls, including 40 Hypothesis-generated argument
and HTTP mutations. New controls refuse omitted and swapped native histories,
malformed histories, hidden exhausted attempts, rewritten exceptions, lost or
swapped committed effects, wrong HTTP digest joins and completion substituted
for failure. The exact implementation revision is
`3893a4536a607f85971a75b06ce87b2705978225`. Python 3.13.15 with the locked
cryptography 46.0.7 runtime executes installed producer wheels outside the
checkout. A separately installed dedicated reader, without Pydantic AI,
reconstructs the complete seven-case packet and passes six additional semantic
refusal controls after reselected hashes.

A freshly installed dedicated reader also passes all 14 original
archive/refusal controls, including byte-exact original v0 report reconstruction.
The producer and reader code pass the declared Ruff checks and complexity limit.

FunctionModel is a scripted native provider interface, with no inference or
provider call. The operator, keys, store and clock remain controlled by Probity.
A retained local effect does not establish independent custody, arbitrary effect
capture, process-crash durability, production deployment or recurring host use.
The producer supplies inspection pins; using them here is an explicit local
selection, not independent prior policy selection.

The initial dedicated-wheel build used a uv-created environment without pip.
That build failed before creating wheels; dependent command tests could not
find installed commands. Installing pip, rebuilding and reinstalling repaired
the environment, and the full original archive suite then passed. This was an
environment bootstrap failure; the failed stage is not counted as a reader result.

The fresh exact-revision run and wheel receipts are recorded in the companion
`failure-run-2026-10-02.json`. Raw original histories, HTTP packets, source bytes,
pins and results remain in the private program's retained execution archive and
the native workflow's artifact, with source revision stated in each plan.
