# AAE decision to protected dispatch

The AAE kernel can now gate the protected local write path. The host replays a
consumer-pinned unsigned mandate and exact transaction, commits the resulting
decision into its signed configuration, and retains the grant-before-dispatch
journal and completed native effect. A consumer can replay the decision and
verify the whole retained relation after restart.

Run the reference case:

```sh
python -m pip install -e '.[test]'
pytest -q tests/test_aae_dispatch.py tests/test_aae_binding.py tests/test_aae_enforce.py
python examples/aae_protected_dispatch_demo.py ./aae-protected-run
```

The output directory must be empty. It contains the native inputs, exact action,
local signed grant, consumer pins, protected journal, native history and ledger,
read-back file, report, and a SHA-256 manifest. Private keys are not written.
The report includes the existing 26-case pinned native replay, the completed
join, a restart that returns the saved result without another write, an explicit
missing-bundle outcome, and a wrong-pin refusal. Demonstration pins are written
by the same operator; a real consumer must obtain pins through its own channel.

## What is bound

| Evidence | Check |
| --- | --- |
| Unsigned native mandate | Its JCS digest matches the consumer-selected pin. |
| Transaction and core | The kernel is rerun; the transaction matches the exact local request and all invocation fields have exact grant constraints. |
| Decision commitment | A domain-separated digest covers the native mandate, core and transaction digests. |
| Protected configuration | The new optional `decisionDigest` is signed and witnessed at initialization, separately from `executionDigest`. |
| Before-effect journal | The existing grant-before-dispatch entry commits the same configuration digest, local signed grant, exact request and native starting checkpoint. |
| Completed effect | The existing native packet, history, ledger, completed response and retained authorization head are verified; optional target read-back must match. |

`AaeProtectedDispatcher` freezes canonical input bytes when constructed and
replays them before each invocation. It still requires the separate local
issuer grant and preserves the protected dispatcher's expiry, pending-state,
restart, exact-request and content checks. A pending interrupted attempt is
refused until operator recovery; it is not automatically written again.

`verify_aae_dispatch_bundle` recomputes the decision commitment before calling
the protected verifier. Passing `directory=None` means evidence is missing and
returns `execution: unknown`. A supplied incomplete, corrupted or mismatched
bundle fails verification. Neither a generic unbound dispatch bundle nor a new
valid mandate/core/pin can be substituted into an old completed relation.

The optional field leaves existing configurations and signed bytes unchanged
when omitted. Generic `verify_dispatch_bundle` authenticates the supplied digest;
it does not itself replay AAE semantics. Use the AAE verifier for this profile.

## Sources and limits

This integration builds on Observer
[`f02130fba3659a077cc6cfc446c2b0712210ec41`](https://github.com/probityai/agent-evidence-observer/tree/f02130fba3659a077cc6cfc446c2b0712210ec41).
The kernel fixtures remain pinned to MoltyCel/aae-conformance-vectors
[`531f880155ea1ce993a7ca74137b12c255d5b2ee`](https://github.com/MoltyCel/aae-conformance-vectors/tree/531f880155ea1ce993a7ca74137b12c255d5b2ee),
with their unchanged source manifest, license and notice. This adds a Probity
local-file adapter; it does not change native AAE semantics.

A successful result remains same-operator PEER/artifact evidence. The local
issuer signature is authenticated, but the unsigned AAE issuer is not. This
case does not run the nine-step JWS verifier, execute EVM transfers, launch an
isolated child, establish independent custody or complete effect capture, or
show producer adoption or production deployment. A host retaining keys or direct
workspace access can bypass this library path. The retained journal provides
local signed ordering, not an externally witnessed pre-effect commitment.
