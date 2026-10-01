# Declared pilot replay

A signed consumption record can bind a reported success to exact bytes while
the report itself is false. This profile adds actual offline native replay. It
does not change the generic consumption record's signer-asserted meaning.

From a clean source checkout containing this profile:

```sh
python examples/replay_demo.py ./replay-run --source-revision "$(git rev-parse HEAD)"
python examples/replay_demo.py ./replay-run --replay --trusted-policy ./replay-run/replay-policy.json
```

The first command generates one local protected write, then replays its grant,
authorization binding, broker history, current target bytes and retained witness
head. All keys belong to the demo operator. Its source revision is an explicit
caller assertion: the offline runner checks object-id syntax and source-byte
pins, not whether those bytes belong to a remote Git revision. Use the second
command's demo policy only for same-operator reproduction. A real consumer must
acquire policy, provenance and key pins outside the candidate package.

## What the consumer freezes

`ReplayPolicy` selects the action, claim, consumption signer, immutable Git
source pins, exact checker-source digest, declared fixture names, workspace
names and every input role. The signed results also carry the policy digest.
Git source revisions are full lowercase SHA-1 or SHA-256 object IDs; this
Git-specific rule does not narrow `ArtifactPin` for other ecosystems.

The declared replay context includes exact bytes for:

- Grant, observer packet and expected action request.
- Grant policy, native admission policy, issuer/observer/witness key pins and
  explicit historical UTC reference time.
- Broker history, witness receipt log and the consumer's retained witness head.
- Workspace manifest and every declared current workspace member.
- Separate owner and copy fixture manifests and every declared member of both.

Both fixture manifests must describe the consumer-selected population. Every
owner member must match its manifest, and each copied member must match the
owner byte-for-byte. This checks declared source binding, not who controls the
source, whether every relevant fixture was declared, or mutation adequacy.
Native signed bytes are never rewritten.

## Results and the gate

`replay_checks` performs the checks without trusting a consumption receipt.
`replay_consumption` first verifies the receipt's signature, provenance and byte
bindings, then performs the same native checks freshly. Signature success and
actual outcomes are reported separately.

The closed outcomes are `pass`, `refusal`, `invalid`, `incomplete`, `error` and
`not-run`. Missing declared context produces `incomplete` with checks `not-run`.
Malformed profile data and substituted pins are refused before native replay.
Native refusals and checker errors remain explicit. Only passing actual checks
that agree with all reported outcomes yield `replay-acceptable`; every other
case blocks. A block establishes insufficient evidence for this gate, not that
the earlier effect did not occur.

The retained replay command prints actual results and exits with status 1 if
the gate blocks. A signed success alone cannot make that command succeed.

The demonstration signs a fabricated all-pass report over a packet with its
authorization binding removed. Generic binding verification succeeds; actual
observation replay refuses it and the gate blocks. The retained matrix also
covers a substituted fixture copy, missing owner bytes and a stale checker pin.
It is a finite fault set, not a completeness or adequacy result.

## Bounds and retained files

The profile allows at most 48 input roles, 12 fixture names and 12 workspace
names. Each input is at most 64 KiB; total retained input bytes are at most
512 KiB. A consumption record is at most 64 KiB. JSON structures are bounded
to depth 16 and 4096 visited nodes; native histories and ledgers are bounded to
128 canonical JSON lines each. Member names are normalized relative ASCII paths
without traversal, aliases or file/directory collisions. No remote fetch,
arbitrary checker name or candidate executable is dispatched.

`replay-inputs/` retains original context bytes, while `input-paths.json` names
their roles. `replay-policy.json`, `consumption-record.json`,
`replay-result.json` and `mutation-matrix.json` keep selected pins, reported
outcomes, actual outcomes and controls. The fabricated control retains its
mutated native observation as hex so its exact bytes can be recovered without
altering the clean input. `checker-source/` and its manifest retain the local
checker sources. `replay-manifest.json` hashes all retained files.

These are input/work bounds, not CPU deadlines, process isolation or a hostile
host defense. The interpreter, dependencies, loaded functions and local
filesystem remain trusted. Source digests alone do not attest running bytecode.

## Limits

This is post-action replay. It neither gates the demonstration's earlier write
nor persists a consumer admission. A host should use the existing protected
action check and its own protected `AdmissionStore` before any downstream
decision that requires durable replay protection. This profile checks native
admission expectations and witness continuity, but does not reset or replace
that store. Repeating offline replay is intentionally permitted.

Coverage is `declared-inputs-only`; records remain `PEER`. No complete-accounting
denominator, independent custody, external identity authority, current freshness,
global exactly-once effect, native APS/MCP/A2A conformance, or payment entitlement
is established. The signed grant path and isolated launch remain separate
unless a separately verified integration joins them.
