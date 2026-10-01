# Declaration to action

The crosswalk asks a narrow question: do these declared bytes, supplied runtime
values, local verifier result and read-back effect refer to the same work?
It does not decide whether an agent is safe or whether an organization should
admit it.

This is a proposed Probity reference profile. CoSAI WS4 PR #210 names
declaration-to-action cases as proposed work; it is still an open proposal.
The mapper uses fields present in the pinned Agent Manifest source. It does not
claim Manifest, TRACE, Agent Credentials or ODIS conformance.

## Run the cases

From the observer repository:

```bash
PYTHONPATH=src python examples/declaration_demo.py --output declaration-run
```

The output directory must be new or empty. The run retains declaration and
artifact bytes, runtime values, signed grant, issuer policy, exact request,
broker history, witness ledger, sealed packet, actual target file, read-back
effect and per-axis results. The baseline applies one write through the
existing signed-grant broker. It is not an isolated producer run.
`file-manifest.json` binds every retained file except itself.

| Case | Required result |
|---|---|
| Exact local reference fixture | `matched` |
| Loaded policy digest differs | `refused` |
| Live instance differs | `refused` |
| Approved operation names a tool outside the declaration | `refused` |
| Actual replacement bytes differ | `refused` |
| Actual target differs | `refused` |
| Runtime, grant or effect missing | `incomplete` |

`matched` means only that the listed comparisons match. It is not an allow
decision. The local fixture's model file is a byte fixture, not a trained model
or proof that inference ran. All keys and observations belong to one operator.

## Native field mapping

| Native declaration field | Crosswalk comparison |
|---|---|
| Exact JSON payload bytes | Consumer-selected digest versus runtime's declared payload digest |
| `agent_id` | Runtime subject and authenticated local grant's `principal_id` |
| `agent_instance_id` | Explicit runtime instance; absence stays missing |
| `artifacts.system_prompt.hash` | Digest of the retained local prompt file |
| `artifacts.policy_bundle.hash` | Digest of the retained local policy file |
| `artifacts.tool_manifest.catalog_hash` | Recomputed section 3.2.3 catalog root |
| `artifacts.tool_manifest.tools[].tool_id` | Membership of the exact granted tool |
| `artifacts.model_identity.version` | Supplied runtime model version |
| `artifacts.model_identity.model_hash` | Supplied model-byte digest, only for `hash-bound` |

The runtime run ID is also joined to the supplied action's run ID. The
effect is joined to that action by run, attempt, request, target and exact
replacement-byte digest. Tool membership does not authorize an operation.
The existing local grant verifier checks issuer, signature, request and time;
the demo actually verifies each retained grant before passing its
`AuthorizedAction` result to the crosswalk. That constructible Python object is
an in-process input contract, not a transportable proof. The comparator does not
rerun signatures or authenticate caller-supplied runtime/effect values.

Provider-asserted model identity stays `unsupported` for the model-byte axis.
Empty observed hashes stay missing; an empty declared tool catalog cannot
establish membership. Container digest is projected when present, but this
case set does not appraise it or compare it to a boot measurement. Supply-chain,
hardware, native credential, ODIS delegation, TRACE appraisal and complete
history checks remain separate work.

## Rerun the pinned native COSE vector

The optional native path uses the upstream SDK rather than another token
implementation. Obtain the exact source and its declared dependencies:

```bash
git clone https://github.com/agentrust-io/agent-manifest native-manifest
git -C native-manifest checkout fed9aeb091e4c77e0b40e12e959bee30b52e3c75
python -m pip install --target native-deps cbor2==6.1.4 pydantic==2.13.5
PYTHONPATH=src:native-deps python examples/declaration_demo.py \
  --output declaration-native-run --native-sdk-root native-manifest
```

The demo checks every one of the 28 upstream Python module Git blob pins before
importing the SDK. It also checks the exact retained owner vector bytes. The
native output retains those checked SDK sources with their license and notice,
as well as original/tampered envelope bytes and each input context. Parser
dependencies are installed separately; this is not a self-contained offline
environment image. The
native results are recorded without translating them into local pass/fail:

| Native control | Pinned SDK result |
|---|---|
| `AM-VEC-COSE-001` and its fixture context | `VALID`, signature verified |
| One substituted signature byte | `MISMATCH`, signature not verified |
| Different runtime policy hash | `MISMATCH` |
| No trusted keys | `UNVERIFIABLE` |

The owner vector can be natively `VALID` while the action crosswalk is
`incomplete`: it has no tool catalog, live-instance binding or action/effect
evidence. Its hardware and transparency results are false. The public vector
key is test trust, not an assertion that its issuer has production authority.
Native signature checking alone does not appraise unprotected COSE attachments,
time, revocation, hardware, deployment or custody. `project_cose_manifest`
performs that signature-only operation explicitly; full native results in the
demo come from the separate upstream `verify_manifest` call.

The local rerun used Python 3.12.14, cryptography 46.0.0, cbor2 6.1.4 and
pydantic 2.13.5. The SDK and vector source revision is
`fed9aeb091e4c77e0b40e12e959bee30b52e3c75`; the retained vector Git blob is
`687d8f736c96b4286e4597ccaa5dfd7e138ec0ae`. Source pins live beside the vector
in `tests/fixtures/declaration/native-source-pins.json`.

## Bounds and source

The reference parser accepts at most 64 KiB, 2,048 JSON value nodes, depth 12
and 64 catalog tools. Duplicate JSON keys, duplicate tool IDs, inconsistent
catalog roots, unsupported versions and unsupported digest algorithms refuse.
It projects a supported subset; it is not a complete native schema validator.

The owner vector and adjacent LICENSE/NOTICE are unchanged Apache-2.0 material
from [Agent Manifest](https://github.com/agentrust-io/agent-manifest/tree/fed9aeb091e4c77e0b40e12e959bee30b52e3c75).
The field and catalog definitions come from its pinned
[v0.2 specification](https://github.com/agentrust-io/agent-manifest/blob/fed9aeb091e4c77e0b40e12e959bee30b52e3c75/spec/agent-manifest-spec-v0.2.md).
The proposed contribution is tracked in
[CoSAI WS4 PR #210](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/pull/210).
No downstream acceptance, coalition membership or independent custody follows
from a source link or a successful local run.
