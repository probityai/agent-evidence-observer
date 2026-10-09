# Tool grade and local effect: technical reference

Start with the [worked example](../TOOL-MANIFEST-EFFECT.md).

## Source and contributor

Kenneives selected `ask_wiki_question` on `https://mcp.deepwiki.com/mcp` in
[the first collaboration case](https://github.com/probityai/agent-evidence-atlas/issues/49#issuecomment-6071630803).
The complete upstream case is pinned at AgentAvow commit
`36426cfd5152bba6a27766febfac8aaef47b6f34`, in
[tool-manifest-digest-vectors-v1](https://github.com/AgentAvow/AgentAvow/tree/36426cfd5152bba6a27766febfac8aaef47b6f34/docs/standards/tool-manifest-digest-vectors-v1).

The vendored vector file is unchanged. Its SHA-256 is
`488496079155830caf83593be0cafcb21367f72cd70ea363c2400f40eda72647`.
[SOURCE.json](../../tests/fixtures/agentavow-tool-manifest-v1/SOURCE.json)
records the paths, commit, contributor and exact fixture/license hashes.
The Apache-2.0 [license](../../tests/fixtures/agentavow-tool-manifest-v1/LICENSE)
is retained with the fixture. No signature, key or grade is regenerated.

## Run and read the retained effect

Start in an Observer source checkout. All Python commands use its own environment.
The fixture is local. These commands make no MCP or scan-service request.

```sh
set -eu
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/python examples/tool_manifest_effect.py ./manifest-effect-run > manifest-effect-run.stdout.json
.venv/bin/python examples/tool_manifest_effect.py ./manifest-effect-run --verify --consumer-pins ./manifest-effect-run/tool-match/consumer-pins.json > manifest-effect-run.verification.json
.venv/bin/pytest -q tests/test_tool_manifest_effect.py
```

Use a new output directory. A changed source, failed reader or unexpected refusal
must stop the recipe. Preserve stderr and the exit status.

The public `probity_observer.tool_manifest` consumer accepts a separately selected
Ed25519 JWK, a compact JWS and `ToolGate`. `require_served_tool` also recomputes
the digest from the supplied definition. The caller selects the producer key
outside the candidate. The fixture replay uses its pinned contributor key; it
does not establish an independent key-discovery or producer-trust policy.

The digest profile is `agentavow.mcp-tool-definition.v1`. Its RFC 8785 preimage
contains the profile and these tool fields: `name`, `title`, `description`,
`inputSchema`, `outputSchema` and `annotations`. Missing or null fields are
omitted. `_meta` and unknown fields are excluded. The binding covers this graded
field set, rather than raw `tools/list` bytes or ignored metadata.

## Checks and fields

| Input or case | Result |
| --- | --- |
| Three saved definitions | RFC 8785 preimages recompute to the signed per-tool digests |
| Thirteen name/key pairs | Exact UTF-8 percent encoding and upstream 96-character cut agree |
| `tool-match` | All six static axes pass at the historical time; one local retention file is written |
| `unknown-tool` | `tool_binds=false`; `tool_digest_binds=not_evaluated` |
| `tool-drift` | `tool_digest_binds=false` |
| `wrong-subject` | `subject_binds=false` |
| `past-expiry` | `fresh=false` |
| `tampered-payload` | `signature_valid=false`; canonical bytes still pass |
| Assessment at the original run time | Old grade's expiry remains a refusal |
| Changed served definition with copied digest | Recomputed preimage refuses |
| Changed retained file, request, report or negative-case directory | The retained reader refuses |

The six axes retain their original names: `signature_valid`, `canonical_bytes`,
`subject_binds`, `tool_binds`, `tool_digest_binds` and `fresh`. `rely` is their
conjunction. It covers the static grade at the selected time. Admission policy
is a separate decision; `rely` is not an execution or safety field.

All three freshness inputs use the same explicit UTC timestamp contract:
`YYYY-MM-DDTHH:MM:SS[.fraction]Z` or the same form ending in `+00:00`.
The fraction has one to nine digits. Calendar whole seconds and integer
nanoseconds are compared exactly; there is no sub-microsecond truncation.
Comma fractions, greater precision, non-UTC offsets, leap seconds and invalid
calendar values refuse. Issuance is inclusive and expiry is exclusive.

The protected file contains the source pin, fixture hash, JWS hash, historical
gate/axes and the assessment at the original run time. Its request names the local
`retain-static-grade-binding` operation, `/work/binding.json` and exact content
hash. The same hash is the dispatch decision binding. It is not a label for an
`ask_wiki_question` invocation.

`runEvaluationTime` and `runGradeAxes` identify that recorded assessment.
The later reader returns the same recorded time, rather than substituting its
own clock. These static-grade axes are separate from an admission-policy decision.

`consumer-pins.json` is selected before the local effect. The reader needs the
original selection explicitly; it never discovers keys from the candidate
state. Keep that selection outside the candidate when sharing a bundle. This
demonstration stores all public selections under one operator's output tree.
It establishes the selected relation, not independent custody.

## Runtime boundary

The local grant uses the run's current whole-second UTC clock. The static fixture
uses its original explicit historical evaluation clock. The assessment at the
original run time is also retained in the protected file, so changing that report
to a historical time conflicts with the selected content/request digest. The
later `verify_run` reader recomputes that retained assessment at its original
clock; it does not perform a fresh current-time admission.

The completed effect is a local file replacement with `PEER` witness scope. One
operator controls the three ephemeral role keys and local workspace. No live
DeepWiki call, server-side dispatch record, returned answer or isolated remote
authority is observed. The grade's score/tier remain the issuer's static data.

To assert that a remote effect came from this graded definition, a runtime must
retain its selected endpoint, actual served definition, exact named invocation,
authority decision, timing and result. The consumer must authenticate and join
those records under its selected authority. Digest equality alone supplies none
of those missing observations. The static grade does not establish action safety.
