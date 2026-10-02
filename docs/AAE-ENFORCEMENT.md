# AAE enforcement and local effect

The adapter recomputes the unsigned enforce-core 3.0 verdict and its tagged RFC 8785 digest. The 26 retained enforce fixtures come from `MoltyCel/aae-conformance-vectors` at `531f880155ea1ce993a7ca74137b12c255d5b2ee`. The replay checks the source manifest, every fixture's SHA-256 and Git blob ID, then compares verdicts, core digests and trace entries. The included `LICENSE` and `NOTICE` travel with the fixtures.

This covers the enforce and ratify kernels in the pinned draft, plus a Probity local file-write crosswalk. The native JWS vectors and composition vectors are separate sets. The adapter does not run the nine-step AAE verifier, authenticate the mandate's issuer, establish EVM execution or claim upstream conformance.

Ratification checks the prior core's self-digest and shape, then a signature under a key named by the digest-bound mandate. The prior transaction is absent from that call. A `RATIFIED` result reports `priorEnforcement: not-replayed`; it does not prove that the prior verdict was recomputed from its inputs or that the mandate's issuer was authenticated.

`write_local_action` maps the selected `ActionRequest` to a `write-file` transaction. It recomputes the candidate core, checks a mandate digest supplied independently by the consumer, and requires the selected PERMIT grant to have exact constraints for the run, attempt, request, tenant, principal, tool, target and content digest. The selected broker authority and content bytes must also match. A consumer can pin a mandate containing other grants, so the mandate itself is not single-use. A caller with direct access to the broker or writable workspace can bypass this adapter.

After the write, the local observer signs a link to the recomputed core, request and observer claim. `verify_effect_link` checks that link, consumer-pinned observer and witness keys, the packet and witnessed history, and the one expected file write. The demo keeps these checks in one operator's custody. It reports `issuerAuthentication: not-established`, PEER witness scope, and `execution: unknown` when the effect link is absent.

Install the optional `aae` dependency and run:

```sh
python examples/aae_replay.py
python examples/aae_demo.py ./aae-run
pytest -q tests/test_aae_enforce.py tests/test_aae_binding.py
```

Keep the fixture manifest, raw fixture bytes, replay report, consumer pins, core record, observer packet, signed link and exact code revision together when sharing a result. A successful replay says what the retained inputs establish; it does not confer authority on an unsigned issuer.

## Protected dispatch join

The [protected AAE dispatch profile](AAE-PROTECTED-DISPATCH.md) joins the exact
unsigned kernel decision to the pre-effect protected authorization journal,
completed native history and restart replay. The original post-effect link
above remains available and does not by itself establish this prior relation.
