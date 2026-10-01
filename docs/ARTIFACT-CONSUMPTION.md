# Artifact consumption records

An integration should name the artifacts it actually checks, keep their bytes,
and carry their attribution. Listing a project as a dependency is not the same
as consuming its artifact during an action.

```sh
python examples/attribution_demo.py ./attribution-run
```

The example checks the retained signed grant and observer packet from the
Protected Action Kit, then signs a separate consumption record. It carries the
input byte digests, source revision, attribution, license, checker results,
action ID and verified claim digest. Offline checks refuse another action,
another claim, changed input bytes and unpinned provenance or signers.

The consumption record is the signer's account. Its signature does not prove
that the checks ran, that all checks were recorded, or that the signer has
independent custody. The demo performs the checks and retains their inputs;
another consumer can rerun them rather than relying on the reported result.
Coverage is explicitly `listed-checks-only`. A missing receipt leaves the
binding unestablished, not a negative execution finding.

This is a technical attribution profile, not payment rules, endorsement, shared
governance or membership. Authorization, observation and artifact use remain
separate claims. The external MolTrust AAE adapter is not implemented here.
Its source pin is `MoltyCel/aae-conformance-vectors` at
`531f880155ea1ce993a7ca74137b12c255d5b2ee` (tag `v1.4.0`); it needs a separate
verdict-core check and action mapping before it can enter this demonstration.
