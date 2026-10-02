# Eight-component host kit: unfinished checkpoint

This branch contains a partial byte bridge and frozen component selections.
The chained host evaluator, external authority setup and CI remain unimplemented.
No eight-component execution, native host CI, peer approval, protected merge,
external adoption or effect custody is established here.

`SOURCE-SELECTION.json` refreshes all eight public heads and binds every tracked
source file. Vocabulary, admission and Atlas remain source/reference components;
no documentation is presented as a package. Three Python packages were built as
ordinary wheels from these exact checkouts and installed normally: Observer,
Vectors and Verify. Their current source build versions are recorded separately
from published release status; this does not perform the existing owner's release.
Rust uses normal registry dependencies with a frozen `Cargo.lock`:
`jcs-admit=0.1.1` and `dsse=0.1.1`. Registry checksums and crate release VCS
commits are recorded; JCS's published release source differs from current main.
OPA's real official Linux/amd64 1.18.0 asset matches the admission repository's
SHA256 pin. Its version output reports a dirty build-commit suffix; this is not
described as a pristine source build.

The small Rust CLI is implemented and installed normally:

```sh
cargo install --locked --path rust --root /new/host-tools
/new/host-tools/bin/probity-host-byte-gate admit-sign RAW_JSON HOST_SEED_HEX NEW_ENVELOPE
/new/host-tools/bin/probity-host-byte-gate verify ENVELOPE HOST_PUBLIC_HEX NEW_PAYLOAD
```

It checks raw JSON with the actual JCS crate before signing with actual DSSE,
retains raw/canonical/envelope SHA256 commitments, obtains payload only from
DSSE verification under the separately supplied host key, and refuses a verified
payload that is not its selected canonical form. Output creation is exclusive.
This bridge is not an authorization service. A future host launcher must enforce
external source/key/policy/tool selections before starting these commands;
that host launcher and its trusted boundaries do not yet exist.

Continue in the isolated Observer profile without editing shared src, existing
framework consumers, model profiles, Atlas publication, vocabulary term lifecycle
or generation release. The intended finite chain is: raw AEE → JCS/DSSE returned
verified bytes → installed Vectors reference crypto/result → pinned OPA policy
admission; then a pinned Atlas registry/provenance/archive/report and vocabulary
term check plus installed Verify coverage decision; only after these pass may a
separate explicit Observer grant authorize local HTTP ticket dispatch/reopen and
recovery. Signature validity, authority and native effect remain different facts.

Next work must implement externally hash-selected installation/source manifest,
host-owned key/authority and policy setup outside candidate bytes, the actual
chain, meaningful per-boundary mutated negatives, retained refusal/timeout
receipts, actual normal installed CI, independent peer review, normal protected
landing and exact-main readback. Use stable Atlas
`58c89e18033a3c5fdd10d1a9b65497e25093dcc8` authority recovery record to avoid
depending on ongoing Atlas/model publication. Existing owner lanes stay intact.
