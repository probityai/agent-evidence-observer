# Exact tool-argument archive transfer

The original Actions archive is larger than the connector's download limit.
This temporary branch retrieves the existing original from Observer run
37116827382, verifies its provider identity, exact length and SHA-256, and reads
all 14,283 ZIP members. It then retains 36 contiguous byte ranges of at most
28 MiB in separate artifacts, with a complete ordered reconstruction manifest.
Concatenating the verified raw ranges recovers the exact original ZIP.

The source artifact is 11272310915, from
`51e0c12551339cce5898d3bfae2ba9ef3d9607f5`.
Its exact length is 1,051,848,146 bytes; its SHA-256 is
`9ae6d49f3445510ea3b094f6070271898bdc25f02cab405e54ac6825b5137076`.
The complete uncompressed member population is 1,271,176,874 bytes.

The workflow uses read-only contents and Actions permissions. Authentication
stays on the GitHub API request; the signed blob request receives no GitHub
authorization header. The signed URL and token are never retained. Only fixed
selected JSON basenames are copied; other ZIP members are read and hashed
without filesystem extraction. No archive code, installed archive dependency,
model or inference is run. The original artifact is preserved.

The source-bound member manifest retains SHA-256, exact length and CRC32 for
every member, plus the original report, protocol and manifest. Chunk custody
is a transfer mechanism; durable owner-only backup still requires its own
actual upload and complete remote byte/member readback.

Run controls with:

```sh
python -B -m pytest interop/artifact-retention-2026-10-03/tests -q
```
