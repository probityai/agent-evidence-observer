# Native ExecSurface state companion

A finite Linux x86_64 integration: capture one declared file overwrite with the
published ExecSurface Alpha.5 ptrace binary, bind separately captured before/after
bytes to prior authority, and verify the signed ObservedEffect statement with the
unchanged, pinned Vectors reference reader.

```sh
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python download_binary.py execsurface
./execsurface doctor
EXECSURFACE_BINARY="$PWD/execsurface" python -m pytest -q tests
python companion.py run native-run --binary ./execsurface \
  --source-revision "$(git rev-parse HEAD)" --write-pins /tmp/execsurface-selected-pins.json
cp publication-policy.json /tmp/execsurface-selected-policy.json
policy_digest=$(sha256sum publication-policy.json | cut -d' ' -f1)
python companion.py read native-run --pins-file /tmp/execsurface-selected-pins.json \
  --policy-file /tmp/execsurface-selected-policy.json --policy-sha256 "$policy_digest"
```

Setup downloads are hash-selected. Capture and replay make no network requests.
The host selects pins and publication policy outside the packet. A selected
authoritative tier or typed-health requirement refuses publication with exit 1,
while retaining the valid limited evidence report.

This is **same-operator** evidence: voluntary tier, peer vantage, log-import origin,
software-only runtime. The metadata trace supplies no content bytes or byte count.
Separate endpoint snapshots supply a declared single-file state root. Coverage
remains incomplete with the literal target path as its gap; typed collection health
remains unknown. Original backend limits, warnings and outcomes remain carried.

Two additional same-byte writes execute the producer's normal learn/check flow
after the claimed interval. Their baseline, explicit review policy and PASS result
are retained separately; that verdict does not establish observation authority.

See [the protocol](PROTOCOL.md) for bindings, limitations and refusal controls.
