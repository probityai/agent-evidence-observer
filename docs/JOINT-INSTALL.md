# Install Observer and Verify together and run native controls

This recipe selects the reviewed Observer compatibility source and unchanged Verify source. Historical recipes keep their original pins.

Use Linux, Python 3.12 or 3.14, uv, curl and sha256sum. Start in a new directory. Installation and source retrieval need a network connection. The smoke test uses local files and producer/reader processes.

```sh
set -eu
mkdir joint-reader-smoke
cd joint-reader-smoke
uv venv --python 3.12 .venv
curl --fail --location --output observer-source.tar.gz \
  https://codeload.github.com/probityai/agent-evidence-observer/tar.gz/8cb4f8513cadb4c14a3c0a0a4526dea9c541a52d
curl --fail --location --output verify-source.tar.gz \
  https://codeload.github.com/probityai/probity-verify/tar.gz/a2a7e23413be0ab0ad1001d60085a2ff21eaa907
uv pip install --python .venv/bin/python ./observer-source.tar.gz ./verify-source.tar.gz
uv pip check --python .venv/bin/python
mkdir -p verify-controls/scripts
curl --fail --location --output verify-controls/scripts/check-brokered-file-write.py \
  https://raw.githubusercontent.com/probityai/probity-verify/a2a7e23413be0ab0ad1001d60085a2ff21eaa907/scripts/check-brokered-file-write.py
curl --fail --location --output verify-controls/scripts/brokered-file-write-producer.py \
  https://raw.githubusercontent.com/probityai/probity-verify/a2a7e23413be0ab0ad1001d60085a2ff21eaa907/scripts/brokered-file-write-producer.py
sha256sum --check <<'CONTROL_DIGESTS'
c3ade410b059d90ba86f1be7e8020bcd209a66ac2b12e1019c9d3ba5f00e1613  verify-controls/scripts/check-brokered-file-write.py
f7545959a44861cce25e5779ea0e9c0fa2925b59daae1526bf4acf52bff3577a  verify-controls/scripts/brokered-file-write-producer.py
CONTROL_DIGESTS
.venv/bin/python verify-controls/scripts/check-brokered-file-write.py \
  --producer-python "$PWD/.venv/bin/python" \
  --verifier "$PWD/.venv/bin/probity-verify" \
  --output "$PWD/capture"
```

The dependency check and controller must both exit zero. `capture/RESULTS.json` must have `valid: true`. It retains three actual producer outcomes and six installed Verify decisions:

| Producer outcome | Actual process exit | Report says completion happened | Report says completion did not happen |
| --- | --- | --- | --- |
| Normal completion | 0 | supported | contradicted |
| Hard exit after the sealed record | 74 | supported | contradicted |
| Hard exit before the terminal record | 74 | not_established | not_established |

The controller runs the producer with the installed Observer package. It invokes the installed Verify CLI against those original retained bytes. The controller and reader do not import Observer. A source-file digest check does not establish who controls the runtime.

These are author-operated local controls with `witness_scope: PEER`. They do not establish independent custody, a payment-provider effect or customer use. Preserve `capture/` when a control fails; use a new directory for another attempt.
