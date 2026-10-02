# Running the demo

Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/) are needed for these commands:

```sh
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -e '.[test,aae]'
.venv/bin/pytest -q
.venv/bin/agent-evidence-observer demo ./sample-run
.venv/bin/agent-evidence-observer verify ./sample-run
```

The two CLI commands print `status: verified`, `witnessScope: PEER`, and `noDetectedGap: true`. The last field means the broker's sequential file-tree snapshots found no divergence; it does not mean every agent effect was observed. `sample-run/` contains the signed packet, history, public keys, witness state, and current file tree. Private keys exist only in memory. Verification works offline. Outside this demo, consumers need independently obtained key pins; the bundle's own `trusted-keys.json` is not a source of trust.
