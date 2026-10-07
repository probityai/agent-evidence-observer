# Authority unreachable: operator rerun, 2026-10-04

## Results and access
Public evidence for Imran, Marc, Sankalp, Chris and the AAIF working group. No login or production credentials required.

* Observer reference: 58/58 tests passed, all 18 controlled local-ticket scenarios produced and independently read by separate installed producer/reader environments.
* Alakris pinned original tests: 35 passed, 2 failed at API import (`Status code 204 must not have a response body`). This is not a clean native test pass. Original source was not patched.
* Alakris fingerprint discriminator: title, body and media reference change the fingerprint; platform packaging, destination, and changed media bytes behind an unchanged reference do not.
* Lost response after a committed write: the reference reader preserves the observed effect but marks the task failed and publication blocked. Same-request retry produces one effect.

These are controlled test results, not deployed-provider traces, a security certification, peer review, or a matched comparison against MintID/Proofable. Reference signatures have author-operated local custody; no independent key-custody claim is made. The source-discriminator JSON's originalTestsRerun=false applies to that narrow function-execution report; native-tests.xml separately records the original test attempt.

## Pins
Observer runner: https://github.com/probityai/agent-evidence-observer/tree/fb8cabc5c9c54459743497f2325bfef49b137a1a/interop/authority-unreachable-2026-10-03

Alakris source: 68054425873b9b373ce07359f8e994b817bee210
publication_jobs.py SHA256: 3a928ff97f2eb13d2138809d1aebbacd645a07210663d74e2d77bae7fa1002df

Reference base image: python:3.13-slim@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81
Native test image: sha256:d90e04421a5c702288b7a44a813daa57d74897a0d7705b0a67c47bb707d2b860 (local, not publicly distributed).

## Public reproduction
Clone the pinned Observer commit; install its profile requirements in an isolated Python 3.13 environment. Download publication_jobs.py from this repository, verify its SHA256 above, then run:

```sh
bash interop/authority-unreachable-2026-10-03/verify_install.sh \
  /work/results fb8cabc5c9c54459743497f2325bfef49b137a1a \
  /work/alakris-publication_jobs.py
```

Execution used a network-disabled container, no host credentials, limited memory/CPU and no extra capabilities. Dependency installation occurred before execution. `reference-evidence.tar.gz` contains the JUnit report, reader/discriminator reports, 18 signed records and SQLite fixtures, plus wheel hashes; it excludes virtual environments and signing private keys. Public artifact hashes are in SHA256SUMS.

## Native Alakris attempt
Pinned source and its requirements.txt were used internally with a separate schema-only CI PostgreSQL container on an internal Docker network, no published ports and no production data. Provider calls are mocked by the original tests.

```sh
python -m pytest tests/unit/test_publication_jobs.py -q \
  --junitxml=/results/native-tests.xml -o cache_dir=/tmp/pytest-cache
```

Two tests fail before their assertions: test_approve_to_native_applier_with_mock_http and test_api_scope_guard_with_invalid_body. Both import merchant_llm_config_api.py:805 and hit the FastAPI 204-response assertion. The CI image and full private dependency tree are not distributed here; this native attempt is not fully reproducible from the four-file public package alone. No full native execution of the 18 reference scenarios is claimed.

## Next matched comparison
Each implementation should attach its own run evidence to https://github.com/aaif/wg-identity-and-trust/issues/13. Maintain separate authority/content/effect/task-outcome fields and state unsupported cases explicitly. MintID's deployed 180-second freshness limit remains relevant; planned funded recourse and unavailable subdelegation are not treated as deployed features.
