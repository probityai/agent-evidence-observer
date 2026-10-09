# Selected ADK source for the full test suite

Why did ADK's full test suite fail when the installed publication consumer passed?
The two jobs test different things. The native consumer runs the bounded ticket
example against its selected SDK. The full suite also exercises upstream code
and tests outside that example.

The original full-suite attempts against selected source `e94c2e7` failed five
Kubernetes executor cases on each supported Python version. Kubernetes now
validates the owner-reference strings, while those tests supplied mock values.
The executor also used Python field names where Kubernetes requires wire names.
A separate attempt exposed a cleanup test that counted another client's
callback. Those failures remain adverse results for the original source.

## Exact source contract

The [source selection](../../interop/adk-current-consumer-2026-10-03/full-tox-source-selection.json)
binds the clean Google ADK checkout, licensed patch bytes, complete patched Git
tree, unchanged dependency metadata and the separate publication sample.

| Input | Selected identity |
| --- | --- |
| Original SDK commit | `e94c2e726a269e0f04e2e4b202f5c131c80c20de` |
| Isolated GKE correction | `add13dcff08fed54b2ea62ae9e84de7f248bcfb5` |
| Client-scoped cleanup tests | `91eb7f09307cb6fdbe9ae1bfbc296259e7022676` |
| Complete patched Git tree | `3645f920253517623bbb097882008eb978582e10` |
| Patch SHA-256 | `13dd7f57961811dbc41eb601ad47a9f17c8db586f09ca5d0e2882f1c4f989887` |

The GKE correction is an isolated backport of Google's
[already merged fix](https://github.com/google/adk-python/commit/b9a2c0546a856c1520405cae9307f2e2cce4dc65).
It supplies real job metadata in the tests, retains typed owner references for
the Kubernetes serializer, and checks the resulting wire fields. The cleanup
test correction counts the selected client's callback by identity, calls the
real unregister function and checks that other clients survive. It changes no
cleanup runtime code. The patch preserves the original authors and copyright;
its [Apache 2.0 license](../../interop/adk-current-consumer-2026-10-03/upstream-tox-corrections/LICENSE)
travels with the patch.

Only these three SDK files change:

- `src/google/adk/code_executors/gke_code_executor.py`
- `tests/unittests/code_executors/test_gke_code_executor.py`
- `tests/unittests/models/test_completions_http_client.py`

The selection records the original and corrected file hashes. It also pins
unchanged `tox.ini`, `pyproject.toml` and `LICENSE`. The complete-tree check
prevents a matching subset from hiding other source changes. No test is skipped,
dependency downgraded or supported Python version removed.

## Reproduce the source check

Start in the Observer repository root, with its `.venv` installed and a separate,
clean ADK checkout at the original commit. Choose a new receipt path.

```sh
set -eu
profile="$PWD/interop/adk-current-consumer-2026-10-03"
.venv/bin/python -I -B "$profile/test_apply_tox_corrections.py"
.venv/bin/python -I -B "$profile/apply_tox_corrections.py" \
  /absolute/clean-adk-e94 /absolute/new-source-receipt.json
```

The command verifies the owning repository, base, clean checkout, patch, license,
native selection and sample bytes before applying the correction to the index
and working tree. It then requires the exact patched tree and file hashes.
Inherited Git repository and configuration variables cannot select another
checkout. It refuses added source whitespace and an existing receipt. A failed post-application check leaves
the attempted source for inspection and emits no success receipt; stop there.

The [workflow](../../.github/workflows/adk-current-consumer.yml) installs
hash-selected tox tooling and runs this check before adding the unchanged
publication sample. It retains the source receipt, control output, selection,
patch and license with the dependency lock and complete tox logs. The full
suite runs the unchanged `py310`, `py311`, `py312`, `py313` and `py314` tox
environments on that explicitly patched source plus the recorded sample.

## Evidence boundary

The separate native consumer still selects the original SDK commit and its
original installed Python population. The patched full-suite result does not
replace that source identity, repair its historical receipts or establish a
new SDK release. These are author-operated tests. A passing suite does not
establish model quality, production operation or independent adoption.
