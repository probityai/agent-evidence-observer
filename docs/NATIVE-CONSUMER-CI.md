# Read native results in a consumer build

`agent-evidence-read-native` reads the bounded Inspect execution and A2A profiles already published here. It reconstructs their common records from selected original bytes. It runs neither framework nor provider, and does not convert a task error or an unknown start into a missing row. A valid receipt establishes selected-input byte consistency, not model quality, independent capture or custody. The consumer decides how this check affects its own report publication or promotion gate.

Use Python 3.12 on Linux. Install the root package normally from a reviewed immutable Git revision, or build and retain its wheel. Keep a separate checkout of that same revision for the profile readers: the root wheel supplies this wrapper and observer modules, while the profile scripts and common validator remain in the selected checkout. No editable install, Inspect installation or A2A SDK installation is needed for this offline step. The root package remains Apache-2.0; its `LICENSE` is in the selected source manifest. The retained producer packet separately contains its native source/runtime/license bytes.

```sh
python -m pip install 'agent-evidence-observer @ git+https://github.com/probityai/agent-evidence-observer.git@REVIEWED_COMMIT'
git clone https://github.com/probityai/agent-evidence-observer.git reader-source
git -C reader-source checkout REVIEWED_COMMIT
agent-evidence-read-native --source-checkout "$PWD/reader-source" --packet /retained/native-run --selection /policy/selected-inputs.json --selection-sha256 SELECTED_MANIFEST_SHA256 --output /consumer/new-receipt
```

Replace the uppercase values with an actual reviewed commit and selected digest. The output parent must exist; the output directory must be new. The command returns nonzero on refusal. Retain the entire output directory, including child stdout/stderr, selected inputs, launch record and report, even when the step fails. A zero-exit child with no report, malformed report, contradictory counters or a report declaring refusal fails. Stale output and symlink packets fail. A timeout terminates the reader process group. Installation failures must stop the caller before invoking the reader.

## Select the inputs separately

The mandatory selection file is outside the retained packet. Its raw-byte digest is a separate command/workflow input. Select native inputs from the operator's retained declarations and source/output records; obtain their pins through the relying party's accepted channel. Copying `consumer-pins.json` from an untrusted producer bundle does not establish that selection. A reproduction can intentionally select those convenience pins after disclosure; it remains a reproduction.

`--describe-sources inspect-execution` (or `a2a`) prints hashes of all installed `probity_observer` Python sources and the exact checkout reader/validator/profile, `LICENSE` and `pyproject.toml` files. A2A also pins its checkout `sdk-source-pins.json` and `SDK-LICENSE`, which the offline source comparison reads. This describes the local installation for review; it does not authenticate it. Review the code and package before accepting this source manifest. The reader refuses a different source population or any changed hash. The revision is a consumer-selected label tied to those file hashes, not a Git signature check. Pin the actual action/dependency commit in the consumer repository as well.

```json
{
  "format": "probity-native-consumer-selection-v1",
  "profile": "inspect-execution",
  "selection_id": "operator-retained-run-001",
  "reader_revision": "40-lowercase-hex-characters",
  "python_minor": "3.12",
  "reader_sources": {"exact checkout path": "64-lowercase-hex-sha256"},
  "installed_sources": {"exact Python filename": "64-lowercase-hex-sha256"},
  "native_pins": {
    "expected_declaration_sha256": "selected digest",
    "expected_sources_sha256": "selected digest",
    "expected_bindings_sha256": "selected digest",
    "expected_plan_sha256": "selected digest",
    "expected_history_sha256": "selected digest"
  }
}
```

This is a shape guide, not a runnable trust manifest. For `a2a`, `native_pins` has exactly `artifacts` (the selected native artifact filename-to-SHA-256 map), `plan_sha256`, `history_sha256` and `sources_sha256`, as consumed by the existing A2A offline reader. `sources_sha256` is the SHA-256 of the canonical compact JSON map from each of the seven retained source filenames to its raw-byte SHA-256 (sorted keys, UTF-8, no whitespace, no trailing newline). This explicit offline mode selects retained producer SDK/runtime/source bytes; it does not assert that the consumer installed those frameworks. Omitting that option from the original A2A CLI preserves its installed-runtime comparison. The wrappers preserve the profiles' existing finite schema and limitations; arbitrary Inspect logs, other SDK versions/transports and live authority checks are unsupported.

## Composite action

The root `action.yml` supplies the same step to another repository. Pin its `uses:` to the reviewed 40-character commit. Set up Python 3.12 first. The action normally installs the selected root package and its declared cryptography dependency. Framework/provider dependencies are unnecessary. The source manifest covers the installed observer code; resolved dependency versions are runtime observations, not a claim of a locked third-party environment. Operators can preinstall a reviewed wheel and a locked environment instead of using the composite install step. The action neither modifies repository permissions nor uploads data; the consumer owns packet retrieval, input selection, gate policy and retention. Inputs enter the shell through quoted environment variables.

```yaml
permissions:
  contents: read
steps:
  - uses: actions/setup-python@v5
    with:
      python-version: '3.12'
  # Retrieve the retained packet and consumer-selected manifest here.
  - uses: probityai/agent-evidence-observer@REVIEWED_40_CHARACTER_COMMIT
    with:
      packet: /absolute/path/native-run
      selection: /absolute/path/operator-selected-inputs.json
      selection-sha256: SELECTED_MANIFEST_SHA256
      output: /absolute/path/new-consumer-receipt
  - uses: actions/upload-artifact@v4
    if: always()
    with:
      name: consumer-native-reader
      path: /absolute/path/new-consumer-receipt/
      if-no-files-found: error
```

The example uses action version tags for setup/upload as other workflows here do; operators can separately pin those dependencies under their own policy. Do not use `continue-on-error` on the reader if refusal is meant to gate publication. Author CI demonstrates the integration path; an external workflow/manifest adopting it remains a separate event to record with the actual operator and retained result.
