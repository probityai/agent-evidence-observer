# Global action vocabulary intervention

This profile compares a broad-string JSON schema with a global action enum. Both modes use schema-constrained decoding. Every vocabulary case uses the same seven labels: `publish`, `hold`, `admit`, `reject`, `retry`, `inspect`, and `dispatch`. The grammar receives no case target.

The sixteen policy cases are exact copies of the previous 384-call protocol. Each copy retains its full original object and identity. Two modes, two selected SmolLM2 models and two completion caps produce 128 attempts. A fixed SHA256 order ranks the sixteen original case blocks and rotates all eight model/cap/mode cells. Each cell occupies each position twice. The selected protocol, grammar bytes, compiler, helper and dependency lock are frozen before inference.

Preparation allows one selected transfer per payload, within 512 MiB and 180 seconds. The build allows 335 seconds. The native run allows 600 wall seconds, 600 whole-process CPU seconds, 1 GiB peak RSS, 65,536 prompt tokens and 7,680 completion tokens. Paid provider calls and spend are zero. The previous five preparations transferred 2,167,006,362 bytes; this preparation adds its actual transfer, including failures.

Run offline controls with:

```sh
python -m pytest interop/local-model-vocabulary-2026-10-02/tests -q
```

The `local-model-vocabulary.yml` workflow runs offline controls for ordinary changes. Actual inference requires `workflow_dispatch`. Its two artifacts retain the complete preparation and the smaller native packet separately. A failed call stops execution, retains its started/error records and leaves all unstarted attempts in the 128-attempt denominator. Unsupported grammar support has no unconstrained fallback.

An offline reader must use the frozen installed reader and separately select the four hashes in `consumer-pins.json`:

```sh
python interop/local-model-vocabulary-2026-10-02/task_matrix.py PACKET --verify --pins-file SELECTED-PINS.json
```

The reader checks retained runner bytes against its own installed source and checks the active helper against the protocol's selected helper hash. It never imports retained candidate code. It keeps format validity, schema membership and semantic correctness separate. Publication means a complete report within the declared resource limits; it does not establish effect admission, producer acceptance, recurring adoption or independent custody. The workflow's separate reader invocation is a replay using producer pins, not an independent consumer selection.

The selected128-call study completed on October3,2026. [Actual results and installed replay](RESULTS-37094901561.md) retain its complete population, resource receipts and strict quality holds. The original native ZIP is retained in the source tree, and ordinary push/PR CI replays that completed packet through a clean model-free installed reader without new inference. Prior results informed this authored intervention. This is not a representative benchmark or blinded study.

The final registration is `e5bc19b22fba86d1bf7d2bec7f507773099cf611`, with protocol SHA256 `64e0f444a457cb2e82e00dd905e4de186f7384dd95a129600c6185de454c02d2`. Earlier registrations in this branch ran no inference and are superseded. The runner refuses any other registration commit before creating run state.

Build and install the separate model-free reader from the reviewed source contract:

```sh
python interop/local-model-vocabulary-2026-10-02/build_installed_reader.py . reader-wheel \
  --contract interop/local-model-vocabulary-2026-10-02/reader-source-contract.json \
  --contract-sha256 4a3a47b14308f726af505ac489c9cb4c482cd48c09eacd3881c2fafe44f14ff7
python -m venv reader-env
reader-env/bin/python -m pip install --no-index --no-deps reader-wheel/*.whl
reader-env/bin/probity-policy-vocabulary-reader PACKET --pins-file SELECTED-PINS.json
```

The builder requires each selected source hash and exact reviewed commit, verifies all wheel members and entry points, and records the build tools. The installed package has no model dependency. Its default host quality policy requires all sixteen answers and all eight pairs correct in every model/cap/mode row. An evidence-valid packet can therefore return `hold-quality`. Hosts can select weaker thresholds explicitly without changing the retained scores. `--evidence-only` exits on evidence validity and still reports the separate quality and consumer decisions; it does not authorize a protected effect.

The workflow also builds the wheel twice, installs it in a clean environment, repeats a consumer decision, and rejects a changed helper even with resigned packet pins. These installation controls use explicit synthetic fixtures and establish no model execution or outside adoption.

