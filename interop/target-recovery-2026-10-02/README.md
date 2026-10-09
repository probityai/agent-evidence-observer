# Protected target process restart

This additive profile runs an actual HTTP ticket target in fourteen distinct
processes. It preserves the earlier target source and all framework packet pins.
Seven selected cases cover restart before dispatch, hard exit after the committed
intent, hard exit inside the effect transaction, hard exit after the effect
transaction commits but before its response, eight concurrent calls for one exact
intent, missing store and changed configuration.

The SQLite transaction owns the native ticket row, signed state and signed event
history. The target signer stays in host-only files outside the public packet.
Restart uses the same key/configuration and a retained signed head; a missing
store is refused instead of initialized. An interrupted intent refuses automatic
replay; explicit host recovery retains an incomplete outcome with zero native
revision. The committed effect survives target exit and the reopened endpoint
returns the same authenticated revision-one receipt. The concurrency case holds
the native intent window open for 150 ms: concurrent pending callers are refused;
only the admitted original request commits. This is a bounded reference behavior,
not a general exactly-once guarantee.

Run from this directory using Python 3.13:

```sh
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --no-deps -e ../..
python -m pip check
python -m pytest -q
python target_run.py NEW_PACKET --source-revision EXACT_CHECKOUT_COMMIT
python target_reader.py NEW_PACKET --pins-file HOST_SELECTED_PINS
```

The reader requires an explicit pins file. It checks the whole selected manifest,
real process-exit transcript, literal HTTP bytes, signed native readbacks and a
read-only replay of the retained SQLite rows/events. Process IDs and the runner
transcript are unsigned testimony. Reselecting artifact hashes does not make a
changed identity, cached result mislabeled as a fresh effect, missing population,
wrong native revision or rolled-back event prefix acceptable.

The profile builds an additive `probity-target-recovery-reader` wheel with the
`probity-read-target-recovery` command. It requires the selected Observer wheel
and cryptography; no agent framework, model or target signing key is required by
the offline reader. The workflow actually installs both wheels in a separate
virtual environment and calls its installed command through `host_gate.py`.
The host policy separately fixes the profile, pins digest and denominator seven.
The gate requires its reviewed raw policy digest and refuses policy/pins inside
the producer packet, duplicated JSON names or missing/nonclaim populations;
reader refusals and failed launches are retained and refuse publication. A host
must review and maintain its own selected pins/policy and revision/job.

The runner-owned SQLite filesystem, local clock, issuer/service keys and HTTP
listener remain one operator's custody. Hard exits are process exits on a live
host. This does not test power loss, remote identity, independent custody or
production containment. No outside host acceptance or recurring use is established.
The inherited witness scope remains `PEER`.
