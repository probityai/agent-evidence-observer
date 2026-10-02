# Same-operator native state join, version 0

The declared action is one nine-byte overwrite of an existing generated test file.
The workload opens it with O_WRONLY, asserts the write count, fsyncs and closes it.
No production secret, environment value or other file content is collected. The
companion retains only the explicit fixture's before/after bytes, known command,
authority, commitment and native output. It creates a fresh packet and key per run.

Before launch, the companion verifies the published archive/binary selection and
creates the target, authority and plan. The authority digest covers its original
JSON bytes. The plan binds interval identity, target path, permitted bytes,
workload/interpreter/binary digests, command and source revision. The consumer
selects the plan digest, reference-source manifest and Ed25519 public key outside
the packet. Retention adds a host-selected digest of the original packet manifest.
These are local operator selections; neither the generated key nor timestamps
prove an independent principal, external freeze or protected custody.

The signed prior commitment contains authorityDigest, beforeRoot, intervalId and
witnessNonce. Its whole-second committedAt precedes the actual launch. openedAt
and sealedAt bracket the native invocation and separate endpoint captures, with
strictly advancing timestamps. The same operator supplies the clock and captures;
the clock is not an independently authenticated time service.

The original schema-v2 trace is retained without rewriting. It must carry complete
true, no warnings, successful command outcome, ordered unique sequences, one root
exec matching the declared interpreter, an earlier same-process read of the
declared workload and one same-process file_descriptor_access/write for the target.
The Alpha.5 release-source `linux_ptrace.rs` emits this fd event only for a positive
syscall result; its source and the raw event model are retained byte-for-byte in
vendor/execsurface. Schema v2 does not carry the actual write count. Nine-byte
content comes from the separate snapshots and declared workload, not from
inventing an event field. No causal code provenance or absent intermediate write
is asserted. The publication's release tag associates source and binary; this
experiment does not reproduce the Rust build.

State roots are SHA256 over compact sorted-key UTF-8 JSON of exactly:

```json
{"algorithm":"probity-single-file-state-v1","entries":[{"path":"ABSOLUTE_TARGET_PATH","sha256":"CONTENT_SHA256","size":9}]}
```

The root is neither the content digest alone nor an event-stream digest. This
declared one-path algorithm is not a filesystem-wide Merkle tree or a custody
claim. The carried write binds these before/after roots and the literal path. The
ObservedEffect subject has exactly one member naming the after root. authority,
interval, code digest, roots, write, commitment and DSSE payload are joined to the
selected plan and original snapshots before invoking the unmodified Vectors
reference `verify()` with the selected key and workload code digest.

The constructed predicate is voluntary/peer/log-import/software-only. Its
scopeComplete stays false and gaps names the declared target: endpoint snapshots
do not establish full interval observation. The report preserves original backend
capabilities/limitations, native complete/outcome/warnings and separately reports
`unknown-no-typed-envelope` collection health. Successful invocation, valid
predicate bytes, publication-policy acceptance and independent effect custody are
distinct conclusions.

After sealing, two extra declared same-byte overwrites run native learn/check.
Their original baseline, explicit default-review policy, stdout/stderr, commands,
outcomes and verdict are retained as a separate calibration. They do not extend
the claimed interval or change its one-write population. PASS is a producer drift
result for that calibration, not authority, collection health or task quality.

Semantic controls reselect altered manifests, so they exercise joins beyond a
simple checksum mismatch. They include changed after root, dropped/repeated trace
write, native incomplete/warning/command failure, omitted gap, promoted import,
missing commitment, changed endpoint bytes, source/key/policy selection, path/process
binding and successful publication versus selected-tier/health refusal. Separate
controls resign predicate mutations and run the real reference verifier, including
subject/root, missing write, missing gap, promoted import, hardware platform and
commitment signature. No generator or disabled-rule mode is used for admission.
