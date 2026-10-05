# Native APS approval and durable local refund records

This consumer checks an exact synthetic refund approval with installed
`agent-passport-system` 7.2.1, then records one local SQLite effect through
Observer's existing ticket gate. It retains separate process attempts,
durable logical admissions and local effects.

The [published APS candidate](https://github.com/agent-passport-system/agent-passport-system/tree/c31d94aad86713ae9b2e4cbc811deeab4b5d91ed/examples/interop/refund-exact-approval)
supplies the motivating exact-refund profile. Its ten original cases pass.
Additional controls reproduce admission after restart and across instances,
and loss of duplicate-member evidence through ordinary JSON parsing.
This is a separately scoped Probity development artifact.

Run from the repository root on Linux, Python 3.12 and Node 20 or 22:

```sh
bash interop/aps-durable-refund-2026-10-05/verify_install.sh ./aps-refund-run
```

The script builds and installs both wheels, installs locked npm bytes, runs
native and hostile controls, retains eight development control captures and runs a
separate installed public reader twice. Private runtime files stay outside
the capture and are removed after the run. [Source selection](source-selection.json)
and [the protocol](PROTOCOL.md) define the inputs, trust and claim limits.
The first completion and approval-reissue captures share one operation.
Counts are per capture and must not be pooled.

The measured effect is a local refund-record row. Merchant legitimacy,
delegation authority, PIC integration, provider execution, outside adoption,
independent operation and independent custody remain unestablished. The
joint APS/PIC workflow retains its separate signer and scope agreements.
