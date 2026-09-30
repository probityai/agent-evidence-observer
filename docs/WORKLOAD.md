# Brokered Python workload

`run-workload OUTPUT SCRIPT [ARGS...]` copies the script before launch and
commits its SHA-256 digest, the before-root, observer source digest, runtime
digests, exact bubblewrap arguments, and expiry. The sandbox mounts the script
and broker socket. It does not mount the watched tree, observer key, history,
or witness state. The script runs with `python3 -I` in separate namespaces.

The script can send one canonical ASCII JSON line to `/broker/write.sock`:

```json
{"contentHex":"68656c6c6f0a","path":"/work/result.txt","requestId":"one"}
```

Each connection gets one response. The host journals accepted writes, exact
retries, and denied requests. A malformed or oversized request records a
coverage gap. `channelCounts` tallies these durable events; it is not a count
of all agent effects. The command seals a complete packet only after a child
exit code of zero, at least one accepted write, no known gap, and an unchanged
broker workspace. Otherwise it keeps an `incomplete` event and no packet.

The workload's stdout and stderr are retained and hashed under the observer
signature, but neither decides the effect count. Each stream is capped at
1 MiB; excess output fails the run. The offline `verify-workload` command
recomputes the journal counts and checks the script, launch policy, raw
output, authority, packet or incomplete event, and pinned signatures. The
included `trusted-keys.json` is a test fixture. Consumers must pin keys from
another source.

This produces a host record for one mediated file-write channel under one
launch configuration. It cannot establish that arbitrary agent actions,
network effects, transient file writes, or a hostile host were observed.
The signed packet remains `PEER`, and the AVE vantage is `artifact`. The
sample script and CI run demonstrate the path; an independent workload and
witness operator are still needed before claiming an external vantage.
