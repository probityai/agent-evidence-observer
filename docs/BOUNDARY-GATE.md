# Linux boundary probe

Run `agent-evidence-observer boundary-probe ./boundary-run` on a Linux host
with bubblewrap, an unrestricted user namespace, Unix sockets, and
`/usr/bin/python3`. The process exits nonzero if the probe fails. A CI job
retains the run directory, including raw stdout and stderr, on either outcome.

The observer signs its authority and before-root before launching the fixed
`probe_agent.py` bytes. Bubblewrap creates separate user, PID, mount, network,
IPC, UTS, and cgroup namespaces, drops capabilities, clears the environment,
and mounts the interpreter runtime read-only. The host resolves output-derived
mount sources to absolute paths before launch. Only the broker's Unix socket
directory is exposed. The watched `/work` tree, the broker process, history,
witness state, and private keys are not mounted.

The fixed workload attempts a direct write, host process memory read, host
process signal, and outbound TCP connection. It also sends a normal write,
exact retry, changed retry, and traversal request through the socket. The
observer checks the durable broker history and resulting file bytes against
that sequence. The negative attempts are reported by the pinned workload; a
second implementation must reproduce them before treating their results as
an independent boundary finding. A controlled workload can lie about its own
negative attempts, even if the broker history is genuine.

`boundary-report.json` has `attempts`, `exitCode`, raw-output hashes,
`status`, `witnessScope`, and `evidence_vantage`. `probe-stdout.bin` and
`probe-stderr.bin` retain the raw results. `launch-policy.json` holds the exact
command, `agent-probe.py` retains the executed workload, and
`boundary-attestation.json` signs the report digest, authority digest, and
terminal history head. Run `verify-boundary DIRECTORY --observer-key KEY
--witness-key KEY` to check the retained bytes. The included public keys are
convenient fixtures; a consumer must pin them elsewhere. A failed launch or
failed probe ends with a witnessed incomplete interval and no packet.

The AVE mapping is `evidence_vantage: artifact`. The prototype's `PEER` is a
different axis and is not an AVE enum value. This probe does not establish an
unsuppressible substrate, independent witness custody, coverage of arbitrary
agents, or the exact dynamic libraries and host kernel used by the interpreter.
It does not promote the packet to `below-observed` or `EXTERNAL`. A failed
probe is evidence of a failed gate, not evidence of no agent effect.

GitHub's Ubuntu runner invokes the boundary probe with `sudo` because its
unprivileged bubblewrap process could not configure the isolated loopback
interface. This elevates the host broker for that ephemeral run; the agent
still runs inside the separate namespaces with capabilities dropped. The
runner's privilege context is part of the launch evidence and does not prove
that the same policy will work rootless on another host.
The runner keeps the socket and probe mount sources under `/tmp`, outside
the checkout path. After the gate, CI copies the signed bundle to the
workspace for retention. The offline reader checks that copy against the
retained bytes and signed digests.

The current restricted execution workspace refuses Unix socket creation, so
the live probe here produced `isolation setup failed` and a verified incomplete
interval. The unit suite exercises host control flow and tamper checks with a
stub server; it does not count as an isolated run. CI runs the real bubblewrap
command and keeps the raw result bundle even when the gate fails.
