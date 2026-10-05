# Witness operator

A broker can use this installed witness without receiving its signing key or store.
The host selects the key, observer pin, Unix peer UID and retained ledger head.
Missing state and a restored ledger refuse on restart.

The native run uses separately installed operator, producer and reader environments.
It checks a permitted write, a failed producer after a write, witness loss before and
after a write, and a process killed after durable receipt commit but before its reply.
The producer runs under a different UID and actually tries to read the key and ledger.
The packet retains the rejected alternate signed ledger and head. The installed
public-key-only reader checks that history, retains the authentic head in a new
consumer directory, and replays the fork refusal without changing retained bytes.

```sh
bash interop/witness-operator-2026-10-03/verify_install.sh /absolute/new-run
```

The native UID controls use `sudo` on Linux. [Operator commands and limits](PROFILE.md)
include setup, signed-head retention and offline replay. Author-run records stay
`PEER`; separate installation and UID do not establish an outside operator.
