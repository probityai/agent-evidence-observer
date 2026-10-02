# Native A2A caller and committed-history boundary

This profile repeatedly runs two selected follow-up outcomes against the exact
A2A Python runtime at `52030cf43f2e96d25949952e385e3b73fe93bc2a` and actual
MySQL 8.0.46. It uses two native request handlers, the SDK's real JSON-RPC
ASGI dispatcher, native versioned stores and a separate readback connection.
The caller boundary is `httpx.ASGITransport` in the same Python process.

The finite matrix has ten fresh tasks for each case:

| Case | Controlled competing commits | Native caller | Committed user history |
| --- | --- | --- | --- |
| `accepted-retry` | One competing writer commits the unchanged existing task before the first save. Native CAS fails once; the native consumer reloads and retries. | Task result | Initial and successful follow-up |
| `rejected-absent` | Two competing writer commits make both native save attempts stale. The native failed-status save also sees its stale version. | Actual native `InternalError`, JSON-RPC `-32603`, `INTERNAL_ERROR` detail | Initial only; rejected follow-up absent |

`ContendedStore` schedules actual native store commits, then calls `super().save`.
It never fabricates an exception, changes history, alters retry policy or treats
an arbitrary failure as `InternalError`. Exact RPC bytes, native caller results,
protobuf task bytes, CAS/error traces, SQL task/version rows, source bytes,
dependencies and measured container limits remain in every retained packet.
The conflict trace is unsigned same-operator instrumentation.

The installed offline reader joins the literal caller outcomes, native protobuf,
independent-connection readback, SQL rows, exact selected source contract and all
20 cases. It has only the selected protobuf/schema dependencies; no A2A SDK,
SQLAlchemy, HTTPX, Starlette or running database. The unchanged native protobuf
schema is distributed with its Apache license and attribution. `host_gate.py`
requires an external pins file and externally digest-selected policy, retains
both child streams and refuses missing populations or stronger scope.

## Reproduce

The [workflow](../../.github/workflows/a2a-history-boundary.yml) gives all install,
container, native-run, installed-reader and host-selection commands. It pins the
SDK commit, native dependencies from the upstream lock, MySQL OCI digest and
reader/test dependencies. The database uses one CPU, 512 MiB, 128 PIDs and only a
loopback port. The complete native run is limited to 120 seconds; each request
is limited to 15 seconds, and the separate reader to 15 seconds.

From this directory, after installing the workflow's requirements and exact
native SDK, run `python -m pytest -q`. Run the native population with the local
fixture DSN in `PROBITY_FIXTURE_MYSQL_DSN`:

```sh
python boundary_run.py --sdk-source /path/to/a2a-python-at-selected-head \
  --mysql-container probity-a2a-history --output fresh-run
probity-read-a2a-history fresh-run --pins-file fresh-run-pins.json
```

The DSN and Docker credentials in the workflow are public, disposable local
fixture values. The runner retains no environment or unrelated file contents.
The public fixture in `results/` is a retained local measured run, not producer
acceptance, normative TCK adoption or outside-project use. Its pins remain
separate from the ZIP. Semantic mutations reselect their changed bytes and must
still refuse absent successful history, invented error identity, false native
retries, SQL mismatches, incomplete populations and stronger scope.

Python PR [#1303](https://github.com/a2aproject/a2a-python/pull/1303) changed the
integration assertion, not the runtime. Its author's 300 MySQL repetitions are
separate evidence. This profile's twenty controlled repetitions do not establish
all possible error/history outcomes or reproduce all 300 concurrent schedules.
An initial missing-version-header attempt and an unpinned PyMySQL 1.2.3 driver
failure were retained during development; the selected protocol header and the
source lock's PyMySQL 1.1.2/SQLAlchemy 2.0.48 were then used for successful runs.

All reports remain `PEER`. They do not assert independent custody, a network
server process, production authentication, models, all concurrency schedules,
normative TCK adoption, producer acceptance or recurring adoption. Existing A2A
Go and TCK owners remain separate. Any executable TCK contribution needs its own
current source, policy, duplicate/ownership review and actual upstream delivery.
