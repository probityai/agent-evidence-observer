# Selected native deferred-tool recovery

The profile uses Pydantic AI 1.68.0, native `DeferredToolRequests`, exact native
message serialization and `DeferredToolResults`. A first real Agent creates one
typed deferred tool call. Its worker fsyncs the native history and request before
the selected protected HTTP dispatch. That dispatch commits revision one in the
actual signed SQLite target. The worker then calls `os._exit(74)` before native
result continuation. The parent records its PID, argv, environment and actual
exit. The target process also exits. Its replacement reopens the retained store
against the signed history head.

A fresh second worker checks the separately supplied host selection. It joins
the prior authenticated HTTP effect, original typed call and current signed GET
to the exact grant, policy, service key and selected clock. Only this admission
creates an accepted host receipt. Only that receipt can enter native
`DeferredToolResults` under the original tool-call ID. Recovery uses no POST.
The grant was spent on the original dispatch. Its current validity gates result
release rather than authorizing another effect.

The frozen population has nine cases and 18 workers/18 targets. Each first
worker commits one bounded local effect and hard-exits. The sole valid case
resumes the native Agent and retains its new native tool return and text output.
The eight refusal cases preserve the historical revision-one effect and withhold
the native result.

| Case | Recovery boundary |
| --- | --- |
| permit | Reopen actual state, authenticate live authority and release the exact prior result |
| revoked | Durable target revocation refuses release while retaining the old signed effect |
| expired | The current clock equals the grant's exact UTC expiry and refuses release |
| changed-grant | A different current signed-grant object refuses before native resume |
| changed-arguments | A recovered call differs from the frozen typed content and refuses |
| target-key | Actual target startup refuses a different service key |
| missing-store | Actual target startup refuses absent native state |
| rollback-store | Actual target startup refuses state older than the retained signed history head |
| crash-window | Worker exits after commit but before durable HTTP-journal write. Parent readback preserves the effect, but recovery refuses missing original HTTP evidence |

Original native history stays separate from the selected recovery history. The
changed-argument case retains both. Private key files exist only in the parent's
separate host directory, never in the public packet. The parent deletes them
after cleanup. Owned children get an explicit environment allowlist and disabled
tracing. The original packets retain process records, native SQLite snapshots,
exact HTTP bytes, selected sources, dependency selection and current host
receipts. The offline reader imports no agent framework and executes no packet
code. It opens SQLite in immutable read-only mode with query-only, untrusted
schema and a finite instruction limit. Required final signed readbacks preserve
the exact effect body. Revocation is the sole declared final state change.

The installed reader is a separate distribution,
`probity-pydantic-recovery-reader==0.0.1`. Its host gate selects external packet
pins, the entire isolated installation, its interpreter and publication policy
before launch. That closure includes metadata, bytecode and `.pth` surfaces.
The installed modules use the unique `probity_pydantic_recovery` package.
Changing an installed helper refuses even when launcher bytes remain unchanged.
Reader launch clears Python search-path overrides and disables user-site imports.
A hostile inherited `PYTHONPATH` control must leave its execution marker absent.
Repeated reads must produce the same structured report. The host can publish a
complete refusal population. This does not grant permission for a denied action.

## Reproduce

From an isolated Python 3.13 environment, install the selected native dependencies
and exact Observer source. From this profile directory:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --no-deps -e ../..
python -m ruff check recovery_*.py probity_pydantic_recovery tests
python -m ruff check --select C901 --config 'lint.mccabe.max-complexity=5' recovery_*.py probity_pydantic_recovery tests
timeout --signal=TERM --kill-after=5s 180s python -m pytest -q tests
timeout --signal=TERM --kill-after=5s 240s python recovery_run.py fresh-run --source-revision "$(git rev-parse HEAD)" > fresh-report.json
bash verify_install.sh "$(command -v python)"
```

The install script builds normal wheels and creates a separate environment with
no Pydantic AI. It copies selected pins outside the packet, selects the actual
reader closure, runs the host gate twice, compares complete reports and refuses
a changed helper. Workflow output retains these receipts. A new packet path is
mandatory. Existing results never get overwritten.

The controlled model is native `FunctionModel`, with zero external provider
calls and no measured inference quality. The first run ends at the native
deferral boundary. This profile does not make arbitrary interrupted Python
instructions resumable and does not alter the earlier seven-case Pydantic
exception/exhaustion profile. The selected wall clock is a host fixture clock.
The issuer, target, filesystem, retained source, reader and host policy have one
operator. Service keys do not establish independent custody or caller identity.
Host OS and Python standard library remain local custody assumptions.
Power loss, general exactly-once effects, production containment, producer
acceptance and recurring outside adoption remain separate outcomes.

Native test packets are transient controls. A later retained original must state
its exact source commit and measured run independently from those controls.
GitHub artifacts have 90-day retention. Durable archive custody needs its own
byte/member readback receipt.
