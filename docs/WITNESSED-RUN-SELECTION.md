# Witnessed run selection

Two candidate checker/configuration/control pins can both exist before a result.
A producer can then report only the candidate that passes. Timestamped existence
does not select one candidate for execution.

The `probity-evaluation-selection-v1` reader binds one selection for a named run
to a consumer-retained opening checkpoint, a later execution-start event and a
closure of the original evaluation evidence. It reuses the existing
[evaluation plan](EVALUATION-HISTORY.md), hash-chain history and witness checks.

Use one writer per history. Before invoking the checker:

1. Pin the complete `RunPlan` and the original configuration and control bytes.
2. Call `open_run_selection`. Retain its opening checkpoint and configured witness
   public key through the consumer's chosen channel.
3. Call `start_selected_run` with the same plan, original bytes and expected
   operator. It refuses changed selected inputs or operator before dispatch.
4. Execute the selected checker. Retain all attempts, artifacts and source bytes.
5. Call `execution_digest`, then `close_selected_run`. Retain the final checkpoint.
6. Call `verify_selected_history` with both retained checkpoints, the configured
   witness key, expected operator and exact native evidence.

A failure to checkpoint does not authorize execution or an automatic replacement
selection. The reader refuses duplicate selections, late or unknown run events,
different selected inputs, changed closure bytes, missing anchors, omitted history
and forks that conflict with the retained opening. A witness with its original
state also refuses a fork; a fresh signer state does not replace the consumer's
retained opening.

## Run the installed finite profile

From a checkout with Python 3.12 and uv:

```sh
bash interop/witnessed-run-selection-2026-10-04/verify_install.sh /tmp/run-selection
```

The script builds a wheel, installs separate producer and reader environments,
runs the core tests, retains coverage, invokes the installed producer, and reads
the native packet twice from the installed reader. Dependencies are pinned with
hashes. Core and reader locks reuse the existing installed witness profile's pins;
the tool lock adds coverage and Ruff.

The fixture first signs two checker/configuration/control candidates, actually
executes both and picks the passing result afterward. Both native attempt sets
pass the earlier consistency reader. It then runs the selected history protocol
with one positive case and nine hostile controls: substituted configuration,
substituted control, late commitment, multiple candidates, fork, missing opening,
missing history, omitted suffix and unsupported event.

`native/` retains exact checker/configuration/control bytes, plans, attempts,
outputs, candidate receipts, covered histories, consumer checkpoints, results and
a SHA-256/size manifest. The wheel digest and installed runtime/package records
are retained beside it. The finite runner executes only its two bundled checker
sources. The offline reader never executes retained source code.

## Scope and authority

`selected-history-consistent` means one selection and matching closure within
the supplied anchored history for the named run. The result reports exact sequence
coverage and the declared operator. The witness key is a consumer-configured pin;
the reader does not establish who owns that key or the truth of an operator name.

The fixture's UTC dates are declared test values, not trusted execution times.
The report separately records `runtimeStartedAt` and `runtimeEndedAt` from the
local process clock and identifies that clock authority.
The finite profile creates the witness key in the same local process as the
producer. Its reader receives that public key through the local test script.
Separate installations establish a packaging boundary; they do not establish
independent custody. A signer and caller can fabricate a consistent transcript.

Real-time precedence, unique selection across other histories or run identities,
execution truth and independent custody remain `not-established`. Author dates
and signatures do not establish an outside time authority. Stronger deployment
claims require a real operator, externally retained anchors, verified key authority
and the corresponding custody/fault evidence. This is a finite protocol profile,
not a registered study or a new global selection guarantee.

Source: the existing public [evaluation reader](../src/probity_observer/evaluation_history.py),
[history/witness](../src/probity_observer/history.py) and
[witness port](../src/probity_observer/witness_port.py), plus the executable
[candidate-shopping and hostile controls](../src/probity_observer/selection_profile.py)
and the retained installed results.
