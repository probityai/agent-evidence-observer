# Installed run-selection results

The installed profile passed on October 4, 2026. The full core suite passed
1,301 tests in 63.42 seconds. Statement coverage was 100% for `run_selection.py`
and 99% for `selection_profile.py` (290 of 292 combined statements). The two
uncovered statements are the executable module entry. The installed producer and
reader subsequently invoked that entry successfully.

The wheel's two source modules match the retained source digests and current
implementation bytes. The native packet's 57 file-size/SHA-256 assertions pass.
Two separate installed-reader invocations return identical bytes.

| Control | Actual result |
| --- | --- |
| Positive selected run | `selected-history-consistent`, sequences 1–3 |
| Substituted configuration or control | Refused: selected inputs differ |
| Late commitment or fork under the same key | Refused: retained opening does not bind history |
| Multiple candidates or unsupported event | Refused: finite run sequence differs |
| Missing opening | Refused: missing checkpoint |
| Missing history | Refused: checkpoint outside supplied history |
| Omitted history suffix | Refused: missing execution finish |

The candidate-shopping trace executes both pinned checker/configuration/control
sets: one passes, one fails, and the producer chooses the passing candidate after
observing both. Both attempt sets pass the earlier record-consistency reader.
The signed candidate receipts do not establish a unique prior selection.

The actual local runtime interval was 21:20:21.011267–21:20:21.110194 UTC. Assessment
timestamps are synthetic fixture values. The key was created in the producer's
local process; independent custody, globally unique selection, trusted real-time
precedence and execution truth remain unestablished. No registered study ran.

[Provenance](retained/PROVENANCE.json) records the executed local snapshot,
native artifact digest, implementation agent, operator and scope.
[Native manifest](retained/native/manifest.json), [producer results](retained/producer-report.json),
[reader result](retained/reader-report.json), [coverage](retained/coverage.json) and
[test results](retained/core-tests.xml) retain the evidence.

Reproduce with the [installed profile](verify_install.sh). See the
[protocol and scope](../../docs/WITNESSED-RUN-SELECTION.md) before interpreting a pass.
