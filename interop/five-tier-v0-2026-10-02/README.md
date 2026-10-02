# Finite five-tier integration breadth v0.1

This additive profile expands the runnable integration population before the October 8 operational v0. It leaves earlier native profiles, the five-tier contract, and the actual SmolLM2 CPU baseline unchanged. The program's evaluation and distribution lanes can use this package as an installed-framework execution/regression starting point.

**Classification: Probity-operated native mock and deterministic integration.** Inspect's real solver/tool/agent loops execute controlled mock responses; SQLite commits and file readbacks are actual local operations. A2A is a fresh actual SDK client/server HTTP exchange. No new real-model quality result, independent judge, outside operator, external authority, custody or adoption is established.

| Target | Frozen declaration | Observed final local run |
|---|---|---|
| Reasoning | 10 author-written arithmetic tasks | 10 native Inspect completions/scored; responses scripted |
| Tools | 12 scenarios, 4 each arithmetic/scoped file/SQLite | 12 native tool runs; original calls/results join to scoped operation records |
| Agents | 3 configurations, arithmetic and file-state families | native use_tools/generate, react with 8-message cap, react with 12-message cap |
| Workloads | 2 finite workflows | file read/write/read; atomic two-row SQLite read/transfer/read |
| A2A | 2 interaction families in unchanged six-attempt child profile | fresh arithmetic request/result and refusal/error/incomplete interactions; child denominators remain separate |
| Controls | task failure, exhausted mock, declared unstarted | one completed task failure, one native harness error, one not-started |

The A2A child retains six declared attempts: five starts, two complete/scored (one pass, one task failure), two errors, one incomplete and one unknown start. Its original reader maps the explicitly unlaunched case to unknown start; this parent preserves that mapping. No denominators or quality scores are pooled across tiers, controls, or the historical actual-model run. Historical SmolLM2 retains its separate 12 attempts and strict 0/12 result.

## Execute and reconstruct

From the repository root:

```sh
python -m pip install -e '.[inspect]' -e 'interop/a2a-native-2026-10-02[test]' pytest==9.1.1 hypothesis==6.168.3
python -m pytest -q interop/five-tier-v0-2026-10-02/tests
# The output folder must not exist. The process-group envelope is an outer limit.
timeout --signal=TERM --kill-after=5s 185s python interop/five-tier-v0-2026-10-02/run.py fresh-v0-run
python interop/five-tier-v0-2026-10-02/run.py fresh-v0-run --verify --pins-file independently-selected-pins.json
```

`manifest.json` is the versioned reference declaration; the runner regenerates the exact declaration and writes it before any native execution. Frozen limits are 180 seconds before another launch, 12 messages/attempt (8 for the corresponding agent), at most three tool calls, zero model-provider calls/dollars/retries, and 32 MiB retained artifacts. The A2A subprocess has at most 30 seconds of the remaining budget; timeout kills its process group. The enclosing 185-second process deadline supplies the hard runtime bound. Dependency installation is outside the declared run budget and has a separate ten-minute CI job ceiling. Runtime/metadata/source/license artifacts describe the actual installed selected frameworks; the resolver's transitive packages are not claimed to be an immutable install lock.

The runner refuses a nonfresh directory. It retains unsuccessful launches and existing original outputs without automatic retries; a task failure is distinct from a harness error. A missing native sample remains unknown start, and declared not-started stays separate. CI must complete installation, tests, native execution, a fresh report, and a separate offline invocation. An incomplete target or missing A2A completion fails the command. Always-upload retention keeps partial outputs when a prior step fails.

The offline reader accepts caller-selected declaration and artifact-index hashes. It reconstructs records from original native logs, checks the frozen model response/call population, solver/config/scorer bindings, call/result joins, exact scoring, and separate local state readbacks. It invokes the unchanged A2A offline reader over original HTTP/native/common bytes with index-bound source/native pins. Rehashing wrapper claims or changing an A2A summary, launch measurement or solver remains refused. Paths, duplicate JSON names, nonfinite values, altered artifact population and externally pinned bytes are checked. The generated adjacent `consumer-pins.json` only supplies a same-operator convenience round trip; copying producer pins does not authenticate a producer or prior commitment.

## Resources and effects

Launch elapsed uses `perf_counter_ns` around the native task launch. Tool CPU measures the invoking thread inside successful owned tool bodies. Original tool elapsed values and Inspect timing remain retained; mock token zeros are left unknown in normalized resources. No whole-process CPU, RSS, worker-thread accounting or cost-comparison claim is supplied. Whole-run installation, startup, file/database initialization and A2A launcher overhead are not isolated model resource measurements.

File tools access one caller-selected path, and SQLite tools access one fixed two-row database per attempt. The tool API does not accept paths, SQL or URLs. Refused transitions leave the original file/balances unchanged; SQLite rolls back both debit and credit on insufficient funds. These bounded fixtures are not an OS security sandbox. Local state matches are same-operator observations, not signed effects or external authorization. Capture remains incomplete, authority and consumer decisions remain unexercised. Protected authority-to-HTTP effects remain in the separate original [Inspect ticket profile](../evaluation-contract-2026-10-01/README.md).

## Retained evidence

`recorded-run.json` identifies the final local report, declaration, original artifact index, resources and separate earlier failures. Raw local packets remain outside Git; the dedicated workflow will retain its own fresh run for 90 days. Local hashes are not a claim that a CI artifact has already been published. The final local reader round trip and 49 pytest/Hypothesis/native mutation controls pass; focused Ruff, Pyright and production cyclomatic complexity at most five pass.

Remaining evaluation work includes real-model breadth beyond the unchanged CPU smoke baseline, meaningful workload/task diversity, authenticated authority for the new file/SQLite fixtures, independently operated runs and maintained outside consumer gates. Passing this package closes integration breadth only. The repository Apache-2.0 license applies; retained Inspect/A2A materials carry their own original license evidence.
