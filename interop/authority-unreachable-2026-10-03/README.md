# Authority at dispatch and observed effects

A runnable companion to the [unreachable-authority publication case](https://git.elibot.ru/agent-bot/aaif-publication-reference/issues/1). It keeps the authorization decision, committed effect, task terminal and publication decision separate.

Twenty-one controlled cases exercise Observer's real local SQLite ticket service, with signed status evidence and exact approved text, media, destination and catalogue bindings. Producer and reader run in separately installed environments. Both remain author-operated, with `witnessScope: PEER`.

```sh
python -m pip install -r interop/authority-unreachable-2026-10-03/requirements.txt
bash interop/authority-unreachable-2026-10-03/verify_install.sh \
  /tmp/authority-reference "$(git rev-parse HEAD)"
```

Supply the captured Alakris `publication_jobs.py` as a third argument to also execute its two fingerprint functions on six controlled inputs. The script verifies the publisher's SHA-256 before compiling those functions. Their body, title and media-reference checks detect changes; packaging, destination and media bytes behind the same reference remain outside that fingerprint. This is bounded source-function execution, without running the full application or its original tests.

The [workflow](../../.github/workflows/authority-unreachable.yml) retains native databases, signed records, reader output, wheel hashes and test results. The reader consumes selected public-key pins and reads native rows independently of the agent's returned answer.

One result to inspect first: `effect-committed-response-lost` retains a committed row and a failed task. Publication stays blocked. `same-request-retry` retains one effect after two calls; `incomplete-proof-after-effect` retains the observed row while rejecting publication. `binding-veto-override-attempt`, `revoked-authority-superseded-evidence` and `authority-source-unreachable` stay blocked although the executor holds a valid prior grant.

[CONTRACT.md](CONTRACT.md) gives the proposed comparison record, case coverage and implementation boundaries. It is an input to discussion of [AAIF issue 5](https://github.com/aaif/wg-identity-and-trust/issues/5), not an adopted WG format.
