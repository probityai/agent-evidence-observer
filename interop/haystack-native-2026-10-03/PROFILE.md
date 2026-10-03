# Haystack native reference profile v0

Haystack 3.3.0 comes from the official release whose tag resolves to
`daa2d1ffacd083dcb1fc9a455adf541360a9e09c`. Its `Agent` invokes tools directly.
This profile uses the current APIs without a standalone `ToolInvoker` compatibility path.
Producer and reader dependencies have separate hash locks.

Every case runs a real `Pipeline`, `Agent`, `Tool`, and framework tracer.
The chat generator supplies scripted replies. These are runtime fault controls,
not model quality measurements. No provider or model inference runs.

| Case | Scripted generator calls | Native tool calls | Committed writes | Publication |
|---|---:|---:|---:|---|
| permit | 2 | 1 | 1 | release |
| wrong-content | 2 | 1 | 0 | withhold |
| error-before | 2 | 1 | 0 | withhold |
| handled-after | 2 | 1 | 1 | withhold |
| unhandled-after | 1 | 1 | 1 | withhold |
| max-steps | 1 | 1 | 1 | withhold |
| length | 1 | 0 | 0 | withhold |

The host issues an exact signed file-write grant before it starts the pipeline.
The tool checks the grant and exact bytes through `AuthorizedBroker` before dispatch.
The bounded broker records and signs the durable file transition. A failure after
the write cannot erase that effect from the retained history. A handled tool error
and a successful final model message remain distinct. Step exhaustion and response
truncation withhold publication even when their framework call returns normally.

The tracer records native operation names, declared scalar tags, ancestry, exceptions,
and span closure. Content tags are deliberately omitted and listed. The producer
retains the actual model input/output messages separately. It preserves trace ancestry
through context variables, including Haystack tool worker threads, and restores the
previous tracer after each run. This finite reference runs one tool per step;
concurrent independent tool semantics are outside this measured population.

Before native execution, the producer saves every installed Python source file from
Haystack, this profile, and Observer. The host policy pins this complete source manifest,
the native artifact bytes, action identity, issuer/observer/witness keys, and historical
reference time. The reader receives the policy separately with an explicit SHA-256 pin.
Candidate-provided keys or a candidate-selected manifest do not establish trust.

The installed reader has no Haystack dependency. It authenticates the signed grant,
prior commitment, history, claim, and witness checkpoints. It compares current retained
workspace bytes, native messages and tool errors, call populations, trace closure and
ancestry, and terminal state. `--publish NEW_DIRECTORY` first checks the whole population,
then writes only the released record. Refusal creates no publication directory.
Raw retained evidence includes negative cases so future readers can repeat the controls.

This is a local reference with `PEER` witness scope. One test operator controls all
keys, the workspace, and the clock. Separate keys and processes do not establish
independent effect custody, hostile-process isolation, complete capture, external
producer acceptance, scheduled host adoption, or general model reliability.
The native broker's `doesNotAssert` fields remain unchanged.

Primary sources: the [native Agent source](https://github.com/deepset-ai/haystack/blob/daa2d1ffacd083dcb1fc9a455adf541360a9e09c/haystack/components/agents/agent.py),
the [native tracer interface](https://github.com/deepset-ai/haystack/blob/daa2d1ffacd083dcb1fc9a455adf541360a9e09c/haystack/tracing/tracer.py),
and the [official 3.3.0 release metadata](https://pypi.org/pypi/haystack-ai/3.3.0/json).
