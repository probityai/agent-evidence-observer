# CrewAI native job fences and body effects: technical reference

Read the [worked example](../CREWAI-JOB-FENCES.md) for the problem and outcome.
This reference retains the exact source, recorded checks, and evidence boundary.

The profile at [crewai-job-fences-2026-10-04](../../interop/crewai-job-fences-2026-10-04/) runs the experimental job API at [738c8e19e35c2888d8e0663bc5cc45c5acf6ac2d](https://github.com/crewAIInc/crewAI/commit/738c8e19e35c2888d8e0663bc5cc45c5acf6ac2d). All 529 CrewAI, 28 core and 81 CLI Python files are selected by their original Git blobs before SDK imports. Installation uses the publisher's retained uv.lock. The installed producer and SDK-free reader are separate environments.

Seventeen direct calls check ownership, revision, attempt, duplicate and regressing sequence, stage ordering, typed outputs, immutable inputs and lifecycle fields, post-terminal refusal and strict boolean admission. A sequence gap is accepted by the pinned native contract. The cases retain original model JSON bytes, caller inputs, native return values and complete before/after state. The pinned serializer adds error:null when the caller omits error; the reader binds exactly that native default and refuses non-null or missing materialization.

Three actual JobRunner/JobWorkFlow executions separate the valid path, a stale-revision refusal before a body call, and a stale-revision refusal after a body effect. The public file write goes through the installed Observer broker at [8c074d7b](https://github.com/probityai/agent-evidence-observer/commit/8c074d7b8f380dd01fd55277b68a37ad8217c8cb). Source-selected callbacks, worker receipts, final files, signed histories and prior commitments are retained. A rejected output commit does not roll back an earlier file write.

The conversational flow makes one explicit foreground status turn after each job settles. Raw state immediately before that turn distinguishes committed job outputs from published messages. The reader binds the exact foreground input, native return, complete pre/post state transition and all seven serialized message fields, including four null defaults and empty metadata. The profile makes no model or provider calls; SDK telemetry is disabled using its supported configuration, and native execution has no network authority.

The reader verifies selected bytes, callback ordering, call-to-effect joins and signed histories twice in an environment without CrewAI. Thirty semantic controls mutate and reselect evidence hashes; structural or semantic mismatches still fail admission.

The normally installed [Verify event_absence/v1 adapter](https://github.com/probityai/probity-verify/tree/e835ce2bd6a960e7a1cc2fa6522f16d55dce728a) evaluates the absence of a body effect in each finite worker interval. The valid and effect-before-refusal observations contain a body effect, while the refusal-before-body path contains none. Each decision runs twice, followed by event-present, unknown-coverage and malformed-input controls. Its source, wheel, derivation and literal decision bytes are retained separately from the job reader.

The [workflow](../../.github/workflows/crewai-job-fences.yml) contains exact setup and replay commands. Its original artifact includes setup logs, the publisher lock, all selected native source files, normal installation probes, before-run plan, original callbacks and effects, two reader decisions, controls and actual Verify decisions. A failed first attempt remains an original; later correction runs use new run IDs and artifacts.

The operator, keys, witness and storage are Probity author-operated PEER work. These finite source qualifications leave the historical 16-row native comparison and unstarted prospective eight-task implementation-owned run unchanged.
