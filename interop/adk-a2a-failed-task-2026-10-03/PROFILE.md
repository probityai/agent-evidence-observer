# Selected native contract

ADK baseline is google/adk-python at 63aed55113d4fe78245d3d6667b6e87569888bf5. The proposed fix is ferponse/adk-python at 23d253f2587ac090412394fe1a71ef5694fe2eda, the source of google/adk-python PR #7398. Both report version 2.11.0. Each selection enumerates all 778 Python files from its immutable Git tree. A2A SDK 1.2.1 has 127 Python files, byte-identical between its selected release wheel and a2aproject/a2a-python v1.2.1 at 041c17bbe8d5ced7a8f6c48761152ce01ffbfc14. Dependency versions and hashes are locked separately.

Three environments install built wheels: the baseline producer, proposed-fix producer and offline reader. The reader installs neither ADK nor A2A. Before importing either SDK, each producer qualifies every selected installed Python file, refuses unlisted importable source, symlinks, bytecode and compiled-module overrides, and retains the native, broker and profile source bytes. The reader authenticates this retained population against its installed core/profile and packaged primary SDK source hashes.

The server uses native AgentExecutor, TaskUpdater, InMemoryTaskStore and JSONRPC/SSE routes. The client uses native ClientFactory, RemoteA2aAgent and Runner. Exact ASGI HTTP body chunks are retained before the client reads them. ASGITransport runs this native serialization, parsing and conversion path locally without sockets or external credentials; it buffers the server response before caller iteration.

| Case | Modes | Signed writes per mode | Remote task | Caller closure | Publication |
| --- | --- | ---: | --- | --- | --- |
| permit | streamed, nonstreamed | 1 | COMPLETED | complete | RELEASE |
| failed-before | streamed, nonstreamed | 0 | FAILED | complete | WITHHOLD |
| failed-after | streamed, nonstreamed | 1 | FAILED | complete | WITHHOLD |
| failed-after-bare | streamed, nonstreamed | 1 | FAILED | complete | WITHHOLD |
| status-after-content | streamed, nonstreamed | 1 | FAILED | complete | WITHHOLD |
| dropped-closure | streamed | 1 | FAILED | caller stops at WORKING | WITHHOLD |

Each source pin runs 11 native tasks and commits nine signed writes: 22 tasks and 18 writes total. Each pin has two matched permit controls. The failed-before controls preserve a grant with no committed effect. The failed-after cases preserve the write, rather than inferring rollback from FAILED. The status-after-content case emits working text "done" before FAILED. The dropped-closure control closes the caller generator after that working text; the separately retained ASGI wire still includes the server's FAILED terminal event. This is a caller-capture interruption, not a server-side crash or interrupted network transport.

At baseline every failed task has error_code and error_message set to None. The proposed fix marks the eight complete failed tasks with A2A_TASK_FAILED. For a bare streamed failure it uses "Remote A2A task failed". For a bare nonstreamed failure the native converter retains "working" from task history, and the proposed fix uses that content as error_message. The reader preserves this distinction. In both versions, WORKING content can have is_final_response() equal to True; that flag alone does not establish terminal task success.

The external host policy selects keys, exact requests, source bytes and original native artifacts. The reader requires its explicit SHA-256, verifies signed requests, target contents and peer witness checkpoints, checks complete transport/task identities and event/session ordering, and retains all failed effects in its report. The published result contains only permit rows. Report and publication JSON are unsigned summaries of signed effect packets.

This profile uses a plain non-ADK A2A server, so its native responses take ADK's legacy conversion handler. It does not claim coverage of the integration-extension v2 handler, task mode, a2a-sdk 0.3.x, provider inference, network timing, independent effect custody, producer acceptance or recurring outside adoption. Witness scope remains PEER, and the core doesNotAssert limits are unchanged. Interpreter, installed metadata and dependency packages remain trusted.
