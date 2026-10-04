# AG2 push URL admission and effects

This runs AG2's new URL validator at
[`fd789e3`](https://github.com/ag2ai/ag2/commit/fd789e3ca8a77d14c8e3e89923665fe62c00cb9a)
through JSON-RPC, REST and gRPC. The A2A Python SDK is pinned separately at
[`e649325`](https://github.com/a2aproject/a2a-python/commit/e649325e041e44c0b0fe57e3eef0699cad164a1e).
All 453 installed AG2 and 127 installed SDK Python files must match their Git
blobs before the producer imports either framework. Their source and licenses
stay with the original run packet.

Each case first completes a real native AG2 task using its fixed-text TestConfig.
It then registers a callback URL. The host explicitly calls the unchanged SDK
push sender with that completed task; the callback target has its own acceptance
decision and Observer-backed file write. Raw native callback JSON, protobuf bytes,
stored configs, policy calls, target requests and signed write history remain
separate. A second environment has neither AG2 nor A2A installed; its reader
reconstructs the finite run twice.

| case, repeated across all three transports | stored configs | target callbacks | writes |
| --- | --- | --- | --- |
| allowed registration, dispatch and target | 1 | 1 | 1 |
| registration policy refuses URL | 0 | 0 | 0 |
| dispatch policy refuses stored URL | 1 | 0 | 0 |
| target returns 403 | 1 | 1 | 0 |
| no registration policy, config only | 1 | 0 | 0 |
| SDK policy refuses three internal/file URLs | 0 | 0 | 0 |

The [workflow](../../.github/workflows/ag2-push-authority.yml) installs normal
wheels and the pinned native sources under Python 3.12.14. `requirements.lock`
pins dependency bytes. The source install replaces the SDK registry wheel;
version strings alone do not establish source equality. Sixteen reader controls
include changed task IDs, policy decisions, raw duplicate keys, credentials,
signed history and target effects, with input hashes reselected.

For an original Actions ZIP, verify its recorded digest before extraction.
ZIPs omit empty directories; restore each absent `packet/cases/*/*/workspace`
directory before replay. This adds no file bytes. Install `requirements-reader.lock`
and both retained wheels in a new environment. Run the installed reader twice,
using the retained host-policy SHA-256:

```sh
replay/bin/python -I -B -c \
  'from probity_ag2_push.reader import main; raise SystemExit(main())' \
  retained/packet --policy retained/host-policy.json \
  --policy-sha256 RECORDED_SHA256 --output replay-decision.json
```

The raw protobuf bytes are retained; the offline reader checks original JSON
semantics and does not decode the protobuf wire format. JSON-RPC, REST and callback
HTTP use native ASGI transports. gRPC uses a real plaintext loopback listener.
The post-completion sender call, target, keys, witness and readers share one author
operator and PEER custody. No provider inference runs here. The older comparison
pins stay unchanged; the prospective eight-task study remains not started.
