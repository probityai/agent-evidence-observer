# AG2 push URL qualification

[Run the pinned profile](../interop/ag2-push-authority-2026-10-04/README.md).
It keeps registration admission, stored configuration, dispatch screening,
callback acceptance and observed writes distinct across three native transports.

The SDK sender's `None` return is not a delivery receipt. A target can receive a
callback, return 403 and leave the observed workspace unchanged. A deployment can
also retain the legacy no-policy registration behavior without sending anything.
The retained raw requests and signed effects let the offline reader check these
boundaries without installing either SDK.

Every native task uses AG2's fixed public TestConfig. The host dispatches after
task completion through the SDK's sender; it does not claim automatic native task
callbacks. HTTP uses in-process ASGI transports and gRPC uses plaintext loopback.
This is a finite source qualification with author-operated PEER custody.
