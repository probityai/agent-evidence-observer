# Native Pydantic result recovery

This finite profile resumes a real Pydantic AI deferred tool after its worker
dies following one protected HTTP effect. A new worker authenticates the prior
effect and current target/authority before releasing the retained result.
Recovery never sends another POST.

Nine cases cover valid recovery, revocation, exact expiry, changed grant or
arguments, target key drift, missing/rolled-back store and a missing HTTP journal.
The model is scripted `FunctionModel`, with no provider inference. Keys, clocks
and stores remain under one operator. [Scope and commands](PROFILE.md) describe
the native boundaries, durable bytes and framework-free installed reader.

The earlier Pydantic v0/v1 exhaustion and exception populations remain unchanged.
Complete refusal evidence can be published without admitting a denied recovery.
