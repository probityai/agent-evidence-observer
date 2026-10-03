# Native ControlArena publication profile

This framework-free reader supports one declared ControlArena echo/submit plan:
alpha/beta × epochs 1/2, honest policy, the default react scaffold and Inspect
0.3.257. It understands native ControlArena solver, submission-store and nested
span events. It does not reuse the plain Inspect reader's grammar.

The [workflow](../../.github/workflows/control-arena-native-reader.yml) pins the
[native host source](https://github.com/astrogilda/control-arena/commit/7c0ebaa21c9d59d146c0eafcf7d6938734e8e430).
It installs a byte-selected wheel into a separate environment **before** running
the host, freezes source/population/version/time selection, then independently
hashes the original `.eval` and JSON export. The installed reader publishes only
the complete selected log. Raw logs and unsuccessful attempts stay outside Git.

See [execution and grammar](EXECUTION.md) for reproduction, trust selection,
native timing precision and refusal controls. Publication is **PEER** log
evidence. It does not establish model quality, external target effects,
independent key/clock/store/retention custody, producer acceptance, recurring
outside adoption or support for other native plans.
