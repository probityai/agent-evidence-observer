# Native Haystack publication and dispatch consumer

This profile gates native Haystack 3.3.0 tool writes and publishes verified evidence.
It is for hosts that use `Pipeline`, `Agent`, and `Tool`.
The source package depends on `agent-evidence-observer==0.0.1`.

From a selected source checkout, run the complete installed verification:

```sh
bash interop/haystack-native-2026-10-03/verify_install.sh /tmp/haystack-verification
```

The command builds two wheels, installs a separate reader without Haystack,
runs the native controls, and writes a report plus one released record.
This source profile is version 0.0.1; no package-index release or outside adoption is claimed.

| Document | Job |
|---|---|
| [Contract](PROFILE.md) | Native population, source selection, effect and publication boundaries |
| [Producer](probity_haystack/producer.py) | Actual Haystack pipeline and signed broker dispatch |
| [Reader](probity_haystack/reader.py) | Framework-free retained evidence verification |
