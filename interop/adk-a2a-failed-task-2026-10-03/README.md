# Native ADK/A2A task failure and effects

Run a plain A2A server through ADK's public RemoteA2aAgent and Runner, with a signed target write before FAILED. The installed offline reader preserves both the write and the failure, and publishes only the matched COMPLETED controls.

```bash
git clone https://github.com/google/adk-python.git vendor-adk-baseline
git -C vendor-adk-baseline checkout 63aed55113d4fe78245d3d6667b6e87569888bf5
git clone https://github.com/ferponse/adk-python.git vendor-adk-proposed-fix
git -C vendor-adk-proposed-fix checkout 23d253f2587ac090412394fe1a71ef5694fe2eda
bash interop/adk-a2a-failed-task-2026-10-03/verify_install.sh \
  /tmp/adk-a2a-failure vendor-adk-baseline vendor-adk-proposed-fix
```

Requires Python 3.12 and uv. [PROFILE.md](PROFILE.md) gives the source pins, controls and exact scope. [.github/workflows/adk-a2a-failed-task.yml](../../.github/workflows/adk-a2a-failed-task.yml) runs the same command and retains native transport bodies, session events, signed effects, installed wheels and reader reports.
