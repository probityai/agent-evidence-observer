# Native smolagents publication consumer

Run a source-pinned ToolCallingAgent, retain its actual model attempts and tool forwards, then check the packet with a separately installed reader.

The reader publishes the authorized permit case after checking the signed effect, selected SDK source, native callbacks and terminal state. Eight cases exercise wrong content, errors before and after a write, exhausted steps, a model error, incomplete closure and a final answer without a write.

From the Observer checkout:

~~~bash
git clone https://github.com/huggingface/smolagents /tmp/probity-smolagents-sdk
git -C /tmp/probity-smolagents-sdk checkout c30b115286e000e98711fae5e85993547b73d826
python -m pip install uv==0.8.22
bash interop/smolagents-native-2026-10-03/verify_install.sh \
  /tmp/probity-smolagents-evidence /tmp/probity-smolagents-sdk
~~~

The output directory must be new. The runner builds wheels and creates separate producer and reader environments. The selected dependency locks and actual native bytes are retained with the reports.

Use the installed reader on a saved capture:

~~~bash
evidence=/tmp/probity-smolagents-evidence
policy_sha=$(sha256sum "$evidence/native/host-policy.json" | cut -d' ' -f1)
"$evidence/reader/bin/python" -I -B -m probity_smolagents.reader \
  "$evidence/native/packet" \
  --host-policy "$evidence/native/host-policy.json" \
  --policy-sha256 "$policy_sha" --publish /tmp/probity-smolagents-publication
~~~

The host policy stays outside the packet. Publication requires a new directory outside the packet. See [PROFILE.md](PROFILE.md) for the finite contract and trust boundaries.

