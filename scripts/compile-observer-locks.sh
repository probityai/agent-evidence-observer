#!/usr/bin/env bash
# Run from the repository root. Keep existing profile versions as constraints.
set -euo pipefail

compile() {
  local input=$1 output=$2
  uv pip compile pyproject.toml "$input" --constraint "$output" \
    --python-version 3.13 --generate-hashes --output-file "$output"
}

compile interop/target-recovery-2026-10-02/requirements.in interop/target-recovery-2026-10-02/requirements.lock
cp interop/target-recovery-2026-10-02/requirements.lock interop/joint-recovery-2026-10-02/requirements-reader.lock
compile interop/pydantic-ai-native-2026-10-02/requirements.in interop/pydantic-ai-native-2026-10-02/requirements.lock
cp interop/pydantic-ai-native-2026-10-02/requirements.lock interop/pydantic-recovery-2026-10-03/requirements.lock
compile interop/pydantic-ai-native-2026-10-02/requirements-reader.in interop/pydantic-ai-native-2026-10-02/requirements-reader.lock
cp interop/pydantic-ai-native-2026-10-02/requirements-reader.lock interop/pydantic-recovery-2026-10-03/requirements-reader.lock
compile interop/haystack-native-2026-10-03/requirements.in interop/haystack-native-2026-10-03/requirements.lock
compile interop/haystack-native-2026-10-03/requirements-reader.in interop/haystack-native-2026-10-03/requirements-reader.lock
compile interop/smolagents-native-2026-10-03/requirements-reader.in interop/smolagents-native-2026-10-03/requirements-reader.lock
