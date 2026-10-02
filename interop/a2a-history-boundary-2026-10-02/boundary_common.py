"""Finite population, strict JSON and declared same-operator limits."""

import hashlib
import json
from typing import Any

PROFILE = "probity-a2a-native-history-boundary-v1"
SOURCE_HEAD = "52030cf43f2e96d25949952e385e3b73fe93bc2a"
IMAGE = "public.ecr.aws/docker/library/mysql@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"
NONCLAIMS = [
    "independent-custody",
    "network-server-process",
    "production-authentication",
    "models",
    "all-concurrency-schedules",
    "normative-tck-adoption",
    "producer-acceptance",
    "recurring-adoption",
]
CASES = [
    (f"{kind}-{index:02d}", budget)
    for index in range(10)
    for kind, budget in [("accepted-retry", 1), ("rejected-absent", 2)]
]
SDK_FILES = [
    "src/a2a/server/agent_execution/active_task.py",
    "src/a2a/server/cluster/database_task_store.py",
    "src/a2a/server/cluster/task_store.py",
    "src/a2a/server/request_handlers/default_request_handler_v2.py",
    "src/a2a/server/routes/jsonrpc_dispatcher.py",
    "src/a2a/server/tasks/task_manager.py",
    "src/a2a/types/a2a_pb2.py",
    "uv.lock",
]


def sha(raw: bytes) -> str:
    """Select literal retained bytes."""
    return hashlib.sha256(raw).hexdigest()


def names(pairs):
    """Refuse duplicate object names."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-json-name")
        result[key] = value
    return result


def nonfinite(value):
    """Refuse nonfinite JSON."""
    raise ValueError("nonfinite-json-" + value)


def decode(raw: bytes) -> Any:
    """Read finite uniquely named JSON."""
    return json.loads(raw, object_pairs_hook=names, parse_constant=nonfinite)


def same(left, right, label):
    """Preserve JSON types including integer versus boolean."""
    if isinstance(left, set) and isinstance(right, set):
        left, right = sorted(left), sorted(right)
    if json.dumps(left, sort_keys=True, separators=(",", ":")) != json.dumps(
        right, sort_keys=True, separators=(",", ":")
    ):
        raise ValueError(label)


SOURCE_DIGESTS = {
    "src/a2a/server/agent_execution/active_task.py": "00206df64d77bcd26749abc20d86cb1ead30061c06fe5701ebff8e25e58f8e00",
    "src/a2a/server/cluster/database_task_store.py": "680d5e48c58545a5c570318b396f2ea573087898aad48549f4b768a8fe40b416",
    "src/a2a/server/cluster/task_store.py": "c75dcb36d081526f7a809552dc7bc31630cc5211af9353a634db0c7cbd3173ed",
    "src/a2a/server/request_handlers/default_request_handler_v2.py": "31fe7f23b7086bdd40b7332f17a32a15dadc4b7982912df3d0bb2d90e02e4427",
    "src/a2a/server/routes/jsonrpc_dispatcher.py": "b46a2baa065ba7f8e150b03ffee9bf5864a73bf49a9f9bcece6b2d54d01a0f86",
    "src/a2a/server/tasks/task_manager.py": "fae8ea37c727d44dc41048646fd5030c685228f5ab876920637959d9f61a40a1",
    "src/a2a/types/a2a_pb2.py": "d0aac0be3a3b639b17be3f3c42ac2aab185a10e3d085f38c05410472769483ba",
    "uv.lock": "dcdc91b35a5409ff03c834cd8613799d919249244b737313d5c1117ab3e4ac07",
}
