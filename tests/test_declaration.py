"""Declaration, observed-artifact and exact-effect comparisons stay separate."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from hypothesis import given
from hypothesis import strategies as st

from probity_observer.authorization import (
    ActionRequest,
    GrantPolicy,
    issue_grant,
    verify_grant,
)
from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.declaration import (
    MAX_PAYLOAD_BYTES,
    EffectObservation,
    RuntimeObservation,
    check_crosswalk,
    project_cose_manifest,
    project_manifest,
    sha256_bytes,
    tool_catalog_digest,
)

EXAMPLE = Path(__file__).parents[1] / "examples/declaration_demo.py"
SPEC = importlib.util.spec_from_file_location("declaration_demo", EXAMPLE)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)
reference_manifest = DEMO.reference_manifest
run_demo = DEMO.run_demo


def _payload(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True).encode()


def _project(manifest: dict):
    payload = _payload(manifest)
    return project_manifest(payload, expected_sha256=sha256_bytes(payload))


@pytest.fixture
def manifest() -> dict:
    return reference_manifest()[0]


@pytest.fixture
def context(manifest: dict) -> dict:
    projection = _project(manifest)
    request = ActionRequest(
        "run-1",
        "attempt-1",
        "request-1",
        "tenant-a",
        manifest["agent_id"],
        "org.probity.files.replace",
        "/work/report.txt",
        hashlib.sha256(b"expected effect").hexdigest(),
    )
    now = datetime(2026, 10, 1, tzinfo=UTC)
    key = SigningKey.generate()
    grant = issue_grant(
        request, key, issued_at=now, expires_at=now + timedelta(minutes=5)
    )
    action = verify_grant(grant, request, GrantPolicy(key.public_hex), now=now)
    runtime = RuntimeObservation(
        manifest["agent_id"],
        manifest["agent_instance_id"],
        projection.payload_sha256,
        projection.artifact_hashes,
        projection.model_version,
        projection.model_hash,
        "run-1",
        "same-operator-test-fixture",
    )
    effect = EffectObservation(
        request.run_id,
        request.attempt_id,
        request.request_id,
        request.target_path,
        request.content_sha256,
        "same-operator-target-readback",
    )
    return {
        "projection": projection,
        "runtime": runtime,
        "action": action,
        "effect": effect,
    }


class TestManifestProjection:
    class TestPassingCases:
        @pytest.mark.parametrize("version", ["0.1", "0.2"])
        def test_native_versions_map_without_claiming_authentication(
            self, manifest: dict, version: str
        ) -> None:
            manifest["version"] = version
            projected = _project(manifest)
            assert projected.version == version
            assert projected.tool_ids == ("org.probity.files.replace",)
            assert projected.agent_instance_id == "fixture-instance-1"

        def test_empty_catalog_is_distinct_from_absent_catalog(
            self, manifest: dict
        ) -> None:
            catalog = manifest["artifacts"]["tool_manifest"]
            catalog["tools"] = []
            catalog["catalog_hash"] = tool_catalog_digest([])
            assert _project(manifest).tool_ids == ()
            del manifest["artifacts"]["tool_manifest"]
            assert _project(manifest).tool_ids is None

        def test_native_two_tool_vector(self) -> None:
            tools = [
                {
                    "tool_id": "com.example.read_customer_record",
                    "schema_hash": "sha256:" + "aa" * 32,
                    "description_hash": "sha256:" + "bb" * 32,
                },
                {
                    "tool_id": "com.example.send_notification",
                    "schema_hash": "sha256:" + "cc" * 32,
                    "description_hash": "sha256:" + "dd" * 32,
                },
            ]
            expected = (
                "sha256:"
                "afd1d90ec5aa07f31ae20ab040a04652c76f3078c4d0434de2a17b0cb61c40dd"
            )
            assert tool_catalog_digest(tools) == expected
            assert tool_catalog_digest(list(reversed(tools))) == expected

        def test_owner_cose_payload_is_projectable_but_has_no_action_tool(self) -> None:
            vector = json.loads(
                (
                    Path(__file__).parent / "fixtures/declaration/AM-VEC-COSE-001.json"
                ).read_bytes()
            )
            payload = bytes.fromhex(vector["expected"]["cose"]["payload_hex"])
            projection = project_manifest(
                payload, expected_sha256=vector["expected"]["cose"]["manifest_hash"]
            )
            assert projection.tool_ids is None
            assert projection.agent_instance_id is None
            assert projection.model_attestation_type is None
            assert (
                check_crosswalk(projection, runtime=None, action=None, effect=None)[
                    "outcome"
                ]
                == "incomplete"
            )

    class TestFailingCases:
        def test_native_signature_refusal_is_normalized(
            self, monkeypatch, caplog
        ) -> None:
            def invalid_signature(envelope: bytes, keys: dict):
                raise InvalidSignature

            monkeypatch.setitem(
                sys.modules,
                "agent_manifest",
                SimpleNamespace(verify_cose_manifest=invalid_signature),
            )
            envelope = b"unit-refusal-control-not-a-native-vector"
            with pytest.raises(
                VerificationError, match="native COSE signature is invalid"
            ):
                project_cose_manifest(
                    envelope, expected_sha256=sha256_bytes(envelope), trusted_keys={}
                )
            assert "native COSE signature is invalid" in caplog.text

        def test_changed_payload_cannot_choose_its_expected_pin(
            self, manifest: dict, caplog
        ) -> None:
            payload = _payload(manifest)
            with pytest.raises(
                VerificationError, match="differs from the expected pin"
            ):
                project_manifest(payload + b" ", expected_sha256=sha256_bytes(payload))
            assert "differs from the expected pin" in caplog.text

        @pytest.mark.parametrize(
            "value",
            [
                b"",
                b"{}",
                b"[]",
                b"null",
                b"\xff",
                b'{"version":"0.2","version":"0.1"}',
                b'{"version":NaN}',
            ],
        )
        def test_invalid_payload_never_maps(self, value: bytes) -> None:
            with pytest.raises(VerificationError):
                project_manifest(value, expected_sha256=sha256_bytes(value))

        @pytest.mark.parametrize(
            "field", ["manifest_id", "agent_id", "agent_instance_id"]
        )
        def test_control_character_identity_is_refused(
            self, manifest: dict, field: str
        ) -> None:
            manifest[field] += "\n"
            with pytest.raises(VerificationError, match="control character"):
                _project(manifest)

        @pytest.mark.parametrize("version", ["0.3", "main", None, False, {}, []])
        def test_unsupported_version_is_refused(self, manifest: dict, version) -> None:
            manifest["version"] = version
            with pytest.raises(VerificationError, match="unsupported"):
                _project(manifest)

        def test_payload_limit(self) -> None:
            payload = b" " * (MAX_PAYLOAD_BYTES + 1)
            with pytest.raises(VerificationError, match="byte limit"):
                project_manifest(payload, expected_sha256=sha256_bytes(payload))

        def test_depth_limit(self, manifest: dict) -> None:
            manifest["extra"] = [[[[[[[[[[[[["deep"]]]]]]]]]]]]]
            with pytest.raises(VerificationError, match="structural limits"):
                _project(manifest)

        def test_node_limit(self, manifest: dict) -> None:
            manifest["extra"] = [0] * 2048
            with pytest.raises(VerificationError, match="structural limits"):
                _project(manifest)

        def test_duplicate_tool_is_not_collapsed(self, manifest: dict) -> None:
            catalog = manifest["artifacts"]["tool_manifest"]
            catalog["tools"].append(copy.deepcopy(catalog["tools"][0]))
            with pytest.raises(VerificationError, match="duplicate tool"):
                _project(manifest)

        def test_catalog_entries_are_bound_by_the_root(self, manifest: dict) -> None:
            manifest["artifacts"]["tool_manifest"]["tools"][0]["description_hash"] = (
                "sha256:" + "0" * 64
            )
            with pytest.raises(VerificationError, match="catalog hash differs"):
                _project(manifest)

        def test_provider_assertion_cannot_claim_weight_hash(
            self, manifest: dict
        ) -> None:
            manifest["artifacts"]["model_identity"]["model_attestation_type"] = (
                "provider-asserted"
            )
            with pytest.raises(VerificationError, match="cannot carry a weight hash"):
                _project(manifest)

        def test_unsupported_digest_algorithm_does_not_silently_downgrade(
            self, manifest: dict
        ) -> None:
            manifest["artifacts"]["system_prompt"]["hash"] = "shake256:" + "0" * 64
            with pytest.raises(VerificationError, match="sha256 identifier"):
                _project(manifest)


class TestDeclarationCrosswalk:
    class TestPassingCases:
        def test_exact_local_comparisons_match(self, context: dict) -> None:
            result = check_crosswalk(**context)
            assert result["outcome"] == "matched"
            assert {check["status"] for check in result["checks"]} == {"matched"}
            assert "native validity and custody not established" in result["scope"]

        @pytest.mark.parametrize("missing", ["runtime", "action", "effect"])
        def test_absence_is_incomplete_not_success(
            self, context: dict, missing: str
        ) -> None:
            context[missing] = None
            assert check_crosswalk(**context)["outcome"] == "incomplete"

        def test_valid_empty_runtime_hashes_are_incomplete(self, context: dict) -> None:
            context["runtime"] = replace(context["runtime"], artifact_hashes=())
            result = check_crosswalk(**context)
            assert result["outcome"] == "incomplete"
            assert [
                check["status"]
                for check in result["checks"]
                if check["axis"] == "policy_bundle"
            ] == ["missing"]

        def test_provider_asserted_model_remains_unsupported(
            self, manifest: dict, context: dict
        ) -> None:
            model = manifest["artifacts"]["model_identity"]
            model["model_attestation_type"] = "provider-asserted"
            model["model_hash"] = None
            context["projection"] = _project(manifest)
            context["runtime"] = replace(
                context["runtime"], manifest_sha256=context["projection"].payload_sha256
            )
            result = check_crosswalk(**context)
            assert result["outcome"] == "incomplete"
            assert (
                next(
                    check
                    for check in result["checks"]
                    if check["axis"] == "model-bytes"
                )["status"]
                == "unsupported"
            )

    class TestFailingCases:
        @pytest.mark.parametrize(
            "field,value",
            [
                ("agent_id", "spiffe://other/agent"),
                ("agent_instance_id", "another-instance"),
                ("manifest_sha256", "sha256:" + "0" * 64),
                ("model_version", "other-version"),
                ("model_hash", "sha256:" + "0" * 64),
                ("run_id", "other-run"),
            ],
        )
        def test_wrong_runtime_binding_refuses(
            self, context: dict, field: str, value: str
        ) -> None:
            context["runtime"] = replace(context["runtime"], **{field: value})
            assert check_crosswalk(**context)["outcome"] == "refused"

        @pytest.mark.parametrize(
            "field,value",
            [
                ("run_id", "other-run"),
                ("attempt_id", "other-attempt"),
                ("request_id", "other-request"),
                ("target_path", "/work/other.txt"),
                ("content_sha256", "0" * 64),
            ],
        )
        def test_changed_actual_effect_refuses(
            self, context: dict, field: str, value: str
        ) -> None:
            context["effect"] = replace(context["effect"], **{field: value})
            assert check_crosswalk(**context)["outcome"] == "refused"

        def test_empty_declared_catalog_cannot_authorize_operation(
            self, manifest: dict, context: dict
        ) -> None:
            catalog = manifest["artifacts"]["tool_manifest"]
            catalog["tools"], catalog["catalog_hash"] = [], tool_catalog_digest([])
            context["projection"] = _project(manifest)
            assert check_crosswalk(**context)["outcome"] == "refused"

        @pytest.mark.parametrize(
            "bindings",
            [
                (("policy_bundle", "sha256:" + "0" * 64),) * 2,
                (("unknown", "sha256:" + "0" * 64),),
                (("policy_bundle", "sha256:" + "A" * 64),),
            ],
        )
        def test_ambiguous_observation_is_refused(
            self, context: dict, bindings: tuple
        ) -> None:
            with pytest.raises(VerificationError):
                replace(context["runtime"], artifact_hashes=bindings)

        @given(suffix=st.binary(min_size=1, max_size=64))
        def test_any_changed_effect_bytes_change_the_bound_hash(
            self, suffix: bytes
        ) -> None:
            original = b"expected effect"
            assert sha256_bytes(original + suffix) != sha256_bytes(original)


class TestDeclarationDemo:
    class TestPassingCases:
        def test_retained_demo_uses_actual_broker_effect(self, tmp_path: Path) -> None:
            report = run_demo(tmp_path / "demo")
            assert report["cases"]["matched-local-fixture"]["outcome"] == "matched"
            assert report["native"]["status"] == "not-run"
            assert (
                tmp_path / "demo/workspace/report.txt"
            ).read_bytes() == b"one declaration-linked effect\n"
            assert (tmp_path / "demo/results.json").is_file()
            inputs = json.loads((tmp_path / "demo/action-inputs.json").read_bytes())
            alternate = ActionRequest(**inputs["outsideCatalogRequest"])
            verified = verify_grant(
                inputs["outsideCatalogGrant"],
                alternate,
                GrantPolicy(**inputs["grantPolicy"]),
                now=datetime.fromisoformat(inputs["referenceTime"]),
            )
            assert verified.request.tool_id == "org.other.files.replace"
            retained = json.loads((tmp_path / "demo/file-manifest.json").read_bytes())[
                "fileSha256"
            ]
            actual = {
                path.relative_to(tmp_path / "demo").as_posix(): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in (tmp_path / "demo").rglob("*")
                if path.is_file() and path.name != "file-manifest.json"
            }
            assert retained == actual

    class TestFailingCases:
        def test_existing_output_is_never_overwritten(self, tmp_path: Path) -> None:
            marker = tmp_path / "marker"
            marker.write_bytes(b"keep")
            with pytest.raises(ValueError, match="empty"):
                run_demo(tmp_path)
            assert marker.read_bytes() == b"keep"
