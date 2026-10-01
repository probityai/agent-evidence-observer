"""Check native verdict cores, ratification guards and fixed owner fixtures."""

from __future__ import annotations

import json
import re
import runpy
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

from probity_observer import aae_enforce as kernel
from probity_observer.aae_enforce import (
    RatifyError,
    canonical_bytes,
    enforce_check,
    native_digest,
    ratify,
    ratify_statement,
)

FIXTURES = Path(__file__).parent / "fixtures/aae-enforce"
VECTORS = sorted(FIXTURES.glob("[0-9][0-9]-*.json"))


def _vector(path: Path) -> dict[str, Any]:
    return json.loads(path.read_bytes())


def _mandate(action: Any, constraints=None, disposition="allow") -> dict[str, Any]:
    return {
        "grants": [
            {
                "action_binding": native_digest("action", action),
                "type_fields": ["verb"],
                "disposition": disposition,
                "constraints": [] if constraints is None else constraints,
            }
        ]
    }


def _ratification():
    private = Ed25519PrivateKey.generate()
    mandate = _mandate({"verb": "write-file"}, disposition="hold")
    mandate["principal"] = {
        "did": "did:example:principal",
        "public_key": private.public_key().public_bytes_raw().hex(),
    }
    prior = enforce_check(mandate, {"action": {"verb": "write-file"}})
    statement = ratify_statement(
        prior["core_digest"], "APPROVED", "did:example:principal"
    )
    proof = {
        "mandate": mandate,
        "authority": "did:example:principal",
        "signature": private.sign(statement).hex(),
    }
    return prior, proof


def _refuse(operation, expected: str, caplog, exception=RatifyError) -> None:
    with pytest.raises(exception, match=f"^{re.escape(expected)}$") as caught:
        operation()
    assert str(caught.value) == expected
    assert caplog.records == []


class TestEnforceKernel:
    class TestPassingCases:
        @pytest.mark.parametrize(
            "path",
            [path for path in VECTORS if "error" not in _vector(path)["expected"]],
            ids=lambda path: path.name,
        )
        def test_owner_vector_reproduces_verdict_digest_and_trace(self, path):
            replay = runpy.run_path(
                str(Path(__file__).parents[1] / "examples/aae_replay.py")
            )
            result = replay["replay_vector"](_vector(path))
            assert result["passed"] is True
            assert result["comparisons"]["core_digest"] is True
            assert result["comparisons"]["trace"] is True

        def test_all_26_owner_fixture_bytes_replay(self):
            replay = runpy.run_path(
                str(Path(__file__).parents[1] / "examples/aae_replay.py")
            )
            report = replay["run_replay"](FIXTURES)
            assert (report["passed"], report["total"]) == (26, 26)
            assert report["nativeJwsVectorsRun"] == report["compositionVectorsRun"] == 0
            assert report["issuerAuthentication"] == "not-established"
            assert report["execution"] == "not-tested-by-enforce-vectors"

        def test_ratification_does_not_upgrade_unreplayed_prior(self):
            prior, proof = _ratification()
            result = ratify(prior, "APPROVED", proof)
            assert result["status"] == "RATIFIED"
            assert result["priorEnforcement"] == "not-replayed"

        @given(value=st.integers(min_value=0, max_value=10**15))
        def test_closed_range_includes_both_bounds(self, value):
            action = {"verb": "write-file"}
            constraints = [
                {"type": "range", "field": "amount", "lo": value, "hi": value}
            ]
            result = enforce_check(
                _mandate(action, constraints), {"action": action, "amount": value}
            )
            assert result["verdict"] == "PERMIT"
            assert result["core_digest"] == native_digest("core", result["core"])

        @given(
            text=st.text(
                alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100
            )
        )
        def test_utf8_exact_constraint_uses_exact_bytes(self, text):
            action = {"verb": "write-file"}
            constraints = [{"type": "exact", "field": "value", "value": text}]
            result = enforce_check(
                _mandate(action, constraints), {"action": action, "value": text}
            )
            assert result["verdict"] == "PERMIT"

        def test_enumeration_compares_every_member(self, monkeypatch):
            calls = []
            original = kernel._same

            def counted(left, right):
                calls.append((left, right))
                return original(left, right)

            monkeypatch.setattr(kernel, "_same", counted)
            result = kernel._constraint(
                {
                    "type": "enum",
                    "field": "value",
                    "values": ["first"] + ["other"] * 511,
                },
                {"value": "first"},
            )
            assert result["result"] == "PASS"
            assert len(calls) == 512

        def test_key_order_and_diagnostic_reason_do_not_change_core(self):
            vector = _vector(VECTORS[0])
            inputs = vector["input"]
            baseline = enforce_check(inputs["mandate"], inputs["transaction"])
            reordered = json.loads(json.dumps(inputs, sort_keys=True))
            result = enforce_check(reordered["mandate"], reordered["transaction"])
            assert result["core_digest"] == baseline["core_digest"]
            result["reason"] = "another diagnostic"
            assert native_digest("core", result["core"]) == baseline["core_digest"]

        def test_jcs_uses_utf16_sorting_and_ecmascript_numbers(self):
            value = {"\U0001f600": 1e30, "\ue000": -0.0, "a": 1e-6}
            assert canonical_bytes(value) == rfc8785.dumps(value)
            assert canonical_bytes(value).startswith(b'{"a":0.000001,')
            assert canonical_bytes(value).find("\U0001f600".encode()) < canonical_bytes(
                value
            ).find("\ue000".encode())

    class TestFailingCases:
        @pytest.mark.parametrize(
            "path,expected",
            [
                (VECTORS[23], "prior verdict is not ratifiable"),
                (
                    VECTORS[24],
                    "prev_core_digest must equal the core_digest "
                    "of the record being ratified",
                ),
            ],
        )
        def test_owner_ratification_guards_raise_exact_errors(
            self, path, expected, caplog
        ):
            inputs = _vector(path)["input"]
            _refuse(
                lambda: ratify(
                    inputs["prior_record"],
                    inputs["decision"],
                    inputs["authority_proof"],
                    inputs.get("prev_core_digest"),
                ),
                expected,
                caplog,
            )

        @pytest.mark.parametrize("value", [True, False, 0.5, 1e3, 10**15 + 1])
        def test_range_refuses_boolean_float_and_over_cap_values(self, value):
            action = {"verb": "write-file"}
            constraints = [{"type": "range", "field": "amount", "lo": 0, "hi": 10**15}]
            result = enforce_check(
                _mandate(action, constraints), {"action": action, "amount": value}
            )
            assert result["verdict"] == "DENY"

        @pytest.mark.parametrize(
            "action", [None, False, 1, "write-file", ["write-file"]]
        )
        def test_nonobject_action_is_denied_even_with_matching_digest(self, action):
            result = enforce_check(_mandate(action), {"action": action})
            assert result["verdict"] == "DENY"
            assert result["trace"][-1]["predicate"] == "type_fields"

        def test_signed_stranger_does_not_become_mandate_authority(self):
            prior, proof = _ratification()
            stranger = Ed25519PrivateKey.generate()
            proof["authority"] = "did:example:stranger"
            proof["public_key"] = stranger.public_key().public_bytes_raw().hex()
            proof["signature"] = stranger.sign(
                ratify_statement(prior["core_digest"], "APPROVED", proof["authority"])
            ).hex()
            result = ratify(prior, "APPROVED", proof)
            assert result["status"] == "REJECTED"
            assert result["authority"] is None
            assert prior["verdict"] == "PENDING"

        @pytest.mark.parametrize(
            "change", ["signature", "mandate", "duplicate-did", "did-fragment"]
        )
        def test_ratification_rejects_proof_substitution_and_ambiguous_authority(
            self, change
        ):
            prior, proof = _ratification()
            if change == "signature":
                proof["signature"] = "ff" * 64
            elif change == "mandate":
                proof["mandate"]["extra"] = "changed"
            elif change == "duplicate-did":
                proof["mandate"]["ratification_authorities"] = [
                    proof["mandate"]["principal"]
                ]
                prior["core"]["mandate_digest"] = native_digest(
                    "mandate", proof["mandate"]
                )
                prior["core_digest"] = native_digest("core", prior["core"])
            else:
                proof["authority"] += "#key"
            result = ratify(prior, "APPROVED", proof)
            assert result["status"] == "REJECTED"
            assert result["authority"] is None

        def test_prior_core_substitution_is_caller_error(self, caplog):
            prior, proof = _ratification()
            prior["core"]["trace"] = []
            _refuse(
                lambda: ratify(prior, "APPROVED", proof),
                "prior_record.core_digest does not match its own core",
                caplog,
            )

        def test_missing_mandate_digest_is_caller_error(self, caplog):
            prior, proof = _ratification()
            del prior["core"]["mandate_digest"]
            prior["core_digest"] = native_digest("core", prior["core"])
            _refuse(
                lambda: ratify(prior, "APPROVED", proof),
                "prior_record has no mandate_digest",
                caplog,
            )

        @pytest.mark.parametrize("entries", [None, False, 0, "", {}, [{}], [{}] * 65])
        def test_malformed_or_over_cap_authorities_reject_whole_candidate(
            self, entries
        ):
            prior, proof = _ratification()
            proof["mandate"]["ratification_authorities"] = entries
            prior["core"]["mandate_digest"] = native_digest("mandate", proof["mandate"])
            prior["core_digest"] = native_digest("core", prior["core"])
            result = ratify(prior, "APPROVED", proof)
            assert result["status"] == "REJECTED"
            assert result["authority"] is None
            assert result["trace"][-1]["predicate"] == "authority_in_mandate"

        def test_missing_principal_rejects_named_authority(self):
            prior, proof = _ratification()
            del proof["mandate"]["principal"]
            prior["core"]["mandate_digest"] = native_digest("mandate", proof["mandate"])
            prior["core_digest"] = native_digest("core", prior["core"])
            result = ratify(prior, "APPROVED", proof)
            assert result["status"] == "REJECTED"

        @pytest.mark.parametrize(
            "field,value,expected",
            [
                (
                    "mandate_digest",
                    True,
                    "prior_record core has malformed input digests",
                ),
                (
                    "transaction_digest",
                    1,
                    "prior_record core has malformed input digests",
                ),
                (
                    "prev_core_digest",
                    False,
                    "prior_record core has a malformed predecessor digest",
                ),
                ("grant_index", False, "prior_record core has a malformed grant index"),
                ("trace", [{}], "prior_record core has a malformed predicate trace"),
            ],
        )
        def test_ratification_rejects_malformed_self_digested_prior_core(
            self, field, value, expected, caplog
        ):
            prior, proof = _ratification()
            prior["core"][field] = value
            prior["core_digest"] = native_digest("core", prior["core"])
            _refuse(lambda: ratify(prior, "APPROVED", proof), expected, caplog)

        @pytest.mark.parametrize(
            "change,expected",
            [
                ("version", "prior_record enforce version is not 3.0"),
                ("extra", "prior_record core fields differ from enforce-core 3.0"),
                ("missing", "prior_record core fields differ from enforce-core 3.0"),
            ],
        )
        def test_ratification_requires_exact_prior_profile(
            self, change, expected, caplog
        ):
            prior, proof = _ratification()
            if change == "version":
                prior["core"]["enforce_version"] = "2.0"
            elif change == "extra":
                prior["core"]["extra"] = "unknown"
            else:
                del prior["core"]["trace"]
            prior["core_digest"] = native_digest("core", prior["core"])
            _refuse(lambda: ratify(prior, "APPROVED", proof), expected, caplog)

        def test_substituted_owner_fixture_bytes_are_refused(self, tmp_path, caplog):
            for path in FIXTURES.iterdir():
                if path.is_file():
                    (tmp_path / path.name).write_bytes(path.read_bytes())
            damaged = tmp_path / VECTORS[0].name
            damaged.write_bytes(damaged.read_bytes() + b" ")
            replay = runpy.run_path(
                str(Path(__file__).parents[1] / "examples/aae_replay.py")
            )
            _refuse(
                lambda: replay["run_replay"](tmp_path),
                "AAE fixture bytes differ from the source manifest",
                caplog,
                ValueError,
            )

        @pytest.mark.parametrize("name", ["LICENSE", "NOTICE"])
        def test_substituted_attribution_bytes_are_refused(
            self, tmp_path, caplog, name
        ):
            for path in FIXTURES.iterdir():
                if path.is_file():
                    (tmp_path / path.name).write_bytes(path.read_bytes())
            damaged = tmp_path / name
            damaged.write_bytes(damaged.read_bytes() + b" ")
            replay = runpy.run_path(
                str(Path(__file__).parents[1] / "examples/aae_replay.py")
            )
            _refuse(
                lambda: replay["run_replay"](tmp_path),
                "AAE fixture bytes differ from the source manifest",
                caplog,
                ValueError,
            )

        def test_substituted_owner_manifest_is_refused(self, tmp_path, caplog):
            raw = (FIXTURES / "source-manifest.json").read_bytes()
            (tmp_path / "source-manifest.json").write_bytes(raw + b" ")
            replay = runpy.run_path(
                str(Path(__file__).parents[1] / "examples/aae_replay.py")
            )
            _refuse(
                lambda: replay["run_replay"](tmp_path),
                "AAE fixture manifest differs from the verified owner manifest",
                caplog,
                ValueError,
            )
