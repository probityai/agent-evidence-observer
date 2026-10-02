"""Real installed whole-chain and no-dispatch boundary controls.

The workflow requires explicit external ``PROBITY_KIT_INSTALLATION`` and
``PROBITY_KIT_INSTALLATION_SHA256`` selections. These tests never silently skip
the native chain or replace a missing Rust/OPA/HTTP substrate with a mock.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_candidate import prepare_candidate  # noqa: E402
from run_host import execute, require_child, run_child  # noqa: E402
from trust import (HostRefusal, file_binding, read_json, sha256,  # noqa: E402
                   validate_host, write_json)


@pytest.fixture(scope="session")
def selected() -> dict[str, Any]:
    """Require the real ordinary installation and its separately selected hash."""
    path = Path(os.environ["PROBITY_KIT_INSTALLATION"])
    digest = os.environ["PROBITY_KIT_INSTALLATION_SHA256"]
    return {"path": path, "digest": digest, "manifest": validate_host(path, digest)}


@pytest.fixture
def candidate(selected: dict[str, Any], tmp_path: Path) -> Path:
    """Make one independent candidate from the original signed source fixture."""
    result = tmp_path / "candidate"
    prepare_candidate(Path(selected["manifest"]["sources"]), result)
    return result


def run_case(selected: dict[str, Any], candidate: Path, output: Path,
             scenario: str = "completed") -> dict[str, Any]:
    """Execute actual subprocess, crypto, OPA, reader and HTTP boundaries."""
    return execute(selected["path"], selected["digest"], candidate, output, scenario)


def select_policy(selected: dict[str, Any], policy: dict[str, Any], folder: Path) -> dict[str, Any]:
    """Create a separately host-selected policy mutation, never candidate trust."""
    folder.mkdir()
    path = folder / "policy.json"
    write_json(path, policy)
    manifest = copy.deepcopy(selected["manifest"])
    previous = manifest["policy"]
    replacement = file_binding(path)
    manifest["policy"] = replacement
    manifest["selectedFiles"] = [replacement if item == previous else item
                                  for item in manifest["selectedFiles"]]
    manifest_path = folder / "installation.json"
    write_json(manifest_path, manifest)
    return {"path": manifest_path, "digest": sha256(manifest_path.read_bytes()), "manifest": manifest}


def assert_no_dispatch(result: dict[str, Any], caplog: pytest.LogCaptureFixture, reason: str) -> None:
    """Require the exact logged refusal, absent grant, and zero actual HTTP calls."""
    assert result["status"] == "refused"
    assert result["httpDispatchRequests"] == 0
    assert result["reason"] == reason
    assert not any(gate["gate"] == "host-issued-grant" for gate in result["gates"])
    assert "eight-component run retained refusal: " + reason in caplog.text


class TestHostRun:
    """Exercise exact installation gates and native effect/recovery semantics."""

    class TestPassingCases:
        @pytest.mark.parametrize("scenario", ["completed", "after-effect"])
        def test_full_native_chain_retains_one_committed_revision(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path, scenario: str,
        ) -> None:
            output = tmp_path / "run"
            result = run_case(selected, candidate, output, scenario)
            assert result["status"] == "measured", result
            assert result["effect"]["nativeRevision"] == 1
            assert result["effect"]["recoveryPostStatus"] == 200
            assert result["httpDispatchRequests"] == 2
            assert result["childProcesses"] == 11
            assert [gate["gate"] for gate in result["gates"]] == [
                "jcs-dsse", "vectors", "admission-opa", "vocabulary", "atlas", "verify",
                "host-issued-grant", "native-effect-readback",
            ]
            assert all(gate["admitted"] for gate in result["gates"])
            assert result["gates"][1]["tiersWithSelectedKeys"] == ["attested"]
            assert result["gates"][1]["tiersWithoutKeys"] == ["unattested"]
            assert result["gates"][4]["originalMembers"] == 110
            assert result["gates"][5]["decision"]["decision"] == "supported"
            assert result["gates"][-1]["result"]["witnessScope"] == "PEER"
            assert result["acceptance"] == result["adoption"] == result["custody"] == "not-established"
            assert result["componentHeads"] == selected["manifest"]["componentHeads"]
            readback = read_json(output / "retained-readback.json")
            assert bytes.fromhex(readback["contentHex"]) == (output / "verified-payload.json").read_bytes()
            first = read_json(output / "target-1.exit.json")
            assert first["returnCode"] == (73 if scenario == "after-effect" else -15)
            assert "general-containment" in result["doesNotAssert"]

    class TestFailingCases:
        @pytest.mark.parametrize("scenario,revision,phase,retry_status,native_reason", [
            ("after-intent", 0, "incomplete", 409, "ticket consumer requires unrevoked bounded completion"),
            ("inside-effect-transaction", 0, "incomplete", 409, "ticket consumer requires unrevoked bounded completion"),
            ("revoked-after", 1, "completed", 409, "ticket consumer requires unrevoked bounded completion"),
            ("expired-after", 1, "completed", 409, "grant is not valid at the reference time"),
            ("rollback-after", 1, "completed", 409, "ticket consumer clock predates completed effect"),
        ])
        def test_native_recovery_refuses_current_authority_without_losing_prior_commit(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture, scenario: str, revision: int,
            phase: str, retry_status: int, native_reason: str,
        ) -> None:
            output = tmp_path / "run"
            result = run_case(selected, candidate, output, scenario)
            assert result["status"] == "refused"
            assert result["reason"] == "verify-effect gate refused or did not complete"
            assert result["effect"]["nativeRevision"] == revision
            assert result["effect"]["phase"] == phase
            assert result["effect"]["recoveryPostStatus"] == retry_status
            assert result["httpDispatchRequests"] == 2
            assert result["gates"][-1]["outcome"] == "refused"
            assert result["gates"][-1]["reason"] == native_reason
            assert "eight-component run retained refusal: verify-effect gate refused or did not complete" in caplog.text
            readback = read_json(output / "retained-readback.json")
            assert readback["revision"] == revision
            assert readback["receipt"]["payload"]["revoked"] is (scenario == "revoked-after")

        def test_signed_retained_head_refuses_database_rollback(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output = tmp_path / "run"
            result = run_case(selected, candidate, output, "store-rollback")
            assert result["status"] == "refused"
            assert result["reason"] == "native HTTP target exited before readiness"
            assert result["effect"]["nativeRevision"] == 1
            assert result["httpDispatchRequests"] == 2
            assert read_json(output / "retained-readback.json")["revision"] == 1
            assert read_json(output / "target-3.exit.json")["returnCode"] != 0
            assert "ticket history predates retained head" in (output / "target-3.stderr").read_text()
            assert "eight-component run retained refusal: native HTTP target exited before readiness" in caplog.text


class TestEvidenceBoundaries:
    """Mutate actual candidate bytes and host selections to prove no dispatch."""

    class TestPassingCases:
        def test_original_raw_bytes_are_not_used_in_place_of_verified_payload(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
        ) -> None:
            output = tmp_path / "run"
            result = run_case(selected, candidate, output)
            assert result["status"] == "measured"
            raw, verified = (output / "raw-aee.json").read_bytes(), (output / "verified-payload.json").read_bytes()
            assert raw != verified
            assert result["gates"][0]["rawSha256"] == sha256(raw)
            assert result["gates"][0]["verifiedPayloadSha256"] == sha256(verified)
            assert result["gates"][1]["payloadSha256"] == sha256(verified)
            envelope = read_json(output / "envelope.json")
            assert base64.b64decode(envelope["payload"]) == verified

    class TestFailingCases:
        @pytest.mark.parametrize("member", ["signature", "run-binding", "missing-class", "false-result"])
        def test_real_vectors_mutants_prevent_grant_and_dispatch(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture, member: str,
        ) -> None:
            statement = read_json(candidate / "raw-aee.json")
            predicate = statement["predicate"]
            if member == "signature":
                signature = predicate["observationRecords"][0]["signatures"][0]["sig"]
                predicate["observationRecords"][0]["signatures"][0]["sig"] = ("A" if signature[0] != "A" else "B") + signature[1:]
            elif member == "run-binding":
                predicate["observationEnvironment"]["runEntropy"]["digest"]["sha256"] = "0" * 64
            elif member == "missing-class":
                predicate["coverage"]["assessedClasses"] = []
            else:
                predicate["result"] = "fail"
            (candidate / "raw-aee.json").write_text(json.dumps(statement))
            result = run_case(selected, candidate, tmp_path / "run")
            assert_no_dispatch(result, caplog, "vectors gate refused or did not complete")
            assert result["childProcesses"] == 3
            if member == "signature":
                assert result["gates"][-1]["validity"] == "valid"
                assert result["gates"][-1]["tiersWithSelectedKeys"] == ["unattested"]

        @pytest.mark.parametrize("anchor", ["expected_corpus_digest", "expected_substrate_digest", "demanded_classes", "accepted_results"])
        def test_real_opa_consumer_obligations_prevent_dispatch(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture, anchor: str,
        ) -> None:
            policy = read_json(Path(selected["manifest"]["policy"]["path"]))
            values = {"expected_corpus_digest": "0" * 64, "expected_substrate_digest": "0" * 64,
                      "demanded_classes": ["absent-class"], "accepted_results": ["fail"]}
            policy["opa"]["consumer"][anchor] = values[anchor]
            changed = select_policy(selected, policy, tmp_path / "host")
            result = run_case(changed, candidate, tmp_path / "run")
            assert_no_dispatch(result, caplog, "OPA consumer admission refused")
            assert result["childProcesses"] == 4
            assert result["gates"][-1]["errors"]

        @pytest.mark.parametrize("mutation,outcome", [
            ("missing-span", "not_established"), ("selected-omission", "contradicted"),
            ("malformed-case", "malformed"), ("self-hashed-source", "not_established"),
        ])
        def test_installed_verify_outcomes_remain_distinct_and_prevent_dispatch(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture, mutation: str, outcome: str,
        ) -> None:
            changed = selected
            case = read_json(candidate / "coverage-case.json")
            if mutation in {"missing-span", "selected-omission"}:
                (candidate / "record.txt").write_text('"outsideRecurringUse": "not-established"\n')
                record = (candidate / "record.txt").read_bytes()
                case["artifacts"]["record"].update(sha256=sha256(record), length=len(record))
                if mutation == "selected-omission":
                    policy = read_json(Path(selected["manifest"]["policy"]["path"]))
                    policy["verify"]["assessments"]["atlas-provenance-nonclaims"]["record_sha256"] = sha256(record)
                    changed = select_policy(selected, policy, tmp_path / "host")
            elif mutation == "malformed-case":
                case["schema_version"] = "unsupported/v1"
            else:
                case["artifacts"]["source"] = case["artifacts"]["record"]
            (candidate / "coverage-case.json").write_text(json.dumps(case))
            result = run_case(changed, candidate, tmp_path / "run")
            assert_no_dispatch(result, caplog, "verify gate refused or did not complete")
            assert result["childProcesses"] == 7
            gate = result["gates"][-1]
            actual = gate.get("outcome") if outcome == "malformed" else gate["decision"]["decision"]
            assert actual == outcome

        @settings(max_examples=8, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
        @given(member=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8))
        def test_duplicate_raw_members_are_refused_before_lossy_json_parsing(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture, member: str,
        ) -> None:
            original = Path(selected["manifest"]["sources"]) / "agent-evidence-vectors/vectors/statements/vcc938c6038536dcb.json"
            raw = original.read_bytes().lstrip()
            prefix = ('{"' + member + '":0,"' + member + '":1,').encode()
            (candidate / "raw-aee.json").write_bytes(prefix + raw[1:])
            output = tmp_path / ("duplicate-" + member)
            if output.exists():
                output = tmp_path / ("duplicate-" + member + "-" + str(len(list(tmp_path.iterdir()))))
            result = run_case(selected, candidate, output)
            assert_no_dispatch(result, caplog, "byte-sign refused or did not complete")
            assert result["childProcesses"] == 1


class TestTrustSelection:
    """Protect host-owned code, installation, sources and key/policy boundaries."""

    class TestPassingCases:
        def test_source_heads_and_installed_component_versions_are_separate(
            self, selected: dict[str, Any],
        ) -> None:
            manifest = validate_host(selected["path"], selected["digest"])
            assert len(manifest["componentHeads"]) == 8
            versions = manifest["componentVersions"]
            assert versions == {"agent-evidence-observer": "0.0.1", "agent-evidence-vectors": "0.15.0", "probity-verify": "0.1.0"}
            assert len(manifest["wheels"]) == 3

    class TestFailingCases:
        def test_manifest_substitution_does_not_start_a_child(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            result = execute(selected["path"], "0" * 64, candidate, tmp_path / "run")
            assert_no_dispatch(result, caplog, "external host manifest digest differs")
            assert result["childProcesses"] == 0
            with pytest.raises(HostRefusal, match="^external host manifest digest differs$"):
                validate_host(selected["path"], "0" * 64)
            assert "eight-component host refused: external host manifest digest differs" in caplog.text

        @pytest.mark.parametrize("boundary", ["policy", "key", "wheel", "program", "source", "installed"])
        def test_exact_bytes_are_selected_before_children_or_dispatch(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture, boundary: str,
        ) -> None:
            manifest = selected["manifest"]
            paths = {"policy": manifest["policy"]["path"], "key": manifest["seedFiles"]["issuer"]["path"],
                     "wheel": manifest["wheels"][0]["path"], "program": manifest["programs"][1]["path"],
                     "source": str(Path(manifest["sources"]) / "agent-evidence-atlas/experiments/authority-recovery-2026-10-02/original-artifact.zip"),
                     "installed": next(item["path"] for item in manifest["installedFiles"] if item["path"].endswith("probity_verify/core.py"))}
            path = Path(paths[boundary])
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\nchanged-boundary")
                result = run_case(selected, candidate, tmp_path / "run")
            finally:
                path.write_bytes(original)
            reasons = {"source": "pinned component source bytes differ", "installed": "installed package bytes differ"}
            reason = reasons.get(boundary, "host-selected executable policy or key bytes differ")
            assert_no_dispatch(result, caplog, reason)
            assert result["childProcesses"] == 0

        def test_added_installed_module_is_not_outside_the_manifest_closure(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            root = Path(selected["manifest"]["packageClosures"][0]["root"]) / "probity_observer"
            path = root / "candidate_injected_reader.py"
            try:
                path.write_text("raise RuntimeError('untrusted injected module')\n")
                result = run_case(selected, candidate, tmp_path / "run")
            finally:
                path.unlink()
            assert_no_dispatch(result, caplog, "installed package file closure differs")
            assert result["childProcesses"] == 0

        @pytest.mark.parametrize("name", ["host-injected.pth", "sitecustomize.py", "cryptography/host_injected.py"])
        def test_added_startup_hook_or_dependency_cannot_start_a_child(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture, name: str,
        ) -> None:
            root = Path(selected["manifest"]["packageClosures"][0]["root"])
            path = root / name
            sentinel = tmp_path / "hook-executed.txt"
            code = "import pathlib;pathlib.Path(" + repr(str(sentinel)) + ").write_text('executed')\n"
            try:
                with path.open("x") as output:
                    output.write(code)
                result = run_case(selected, candidate, tmp_path / "run")
            finally:
                path.unlink()
            assert_no_dispatch(result, caplog, "installed package file closure differs")
            assert result["childProcesses"] == 0
            assert not sentinel.exists()

        def test_added_source_module_is_refused_before_dynamic_atlas_import(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            root = Path(selected["manifest"]["sources"]) / "agent-evidence-atlas/tools"
            path = root / "host_injected.py"
            try:
                path.write_text("raise RuntimeError('source code outside frozen selection')\n")
                result = run_case(selected, candidate, tmp_path / "run")
            finally:
                path.unlink()
            assert_no_dispatch(result, caplog, "pinned component source file closure differs")
            assert result["childProcesses"] == 0

        def test_added_package_directory_cannot_redirect_imports_outside_closure(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            target = tmp_path / "unselected-package"
            target.mkdir()
            sentinel = tmp_path / "redirect-executed.txt"
            code = "import pathlib;pathlib.Path(" + repr(str(sentinel)) + ").write_text('executed')\n"
            (target / "__init__.py").write_text(code)
            root = Path(selected["manifest"]["packageClosures"][0]["root"])
            redirect = root / "host_injected_package"
            try:
                redirect.symlink_to(target, target_is_directory=True)
                result = run_case(selected, candidate, tmp_path / "run")
            finally:
                redirect.unlink()
            assert_no_dispatch(result, caplog, "installed package directory redirects")
            assert result["childProcesses"] == 0
            assert not sentinel.exists()

        def test_selected_launcher_configuration_is_bound(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            # GitHub's selected base interpreter may have no virtual environment.
            bindings = selected["manifest"]["launcherConfiguration"]
            if not bindings:
                assert selected["manifest"]["python"]["invocationPath"] == selected["manifest"]["python"]["path"]
                return
            path = Path(bindings[0]["path"])
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\ninclude-system-site-packages = true\n")
                result = run_case(selected, candidate, tmp_path / "run")
            finally:
                path.write_bytes(original)
            assert_no_dispatch(result, caplog, "host-selected executable policy or key bytes differ")
            assert result["childProcesses"] == 0

        def test_signer_issuer_and_service_roles_cannot_be_collapsed(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            policy = read_json(Path(selected["manifest"]["policy"]["path"]))
            policy["publicKeys"]["service"] = policy["publicKeys"]["issuer"]
            changed = select_policy(selected, policy, tmp_path / "host")
            result = run_case(changed, candidate, tmp_path / "run")
            assert_no_dispatch(result, caplog, "host signer authority and effect keys must differ")
            assert result["childProcesses"] == 0


class TestRustByteGate:
    """Verify real installed DSSE key/type refusal and exclusive output creation."""

    class TestPassingCases:
        def test_installed_binary_is_hash_selected(self, selected: dict[str, Any]) -> None:
            binding = selected["manifest"]["tools"]["byteGate"]
            assert sha256(Path(binding["path"]).read_bytes()) == binding["sha256"]

    class TestFailingCases:
        def test_wrong_external_envelope_key_prevents_dispatch(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            manifest = copy.deepcopy(selected["manifest"])
            public = tmp_path / "wrong-envelope.public"
            public.write_text("0" * 64 + "\n")
            previous = manifest["publicFiles"]["envelope"]
            replacement = file_binding(public)
            manifest["publicFiles"]["envelope"] = replacement
            manifest["selectedFiles"] = [replacement if item == previous else item for item in manifest["selectedFiles"]]
            path = tmp_path / "installation.json"
            write_json(path, manifest)
            changed = {"path": path, "digest": sha256(path.read_bytes()), "manifest": manifest}
            result = run_case(changed, candidate, tmp_path / "run")
            assert_no_dispatch(result, caplog, "byte-verify refused or did not complete")
            assert result["childProcesses"] == 2

        def test_signature_valid_payload_type_substitution_is_refused(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            manifest = selected["manifest"]
            raw = json.dumps(read_json(candidate / "raw-aee.json"), sort_keys=True, separators=(",", ":")).encode()
            media = b"application/vnd.host-other+json"
            pae = b"DSSEv1 " + str(len(media)).encode() + b" " + media + b" " + str(len(raw)).encode() + b" " + raw
            seed = bytes.fromhex(Path(manifest["seedFiles"]["envelope"]["path"]).read_text().strip())
            signature = Ed25519PrivateKey.from_private_bytes(seed).sign(pae)
            envelope = tmp_path / "wrong-type.json"
            write_json(envelope, {"payloadType": media.decode(), "payload": base64.b64encode(raw).decode(),
                                  "signatures": [{"keyid": "host-selected-example", "sig": base64.b64encode(signature).decode()}]})
            output = tmp_path / "verified.json"
            command = [manifest["tools"]["byteGate"]["path"], "verify", str(envelope),
                       manifest["publicFiles"]["envelope"]["path"], str(output)]
            receipt = run_child(command, tmp_path / "byte-gate")
            assert receipt["returnCode"] == 1
            assert not output.exists()
            assert read_json(tmp_path / "byte-gate.stderr")["reason"] == "selected payload type differs"
            with pytest.raises(HostRefusal, match="^selected payload type differs$"):
                require_child(receipt, "selected payload type differs")
            assert "eight-component host refused: selected payload type differs" in caplog.text

        def test_existing_output_bytes_are_preserved(
            self, selected: dict[str, Any], candidate: Path, tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            manifest = selected["manifest"]
            output = tmp_path / "already-present.json"
            output.write_bytes(b"earlier retained output\n")
            command = [manifest["tools"]["byteGate"]["path"], "admit-sign", str(candidate / "raw-aee.json"),
                       manifest["seedFiles"]["envelope"]["path"], str(output)]
            receipt = run_child(command, tmp_path / "byte-gate")
            assert receipt["returnCode"] == 1
            assert output.read_bytes() == b"earlier retained output\n"
            assert read_json(tmp_path / "byte-gate.stderr")["reason"] == "output already exists"
            with pytest.raises(HostRefusal, match="^output already exists$"):
                require_child(receipt, "output already exists")
            assert "eight-component host refused: output already exists" in caplog.text


class TestChildReceipts:
    """Retain misleading nonzero reports and partial timeout streams faithfully."""

    class TestPassingCases:
        def test_raw_stream_hashes_bind_the_actual_child_bytes(self, tmp_path: Path) -> None:
            prefix = tmp_path / "child"
            command = [sys.executable, "-I", "-c", "import sys;sys.stdout.buffer.write(b'raw\\x00bytes');sys.stderr.write('native diagnostic')"]
            receipt = run_child(command, prefix)
            assert receipt["returnCode"] == 0
            assert receipt["stdoutSha256"] == sha256(b"raw\x00bytes")
            assert receipt["stderrSha256"] == sha256(b"native diagnostic")
            assert prefix.with_suffix(".stdout").read_bytes() == b"raw\x00bytes"

    class TestFailingCases:
        def test_nonzero_exit_cannot_be_overruled_by_optimistic_json(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            prefix = tmp_path / "child"
            receipt = run_child([sys.executable, "-I", "-c", 'print(\'{"admitted":true}\');raise SystemExit(9)'], prefix)
            assert receipt["returnCode"] == 9
            assert read_json(prefix.with_suffix(".stdout"))["admitted"] is True
            with pytest.raises(HostRefusal, match="^selected child failed$"):
                require_child(receipt, "selected child failed")
            assert "eight-component host refused: selected child failed" in caplog.text

        def test_timeout_retains_partial_stdout_and_stderr(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            prefix = tmp_path / "child"
            code = "import sys,time;print('partial stdout',flush=True);print('partial stderr',file=sys.stderr,flush=True);time.sleep(10)"
            receipt = run_child([sys.executable, "-I", "-c", code], prefix, timeout=0.2)
            assert receipt["timedOut"] is True
            assert receipt["returnCode"] is None
            assert prefix.with_suffix(".stdout").read_bytes() == b"partial stdout\n"
            assert prefix.with_suffix(".stderr").read_bytes() == b"partial stderr\n"
            with pytest.raises(HostRefusal, match="^selected child timed out$"):
                require_child(receipt, "selected child timed out")
            assert "eight-component host refused: selected child timed out" in caplog.text
