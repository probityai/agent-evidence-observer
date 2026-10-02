"""Installed immutable 384-call replay and independently selected quality controls."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

import boundary_policy as boundary
import model_gate as gate
from run_boundary_upgrade_example import prepare_boundary

ROOT = Path(__file__).resolve().parents[1]


def digest(raw: bytes) -> str:
    """Return raw-byte SHA256 for selections held outside the candidate packet."""
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def selected(tmp_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Authenticate the real original compact artifact, retaining every member."""
    packet = tmp_path / "packet"
    prepare_boundary(packet)
    policy = json.loads((ROOT / "boundary-evidence-policy.json").read_bytes())
    report = json.loads((packet / "report.json").read_bytes())
    return packet, policy, report


def invoke(
    selected: tuple[Path, dict[str, Any], dict[str, Any]],
    output: Path,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute the normally installed reader under a separately frozen host policy."""
    packet, evidence, _ = selected
    policy_file = output.parent / (output.name + "-policy.json")
    policy_file.write_text(json.dumps(policy or evidence, indent=2) + "\n")
    return gate.gate(
        packet,
        ROOT / "boundary-native-pins.json",
        policy_file,
        digest(policy_file.read_bytes()),
        output,
        60,
    )


class TestBoundaryProfile:
    """The complete native population survives ordinary installed replay."""

    class TestPassingCases:
        def test_installed_original_report_and_resources_are_exact(
            self, selected, tmp_path
        ):
            result = invoke(selected, tmp_path / "receipts")
            assert result["publicationDecision"] == "publish"
            assert result["evidenceDecision"] == "verified"
            actual = json.loads((tmp_path / "receipts/reader.stdout").read_bytes())
            assert actual == selected[2]
            assert result["casePopulation"] == dict(
                authoredIdentities=48,
                uniqueLiteralInputs=46,
                casesPerFamily=16,
                pairsPerFamily=8,
            )
            assert len(actual["quality"]) == 24
            assert actual["population"] == dict(
                planned=384,
                started=384,
                scored=384,
                error=0,
                incomplete=0,
                unsupported=0,
                **{"unknown-start": 0},
            )
            assert result["resources"] == dict(
                elapsedNs=257401173568,
                promptTokens=35280,
                completionTokens=7498,
                returnedCallProcessCpuNs=496051239620,
                totalProcessCpuNs=497394631919,
                processLifetimePeakRssKiB=567192,
                preparationPayloadBytes=472221945,
            )

        def test_duplicated_literal_inputs_remain_distinct_authored_cases(
            self, selected
        ):
            cases = selected[1]["cases"]
            assert len({case["id"] for case in cases}) == 48
            assert len({case["inputSha256"] for case in cases}) == 46
            for left, right in (
                ("policy-publish-consent-a", "policy-publish-checks-a"),
                ("policy-admit-expiry-a", "policy-admit-signature-a"),
            ):
                selected_cases = {case["id"]: case for case in cases}
                assert (
                    selected_cases[left]["inputSha256"]
                    == selected_cases[right]["inputSha256"]
                )
                assert selected_cases[left]["pair"] != selected_cases[right]["pair"]

        @pytest.mark.parametrize(
            "model,correct,pairs", [("smol135-q4", 16, 8), ("smol360-q4", 13, 5)]
        )
        @pytest.mark.parametrize("configuration", ["short24", "long96"])
        def test_typed_rows_remain_distinct(
            self, selected, model, correct, pairs, configuration
        ):
            row = next(
                row
                for row in selected[2]["quality"]
                if row["model"] == model
                and row["configuration"] == configuration
                and row["decoder"] == "schema"
                and row["family"] == "typed-boundary"
            )
            assert (row["correct"], row["fullyCorrectPairs"], row["schemaValid"]) == (
                correct,
                pairs,
                16,
            )

        def test_schema_validity_does_not_override_eight_weak_rows(
            self, selected, tmp_path
        ):
            policy = json.loads((ROOT / "boundary-quality-policy.json").read_bytes())
            result = invoke(selected, tmp_path / "quality-receipts", policy)
            assert result["evidenceDecision"] == "verified"
            assert result["publicationDecision"] == "hold-selected-score-or-resource"
            failures = result["policyFailures"]
            assert len(failures) == 16
            for model in ("smol135-q4", "smol360-q4"):
                for cap in ("short24", "long96"):
                    for family in ("policy-boundary", "grounded-boundary"):
                        row_failures = [
                            failure
                            for failure in failures
                            if failure["row"]
                            == dict(
                                model=model,
                                decoder="schema",
                                configuration=cap,
                                family=family,
                            )
                        ]
                        assert {failure["field"] for failure in row_failures} == {
                            "correct",
                            "fullyCorrectPairs",
                        }
                        paired = next(
                            failure
                            for failure in row_failures
                            if failure["field"] == "fullyCorrectPairs"
                        )
                        assert (paired["measured"], paired["minimum"]) == (0, 4)
            assert (
                sum(
                    row["schemaValid"]
                    for row in selected[2]["quality"]
                    if row["decoder"] == "schema"
                )
                == 192
            )

        @settings(max_examples=32)
        @given(
            index=st.integers(min_value=0, max_value=23),
            minimum=st.integers(min_value=0, max_value=8),
        )
        def test_pair_minimum_applies_only_to_its_complete_row(self, index, minimum):
            provenance = json.loads(
                (ROOT / "boundary-fixture-provenance.json").read_bytes()
            )
            import zipfile

            with zipfile.ZipFile(ROOT / provenance["fixturePath"]) as archive:
                report = json.loads(archive.read("report.json"))
            policy = json.loads((ROOT / "boundary-evidence-policy.json").read_bytes())
            policy["rows"][index]["minFullyCorrectPairs"] = minimum
            result = boundary.decide(report, policy)
            expected = report["quality"][index]["fullyCorrectPairs"] < minimum
            assert (
                result["publicationDecision"] == "hold-selected-score-or-resource"
            ) == expected
            assert len(result["policyFailures"]) == int(expected)
            if expected:
                assert result["policyFailures"][0] == dict(
                    row={
                        name: policy["rows"][index][name]
                        for name in boundary.IDENTITY_FIELDS
                    },
                    field="fullyCorrectPairs",
                    measured=report["quality"][index]["fullyCorrectPairs"],
                    minimum=minimum,
                )

    class TestFailingCases:
        @pytest.mark.parametrize(
            "outcome", ["error", "incomplete", "unknown-start", "unsupported"]
        )
        def test_incomplete_population_is_retained_and_refused(
            self, selected, caplog, outcome
        ):
            report = copy.deepcopy(selected[2])
            report["population"][outcome] = 1
            message = "boundary report population differs from host selection"
            with pytest.raises(ValueError, match=message):
                boundary.decide(report, selected[1])
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            "mutant,message",
            [
                (
                    "missing-row",
                    "boundary report requires all twenty-four quality rows",
                ),
                (
                    "duplicate-row",
                    "boundary report quality identities differ or repeat",
                ),
                ("boolean-count", "boundary counts require nonnegative integers"),
                (
                    "impossible-schema",
                    "boundary semantic, schema and format counts are inconsistent",
                ),
                (
                    "impossible-pair",
                    "boundary paired correctness exceeds semantic correctness",
                ),
                (
                    "false-pair",
                    "boundary quality or paired/resource subtotals differ from attempts",
                ),
                ("missing-attempt", "boundary report requires all 384 attempts"),
                ("duplicate-attempt", "boundary attempt population differs or repeats"),
                ("false-role", "boundary attempt pair identity or role differs"),
                (
                    "false-score",
                    "boundary quality or paired/resource subtotals differ from attempts",
                ),
                ("total-token", "boundary native token subtotal differs"),
                ("whole-cpu", "boundary returned-call CPU exceeds whole-process CPU"),
                ("preparation", "boundary preparation payload subtotal differs"),
                ("scope", "boundary row resource scope differs"),
                ("missing-field", "boundary report fields differ"),
            ],
        )
        def test_malformed_report_cannot_publish(
            self, selected, caplog, mutant, message
        ):
            report = copy.deepcopy(selected[2])
            mutations = {
                "missing-row": lambda: report["quality"].pop(),
                "duplicate-row": lambda: report["quality"].__setitem__(
                    1, copy.deepcopy(report["quality"][0])
                ),
                "boolean-count": lambda: report["quality"][0].__setitem__(
                    "correct", False
                ),
                "impossible-schema": lambda: report["quality"][0].__setitem__(
                    "correct", 1
                ),
                "impossible-pair": lambda: report["quality"][0].__setitem__(
                    "fullyCorrectPairs", 1
                ),
                "false-pair": lambda: report["quality"][3].__setitem__(
                    "fullyCorrectPairs", 7
                ),
                "missing-attempt": lambda: report["attempts"].pop(),
                "duplicate-attempt": lambda: report["attempts"].__setitem__(
                    1, copy.deepcopy(report["attempts"][0])
                ),
                "false-role": lambda: report["attempts"][0].__setitem__(
                    "pairRole", "a"
                ),
                "false-score": lambda: report["attempts"][0].update(
                    correct=True, schemaValid=True, formatValid=True
                ),
                "total-token": lambda: report["nativeTokens"].__setitem__(
                    "prompt", 35281
                ),
                "whole-cpu": lambda: report.__setitem__("process_cpu_ns", 496051239619),
                "preparation": lambda: report["preparation"].__setitem__(
                    "selectedPayloadBytes", 472221944
                ),
                "scope": lambda: report["quality"][0].__setitem__(
                    "resourceScope", "per-task allocation"
                ),
                "missing-field": lambda: report.pop("attempts"),
            }
            mutations[mutant]()
            with pytest.raises(ValueError, match=message):
                boundary.decide(report, selected[1])
            assert caplog.messages[-1] == message


class TestBoundaryHostPolicy:
    """Host selection, source and every resource bound remain outside the packet."""

    class TestPassingCases:
        def test_source_contract_preserves_all_three_historical_reader_bytes(self):
            contract = json.loads((ROOT / "source-contract.json").read_bytes())
            expected = {
                "model_task_reader.py": "1ced4b0875d56ee33e1bc8749c44669aa44ce87036ad0bbbdfc798cdffa5cee2",
                "model_comparison_reader.py": "744eb9a5af0328be0a4d4916b972770aa9babf91f97d4866abff34c37c453897",
                "model_format_reader.py": "3f386686ea0666dda06d68dc01c7a53157a19e8c82ba2957b46dda399169c072",
                "model_boundary_reader.py": "52a6000faae93178ce9e5acbf0e19c246fde69ee57055eb28cca8bddcc8f99b3",
            }
            assert contract["version"] == "0.0.4"
            for name, expected_digest in expected.items():
                pin = contract["files"][name]
                assert pin["sha256"] == expected_digest
                assert (
                    digest((ROOT.parents[1] / pin["path"]).read_bytes())
                    == expected_digest
                )

        def test_every_resource_is_bounded_independently(self, selected):
            for name in boundary.LIMIT_KEYS:
                policy = copy.deepcopy(selected[1])
                policy["limits"][name] = 0
                result = boundary.decide(selected[2], policy)
                assert result["evidenceDecision"] == "verified"
                assert (
                    result["publicationDecision"] == "hold-selected-score-or-resource"
                )
                assert result["policyFailures"] == [
                    dict(resource=name, measured=result["resources"][name], maximum=0)
                ]

    class TestFailingCases:
        @pytest.mark.parametrize(
            "field",
            [
                "model",
                "decoder",
                "configuration",
                "family",
                "plannedPairs",
                "minFullyCorrectPairs",
            ],
        )
        def test_row_selection_cannot_omit_any_identity_or_pair_threshold(
            self, selected, caplog, field
        ):
            policy = copy.deepcopy(selected[1])
            policy["rows"][0].pop(field)
            message = "boundary policy row fields differ"
            with pytest.raises(ValueError, match=message):
                boundary.validate_policy(policy)
            assert caplog.messages[-1] == message

        @pytest.mark.parametrize(
            "mutant,message",
            [
                ("legacy-schema", "boundary policy schema or profile differs"),
                (
                    "missing-case",
                    "boundary policy requires all forty-eight case identities",
                ),
                ("duplicate-case", "duplicate selected boundary case identity"),
                ("pooled-row", "boundary quality row identities differ or repeat"),
                (
                    "changed-unique-inputs",
                    "boundary authored population differs from frozen selection",
                ),
                ("missing-resource", "boundary policy resource fields differ"),
                (
                    "invalid-pairs",
                    "boundary pair threshold exceeds selected pair population",
                ),
                (
                    "duplicate-role",
                    "boundary pairs require exactly one case of each role",
                ),
            ],
        )
        def test_omission_aggregation_and_policy_version_are_refused(
            self, selected, caplog, mutant, message
        ):
            policy = copy.deepcopy(selected[1])
            mutations = {
                "legacy-schema": lambda: policy.__setitem__(
                    "schema", "probity-model-publication-policy-v2"
                ),
                "missing-case": lambda: policy["cases"].pop(),
                "duplicate-case": lambda: policy["cases"].__setitem__(
                    1, copy.deepcopy(policy["cases"][0])
                ),
                "pooled-row": lambda: policy["rows"][0].__setitem__(
                    "family", "all-families"
                ),
                "changed-unique-inputs": lambda: policy["casePopulation"].__setitem__(
                    "uniqueLiteralInputs", 48
                ),
                "missing-resource": lambda: policy["limits"].pop("totalProcessCpuNs"),
                "invalid-pairs": lambda: policy["rows"][0].__setitem__(
                    "minFullyCorrectPairs", 9
                ),
                "duplicate-role": lambda: policy["cases"][0].__setitem__(
                    "pairRole", "b"
                ),
            }
            mutations[mutant]()
            with pytest.raises(ValueError, match=message):
                boundary.validate_policy(policy)
            assert caplog.messages[-1] == message

        @given(
            value=st.one_of(
                st.booleans(),
                st.integers(max_value=-1),
                st.floats(allow_nan=True, allow_infinity=True),
            )
        )
        def test_numeric_coercion_cannot_enable_publication(self, value):
            policy = json.loads((ROOT / "boundary-evidence-policy.json").read_bytes())
            policy["rows"][0]["minCorrect"] = value
            with pytest.raises(
                ValueError, match="boundary counts require nonnegative integers"
            ):
                boundary.validate_policy(policy)

        def test_changed_protocol_case_selection_is_refused_before_launch(
            self, selected, tmp_path, caplog
        ):
            policy = copy.deepcopy(selected[1])
            policy["cases"][0]["inputSha256"] = "0" * 64
            result = invoke(selected, tmp_path / "receipts", policy)
            assert (
                result["reason"] == "boundary protocol cases differ from host selection"
            )
            assert result["launched"] is False
            assert caplog.messages[-1] == result["reason"]

        @pytest.mark.parametrize(
            "path,kind,reason",
            [
                ("terminal.json", "change", "selected artifact changed"),
                ("sources/task_matrix.py", "change", "original retained bytes changed"),
                (
                    "sources/grammars/typed-integer-zero.gbnf",
                    "change",
                    "original retained bytes changed",
                ),
                (
                    "sources/llama-cpp-python/LICENSE.md",
                    "delete",
                    "selected artifact must be a regular retained local file",
                ),
                (
                    "sources/extra-source.py",
                    "extra",
                    "retained original population changed",
                ),
            ],
        )
        def test_installed_native_source_and_population_substitution_refuse(
            self, selected, tmp_path, path, kind, reason
        ):
            member = selected[0] / path
            if kind == "delete":
                member.unlink()
            else:
                member.write_bytes(b"changed selected bytes\n")
            result = invoke(selected, tmp_path / "receipts")
            assert result["evidenceDecision"] == "not-verified"
            assert result["child"]["returncode"] == 1
            reader = json.loads((tmp_path / "receipts/reader.stdout").read_bytes())
            assert reader["reason"] == reason

        def test_receipts_under_producer_packet_are_refused_without_modifying_it(
            self, selected
        ):
            output = selected[0] / "forbidden-receipts"
            policy = ROOT / "boundary-evidence-policy.json"
            with pytest.raises(
                ValueError, match="receipt directory must be outside producer packet"
            ):
                gate.gate(
                    selected[0],
                    ROOT / "boundary-native-pins.json",
                    policy,
                    digest(policy.read_bytes()),
                    output,
                    60,
                )
            assert not output.exists()
