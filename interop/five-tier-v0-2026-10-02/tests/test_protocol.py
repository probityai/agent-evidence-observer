"""Population denominators and unknown/error distinctions under property inputs."""
from __future__ import annotations

from collections import Counter

import pytest
from hypothesis import given
from hypothesis import strategies as st
from protocol import manifest, population
from reader import decode, require


class TestFrozenPopulation:
    class TestPassingCases:
        def test_exact_target_breadth_and_configuration(self):
            value = manifest()
            assert Counter(row["tier"] for row in value["attempts"]) == {"reasoning": 10, "tools": 12, "agents": 3, "workloads": 2}
            tools = [row for row in value["attempts"] if row["tier"] == "tools"]
            assert Counter(row["family"] for row in tools) == {"arithmetic": 4, "scoped-file": 4, "sqlite-transaction": 4}
            agents = [row for row in value["attempts"] if row["tier"] == "agents"]
            assert len({row["solver"] for row in agents}) == 3
            assert len({row["family"] for row in agents}) == 2
            assert value["historical_cpu_baseline"]["pooling"] == "prohibited"
            assert value["budget"]["provider_dollars"] == 0

        @given(st.lists(st.sampled_from(["complete", "error", "incomplete", "not-started", "start-unknown"]), max_size=100))
        def test_all_declared_attempts_are_preserved(self, statuses):
            records = [{"status": status, "task_outcome": "unknown"} for status in statuses]
            result = population(records)
            assert result["planned"] == len(statuses)
            assert result["started"] + result["not_started"] + result["unknown_start"] == len(statuses)
            assert result["complete"] + result["error"] + result["incomplete"] + result["not_started"] + result["unknown_start"] == len(statuses)
            assert result["scored"] == 0

    class TestFailingCases:
        @pytest.mark.parametrize("raw,reason", [(b'{"name":1,"name":2}', "duplicate_json_member"), (b'{"value":NaN}', "nonfinite_json"), (b'{"value":Infinity}', "nonfinite_json")])
        def test_ambiguous_or_nonfinite_json_refused(self, raw, reason, caplog):
            with pytest.raises(ValueError, match=f"^{reason}$"):
                decode(raw)
            assert caplog.records[-1].getMessage() == reason

        def test_refusal_message_matches_log(self, caplog):
            with pytest.raises(ValueError, match="^selected_refusal$"):
                require(False, "selected_refusal")
            assert caplog.records[-1].getMessage() == "selected_refusal"
