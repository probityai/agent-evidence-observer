"""Atomicity, refusal and original local readback controls."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from owned_tools import OwnedTools


class TestOwnedTools:
    class TestPassingCases:
        @given(st.integers(min_value=1, max_value=10))
        def test_transaction_preserves_sum_and_committed_rows(self, amount):
            with tempfile.TemporaryDirectory() as folder:
                owned = OwnedTools(Path(folder))
                assert owned.transfer(amount) == f"{10 - amount},{amount}"
                assert owned.readback()["sqlite"] == f"{10 - amount},{amount}"
                assert sum(map(int, owned.balance().split(","))) == 10

        @pytest.mark.parametrize("value", [-100, -1, 0, 1, 100])
        def test_bounded_arithmetic(self, value, tmp_path):
            assert OwnedTools(tmp_path).perform("double", {"value": value}) == str(2 * value)

        def test_file_committed_readback(self, tmp_path):
            owned = OwnedTools(tmp_path)
            assert owned.perform("write_file", {"content": "DONE"}) == "DONE"
            assert owned.readback()["file"] == "DONE"

    class TestFailingCases:
        @pytest.mark.parametrize("amount", [True, False, None, "4", 0, 11, -1])
        def test_refused_transfer_leaves_both_rows(self, amount, tmp_path):
            owned = OwnedTools(tmp_path)
            assert owned.transfer(amount) == "refused:amount"
            assert owned.balance() == "10,0"

        def test_insufficient_funds_rolls_back_both_writes(self, tmp_path):
            owned = OwnedTools(tmp_path)
            assert owned.transfer(7) == "3,7"
            assert owned.transfer(4) == "refused:insufficient-funds"
            assert owned.balance() == "3,7"

        @given(st.text().filter(lambda value: value != "DONE"))
        def test_invalid_ticket_transition_leaves_original(self, content):
            with tempfile.TemporaryDirectory() as folder:
                owned = OwnedTools(Path(folder))
                assert owned.perform("write_file", {"content": content}) == "refused:content"
                assert owned.readback()["file"] == "OPEN"

        @pytest.mark.parametrize("value", [True, False, None, 101, -101, "2", 2.0])
        def test_integer_refusal(self, value, tmp_path):
            assert OwnedTools(tmp_path).perform("double", {"value": value}) == "refused:integer"
