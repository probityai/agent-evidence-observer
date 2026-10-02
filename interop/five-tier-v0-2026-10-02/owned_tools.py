"""Finite local operations; these are scoped fixtures, not a security sandbox."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class OwnedTools:
    """Operate one fixed file and two SQLite balance rows per declared attempt.

    Parameters
    ----------
    directory : pathlib.Path
        New attempt directory selected by the runner, never by model arguments.

    Notes
    -----
    The recorder and targets share an operator. Local refusal checks do not
    establish external authority, global containment or independent effects.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.target = directory / "ticket.txt"
        self.database = directory / "balances.sqlite"
        self.target.write_text("OPEN", encoding="utf-8")
        with sqlite3.connect(self.database) as connection:
            connection.executescript("CREATE TABLE balances(id INTEGER PRIMARY KEY, amount INTEGER NOT NULL CHECK(amount >= 0)); INSERT INTO balances VALUES (1,10),(2,0);")

    def balance(self) -> str:
        """Read original SQLite rows through a fresh connection after commit."""
        with sqlite3.connect(self.database) as connection:
            rows = connection.execute("SELECT amount FROM balances ORDER BY id").fetchall()
        return ",".join(str(row[0]) for row in rows)

    def transfer(self, amount: Any) -> str:
        """Apply one atomic debit/credit or return a bounded refusal.

        Parameters
        ----------
        amount : int
            Exact integer from one through ten. SQLite constraints prohibit a
            negative source balance, and an exception rolls back both writes.

        Returns
        -------
        str
            Committed balance readback, ``refused:amount`` or
            ``refused:insufficient-funds``; no partial debit is retained.
        """
        if type(amount) is not int or not 1 <= amount <= 10:
            return "refused:amount"
        try:
            with sqlite3.connect(self.database) as connection:
                connection.execute("UPDATE balances SET amount=amount-? WHERE id=1", (amount,))
                connection.execute("UPDATE balances SET amount=amount+? WHERE id=2", (amount,))
        except sqlite3.IntegrityError:
            return "refused:insufficient-funds"
        return self.balance()

    def _double(self, arguments: dict[str, Any]) -> str:
        """Refuse noninteger/out-of-bound inputs before arithmetic."""
        value = arguments.get("value")
        return str(value * 2) if type(value) is int and -100 <= value <= 100 else "refused:integer"

    def _write_file(self, arguments: dict[str, Any]) -> str:
        """Allow only the declared transition; retain every other refusal."""
        content = arguments.get("content")
        if content != "DONE":
            return "refused:content"
        self.target.write_text(content, "utf-8")
        return self.target.read_text("utf-8")

    def perform(self, name: str, arguments: dict[str, Any]) -> str:
        """Dispatch the selected finite tool; unknown names remain refusals."""
        operations = {"double": self._double, "read_file": lambda _: self.target.read_text("utf-8"), "write_file": self._write_file, "read_balance": lambda _: self.balance(), "transfer": lambda args: self.transfer(args.get("amount"))}
        operation = operations.get(name)
        return "refused:unknown-tool" if operation is None else operation(arguments)

    def invoke(self, name: str, arguments: dict[str, Any]) -> str:
        """Retain the completed tool interval and returned value as JSONL.

        Timing uses monotonic wall elapsed and invoking-thread CPU deltas. It
        excludes other threads, harness work and resources outside the tool body.
        """
        start, cpu = time.perf_counter_ns(), time.thread_time_ns()
        result = self.perform(name, arguments)
        event = {"name": name, "arguments": arguments, "result": result, "elapsed_ns": time.perf_counter_ns() - start, "thread_cpu_ns": time.thread_time_ns() - cpu}
        with (self.directory / "tool-events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
            stream.flush()
        return result

    def readback(self) -> dict[str, str]:
        """Return separately reread scoped file and committed SQLite state."""
        return {"file": self.target.read_text("utf-8"), "sqlite": self.balance()}
