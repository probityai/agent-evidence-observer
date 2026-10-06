"""An append-only witness log for multiple broker intervals.

The log is useful only when its key and storage are outside the agent's reach.
Local use remains a PEER witness, as in the rest of this prototype.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature
from .history import GENESIS, Witness, read_history, unresolved_intents, verify_incomplete_terminal

RECEIPT_DOMAIN = "probity-witness-receipt-v0"
HEAD_DOMAIN = "probity-witness-ledger-head-v0"
LOGGER = logging.getLogger(__name__)
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _ledger_position(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the count and head of a validated receipt log."""
    return {"count": len(receipts), "head": receipts[-1]["hash"] if receipts else GENESIS}


def _head_payload(head: dict[str, Any]) -> dict[str, Any]:
    """Require the fixed signed-head fields before signature verification."""
    fields = {"format", "count", "head", "keyid", "signature"}
    if not isinstance(head, dict) or set(head) != fields:
        raise VerificationError("witness ledger head has invalid fields")
    if head["format"] != HEAD_DOMAIN:
        raise VerificationError("witness ledger head has an unsupported format")
    if not isinstance(head["signature"], str):
        raise VerificationError("witness ledger head has an invalid signature")
    return {key: head[key] for key in ("format", "count", "head")}


def _verify_head_position(payload: dict[str, Any]) -> None:
    """Reject counts and hashes outside the ledger-head profile."""
    if type(payload["count"]) is not int or payload["count"] < 0:
        raise VerificationError("witness ledger head has an invalid count")
    if not isinstance(payload["head"], str) or not HEX_DIGEST.fullmatch(payload["head"]):
        raise VerificationError("witness ledger head has an invalid hash")


def _verify_retained_head(
    receipts: list[dict[str, Any]],
    retained_head: dict[str, Any],
    pinned_witness_key: str,
) -> None:
    """Authenticate a retained head and bind it to the supplied log prefix."""
    payload = _head_payload(retained_head)
    _verify_head_position(payload)
    if retained_head["keyid"] != pinned_witness_key:
        raise VerificationError("witness ledger head key differs from the pinned key")
    verify_signature(pinned_witness_key, HEAD_DOMAIN, payload, retained_head["signature"])
    count = payload["count"]
    if count > len(receipts):
        raise VerificationError("ledger is shorter than the retained witness head")
    prefix = receipts[count - 1]["hash"] if count else GENESIS
    if prefix != payload["head"]:
        raise VerificationError("ledger does not extend the retained witness head")


def _interval_summary(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Name begun intervals for which the retained log has no terminal receipt."""
    missing: dict[str, dict[str, Any]] = {}
    registered = 0
    for receipt in receipts:
        interval = receipt["intervalId"]
        if receipt["phase"] == "begin":
            registered += 1
            missing[interval] = {key: receipt[key] for key in ("intervalId", "authorityDigest", "observerKey")}
        else:
            del missing[interval]
    return {**_ledger_position(receipts), "registeredIntervals": registered, "missingTerminals": list(missing.values())}


def verify_ledger_head(
    ledger_path: Path,
    retained_head: dict[str, Any],
    pinned_witness_key: str,
) -> dict[str, Any]:
    """Verify a witness log against a head retained outside the bundle.

    Args:
        ledger_path: Full receipt log.
        retained_head: Signed prefix acquired and retained through a trusted
            channel. Valid extensions are permitted.
        pinned_witness_key: Consumer-selected witness key.

    Returns:
        Current count/head, registered interval count, and missing terminal
        identities. Check the corresponding histories to distinguish aborts
        from success.

    Raises:
        VerificationError: Invalid receipts, signature, or prefix binding.

    This covers registered intervals only. A head supplied with the current
    bundle cannot establish rollback protection, custody, or freshness.
    """
    try:
        receipts = read_ledger(ledger_path, pinned_witness_key)
        _verify_retained_head(receipts, retained_head, pinned_witness_key)
    except VerificationError as exc:
        LOGGER.warning("witness ledger verification failed: %s", exc)
        raise
    return _interval_summary(receipts)


def read_ledger(path: Path, pinned_witness_key: str) -> list[dict[str, Any]]:
    """Check every receipt and return the retained witness history."""
    if not path.exists():
        return []
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise VerificationError("witness ledger ends with an incomplete line")
    receipts: list[dict[str, Any]] = []
    intervals: dict[str, dict[str, Any]] = {}
    terminal_intervals: set[str] = set()
    for line in raw.splitlines():
        receipt = strict_loads(line)
        if not isinstance(receipt, dict) or set(receipt) != {
            "sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase",
            "checkpoint", "hash", "keyid", "signature",
        } or type(receipt["sequence"]) is not int:
            raise VerificationError("witness receipt has invalid fields")
        body = {key: receipt[key] for key in (
            "sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase", "checkpoint",
        )}
        previous = receipts[-1]["hash"] if receipts else GENESIS
        if receipt["sequence"] != len(receipts) + 1 or receipt["previous"] != previous:
            raise VerificationError("witness ledger sequence or predecessor differs")
        if receipt["hash"] != digest(RECEIPT_DOMAIN, body):
            raise VerificationError("witness receipt digest differs")
        if receipt["keyid"] != pinned_witness_key:
            raise VerificationError("witness receipt key differs from the pinned key")
        verify_signature(pinned_witness_key, RECEIPT_DOMAIN, body, receipt["signature"])
        checkpoint = receipt["checkpoint"]
        if not isinstance(checkpoint, dict) or set(checkpoint) != {"count", "head", "keyid", "signature"} or (
            checkpoint["keyid"] != pinned_witness_key
            or type(checkpoint["count"]) is not int
            or checkpoint["count"] < 1
        ):
            raise VerificationError("witness checkpoint key or count differs")
        checkpoint_payload = {"count": checkpoint["count"], "head": checkpoint["head"]}
        verify_signature(pinned_witness_key, "probity-checkpoint-v0", checkpoint_payload, checkpoint["signature"])
        interval = receipt["intervalId"]
        earlier = intervals.get(interval)
        if receipt["phase"] == "begin":
            if earlier is not None or checkpoint["count"] != 1:
                raise VerificationError("witness interval has a repeated begin")
            intervals[interval] = receipt
        elif receipt["phase"] == "terminal":
            if earlier is None or interval in terminal_intervals:
                raise VerificationError("witness interval has no unique begin")
            if (receipt["authorityDigest"], receipt["observerKey"]) != (
                earlier["authorityDigest"], earlier["observerKey"]
            ) or checkpoint["count"] <= 1:
                raise VerificationError("witness terminal differs from its begin")
            terminal_intervals.add(interval)
        else:
            raise VerificationError("witness receipt has an unknown phase")
        receipts.append(receipt)
    return receipts


def _begin_identity(entries: list[dict[str, Any]], pinned_observer_key: str) -> tuple[str, str]:
    if not entries or entries[0]["event"]["kind"] != "begin":
        raise VerificationError("witness history has no begin event")
    begin = entries[0]["event"]
    commitment = begin["commitment"]
    payload = {"preimage": commitment["preimage"], "committedAt": commitment["committedAt"]}
    if commitment["keyid"] != pinned_observer_key:
        raise VerificationError("witness history has an unpinned observer key")
    verify_signature(pinned_observer_key, "probity-prior-commitment-v0", payload, commitment["signature"])
    if begin["commitmentDigest"] != digest("probity-prior-commitment-v0", payload):
        raise VerificationError("witness history differs from the signed commitment")
    preimage = commitment["preimage"]
    return preimage["intervalId"], preimage["authorityDigest"]


def _verify_terminal_intents(entries: list[dict[str, Any]]) -> None:
    """Use the offline reader's rules before signing an incomplete terminal."""
    terminal = entries[-1]["event"]
    if terminal["kind"] == "incomplete":
        verify_incomplete_terminal(terminal, unresolved_intents(entries[:-1]))
        return
    if unresolved_intents(entries):
        reason = "witness terminal disagrees with write intents"
        LOGGER.warning("witness terminal refused: %s", reason)
        raise VerificationError(reason)


class LedgerWitness(Witness):
    """Witness broker intervals under one key and one durable log.

    The lock prevents concurrent local writers from signing competing heads.
    An external operator must protect the log and publish its head for a
    relying party to detect a restored or withheld log.
    """

    def __init__(self, ledger_path: Path, signing_key: SigningKey, observer_key: str) -> None:
        super().__init__(ledger_path, signing_key)
        self.observer_key = observer_key

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize receipt append and head export under the same local lock."""
        import fcntl

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def signed_head(self) -> dict[str, Any]:
        """Export a signed ledger head under the receipt writer's local lock.

        Returns:
            Fixed format, count, head hash, witness key ID, and signature.

        Raises:
            VerificationError: The retained receipt log fails verification.

        This method does not publish the head. Consumers must retain it separately
        and call verify_ledger_head before accepting a later log. A head copied
        from the current bundle does not expose a withheld suffix.
        """
        with self._locked():
            receipts = read_ledger(self.state_path, self.signing_key.public_hex)
            payload = {"format": HEAD_DOMAIN, **_ledger_position(receipts)}
            return {
                **payload,
                "keyid": self.signing_key.public_hex,
                "signature": self.signing_key.sign(HEAD_DOMAIN, payload),
            }

    def checkpoint(self, history_path: Path, *, max_ledger_bytes: int | None = None) -> dict[str, Any]:
        """Append a checkpoint, optionally bounded by actual serialized log bytes.

        Parameters
        ----------
        history_path : Path
            Complete broker history to checkpoint.
        max_ledger_bytes : int or None
            Optional host-selected cap. Capacity is checked under the append
            lock before writing; a refusal leaves the receipt log unchanged.

        Returns
        -------
        dict
            Signed checkpoint and durable receipt.
        """
        with self._locked():
            entries = read_history(history_path)
            interval, authority_digest = _begin_identity(entries, self.observer_key)
            receipts = read_ledger(self.state_path, self.signing_key.public_hex)
            prior = next((r for r in receipts if r["intervalId"] == interval and r["phase"] == "begin"), None)
            if prior is None:
                if len(entries) != 1:
                    raise VerificationError("witness first checkpoint must precede effects")
                phase = "begin"
            else:
                if any(r["intervalId"] == interval and r["phase"] == "terminal" for r in receipts):
                    raise VerificationError("witness interval already has a terminal head")
                if entries[0]["hash"] != prior["checkpoint"]["head"]:
                    raise VerificationError("history does not extend the witnessed begin")
                if entries[-1]["event"]["kind"] not in {"seal", "incomplete"}:
                    raise VerificationError("witness terminal checkpoint needs a terminal event")
                _verify_terminal_intents(entries)
                phase = "terminal"
            payload = {"count": len(entries), "head": entries[-1]["hash"]}
            checkpoint = {
                **payload,
                "keyid": self.signing_key.public_hex,
                "signature": self.signing_key.sign("probity-checkpoint-v0", payload),
            }
            body = {
                "sequence": len(receipts) + 1,
                "previous": receipts[-1]["hash"] if receipts else GENESIS,
                "intervalId": interval,
                "authorityDigest": authority_digest,
                "observerKey": self.observer_key,
                "phase": phase,
                "checkpoint": checkpoint,
            }
            receipt = {
                **body,
                "hash": digest(RECEIPT_DOMAIN, body),
                "keyid": self.signing_key.public_hex,
                "signature": self.signing_key.sign(RECEIPT_DOMAIN, body),
            }
            self._append_receipt(canonical(receipt) + b"\n", max_ledger_bytes)
            return {**checkpoint, "ledgerReceipt": receipt}

    def _append_receipt(self, raw: bytes, maximum: int | None) -> None:
        """Flush only after checking the exact append size under the writer lock."""
        self._check_capacity(raw, maximum)
        with self.state_path.open("ab") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        parent = os.open(self.state_path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

    def _check_capacity(self, raw: bytes, maximum: int | None) -> None:
        """Never admit a receipt whose actual bytes exceed the host's cap."""
        if maximum is None:
            return
        if type(maximum) is not int or maximum < 0:
            raise VerificationError("witness ledger capacity is invalid")
        if self._existing_size() + len(raw) > maximum:
            raise VerificationError("witness ledger capacity reached")

    def _existing_size(self) -> int:
        """Retain legacy fresh-log behavior while measuring an existing append."""
        return self.state_path.stat().st_size if self.state_path.exists() else 0

    def latest_checkpoint(self, history_path: Path) -> dict[str, Any]:
        entries = read_history(history_path)
        interval, _ = _begin_identity(entries, self.observer_key)
        receipts = read_ledger(self.state_path, self.signing_key.public_hex)
        found = [r for r in receipts if r["intervalId"] == interval]
        if len(found) != 1 or found[0]["phase"] != "begin":
            raise VerificationError("the prior witness checkpoint is missing")
        return {**found[0]["checkpoint"], "ledgerReceipt": found[0]}

    def receipt_log(self, history_path: Path) -> bytes:
        """Return public receipts only for an already acknowledged exact history.

        This read takes the same lock as append. It does not add a receipt or
        initialize a missing log. Separate consumers still need their own key
        selection and retained head to detect rollback or a signed fork.
        """
        with self._locked():
            entries = read_history(history_path)
            interval, authority = _begin_identity(entries, self.observer_key)
            receipts = read_ledger(self.state_path, self.public_hex)
            matching = [
                receipt for receipt in receipts
                if receipt["intervalId"] == interval
                and receipt["authorityDigest"] == authority
                and receipt["checkpoint"]["count"] == len(entries)
                and receipt["checkpoint"]["head"] == entries[-1]["hash"]
            ]
            if len(matching) != 1:
                raise VerificationError("native history lacks its recorded witness receipt")
            return self.state_path.read_bytes()


def verify_ledger_receipts(
    ledger_path: Path,
    start_checkpoint: dict[str, Any],
    terminal_checkpoint: dict[str, Any],
    pinned_witness_key: str,
    pinned_head: str | None = None,
) -> dict[str, Any]:
    """Check inclusion in the full log and extension from a pinned head."""
    receipts = read_ledger(ledger_path, pinned_witness_key)
    if pinned_head is not None and not any(r["hash"] == pinned_head for r in receipts):
        raise VerificationError("ledger does not extend the pinned head")
    start = start_checkpoint["ledgerReceipt"]
    terminal = terminal_checkpoint["ledgerReceipt"]
    if start not in receipts or terminal not in receipts:
        raise VerificationError("witness checkpoint is absent from the ledger")
    if start["phase"] != "begin" or terminal["phase"] != "terminal":
        raise VerificationError("witness receipts lack begin and terminal phases")
    if start["intervalId"] != terminal["intervalId"] or start["sequence"] >= terminal["sequence"]:
        raise VerificationError("witness receipts name different intervals or order")
    if start["checkpoint"] != {k: v for k, v in start_checkpoint.items() if k != "ledgerReceipt"}:
        raise VerificationError("begin checkpoint differs from its witness receipt")
    if terminal["checkpoint"] != {k: v for k, v in terminal_checkpoint.items() if k != "ledgerReceipt"}:
        raise VerificationError("terminal checkpoint differs from its witness receipt")
    return {"count": len(receipts), "head": receipts[-1]["hash"]}
