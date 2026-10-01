"""Consumer-owned policy, replay state, and bounded packet admission.

Admission evaluates the PEER prototype; it does not strengthen its vantage.
The consumer must protect its state and acquire policy and witness pins outside
the candidate bundle. See :class:`AdmissionPolicy` and :class:`AdmissionStore`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .crypto import VerificationError, canonical, digest, strict_loads
from .history import GENESIS
from .ledger import read_ledger, verify_ledger_head, verify_ledger_receipts
from .verify import verify_packet

LOGGER = logging.getLogger(__name__)
STATE_FORMAT = "probity-consumer-admission-v0"
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _valid_hex(value: Any) -> bool:
    """Return whether a key or digest has the fixed lowercase hexadecimal form."""
    return isinstance(value, str) and HEX_DIGEST.fullmatch(value) is not None


def _valid_interval(value: Any) -> bool:
    """Return whether an interval is a nonempty string in the ASCII profile."""
    return isinstance(value, str) and bool(value) and value.isascii()


def _require_fields(value: Any, fields: set[str], reason: str) -> None:
    """Refuse non-objects and unexpected fields without logging their contents."""
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(reason)


@dataclass(frozen=True)
class AdmissionPolicy:
    """Consumer expectations acquired independently of a candidate packet.

    Parameters
    ----------
    interval_id : str
        Exact interval requested by this consumer. An interval can be admitted
        only once in a store bound to the same observer and witness keys.
    authority_digest : str
        :func:`probity_observer.crypto.digest` of the consumer's expected
        authority, using the ``probity-authority-v0`` domain. This binds the
        entire declaration, including scope, operation, and measured fields.
        Computing this value from the candidate is not authorization.
    observer_key, witness_key : str
        Distinct public Ed25519 keys pinned by the consumer outside the bundle.
    retained_witness_head : dict[str, Any]
        Signed ledger head acquired and retained through a trusted channel.
        A head included with the candidate cannot establish rollback protection.

    Notes
    -----
    This policy accepts the prototype's PEER records with no detected gap on
    its declared broker channel. It establishes neither independent custody,
    wall-clock freshness, absence of other effects, nor production isolation.
    The head is copied before use; callers must not mutate inputs concurrently.
    """

    interval_id: str
    authority_digest: str
    observer_key: str
    witness_key: str
    retained_witness_head: dict[str, Any]


def _check_keys(observer_key: str, witness_key: str) -> None:
    """Require two distinct public keys in the prototype's hexadecimal form."""
    if not all(_valid_hex(key) for key in (observer_key, witness_key)):
        raise VerificationError("consumer policy has an invalid public key")
    if observer_key == witness_key:
        raise VerificationError("consumer observer and witness keys must differ")


def _check_policy(policy: AdmissionPolicy) -> None:
    """Reject malformed consumer expectations before reading candidate bytes."""
    _check_keys(policy.observer_key, policy.witness_key)
    if not _valid_interval(policy.interval_id):
        raise VerificationError("consumer policy has an invalid interval id")
    if not _valid_hex(policy.authority_digest):
        raise VerificationError("consumer policy has an invalid authority digest")


@contextmanager
def _locked(state_path: Path) -> Iterator[None]:
    """Serialize local consumer decisions using a stable sibling lock file."""
    import fcntl

    state_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_path.with_name(state_path.name + ".lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _sync_parent(path: Path) -> None:
    """Flush a state-file directory after creation or atomic replacement."""
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _save_state(path: Path, state: dict[str, Any]) -> None:
    """Replace consumer state atomically and flush it before returning success."""
    descriptor, name = tempfile.mkstemp(prefix=".admission-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(state))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_parent(path)
    finally:
        temporary.unlink(missing_ok=True)


def _check_position(position: dict[str, Any]) -> None:
    """Reject a malformed locally retained receipt-log position."""
    _require_fields(
        position,
        {"count", "head"},
        "consumer admission state has an invalid ledger position",
    )
    if type(position["count"]) is not int or position["count"] < 0:
        raise VerificationError("consumer admission state has an invalid ledger count")
    if not _valid_hex(position["head"]):
        raise VerificationError("consumer admission state has an invalid ledger head")


def _check_decision(decision: dict[str, Any]) -> None:
    """Require one bounded decision with valid identities, digests, and position."""
    fields = {
        "status",
        "intervalId",
        "authorityDigest",
        "claimDigest",
        "afterRoot",
        "historyHead",
        "ledger",
        "witnessScope",
    }
    _require_fields(decision, fields, "consumer admission state has invalid decisions")
    if (decision["status"], decision["witnessScope"]) != ("admitted", "PEER"):
        raise VerificationError("consumer admission state has invalid decisions")
    _check_decision_identity(decision)
    _check_position(decision["ledger"])


def _check_decision_identity(decision: dict[str, Any]) -> None:
    """Validate the identifiers retained for replay checks and later replay."""
    if not _valid_interval(decision["intervalId"]):
        raise VerificationError("consumer admission state has invalid decisions")
    fields = ("authorityDigest", "claimDigest", "afterRoot", "historyHead")
    if not all(_valid_hex(decision[key]) for key in fields):
        raise VerificationError("consumer admission state has invalid decisions")


def _check_decision_order(previous: dict[str, Any], current: dict[str, Any]) -> None:
    """Refuse locally inconsistent ledger positions in the admission history."""
    if current["count"] < previous["count"]:
        raise VerificationError(
            "consumer admission state has inconsistent ledger positions"
        )
    if current["count"] == previous["count"] and current["head"] != previous["head"]:
        raise VerificationError(
            "consumer admission state has inconsistent ledger positions"
        )


def _check_decisions(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate the admission history and return its final retained position."""
    if not isinstance(decisions, list):
        raise VerificationError("consumer admission state has invalid decisions")
    previous = {"count": 0, "head": GENESIS}
    seen: set[str] = set()
    for decision in decisions:
        _check_decision(decision)
        if decision["intervalId"] in seen:
            raise VerificationError("consumer admission state repeats an interval")
        seen.add(decision["intervalId"])
        _check_decision_order(previous, decision["ledger"])
        previous = decision["ledger"]
    return previous


def _read_state(path: Path, policy: AdmissionPolicy) -> dict[str, Any]:
    """Read an existing consumer store; a missing store never resets replay state."""
    if not path.exists():
        raise VerificationError("consumer admission state is missing")
    state = strict_loads(path.read_bytes())
    fields = {"format", "observerKey", "witnessKey", "ledger", "admissions"}
    _require_fields(state, fields, "consumer admission state has invalid fields")
    if state["format"] != STATE_FORMAT:
        raise VerificationError("consumer admission state has invalid fields")
    if (state["observerKey"], state["witnessKey"]) != (
        policy.observer_key,
        policy.witness_key,
    ):
        raise VerificationError("consumer admission state belongs to different keys")
    _check_position(state["ledger"])
    if state["ledger"] != _check_decisions(state["admissions"]):
        raise VerificationError(
            "consumer admission state differs from its decision history"
        )
    return cast(dict[str, Any], state)


def _check_claim(claim: dict[str, Any], policy: AdmissionPolicy) -> None:
    """Bind an internally verified claim to independently selected expectations."""
    if claim["intervalId"] != policy.interval_id:
        raise VerificationError("packet interval differs from consumer policy")
    if claim["authorityDigest"] != policy.authority_digest:
        raise VerificationError("packet authority differs from consumer policy")
    if claim["coverage"]["noDetectedGap"] is not True:
        raise VerificationError("consumer admission requires no detected coverage gap")


def _check_replay(state: dict[str, Any], policy: AdmissionPolicy) -> None:
    """Refuse a second admission even when the packet remains correctly signed."""
    if any(
        decision["intervalId"] == policy.interval_id for decision in state["admissions"]
    ):
        raise VerificationError("interval was already admitted by this consumer")


def _check_extension(receipts: list[dict[str, Any]], position: dict[str, Any]) -> None:
    """Require the supplied log to extend the consumer's last accepted prefix."""
    count = position["count"]
    if count > len(receipts):
        raise VerificationError("ledger is shorter than the consumer retained head")
    prefix = receipts[count - 1]["hash"] if count else GENESIS
    if prefix != position["head"]:
        raise VerificationError("ledger does not extend the consumer retained head")


def _check_receipt_identity(packet: dict[str, Any], policy: AdmissionPolicy) -> None:
    """Prevent swapping valid witness receipts from another signed interval."""
    for checkpoint in (packet["startCheckpoint"], packet["checkpoint"]):
        receipt = checkpoint["ledgerReceipt"]
        identity = (
            receipt["intervalId"],
            receipt["authorityDigest"],
            receipt["observerKey"],
        )
        if identity != (
            policy.interval_id,
            policy.authority_digest,
            policy.observer_key,
        ):
            raise VerificationError("witness receipt differs from consumer policy")


def _verify_bundle(
    packet: dict[str, Any],
    history: Path,
    ledger: Path,
    policy: AdmissionPolicy,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Check fixed input snapshots, policy, receipt inclusion, and both head pins."""
    claim = verify_packet(packet, history, policy.observer_key, policy.witness_key)
    _check_claim(claim, policy)
    summary = verify_ledger_head(
        ledger, policy.retained_witness_head, policy.witness_key
    )
    verify_ledger_receipts(
        ledger, packet["startCheckpoint"], packet["checkpoint"], policy.witness_key
    )
    _check_receipt_identity(packet, policy)
    _check_extension(read_ledger(ledger, policy.witness_key), state["ledger"])
    return {
        "status": "admitted",
        "intervalId": policy.interval_id,
        "authorityDigest": policy.authority_digest,
        "claimDigest": digest("probity-claim-v0", claim),
        "afterRoot": claim["afterRoot"],
        "historyHead": packet["checkpoint"]["head"],
        "ledger": {key: summary[key] for key in ("count", "head")},
        "witnessScope": "PEER",
    }


class AdmissionStore:
    """Durable local replay protection and admission history for one trusted key pair.

    Parameters
    ----------
    state_path : Path
        Consumer-controlled canonical JSON state, outside candidate bundles and
        producer-writable paths. Initialize once with :meth:`initialize`.

    Notes
    -----
    The sibling lock serializes Linux processes using this same path. State is
    unsigned consumer-owned data, not a witness statement. Protect its directory
    against replacement, deletion, and rollback; deleting or restoring it can
    erase replay protection. A missing or corrupt state is refused. This store
    does not provide cross-host consensus or exactly-once downstream effects.
    """

    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path.resolve()

    def initialize(self, observer_key: str, witness_key: str) -> None:
        """Create a new store explicitly, refusing to overwrite prior decisions.

        Parameters
        ----------
        observer_key, witness_key : str
            Distinct consumer-pinned public keys for this store's trust domain.

        Raises
        ------
        VerificationError
            If the keys are invalid or the state already exists.
        OSError
            If protected storage cannot be created or durably flushed.
        """
        _check_keys(observer_key, witness_key)
        state = {
            "format": STATE_FORMAT,
            "observerKey": observer_key,
            "witnessKey": witness_key,
            "ledger": {"count": 0, "head": GENESIS},
            "admissions": [],
        }
        with _locked(self.state_path):
            try:
                descriptor = os.open(
                    self.state_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
            except FileExistsError as exc:
                LOGGER.warning("consumer initialization refused: state already exists")
                raise VerificationError(
                    "consumer admission state already exists"
                ) from exc
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical(state))
                stream.flush()
                os.fsync(stream.fileno())
            _sync_parent(self.state_path)

    def admit(
        self,
        packet: dict[str, Any],
        history_path: Path,
        ledger_path: Path,
        policy: AdmissionPolicy,
    ) -> dict[str, Any]:
        """Verify a complete record and persist its admission before returning.

        Parameters
        ----------
        packet : dict[str, Any]
            Candidate signed packet with begin and terminal ledger receipts.
        history_path, ledger_path : Path
            Retained broker history and full witness receipt log. Private copies
            ensure repeated checks use the same captured bytes.
        policy : AdmissionPolicy
            Consumer expectations and externally retained signed witness head.

        Returns
        -------
        dict[str, Any]
            Unsigned consumer decision linking the expected authority, interval,
            verified claim, after-root, history head, and accepted ledger head.
            The identical decision is retained in this store's history.

        Raises
        ------
        VerificationError
            If verification, policy, inclusion, replay, or continuity fails, or
            input/state bytes are malformed or storage is unavailable. Refusals
            log a bounded reason without candidate content or key values.

        Notes
        -----
        A failure after atomic replacement may have persisted the decision;
        retrying safely refuses that interval. Admission authorizes no separate
        application effect. It does not assert current workspace contents or
        freshness, and it does not promote PEER to independent observation.
        """
        try:
            _check_policy(policy)
            candidate = strict_loads(canonical(packet))
            copied_policy = AdmissionPolicy(
                policy.interval_id,
                policy.authority_digest,
                policy.observer_key,
                policy.witness_key,
                strict_loads(canonical(policy.retained_witness_head)),
            )
            with _locked(self.state_path):
                return self._admit_locked(
                    candidate, history_path, ledger_path, copied_policy
                )
        except VerificationError as exc:
            LOGGER.warning("consumer admission refused: %s", exc)
            raise
        except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
            LOGGER.warning("consumer admission refused: admission input is malformed")
            raise VerificationError("admission input is malformed") from exc
        except OSError as exc:
            LOGGER.warning(
                "consumer admission refused: admission storage is unavailable"
            )
            raise VerificationError("admission storage is unavailable") from exc

    def _admit_locked(
        self,
        packet: dict[str, Any],
        history_path: Path,
        ledger_path: Path,
        policy: AdmissionPolicy,
    ) -> dict[str, Any]:
        """Evaluate snapshots and atomically append under the consumer lock."""
        state = _read_state(self.state_path, policy)
        _check_replay(state, policy)
        with tempfile.TemporaryDirectory() as directory:
            history, ledger = (
                Path(directory) / "history.jsonl",
                Path(directory) / "ledger.jsonl",
            )
            history.write_bytes(history_path.read_bytes())
            ledger.write_bytes(ledger_path.read_bytes())
            decision = _verify_bundle(packet, history, ledger, policy, state)
        state["ledger"] = decision["ledger"]
        state["admissions"].append(decision)
        _save_state(self.state_path, state)
        return decision


def main(argv: Sequence[str] | None = None) -> int:
    """Run explicit initialization or admission using consumer-selected files.

    Parameters
    ----------
    argv : Sequence[str] | None, optional
        Command arguments, or the process arguments when omitted. ``init``
        requires public key pins; ``admit`` requires policy, state, packet,
        broker history, and receipt-log paths.

    Returns
    -------
    int
        Zero after a durable initialization/admission, one for a refusal.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser(
        "init", help="create protected consumer state once"
    )
    initialize.add_argument("--state", type=Path, required=True)
    initialize.add_argument("--observer-key", required=True)
    initialize.add_argument("--witness-key", required=True)
    admit = commands.add_parser(
        "admit", help="evaluate a retained packet against consumer policy"
    )
    for name in ("state", "policy", "packet", "history", "ledger"):
        admit.add_argument("--" + name, type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = _run_command(arguments)
    except (VerificationError, OSError, TypeError) as exc:
        LOGGER.warning("consumer admission command refused: %s", type(exc).__name__)
        print(json.dumps({"status": "refused"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def _run_command(arguments: argparse.Namespace) -> dict[str, Any]:
    """Read explicitly named inputs without discovering trust inside a bundle."""
    store = AdmissionStore(arguments.state)
    if arguments.command == "init":
        store.initialize(arguments.observer_key, arguments.witness_key)
        return {"status": "initialized"}
    policy = AdmissionPolicy(**strict_loads(arguments.policy.read_bytes()))
    packet = strict_loads(arguments.packet.read_bytes())
    return store.admit(packet, arguments.history, arguments.ledger, policy)
