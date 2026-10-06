"""Host-owned exact-action dispatch with retained pre-effect authorization.

One store permits one exact file replacement. Successful responses survive
restart; a durable pending intent never automatically repeats an effect.
Separate role keys remain same-operator PEER/artifact evidence, not independent
custody, a native protocol implementation, or global exactly-once execution.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socketserver
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from .authorization import (
    ActionRequest,
    AuthorizedBroker,
    GrantPolicy,
    utc_clock,
    verify_authorized_packet,
    verify_grant,
)
from .broker import Broker, WriteResult, tree_root
from .crypto import (
    SigningKey,
    VerificationError,
    canonical,
    digest,
    strict_loads,
    verify_signature,
)
from .history import Witness, append_history, read_history, verify_checkpoint
from .ledger import LedgerWitness, read_ledger, verify_ledger_receipts
from .witness_port import DispatchWitnessPorts, WitnessPort

LOGGER = logging.getLogger(__name__)
STATE_DOMAIN = "probity-protected-dispatch-state-v0"
PRIOR_DOMAIN = "probity-protected-dispatch-prior-v0"
CONFIG_DOMAIN = "probity-protected-dispatch-config-v0"
MAX_REQUEST = 65536
MAX_RECEIPTS = 262144
STATE_FIELDS = frozenset(
    {
        "format",
        "configuration",
        "phase",
        "beforeRoot",
        "checkpoint",
        "grant",
        "prior",
        "priorCheckpoint",
        "result",
        "packet",
    }
)


def _refuse(reason: str) -> NoReturn:
    """Raise a finite refusal without logging secrets or candidate contents."""
    LOGGER.warning("protected dispatch refused: %s", reason)
    raise VerificationError(reason)


def _decision_configuration(value: str | None) -> dict[str, str]:
    """Preserve legacy configurations while binding an optional decision."""
    if value is None:
        return {}
    if not isinstance(value, str) or len(value) != 64:
        _refuse("decision digest must be a lowercase SHA-256-sized value")
    if any(character not in "0123456789abcdef" for character in value):
        _refuse("decision digest must be a lowercase SHA-256-sized value")
    return {"decisionDigest": value}


def _sync_directory(path: Path) -> None:
    """Flush a directory after a durable state-file replacement."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _save(path: Path, value: dict[str, Any]) -> None:
    """Atomically replace canonical state and flush bytes and directory."""
    descriptor, name = tempfile.mkstemp(prefix=".dispatch-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialize cooperating local processes on a stable host-owned lock."""
    import fcntl

    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def _envelope(payload: dict[str, Any], key: SigningKey, domain: str) -> dict[str, Any]:
    """Sign a fixed payload under an explicit role key and domain."""
    return {
        "payload": payload,
        "keyid": key.public_hex,
        "signature": key.sign(domain, payload),
    }


def _authenticated(record: Any, public_key: str, domain: str) -> dict[str, Any]:
    """Authenticate a strict signature envelope under an external key pin."""
    if not isinstance(record, dict) or set(record) != {"payload", "keyid", "signature"}:
        _refuse("dispatch signature envelope has unexpected fields")
    if record["keyid"] != public_key or not isinstance(record["payload"], dict):
        _refuse("dispatch signature envelope differs from the pinned key")
    verify_signature(public_key, domain, record["payload"], record["signature"])
    return record["payload"]


def _check_prefix(
    entries: list[dict[str, Any]], retained: dict[str, Any], key: str
) -> None:
    """Require a separately retained signed prefix to survive a restart."""
    count = retained.get("count")
    if type(count) is not int or not 1 <= count <= len(entries):
        _refuse("authorization history is shorter than the retained head")
    verify_checkpoint(entries[:count], retained, key)


def _content(request: ActionRequest, content: bytes) -> None:
    """Compare actual replacement bytes with the separately selected request."""
    if not isinstance(content, bytes):
        _refuse("protected dispatch content must be bytes")
    if hashlib.sha256(content).hexdigest() != request.content_sha256:
        _refuse("content digest differs from the authorized action")


def _state_payload(record: Any, observer: str) -> dict[str, Any]:
    """Apply one fixed state schema to online and offline verification."""
    state = _authenticated(record, observer, STATE_DOMAIN)
    if set(state) != STATE_FIELDS or state["format"] != STATE_DOMAIN:
        _refuse("dispatch state has unexpected fields")
    root = state["beforeRoot"]
    if (
        not isinstance(root, str)
        or len(root) != 64
        or any(character not in "0123456789abcdef" for character in root)
    ):
        _refuse("dispatch state has an invalid before root")
    return state


class ProtectedDispatcher:
    """Own one exact native broker action, durable response, and host socket.

    Parameters
    ----------
    workspace : Path
        Existing, one-writer file tree. It must not contain ``state_dir`` and
        must never be mounted into the isolated child.
    state_dir : Path
        Host-owned directory outside the file tree. Initialize once with
        :meth:`initialize`; missing state on restart is never silently reset.
    expected_request : ActionRequest
        Consumer-selected exact tenant, principal, tool, run, attempt, request,
        literal target, and replacement digest. A store executes only this
        action; use a separate externally selected interval for another action.
    policy : GrantPolicy
        Externally selected issuer key and grant duration limit.
    observer_key : SigningKey
        Host observer signer, distinct from the issuer and witness.
    witness_key : SigningKey or DispatchWitnessPorts
        Existing local signer, or an explicit public-key-only pair of native
        and authorization ports. Both ports must match the selected witness
        key before any target effect. Local signing retains same-operator scope.
    clock : Callable[[], datetime], optional
        Trusted host UTC second-precision clock, checked on every invocation
        including cached retries. The child cannot supply a reference time.
    retained_authorization_head : dict[str, Any] | None, optional
        Signed authorization checkpoint retained through a channel outside the
        candidate storage. Supplying it detects a restored older store. Local
        protected witness state detects ordinary truncation; restoring every
        local file together cannot be detected without this external pin.
    execution_digest : str | None, optional
        Consumer-selected digest of a concrete launch policy. The authorization
        journal commits it before dispatch; ordinary library calls may leave it
        unset and must not claim a measured isolated launch.
    decision_digest : str | None, optional
        Consumer-selected decision binding committed into initialization and the
        prior journal. Use a decision-aware dispatcher to replay its semantics.
        Omission preserves the original configuration schema and signing bytes.

    Notes
    -----
    :meth:`write` persists a witnessed grant/request/native-begin relation and
    pending state before the effect. The completed response is returned only
    after native sealing, completed authorization witnessing, and durable
    result storage. A crash between those steps leaves a refusal, not a guess
    about whether another file replacement is safe. Locks serialize processes
    cooperating on the same stable directory; host compromise, lock replacement,
    external file writers, and cross-host consensus are outside this profile.
    """

    def __init__(
        self,
        workspace: Path,
        state_dir: Path,
        expected_request: ActionRequest,
        policy: GrantPolicy,
        observer_key: SigningKey,
        witness_key: SigningKey | DispatchWitnessPorts,
        *,
        clock: Callable[[], datetime] = utc_clock,
        retained_authorization_head: dict[str, Any] | None = None,
        execution_digest: str | None = None,
        decision_digest: str | None = None,
    ) -> None:
        self.workspace = workspace.resolve(strict=True)
        self.state_dir = state_dir.resolve()
        self.expected_request = expected_request
        self.policy = policy
        self.observer_key = observer_key
        self.witness_key = witness_key
        self._witness_ports = self._select_witness_ports(witness_key)
        self.clock = clock
        self.execution_digest = execution_digest
        self.decision_digest = decision_digest
        self._retained_authorization_head = strict_loads(
            canonical(retained_authorization_head)
        )
        self._check_configuration()
        self._configuration = self._configuration_payload()
        self._configuration_digest = digest(CONFIG_DOMAIN, self._configuration)

    def _select_witness_ports(
        self, selected: SigningKey | DispatchWitnessPorts
    ) -> DispatchWitnessPorts:
        """Adapt the existing local API or select exact public checkpoint ports."""
        if isinstance(selected, DispatchWitnessPorts):
            return selected
        if not isinstance(selected, SigningKey):
            _refuse("dispatch witness selection must be a signer or explicit ports")
        return DispatchWitnessPorts(
            selected.public_hex,
            Witness(self.state_dir / "authorization-witness.json", selected),
            LedgerWitness(
                self.state_dir / "witness-ledger.jsonl",
                selected,
                self.observer_key.public_hex,
            ),
        )

    def _check_witness_pins(self) -> None:
        """Recheck mutable clients against the immutable selected role key."""
        if (
            self._witness_ports.authorization.public_hex != self._witness_ports.public_key
            or self._witness_ports.native.public_hex != self._witness_ports.public_key
        ):
            _refuse("dispatch witness ports differ from the selected key")

    def _check_configuration(self) -> None:
        """Refuse overlapping trust domains and non-distinct role keys."""
        if not self.workspace.is_dir():
            _refuse("dispatch workspace must be an existing directory")
        if self.state_dir.is_relative_to(
            self.workspace
        ) or self.workspace.is_relative_to(self.state_dir):
            _refuse("dispatch state and workspace must be separate trees")
        keys = {
            self.policy.issuer_key,
            self.observer_key.public_hex,
            self._witness_ports.public_key,
        }
        if len(keys) != 3:
            _refuse("issuer, observer, and witness keys must differ")
        self._check_witness_pins()
        for port, name in (
            (self._witness_ports.authorization, "authorization.jsonl"),
            (self._witness_ports.native, "history.jsonl"),
        ):
            error = port.configuration_error(self.workspace, self.state_dir / name)
            if error is not None:
                _refuse(error)
        self._check_execution_digest()
        if self.decision_digest is not None:
            _decision_configuration(self.decision_digest)

    def _check_execution_digest(self) -> None:
        """Validate an optional exact launch-policy digest."""
        if self.execution_digest is None:
            return
        if (
            not isinstance(self.execution_digest, str)
            or len(self.execution_digest) != 64
        ):
            _refuse("execution digest must be a lowercase SHA-256-sized value")
        if any(
            character not in "0123456789abcdef" for character in self.execution_digest
        ):
            _refuse("execution digest must be a lowercase SHA-256-sized value")

    def _configuration_payload(self) -> dict[str, Any]:
        """Capture externally configured exact action, policy, and role pins."""
        return {
            "request": asdict(self.expected_request),
            "policy": asdict(self.policy),
            "observerKey": self.observer_key.public_hex,
            "witnessKey": self._witness_ports.public_key,
            "executionDigest": self.execution_digest,
            **_decision_configuration(self.decision_digest),
        }

    def _paths(self) -> tuple[Path, Path, WitnessPort]:
        """Return the protected journal, state, and monotonic witness store."""
        journal = self.state_dir / "authorization.jsonl"
        state = self.state_dir / "dispatch-state.json"
        return journal, state, self._witness_ports.authorization

    def initialize(self) -> dict[str, Any]:
        """Create an empty, witnessed store exactly once before any invocation.

        Returns
        -------
        dict[str, Any]
            Signed initial authorization checkpoint suitable for independent
            retention. It proves a recorded initial state, not host custody.

        Raises
        ------
        VerificationError
            If a prior store or partial initialization already exists.
        """
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with _locked(self.state_dir / "dispatch.lock"):
            self._check_witness_pins()
            if set(item.name for item in self.state_dir.iterdir()) != {"dispatch.lock"}:
                _refuse("dispatch store must be initialized in an empty directory")
            journal, path, witness = self._paths()
            root = tree_root(self.workspace)
            append_history(
                journal,
                {
                    "kind": "dispatch-created",
                    "configurationDigest": self._configuration_digest,
                    "beforeRoot": root,
                },
            )
            checkpoint = witness.checkpoint(journal)
            verify_checkpoint(read_history(journal), checkpoint, self._witness_ports.public_key)
            state = {
                "format": STATE_DOMAIN,
                "configuration": self._configuration,
                "phase": "ready",
                "beforeRoot": root,
                "checkpoint": checkpoint,
                "grant": None,
                "prior": None,
                "priorCheckpoint": None,
                "result": None,
                "packet": None,
            }
            _save(path, _envelope(state, self.observer_key, STATE_DOMAIN))
            return checkpoint

    def _read(self) -> dict[str, Any]:
        """Authenticate durable state and refuse missing or inconsistent data."""
        journal, path, witness = self._paths()
        if not path.is_file() or (
            isinstance(witness, Witness) and not witness.state_path.is_file()
        ):
            _refuse("dispatch state or retained authorization witness is missing")
        state = _state_payload(
            strict_loads(path.read_bytes()), self.observer_key.public_hex
        )
        if state["configuration"] != self._configuration_payload():
            _refuse("dispatch configuration differs from the retained action")
        entries = read_history(journal)
        verify_checkpoint(
            entries, witness.latest_checkpoint(journal), self._witness_ports.public_key
        )
        verify_checkpoint(entries, state["checkpoint"], self._witness_ports.public_key)
        if self._retained_authorization_head is not None:
            _check_prefix(
                entries, self._retained_authorization_head, self._witness_ports.public_key
            )
        self._check_phase(state, entries)
        return state

    def _check_phase(
        self, state: dict[str, Any], entries: list[dict[str, Any]]
    ) -> None:
        """Require exact journal populations for ready, pending, or completed states."""
        initial = {
            "kind": "dispatch-created",
            "configurationDigest": self._configuration_digest,
            "beforeRoot": state["beforeRoot"],
        }
        if not entries or entries[0]["event"] != initial:
            _refuse("dispatch initialization differs from the retained journal")
        phases = {"ready": 1, "pending": 2, "complete": 3}
        if state["phase"] not in phases or len(entries) != phases[state["phase"]]:
            _refuse("dispatch state differs from the retained journal phase")
        if state["phase"] == "ready":
            self._ready_files(state)

    def _ready_files(self, state: dict[str, Any]) -> None:
        """Refuse an unrecorded effect or incomplete native preparation."""
        if any(
            state[key] is not None
            for key in ("grant", "prior", "priorCheckpoint", "result", "packet")
        ):
            _refuse("ready dispatch state contains an effect record")
        if (self.state_dir / "history.jsonl").exists() or (
            self.state_dir / "witness-ledger.jsonl"
        ).exists():
            _refuse("dispatch preparation is incomplete; operator recovery required")
        if tree_root(self.workspace) != state["beforeRoot"]:
            _refuse("workspace changed outside the protected dispatcher")

    def write(
        self, request: ActionRequest, grant: Mapping[str, Any], content: bytes
    ) -> WriteResult:
        """Authenticate a socket invocation, apply it once, or replay a durable result.

        Parameters
        ----------
        request : ActionRequest
            Exact consumer-configured action; caller-selected substitutions are
            rejected even when another issuer would sign them.
        grant : Mapping[str, Any]
            Signed exact grant. The trusted host clock, not a wire timestamp,
            determines validity. Cached retries still require a valid grant.
        content : bytes
            Exact replacement bytes. They are hashed before any native effect.

        Returns
        -------
        WriteResult
            One native result. ``replayed`` is true only when a previously
            completed, durable result was authenticated without another write.

        Raises
        ------
        VerificationError
            For changed identity, content, issuer, grant, clock, retained state,
            workspace, or a pending ambiguous effect. Native storage exceptions
            propagate and do not convert incomplete work into success.
        """
        if request != self.expected_request:
            _refuse("invocation differs from the expected action")
        self._check_witness_pins()
        _content(request, content)
        candidate = strict_loads(canonical(dict(grant)))
        verify_grant(candidate, request, self.policy, now=self.clock())
        if not self.state_dir.is_dir():
            _refuse("dispatch state or retained authorization witness is missing")
        with _locked(self.state_dir / "dispatch.lock"):
            state = self._read()
            reference = self.clock()
            verify_grant(candidate, request, self.policy, now=reference)
            if state["phase"] == "pending":
                _refuse("write outcome unresolved; operator recovery required")
            if state["phase"] == "complete":
                return self._replay(state, candidate, reference)
            return self._execute(state, candidate, content)

    def _native(self) -> tuple[Broker, WitnessPort]:
        """Construct the native interval through the selected public witness port."""
        witness = self._witness_ports.native
        broker = Broker(
            self.workspace,
            self.state_dir / "history.jsonl",
            {
                "intervalId": self.expected_request.run_id,
                "scope": "/work",
                "operation": "write-file",
            },
            self.observer_key,
            witness,
        )
        return broker, witness

    def _retain_receipts(self) -> None:
        """Save verified public proof bytes without touching a remote private log."""
        history = self.state_dir / "history.jsonl"
        submitted = history.read_bytes()
        raw = self._witness_ports.native.receipt_log(history)
        if history.read_bytes() != submitted:
            _refuse("native history changed during receipt retention")
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_RECEIPTS:
            _refuse("native witness receipt proof exceeds its finite limit")
        path = self.state_dir / "witness-ledger.jsonl"
        descriptor, name = tempfile.mkstemp(prefix=".witness-receipts-", dir=self.state_dir)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            receipts = read_ledger(temporary, self._witness_ports.public_key)
            entries = read_history(history)
            preimage = entries[0]["event"]["commitment"]["preimage"]
            found = [
                receipt for receipt in receipts
                if receipt["intervalId"] == self.expected_request.run_id
                and receipt["observerKey"] == self.observer_key.public_hex
                and receipt["authorityDigest"] == preimage["authorityDigest"]
                and receipt["checkpoint"]["count"] == len(entries)
                and receipt["checkpoint"]["head"] == entries[-1]["hash"]
            ]
            if len(found) != 1:
                _refuse("native witness receipt proof does not bind the current history")
            if path.exists():
                previous = path.read_bytes()
                if not raw.startswith(previous):
                    _refuse("native witness receipt proof does not extend its retained bytes")
                if raw == previous:
                    return
            os.replace(temporary, path)
            _sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _prepare(
        self, state: dict[str, Any], grant: dict[str, Any], broker: Broker
    ) -> AuthorizedBroker:
        """Durably witness the exact grant relation before the native effect path."""
        begun = broker.begin()
        verify_checkpoint(
            read_history(self.state_dir / "history.jsonl"),
            begun["checkpoint"],
            self._witness_ports.public_key,
        )
        self._retain_receipts()
        if begun["commitment"]["preimage"]["beforeRoot"] != state["beforeRoot"]:
            _refuse("native before root differs from the retained initialization")
        reference = self.clock()
        action = verify_grant(grant, self.expected_request, self.policy, now=reference)
        prior_payload = {
            "profile": PRIOR_DOMAIN,
            "configurationDigest": self._configuration_digest,
            "grantDigest": action.grant_digest,
            "request": asdict(self.expected_request),
            "nativeCommitmentDigest": digest(
                "probity-prior-commitment-v0",
                {key: begun["commitment"][key] for key in ("preimage", "committedAt")},
            ),
            "nativeStartCheckpoint": begun["checkpoint"],
            "authorizedAt": reference.isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
        }
        prior = _envelope(prior_payload, self.observer_key, PRIOR_DOMAIN)
        journal, path, witness = self._paths()
        append_history(journal, {"kind": "grant-before-dispatch", "prior": prior})
        checkpoint = witness.checkpoint(journal)
        verify_checkpoint(read_history(journal), checkpoint, self._witness_ports.public_key)
        state.update(
            phase="pending",
            grant=grant,
            prior=prior,
            priorCheckpoint=checkpoint,
            checkpoint=checkpoint,
        )
        _save(path, _envelope(state, self.observer_key, STATE_DOMAIN))

        def dispatch_clock() -> datetime:
            """Refuse a backwards clock before the already witnessed action."""
            current = self.clock()
            verify_grant(grant, self.expected_request, self.policy, now=current)
            if current < reference:
                _refuse("dispatch clock precedes the witnessed authorization")
            return current

        return AuthorizedBroker(
            broker, grant, self.policy, self.expected_request, clock=dispatch_clock
        )

    def _execute(
        self, state: dict[str, Any], grant: dict[str, Any], content: bytes
    ) -> WriteResult:
        """Complete the native effect and only then persist a reusable response."""
        broker, _ = self._native()
        authorized = self._prepare(state, grant, broker)
        self._check_witness_pins()
        result = authorized.write(self.expected_request, content)
        packet = authorized.seal()
        self._retain_receipts()
        journal, path, witness = self._paths()
        _save(self.state_dir / "packet.json", packet)
        append_history(
            journal,
            {
                "kind": "dispatch-completed",
                "packetDigest": digest("probity-protected-dispatch-packet-v0", packet),
                "result": asdict(result),
            },
        )
        checkpoint = witness.checkpoint(journal)
        verify_checkpoint(read_history(journal), checkpoint, self._witness_ports.public_key)
        state.update(
            phase="complete",
            packet=packet,
            result=asdict(result),
            checkpoint=checkpoint,
        )
        _save(path, _envelope(state, self.observer_key, STATE_DOMAIN))
        return result

    def _replay(
        self, state: dict[str, Any], candidate: dict[str, Any], reference: datetime
    ) -> WriteResult:
        """Authenticate the completed result, retained order, and target tree."""
        if candidate != state["grant"]:
            _refuse("retry grant differs from the completed action")
        self._retain_receipts()
        completed_at = datetime.fromisoformat(
            state["packet"]["authorizationBinding"]["payload"]["authorizedAt"].replace(
                "Z", "+00:00"
            )
        )
        if reference < completed_at:
            _refuse("retry clock precedes the completed dispatch")
        _verify_complete(
            self.state_dir,
            state,
            self.expected_request,
            self.policy,
            self.observer_key.public_hex,
            self._witness_ports.public_key,
            self.workspace,
        )
        return WriteResult(**{**state["result"], "replayed": True})

    def retained_head(self) -> dict[str, Any]:
        """Export an authenticated current checkpoint for separate retention."""
        if not self.state_dir.is_dir():
            _refuse("dispatch state or retained authorization witness is missing")
        with _locked(self.state_dir / "dispatch.lock"):
            return self._read()["checkpoint"]


def _verify_prior(
    state: dict[str, Any],
    packet: dict[str, Any],
    request: ActionRequest,
    policy: GrantPolicy,
    observer: str,
) -> None:
    """Authenticate exact grant/native-begin ordering without upgrading custody."""
    prior = _authenticated(state["prior"], observer, PRIOR_DOMAIN)
    required = {
        "profile",
        "configurationDigest",
        "grantDigest",
        "request",
        "nativeCommitmentDigest",
        "nativeStartCheckpoint",
        "authorizedAt",
    }
    if set(prior) != required or prior["profile"] != PRIOR_DOMAIN:
        _refuse("prior authorization has unexpected fields")
    reference = datetime.fromisoformat(prior["authorizedAt"].replace("Z", "+00:00"))
    action = verify_grant(state["grant"], request, policy, now=reference)
    native = {key: packet["commitment"][key] for key in ("preimage", "committedAt")}
    expected = {
        "profile": PRIOR_DOMAIN,
        "configurationDigest": digest(CONFIG_DOMAIN, state["configuration"]),
        "grantDigest": action.grant_digest,
        "request": asdict(request),
        "nativeCommitmentDigest": digest("probity-prior-commitment-v0", native),
        "nativeStartCheckpoint": packet["startCheckpoint"],
        "authorizedAt": prior["authorizedAt"],
    }
    if (
        prior != expected
        or not packet["commitment"]["committedAt"]
        <= prior["authorizedAt"]
        <= packet["authorizationBinding"]["payload"]["authorizedAt"]
    ):
        _refuse("prior authorization differs from the native dispatch relation")


def _verify_complete(
    directory: Path,
    state: dict[str, Any],
    request: ActionRequest,
    policy: GrantPolicy,
    observer: str,
    witness: str,
    workspace: Path | None,
) -> dict[str, Any]:
    """Cross-check the completed authorization journal with the native packet."""
    packet = state["packet"]
    if (
        not isinstance(packet, dict)
        or strict_loads((directory / "packet.json").read_bytes()) != packet
    ):
        _refuse("retained native packet differs from the completed result")
    if (
        packet["claim"]["beforeRoot"] != state["beforeRoot"]
        or packet["commitment"]["preimage"]["beforeRoot"] != state["beforeRoot"]
    ):
        _refuse("native before root differs from the retained initialization")
    entries = read_history(directory / "authorization.jsonl")
    verify_checkpoint(entries[:2], state["priorCheckpoint"], witness)
    expected = {
        "kind": "dispatch-completed",
        "packetDigest": digest("probity-protected-dispatch-packet-v0", packet),
        "result": state["result"],
    }
    if (
        entries[1]["event"]
        != {"kind": "grant-before-dispatch", "prior": state["prior"]}
        or entries[-1]["event"] != expected
    ):
        _refuse("authorization journal differs from the completed result")
    _verify_prior(state, packet, request, policy, observer)
    prior_checkpoint = {
        key: state["prior"]["payload"]["nativeStartCheckpoint"][key]
        for key in ("count", "head", "keyid", "signature")
    }
    verify_checkpoint(
        read_history(directory / "history.jsonl")[:1], prior_checkpoint, witness
    )
    verify_ledger_receipts(
        directory / "witness-ledger.jsonl",
        packet["startCheckpoint"],
        packet["checkpoint"],
        witness,
    )
    dispatch = datetime.fromisoformat(
        packet["authorizationBinding"]["payload"]["authorizedAt"].replace("Z", "+00:00")
    )
    verified = verify_authorized_packet(
        state["grant"],
        request,
        policy,
        packet,
        directory / "history.jsonl",
        observer,
        witness,
        now=dispatch,
        workspace=workspace,
    )
    write = packet["claim"]["writes"][0]
    result = {
        "request_id": request.request_id,
        "path": request.target_path,
        "before_root": write["beforeRoot"],
        "after_root": write["afterRoot"],
        "replayed": False,
    }
    if state["result"] != result:
        _refuse("completed response differs from the recorded effect")
    return verified


def verify_dispatch_bundle(
    directory: Path,
    expected_request: ActionRequest,
    policy: GrantPolicy,
    observer_key: str,
    witness_key: str,
    retained_authorization_head: dict[str, Any],
    *,
    workspace: Path | None = None,
    execution_digest: str | None = None,
    decision_digest: str | None = None,
) -> dict[str, Any]:
    """Verify the witnessed grant relation and exactly one completed native effect.

    Parameters
    ----------
    directory : Path
        Retained host-side dispatch bundle. Candidate key files are not trust
        anchors; all pins and the retained head are selected separately.
    expected_request, policy, observer_key, witness_key
        Exact consumer action, issuer policy, and distinct role key pins.
    retained_authorization_head : dict[str, Any]
        Authorization checkpoint acquired outside the current candidate. It
        detects rollback only as far as that externally retained prefix.
    workspace : Path | None, optional
        If supplied, compare current durable target bytes to the native claim.
    execution_digest, decision_digest : str | None, optional
        Separately selected launch and decision bindings. A present decision
        digest must match; this generic verifier does not replay its semantics.

    Returns
    -------
    dict[str, Any]
        Combined authorization/native verification and the signed prior grant
        relation. Local witness order is authenticated; wall-clock truth,
        independent operation, complete effect capture, and production custody
        remain separate questions.
    """
    if len({policy.issuer_key, observer_key, witness_key}) != 3:
        _refuse("issuer, observer, and witness keys must differ")
    state = _state_payload(
        strict_loads((directory / "dispatch-state.json").read_bytes()), observer_key
    )
    configured = {
        "request": asdict(expected_request),
        "policy": asdict(policy),
        "observerKey": observer_key,
        "witnessKey": witness_key,
        "executionDigest": execution_digest,
        **_decision_configuration(decision_digest),
    }
    if state.get("configuration") != configured or state.get("phase") != "complete":
        _refuse("dispatch bundle differs from the expected completed action")
    entries = read_history(directory / "authorization.jsonl")
    if len(entries) != 3:
        _refuse("completed authorization history has an invalid population")
    verify_checkpoint(entries, state["checkpoint"], witness_key)
    _check_prefix(entries, retained_authorization_head, witness_key)
    initial = {
        "kind": "dispatch-created",
        "configurationDigest": digest(CONFIG_DOMAIN, configured),
        "beforeRoot": state["beforeRoot"],
    }
    if entries[0]["event"] != initial:
        _refuse("dispatch initialization differs from the retained journal")
    verified = _verify_complete(
        directory, state, expected_request, policy, observer_key, witness_key, workspace
    )
    return {
        **verified,
        "priorAuthorization": state["prior"],
        "orderingEvidence": "local-witnessed-grant-before-host-dispatch",
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
    }


def _decode_request(payload: Any) -> tuple[ActionRequest, dict[str, Any], bytes]:
    """Decode only the bounded exact socket request profile."""
    if not isinstance(payload, dict) or set(payload) != {
        "request",
        "grant",
        "contentHex",
    }:
        _refuse("protected socket request has unexpected fields")
    if not isinstance(payload["request"], dict) or set(payload["request"]) != set(
        ActionRequest.__dataclass_fields__
    ):
        _refuse("protected socket action has unexpected fields")
    if not isinstance(payload["grant"], dict) or not isinstance(
        payload["contentHex"], str
    ):
        _refuse("protected socket request fields have invalid types")
    text = payload["contentHex"]
    if len(text) % 2 or any(character not in "0123456789abcdef" for character in text):
        _refuse("protected socket content must use lowercase hexadecimal bytes")
    return ActionRequest(**payload["request"]), payload["grant"], bytes.fromhex(text)


class _ProtectedHandler(socketserver.StreamRequestHandler):
    """Reject malformed input before invoking the host-held action dispatcher."""

    def handle(self) -> None:
        self.connection.settimeout(2)
        try:
            raw = self.rfile.readline(MAX_REQUEST + 1)
            if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                _refuse("protected socket request missing or oversized")
            request, grant, content = _decode_request(strict_loads(raw[:-1]))
            result = self.server.dispatcher.write(request, grant, content)  # type: ignore[attr-defined]
            response = {
                "ok": True,
                "replayed": result.replayed,
                "afterRoot": result.after_root,
            }
        except RecursionError:
            response = {
                "ok": False,
                "error": "protected socket request exceeds structural limits",
            }
        except (ValueError, OSError) as exc:
            response = {"ok": False, "error": str(exc)}
        try:
            self.wfile.write(canonical(response) + b"\n")
        except OSError:
            LOGGER.warning("protected dispatch response channel closed")


class ProtectedWriteServer(socketserver.UnixStreamServer):
    """Expose only exact authorized dispatch through one serial Unix socket.

    Parameters
    ----------
    path : Path
        New socket path outside the watched workspace and protected state.
    dispatcher : ProtectedDispatcher
        Host-owned initialized dispatcher. No wire operation provides native
        broker access, workspace access, signer material, arbitrary reference
        clocks, state initialization, or operator recovery.
    """

    def __init__(self, path: Path, dispatcher: ProtectedDispatcher) -> None:
        self.dispatcher = dispatcher
        super().__init__(str(path), _ProtectedHandler)
