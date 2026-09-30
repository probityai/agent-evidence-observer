"""A bounded file-write broker with before/after observations.

This prototype records calls made through the broker and detects durable byte
changes in its workspace. It does not launch or isolate an agent. Its output
therefore uses ``PEER`` witness scope; a host-side isolated runner is the next
implementation gate before a ``below-observed`` claim can be made.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import SigningKey, VerificationError, canonical, digest
from .history import Witness, append_history, read_history, unresolved_intents, verify_checkpoint

LOGGER = logging.getLogger(__name__)


class CoverageError(ValueError):
    """A requested write or workspace state falls outside the declared scope."""


@dataclass(frozen=True)
class WriteResult:
    """One broker request's observed durable state transition.

    Attributes
    ----------
    request_id : str
        Caller-supplied idempotency key for this interval.
    path : str
        Normalized path beneath the authority's literal scope.
    before_root, after_root : str
        Content-tree roots on either side of the accepted write.
    replayed : bool
        True if this result was returned for a repeated, identical request.
    """

    request_id: str
    path: str
    before_root: str
    after_root: str
    replayed: bool = False


def utc_now() -> str:
    """Return a UTC timestamp in one lexically ordered second-resolution form."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tree_manifest(workspace: Path) -> dict[str, str]:
    """Hash every regular file under a workspace, refusing symlinks.

    Parameters
    ----------
    workspace : Path
        Root whose final durable file contents are the coverage population.

    Returns
    -------
    dict[str, str]
        Relative POSIX file paths mapped to SHA-256 content digests.

    Raises
    ------
    CoverageError
        If a symbolic link or non-regular file prevents a complete walk.

    Notes
    -----
    This snapshots file bytes at call boundaries. It cannot report transient
    intermediate writes, reads, file modes, network traffic, or open handles.
    """
    manifest: dict[str, str] = {}
    for parent, directories, files in os.walk(workspace, followlinks=False):
        parent_path = Path(parent)
        for name in directories + files:
            candidate = parent_path / name
            if candidate.is_symlink():
                raise CoverageError("workspace contains a symbolic link")
        for name in files:
            candidate = parent_path / name
            if not candidate.is_file():
                raise CoverageError("workspace contains a non-regular file")
            relative = candidate.relative_to(workspace).as_posix()
            if not relative.isascii():
                raise CoverageError("workspace path is outside the ASCII profile")
            manifest[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return manifest


def tree_root(workspace: Path) -> str:
    """Return the domain-separated root of :func:`tree_manifest`."""
    return digest("probity-file-tree-v0", tree_manifest(workspace))


def _path_under_scope(scope: str, path: str) -> str:
    """Validate a literal path and return its workspace-relative spelling."""
    if not path.isascii() or not path.startswith("/") or "\x00" in path:
        raise CoverageError("write path must be an ASCII absolute path")
    if any(part in ("", ".", "..") for part in path[1:].split("/")):
        raise CoverageError("write path is not normalized")
    prefix = scope.rstrip("/") + "/"
    if not path.startswith(prefix):
        raise CoverageError("write path is outside the authorized scope")
    return path[len(prefix):]


def _atomic_write(target: Path, content: bytes) -> None:
    """Replace one existing or new file and flush the new bytes and directory."""
    if target.is_symlink() or target.is_dir() or not target.parent.is_dir():
        raise CoverageError("write target or parent is not a regular path")
    if any(parent.is_symlink() for parent in target.parents):
        raise CoverageError("write target has a symbolic-link parent")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".observer-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class Broker:
    """Produce one signed interval and a separately witnessed hash-chain head.

    Parameters
    ----------
    workspace : Path
        Existing directory containing the durable file-byte population.
    history_path : Path
        New, empty JSONL file outside ``workspace``. One broker owns it.
    authority : dict[str, str]
        Explicit ``intervalId``, literal absolute ``scope``, and
        ``operation: write-file``. Its canonical digest is fixed before the
        first request; caller changes afterwards cannot change this instance.
    observer_key : SigningKey
        Signs the prior commitment and final bounded claim.
    witness : Witness
        Signs history heads before any write and after the interval seals.

    Notes
    -----
    The caller is responsible for running an actual agent under a separate
    privilege boundary. Until that exists, the emitted ``witnessScope`` is
    always ``PEER`` regardless of how the caller describes its deployment.
    """

    def __init__(
        self,
        workspace: Path,
        history_path: Path,
        authority: dict[str, str],
        observer_key: SigningKey,
        witness: Witness,
    ) -> None:
        self.workspace = workspace.resolve(strict=True)
        self.history_path = history_path.resolve()
        self.authority = dict(authority)
        self.observer_key = observer_key
        self.witness = witness
        self._check_configuration()
        self._authority_digest = digest("probity-authority-v0", self.authority)
        self._started = False
        self._sealed = False
        self._expected_root = ""
        self._begin: dict[str, Any] = {}
        self._start_checkpoint: dict[str, Any] = {}
        self._results: dict[str, tuple[str, str, WriteResult]] = {}
        self._known_gaps: list[str] = []

    def _check_configuration(self) -> None:
        if not self.workspace.is_dir():
            raise CoverageError("workspace must be an existing directory")
        if self.history_path.is_relative_to(self.workspace):
            raise CoverageError("history must be outside the observed workspace")
        if self.history_path == self.witness.state_path.resolve():
            raise CoverageError("history and witness state must use different files")
        if self.witness.state_path.resolve().is_relative_to(self.workspace):
            raise CoverageError("witness state must be outside the observed workspace")
        if self.witness.signing_key.public_hex == self.observer_key.public_hex:
            raise CoverageError("observer and witness must use different keys")
        if self.history_path.exists() and self.history_path.stat().st_size:
            raise CoverageError("interval history must start empty")
        required = {"intervalId", "scope", "operation"}
        measured = {"probeSha256", "interpreterSha256", "bwrapSha256", "launchPolicySha256", "observerBuildDigest", "beforeRoot", "expiresAt"}
        if not required <= set(self.authority) or set(self.authority) - required not in (set(), measured) or self.authority["operation"] != "write-file":
            raise CoverageError("authority must name intervalId, scope, and write-file")
        scope = self.authority["scope"]
        if not scope.isascii() or not scope.startswith("/") or scope.endswith("/") or any(
            part in ("", ".", "..") for part in scope[1:].split("/")
        ):
            raise CoverageError("authority scope must be a normalized absolute path")
        canonical(self.authority)
        if measured <= set(self.authority):
            hashes = measured - {"expiresAt"}
            if any(len(self.authority[key]) != 64 or any(char not in "0123456789abcdef" for char in self.authority[key]) for key in hashes):
                raise CoverageError("measured authority has an invalid digest")
            try:
                datetime.strptime(self.authority["expiresAt"], "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                raise CoverageError("measured authority needs a UTC expiry")

    def abort(self, reason: str) -> dict[str, Any]:
        """Witness an incomplete interval when launch or boundary checks fail."""
        self._require_active()
        self._require_resolved_history()
        if reason not in {"isolation setup failed", "boundary probes failed"}:
            raise CoverageError("unknown abort reason")
        event = {"kind": "incomplete", "reason": reason, "requestIds": []}
        append_history(self.history_path, event)
        self._sealed = True
        return {
            "status": "incomplete",
            "event": event,
            "startCheckpoint": self._start_checkpoint,
            "checkpoint": self.witness.checkpoint(self.history_path),
        }

    def begin(self) -> dict[str, Any]:
        """Fix authority and before-state, then witness the commitment first.

        Returns
        -------
        dict[str, Any]
            Signed commitment and first independent-key checkpoint. The
            sequence makes later writes distinguishable from precommitted
            fields, but clock truth still depends on the witness operator.
        """
        if self._started:
            raise CoverageError("interval has already begun")
        if "expiresAt" in self.authority and self.authority["expiresAt"] <= utc_now():
            raise CoverageError("measured authority has expired")
        self._expected_root = tree_root(self.workspace)
        if "beforeRoot" in self.authority and self.authority["beforeRoot"] != self._expected_root:
            raise CoverageError("measured authority before root differs from workspace")
        preimage = {
            "authorityDigest": self._authority_digest,
            "beforeRoot": self._expected_root,
            "intervalId": self.authority["intervalId"],
            "witnessNonce": secrets.token_hex(32),
        }
        payload = {"preimage": preimage, "committedAt": utc_now()}
        self._begin = {
            **payload,
            "keyid": self.observer_key.public_hex,
            "signature": self.observer_key.sign("probity-prior-commitment-v0", payload),
        }
        append_history(self.history_path, {
            "kind": "begin",
            "commitmentDigest": digest("probity-prior-commitment-v0", payload),
            "commitment": self._begin,
        })
        self._start_checkpoint = self.witness.checkpoint(self.history_path)
        self._started = True
        return {"commitment": self._begin, "checkpoint": self._start_checkpoint}

    def write(self, request_id: str, path: str, content: bytes) -> WriteResult:
        """Mediate a file replacement and record each accepted or denied call.

        An identical idempotency key repeats the prior result without applying
        the effect twice; reuse with different bytes or path is refused. A
        success response follows durable file replacement and journal append.
        """
        self._require_active()
        self._require_resolved_history()
        if not request_id or not request_id.isascii():
            raise CoverageError("request id must be nonempty ASCII")
        if not isinstance(content, bytes):
            self._deny(request_id, path, "write content must be bytes")
            raise CoverageError("write content must be bytes")
        content_digest = hashlib.sha256(content).hexdigest()
        if request_id in self._results:
            return self._retry(request_id, path, content_digest)
        intent_written = False
        try:
            relative = _path_under_scope(self.authority["scope"], path)
            self._check_unchanged()
            before_root = self._expected_root
            append_history(
                self.history_path,
                {
                    "kind": "write-intent",
                    "requestId": request_id,
                    "path": path,
                    "contentDigest": content_digest,
                    "beforeRoot": before_root,
                },
            )
            intent_written = True
            _atomic_write(self.workspace / relative, content)
            after_root = tree_root(self.workspace)
        except CoverageError as exc:
            if intent_written:
                raise CoverageError("write outcome unresolved; recover incomplete interval") from exc
            self._deny(request_id, path, str(exc))
            if str(exc) in {"workspace changed outside the broker", "workspace contains a symbolic link", "workspace contains a non-regular file"}:
                self._record_gap(str(exc))
            raise
        event = {
            "kind": "write",
            "requestId": request_id,
            "path": path,
            "contentDigest": content_digest,
            "beforeRoot": before_root,
            "afterRoot": after_root,
        }
        append_history(self.history_path, event)
        self._expected_root = after_root
        result = WriteResult(request_id, path, before_root, after_root)
        self._results[request_id] = (path, content_digest, result)
        return result

    def _retry(self, request_id: str, path: str, content_digest: str) -> WriteResult:
        prior_path, prior_digest, result = self._results[request_id]
        if (path, content_digest) != (prior_path, prior_digest):
            self._deny(request_id, path, "idempotency key reused with different request")
            raise CoverageError("idempotency key reused with different request")
        try:
            self._check_unchanged()
        except CoverageError as exc:
            self._deny(request_id, path, str(exc))
            self._record_gap(str(exc))
            raise
        append_history(self.history_path, {"kind": "retry", "requestId": request_id, "path": path})
        return WriteResult(result.request_id, result.path, result.before_root, result.after_root, replayed=True)

    def _check_unchanged(self) -> None:
        if tree_root(self.workspace) != self._expected_root:
            raise CoverageError("workspace changed outside the broker")

    def _deny(self, request_id: str, path: str, reason: str) -> None:
        logged_path = path if path.isascii() else "non-ascii-sha256:" + hashlib.sha256(path.encode("utf-8", errors="surrogatepass")).hexdigest()
        append_history(self.history_path, {"kind": "denied", "requestId": request_id, "path": logged_path, "reason": reason})
        LOGGER.warning("broker denied request %s: %s", request_id, reason)

    def _require_active(self) -> None:
        if not self._started or self._sealed:
            raise CoverageError("interval must be open for writes")

    def _require_resolved_history(self) -> None:
        if unresolved_intents(read_history(self.history_path)):
            raise CoverageError("unresolved write intent; interval cannot be sealed")

    def _record_gap(self, reason: str) -> None:
        if reason not in self._known_gaps:
            self._known_gaps.append(reason)
            append_history(self.history_path, {"kind": "gap", "reason": reason})
            LOGGER.warning("observer coverage gap: %s", reason)

    def seal(self) -> dict[str, Any]:
        """Sign a bounded claim and witness its complete event history.

        A changed tree, symlink, or unreadable tree is recorded as a known gap.
        ``coverage.noDetectedGap`` is true only when no such gap was seen; it
        never proves absence of effects between snapshots. The history and
        checkpoint are returned so an offline verifier can recompute them.
        """
        self._require_active()
        self._require_resolved_history()
        try:
            self._check_unchanged()
        except CoverageError as exc:
            self._record_gap(str(exc))
        writes = [entry["event"] for entry in read_history(self.history_path) if entry["event"]["kind"] == "write"]
        claim = {
            "format": "probity-observer-prototype-v0",
            "intervalId": self.authority["intervalId"],
            "authorityDigest": self._authority_digest,
            "beforeRoot": self._begin["preimage"]["beforeRoot"],
            "afterRoot": self._expected_root,
            "writes": writes,
            "coverage": {
                "scope": self.authority["scope"],
                "observedPopulation": "broker-write-calls-with-valid-request-id",
                "noDetectedGap": not self._known_gaps,
                "knownGaps": self._known_gaps,
                "unmediatedEffects": "not-established",
            },
            "witnessScope": "PEER",
            "doesNotAssert": ["reads", "transient-writes", "file-modes", "network-effects", "host-operator-independence"],
            "sealedAt": utc_now(),
        }
        append_history(self.history_path, {"kind": "seal", "claimDigest": digest("probity-claim-v0", claim)})
        final_checkpoint = self.witness.checkpoint(self.history_path)
        self._sealed = True
        return {
            "authority": self.authority,
            "commitment": self._begin,
            "startCheckpoint": self._start_checkpoint,
            "claim": claim,
            "claimKeyid": self.observer_key.public_hex,
            "claimSignature": self.observer_key.sign("probity-claim-v0", claim),
            "checkpoint": final_checkpoint,
        }


def recover_interrupted(history_path: Path, workspace: Path, witness: Witness) -> dict[str, Any]:
    """Witness an incomplete interval after a broker died during a write."""
    entries = read_history(history_path)
    if not entries or entries[0]["event"]["kind"] != "begin":
        raise VerificationError("interrupted history has no begin event")
    if any(entry["event"]["kind"] in {"seal", "incomplete"} for entry in entries[1:]):
        raise VerificationError("interval already has a terminal event")
    pending = unresolved_intents(entries)
    if not pending:
        raise VerificationError("interrupted history has no unresolved write")
    prior_checkpoint = witness.latest_checkpoint(history_path)
    verify_checkpoint(entries[:1], prior_checkpoint, witness.signing_key.public_hex)
    try:
        recovery_root = tree_root(workspace)
        snapshot_error = None
    except (CoverageError, OSError) as exc:
        recovery_root = None
        snapshot_error = type(exc).__name__
    event = {
        "kind": "incomplete",
        "reason": "write outcome unresolved after interruption",
        "requestIds": [item["requestId"] for item in pending],
        "recoveryRoot": recovery_root,
        "snapshotError": snapshot_error,
    }
    append_history(history_path, event)
    return {
        "status": "incomplete",
        "event": event,
        "startCheckpoint": prior_checkpoint,
        "checkpoint": witness.checkpoint(history_path),
    }
