"""Adversarial checks for the bounded, public authorization reference profile.

The fixtures keep issuer, observer and witness keys distinct but under the same
test operator. Passing these tests establishes contract behavior, not external
custody, APS/MCP conformance, or containment of an untrusted process.
"""

from __future__ import annotations

import copy
import hashlib
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from probity_observer import (
    AdmissionPolicy,
    AdmissionStore,
    Broker,
    LedgerWitness,
    SigningKey,
    VerificationError,
)
from probity_observer.authorization import (
    BINDING_DOMAIN,
    GRANT_DOMAIN,
    PROFILE,
    ActionRequest,
    AuthorizedBroker,
    GrantPolicy,
    issue_grant,
    verify_authorized_packet,
    verify_grant,
)
from probity_observer.crypto import canonical, digest, strict_loads
from probity_observer.history import read_history

NOW = datetime(2026, 10, 1, 15, 0, tzinfo=timezone.utc)
CONTENT = b"controlled reference effect\n"
LOGGER_NAME = "probity_observer.authorization"
IDENTITY_FIELDS = (
    "run_id",
    "attempt_id",
    "request_id",
    "tenant_id",
    "principal_id",
    "tool_id",
)
REQUEST_FIELDS = (*IDENTITY_FIELDS, "target_path", "content_sha256")


@dataclass
class AuthorizedRun:
    """Own one finite write and separately pinned, same-operator signer roles."""

    root: Path
    request: ActionRequest
    issuer: SigningKey
    observer: SigningKey
    witness: LedgerWitness
    policy: GrantPolicy
    grant: dict[str, Any]
    broker: Broker

    @property
    def target(self) -> Path:
        """Return the controlled target selected by the signed request."""
        return self.broker.workspace / "result.txt"

    def authorized(self, *, now: datetime = NOW) -> AuthorizedBroker:
        """Wrap the existing broker with a deterministic grant-checking clock."""
        return AuthorizedBroker(
            self.broker, self.grant, self.policy, self.request, clock=lambda: now
        )

    def produce(self, content: bytes = CONTENT) -> dict[str, Any]:
        """Apply exactly one granted write and seal its retained history."""
        authorized = self.authorized()
        self.broker.begin()
        authorized.write(self.request, content)
        return authorized.seal()

    def verify(
        self,
        packet: dict[str, Any],
        *,
        grant: dict[str, Any] | None = None,
        request: ActionRequest | None = None,
        now: datetime = NOW,
        workspace: Path | None = None,
    ) -> dict[str, Any]:
        """Verify against caller-selected pins rather than bundle-selected keys."""
        return verify_authorized_packet(
            self.grant if grant is None else grant,
            self.request if request is None else request,
            self.policy,
            packet,
            self.broker.history_path,
            self.observer.public_hex,
            self.witness.signing_key.public_hex,
            now=now,
            workspace=workspace,
        )


def make_run(root: Path, content: bytes = CONTENT) -> AuthorizedRun:
    """Create a fresh controlled workspace, history and witness for each case.

    Parameters
    ----------
    root : Path
        Isolated test directory containing issuer/observer fixtures and logs.
    content : bytes, optional
        Exact effect bytes whose SHA-256 digest is included in the request.

    Returns
    -------
    AuthorizedRun
        A precommitted request, signed grant, pinned policy and unopened broker.
        :meth:`AuthorizedRun.produce` opens and seals this interval once.
    """
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    issuer, observer, witness_key = (SigningKey.generate() for _ in range(3))
    request = ActionRequest(
        run_id="run-1",
        attempt_id="attempt-1",
        request_id="request-1",
        tenant_id="tenant-1",
        principal_id="principal-1",
        tool_id="controlled-write-v0",
        target_path="/work/result.txt",
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
    grant = issue_grant(
        request, issuer, issued_at=NOW, expires_at=NOW + timedelta(seconds=300)
    )
    witness = LedgerWitness(root / "ledger.jsonl", witness_key, observer.public_hex)
    broker = Broker(
        workspace,
        root / "history.jsonl",
        {"intervalId": request.run_id, "scope": "/work", "operation": "write-file"},
        observer,
        witness,
    )
    return AuthorizedRun(
        root,
        request,
        issuer,
        observer,
        witness,
        GrantPolicy(issuer.public_hex),
        grant,
        broker,
    )


@pytest.fixture
def run(tmp_path: Path) -> AuthorizedRun:
    """Supply a fresh grant and empty workspace to one contract regression."""
    return make_run(tmp_path)


@pytest.fixture(autouse=True)
def fixed_native_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give synthetic grant and native interval timestamps the same test clock.

    These controlled-clock fixtures exercise chronology validation; they do not
    establish real-world timestamp truth or independent witness time.
    """
    monkeypatch.setattr(
        "probity_observer.broker.utc_now", lambda: "2026-10-01T15:00:00Z"
    )


def assert_refused(
    operation: Callable[[], Any],
    expected: str,
    caplog: pytest.LogCaptureFixture,
    *,
    run: AuthorizedRun | None = None,
) -> None:
    """Require the exact refusal, bounded warning and no disclosed grant bytes.

    Parameters
    ----------
    operation : Callable[[], Any]
        The authorization boundary expected to refuse before applying effects.
    expected : str
        Stable reason shared by the exception and authorization warning.
    caplog : pytest.LogCaptureFixture
        Pytest log capture; unrelated native broker warnings are excluded.
    run : AuthorizedRun | None, optional
        When supplied, additionally establish unchanged history and target bytes.

    Notes
    -----
    This helper deliberately compares literal messages. It does not accept a
    loosely matching substring that would hide a different refusal path.
    """
    caplog.clear()
    before_history = None
    before_target = None
    if run is not None:
        before_history = (
            run.broker.history_path.read_bytes()
            if run.broker.history_path.exists()
            else None
        )
        before_target = run.target.read_bytes() if run.target.exists() else None
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        with pytest.raises(VerificationError) as caught:
            operation()
    assert str(caught.value) == expected
    assert [
        record.message for record in caplog.records if record.name == LOGGER_NAME
    ] == [f"protected action refused: {expected}"]
    if run is not None:
        assert run.issuer.public_hex not in caplog.text
        assert run.grant["signature"] not in caplog.text
        assert (
            run.broker.history_path.read_bytes()
            if run.broker.history_path.exists()
            else None
        ) == before_history
        assert (
            run.target.read_bytes() if run.target.exists() else None
        ) == before_target


def resign_grant(run: AuthorizedRun, **changes: Any) -> dict[str, Any]:
    """Sign a changed candidate so semantic checks cannot hide behind bad crypto."""
    candidate = copy.deepcopy(run.grant)
    candidate.update(changes)
    payload = {
        name: candidate[name]
        for name in ("profile", "request", "issuedAt", "expiresAt")
    }
    candidate["signature"] = run.issuer.sign(GRANT_DOMAIN, payload)
    return candidate


def bind_packet(
    run: AuthorizedRun,
    packet: dict[str, Any],
    *,
    request: ActionRequest | None = None,
    authorized_at: str = "2026-10-01T15:00:00Z",
) -> None:
    """Produce an observer signature over a deliberately chosen native packet.

    An observer possessing its key can truthfully sign bytes that describe the
    wrong effect. These tests require the offline reader to reject that signed
    semantic mismatch rather than relying only on signature verification.
    """
    payload = {
        "profile": PROFILE,
        "grantDigest": digest(GRANT_DOMAIN, run.grant),
        "claimDigest": digest("probity-claim-v0", packet["claim"]),
        "intervalId": run.request.run_id,
        "request": asdict(run.request if request is None else request),
        "authorizedAt": authorized_at,
    }
    packet["authorizationBinding"] = {
        "payload": payload,
        "keyid": run.observer.public_hex,
        "signature": run.observer.sign(BINDING_DOMAIN, payload),
    }


class TestActionRequest:
    class TestPassingCases:
        @pytest.mark.parametrize("field", IDENTITY_FIELDS)
        @pytest.mark.parametrize("value", ["a", "A-_:./@!~", "z" * 128])
        def test_identity_boundaries(
            self, run: AuthorizedRun, field: str, value: str
        ) -> None:
            changed = replace(run.request, **{field: value})
            assert getattr(changed, field) == value

        @pytest.mark.parametrize("path", ["/work/a", "/work/a/b", "/work/" + "x" * 250])
        def test_normalized_literal_paths(self, run: AuthorizedRun, path: str) -> None:
            assert replace(run.request, target_path=path).target_path == path

        @settings(max_examples=30)
        @given(content=st.binary(max_size=256))
        def test_any_byte_digest_is_an_exact_request(self, content: bytes) -> None:
            request = ActionRequest(
                "run",
                "attempt",
                "request",
                "tenant",
                "principal",
                "tool",
                "/work/result",
                hashlib.sha256(content).hexdigest(),
            )
            assert request.content_sha256 == hashlib.sha256(content).hexdigest()

    class TestFailingCases:
        @pytest.mark.parametrize("field", IDENTITY_FIELDS)
        @pytest.mark.parametrize(
            "value",
            ["", "has space", "\n", "\x00", "\x7f", "é", "x" * 129, True, 1, None],
        )
        def test_invalid_identifier_values(
            self,
            run: AuthorizedRun,
            caplog: pytest.LogCaptureFixture,
            field: str,
            value: Any,
        ) -> None:
            assert_refused(
                lambda: replace(run.request, **{field: value}),
                f"{field} must be a nonempty printable ASCII identifier",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "path",
            [
                "/work",
                "/work/",
                "/work//a",
                "/work/./a",
                "/work/../a",
                "/other/a",
                "work/a",
                "/work/a\\b",
                "/work/a b",
                "/work/é",
                "/work/a\x00b",
                "/work/a\x7fb",
                "/work/" + "x" * 251,
                True,
                None,
            ],
        )
        def test_invalid_target_path(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, path: Any
        ) -> None:
            assert_refused(
                lambda: replace(run.request, target_path=path),
                "target_path must be a normalized literal path under /work",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "value", ["", "0" * 63, "0" * 65, "A" * 64, "g" * 64, True, 0, None]
        )
        def test_invalid_content_digest(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, value: Any
        ) -> None:
            assert_refused(
                lambda: replace(run.request, content_sha256=value),
                "content_sha256 must be a lowercase SHA-256-sized hexadecimal value",
                caplog,
                run=run,
            )


class TestGrantPolicy:
    class TestPassingCases:
        @pytest.mark.parametrize("duration", [1, 300, 3600])
        def test_policy_duration_boundaries(
            self, run: AuthorizedRun, duration: int
        ) -> None:
            policy = GrantPolicy(run.issuer.public_hex, duration)
            assert policy.issuer_key == run.issuer.public_hex
            assert policy.max_validity_seconds == duration

    class TestFailingCases:
        @pytest.mark.parametrize(
            "value", [False, True, 0, -1, 3601, 300.0, "300", None]
        )
        def test_invalid_duration(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, value: Any
        ) -> None:
            assert_refused(
                lambda: GrantPolicy(run.issuer.public_hex, value),
                "max_validity_seconds must be an integer from 1 to 3600",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "value", ["", "0" * 63, "A" * 64, "g" * 64, True, None]
        )
        def test_invalid_issuer_key(
            self, caplog: pytest.LogCaptureFixture, value: Any
        ) -> None:
            assert_refused(
                lambda: GrantPolicy(value),
                "issuer_key must be a lowercase SHA-256-sized hexadecimal value",
                caplog,
            )


class TestIssueGrant:
    class TestPassingCases:
        def test_grant_carries_exact_request_without_private_key_bytes(
            self, run: AuthorizedRun
        ) -> None:
            assert set(run.grant) == {
                "profile",
                "request",
                "issuedAt",
                "expiresAt",
                "issuerKey",
                "signature",
            }
            assert run.grant["request"] == asdict(run.request)
            assert run.grant["issuerKey"] == run.issuer.public_hex
            assert run.grant["profile"] == PROFILE
            assert run.grant["issuedAt"] == "2026-10-01T15:00:00Z"
            assert run.grant["expiresAt"] == "2026-10-01T15:05:00Z"
            assert strict_loads(canonical(run.grant)) == run.grant
            assert "private" not in canonical(run.grant).decode("ascii")

        @pytest.mark.parametrize("seconds", [1, 3600])
        def test_issuance_allows_profile_duration_boundaries(
            self, run: AuthorizedRun, seconds: int
        ) -> None:
            grant = issue_grant(
                run.request,
                run.issuer,
                issued_at=NOW,
                expires_at=NOW + timedelta(seconds=seconds),
            )
            action = verify_grant(
                grant, run.request, GrantPolicy(run.issuer.public_hex, seconds), now=NOW
            )
            assert (action.expires_at - action.issued_at).total_seconds() == seconds

        @pytest.mark.parametrize("year", [1, 9999])
        def test_four_digit_year_boundaries_round_trip(
            self, run: AuthorizedRun, year: int
        ) -> None:
            issued = datetime(year, 1, 1, tzinfo=timezone.utc)
            grant = issue_grant(
                run.request,
                run.issuer,
                issued_at=issued,
                expires_at=issued + timedelta(seconds=1),
            )
            assert grant["issuedAt"] == f"{year:04d}-01-01T00:00:00Z"
            assert (
                verify_grant(grant, run.request, run.policy, now=issued).issued_at
                == issued
            )

    class TestFailingCases:
        @pytest.mark.parametrize("field", ["issued_at", "expires_at"])
        @pytest.mark.parametrize(
            "value",
            [
                NOW.replace(tzinfo=None),
                NOW.astimezone(timezone(timedelta(hours=1))),
                "2026-10-01T15:00:00Z",
                None,
            ],
        )
        def test_non_utc_datetimes_are_refused(
            self,
            run: AuthorizedRun,
            caplog: pytest.LogCaptureFixture,
            field: str,
            value: Any,
        ) -> None:
            times = {"issued_at": NOW, "expires_at": NOW + timedelta(seconds=10)}
            times[field] = value
            assert_refused(
                lambda: issue_grant(run.request, run.issuer, **times),
                f"{field} must be a timezone-aware UTC datetime",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("field", ["issued_at", "expires_at"])
        def test_fractional_seconds_are_not_silently_discarded(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            times = {"issued_at": NOW, "expires_at": NOW + timedelta(seconds=10)}
            times[field] = times[field].replace(microsecond=1)
            assert_refused(
                lambda: issue_grant(run.request, run.issuer, **times),
                f"{field} must use UTC second precision",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("seconds", [-1, 0, 3601])
        def test_nonpositive_or_excessive_window(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, seconds: int
        ) -> None:
            assert_refused(
                lambda: issue_grant(
                    run.request,
                    run.issuer,
                    issued_at=NOW,
                    expires_at=NOW + timedelta(seconds=seconds),
                ),
                "grant validity window exceeds policy or is not positive",
                caplog,
                run=run,
            )


class TestVerifyGrant:
    class TestPassingCases:
        @pytest.mark.parametrize("seconds", [0, 1, 299])
        def test_issued_at_inclusive_and_expiry_exclusive(
            self, run: AuthorizedRun, seconds: int
        ) -> None:
            action = verify_grant(
                run.grant, run.request, run.policy, now=NOW + timedelta(seconds=seconds)
            )
            assert action.request == run.request
            assert action.issuer_key == run.policy.issuer_key
            assert action.issued_at == NOW
            assert action.expires_at == NOW + timedelta(seconds=300)
            assert action.grant_digest == digest(GRANT_DOMAIN, run.grant)

        @settings(
            max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture]
        )
        @given(seconds=st.integers(min_value=0, max_value=299))
        def test_every_in_window_second_verifies(
            self, run: AuthorizedRun, seconds: int
        ) -> None:
            assert verify_grant(
                run.grant, run.request, run.policy, now=NOW + timedelta(seconds=seconds)
            ).grant_digest == digest(GRANT_DOMAIN, run.grant)

        def test_verification_does_not_mutate_candidate(
            self, run: AuthorizedRun
        ) -> None:
            before = canonical(run.grant)
            verify_grant(run.grant, run.request, run.policy, now=NOW)
            assert canonical(run.grant) == before

    class TestFailingCases:
        @pytest.mark.parametrize("field", REQUEST_FIELDS)
        def test_all_request_identities_are_compared_to_external_expectations(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            replacement = "different"
            if field == "target_path":
                replacement = "/work/other.txt"
            if field == "content_sha256":
                replacement = "0" * 64
            expected = replace(run.request, **{field: replacement})
            assert_refused(
                lambda: verify_grant(run.grant, expected, run.policy, now=NOW),
                "grant request differs from the expected action",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("seconds", [-1, 300, 301, 86400])
        def test_outside_validity_window(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, seconds: int
        ) -> None:
            assert_refused(
                lambda: verify_grant(
                    run.grant,
                    run.request,
                    run.policy,
                    now=NOW + timedelta(seconds=seconds),
                ),
                "grant is not valid at the reference time",
                caplog,
                run=run,
            )

        def test_candidate_key_cannot_override_policy_pin(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            attacker = SigningKey.generate()
            forged = issue_grant(
                run.request,
                attacker,
                issued_at=NOW,
                expires_at=NOW + timedelta(seconds=30),
            )
            assert_refused(
                lambda: verify_grant(forged, run.request, run.policy, now=NOW),
                "grant issuer differs from the pinned issuer key",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "signature", ["", "!not-base64", "AA==", True, None, []]
        )
        def test_malformed_signature(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, signature: Any
        ) -> None:
            altered = {**run.grant, "signature": signature}
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                "grant signature does not verify under the pinned issuer key",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("field", ["request", "issuedAt", "expiresAt"])
        def test_unsigned_payload_changes_fail_signature(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            altered = copy.deepcopy(run.grant)
            if field == "request":
                altered[field]["tenant_id"] = "other-tenant"
            else:
                altered[field] = "2026-10-01T15:00:01Z"
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                "grant signature does not verify under the pinned issuer key",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "field",
            ["request", "issuedAt", "expiresAt", "profile", "signature", "issuerKey"],
        )
        def test_missing_grant_fields(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            altered = copy.deepcopy(run.grant)
            del altered[field]
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                "grant has unexpected fields",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("candidate", [None, [], b"{}", True])
        def test_nonmapping_grant(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, candidate: Any
        ) -> None:
            assert_refused(
                lambda: verify_grant(candidate, run.request, run.policy, now=NOW),
                "grant has unexpected fields",
                caplog,
                run=run,
            )

        def test_unknown_grant_fields_are_not_ignored(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            altered = {**run.grant, "allowAll": True}
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                "grant has unexpected fields",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "candidate_request", [{"unknown": "field"}, True, None, []]
        )
        def test_signed_malformed_request_is_not_accepted(
            self,
            run: AuthorizedRun,
            caplog: pytest.LogCaptureFixture,
            candidate_request: Any,
        ) -> None:
            altered = resign_grant(run, request=candidate_request)
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                "grant request differs from the expected action",
                caplog,
                run=run,
            )

        def test_signed_extra_request_member_is_rejected(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            request = {**asdict(run.request), "administrativeOverride": True}
            altered = resign_grant(run, request=request)
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                "grant request differs from the expected action",
                caplog,
                run=run,
            )

        def test_unknown_profile_even_with_valid_issuer_signature(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            altered = resign_grant(run, profile="another-protocol")
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                "grant profile is unsupported",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("field", ["issuedAt", "expiresAt"])
        @pytest.mark.parametrize(
            "value",
            [
                "2026-02-30T15:00:00Z",
                "2026-10-01T15:00:00+00:00",
                "2026-10-01T15:00:00.0Z",
                "",
                True,
                None,
            ],
        )
        def test_signed_invalid_wire_timestamp(
            self,
            run: AuthorizedRun,
            caplog: pytest.LogCaptureFixture,
            field: str,
            value: Any,
        ) -> None:
            altered = resign_grant(run, **{field: value})
            assert_refused(
                lambda: verify_grant(altered, run.request, run.policy, now=NOW),
                f"{field} must use canonical UTC second precision",
                caplog,
                run=run,
            )

        def test_policy_duration_is_stricter_than_issuer_profile(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refused(
                lambda: verify_grant(
                    run.grant,
                    run.request,
                    GrantPolicy(run.issuer.public_hex, 299),
                    now=NOW,
                ),
                "grant validity window exceeds policy or is not positive",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            ("reference", "expected"),
            [
                (NOW.replace(tzinfo=None), "now must be a timezone-aware UTC datetime"),
                (
                    NOW.astimezone(timezone(timedelta(hours=-4))),
                    "now must be a timezone-aware UTC datetime",
                ),
                (NOW.replace(microsecond=1), "now must use UTC second precision"),
                (None, "now must be a timezone-aware UTC datetime"),
            ],
        )
        def test_invalid_reference_clock(
            self,
            run: AuthorizedRun,
            caplog: pytest.LogCaptureFixture,
            reference: Any,
            expected: str,
        ) -> None:
            assert_refused(
                lambda: verify_grant(run.grant, run.request, run.policy, now=reference),
                expected,
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("value", ["é", 0.5, 2**53])
        def test_nonportable_json_values_are_refused_before_signature(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, value: Any
        ) -> None:
            candidate = copy.deepcopy(run.grant)
            candidate["request"]["tenant_id"] = value
            assert_refused(
                lambda: verify_grant(candidate, run.request, run.policy, now=NOW),
                "grant is outside the restricted JSON profile",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            ("encoded", "expected"),
            [
                (b'{"profile":"one","profile":"two"}', "duplicate JSON member"),
                (b'{ "profile": "one" }', "JSON document is not canonical"),
                (b'{"profile":"one"}\n', "JSON document is not canonical"),
            ],
        )
        def test_artifact_decode_refuses_ambiguous_bytes(
            self, caplog: pytest.LogCaptureFixture, encoded: bytes, expected: str
        ) -> None:
            with pytest.raises(VerificationError) as caught:
                strict_loads(encoded)
            assert str(caught.value) == expected
            assert [
                record for record in caplog.records if record.name == LOGGER_NAME
            ] == []


class TestAuthorizedBroker:
    class TestPassingCases:
        def test_authorization_precedes_native_write_and_effect_is_bound(
            self, run: AuthorizedRun
        ) -> None:
            packet = run.produce()
            result = run.verify(packet, workspace=run.broker.workspace)
            assert run.target.read_bytes() == CONTENT
            assert result["claim"] == packet["claim"]
            assert result["claim"]["witnessScope"] == "PEER"
            assert result["authorization"] == {
                "status": "verified",
                "profile": PROFILE,
                "grantDigest": digest(GRANT_DOMAIN, run.grant),
                "referenceTime": "2026-10-01T15:00:00Z",
                "authorizedAt": "2026-10-01T15:00:00Z",
                "orderingEvidence": "observer-attested-dispatch-time",
                "currentWorkspaceCompared": True,
            }
            assert len(result["claim"]["writes"]) == 1
            assert (
                result["claim"]["writes"][0]["contentDigest"]
                == run.request.content_sha256
            )
            assert [
                entry["event"]["kind"]
                for entry in read_history(run.broker.history_path)
            ] == ["begin", "write-intent", "write", "seal"]

        def test_exact_retry_records_one_effect_and_same_roots(
            self, run: AuthorizedRun
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            first = authorized.write(run.request, CONTENT)
            second = authorized.write(run.request, CONTENT)
            assert first.replayed is False
            assert second.replayed is True
            assert second.before_root == first.before_root
            assert second.after_root == first.after_root
            packet = authorized.seal()
            assert len(run.verify(packet)["claim"]["writes"]) == 1
            events = [
                entry["event"]["kind"]
                for entry in read_history(run.broker.history_path)
            ]
            assert events.count("write") == 1
            assert events.count("write-intent") == 1
            assert events.count("retry") == 1

        def test_wrapper_snapshots_grant_against_caller_mutation(
            self, run: AuthorizedRun
        ) -> None:
            original = copy.deepcopy(run.grant)
            authorized = run.authorized()
            run.grant["request"]["tenant_id"] = "caller-replaced-tenant"
            run.grant["signature"] = "malformed"
            run.broker.begin()
            authorized.write(run.request, CONTENT)
            packet = authorized.seal()
            result = run.verify(packet, grant=original)
            assert result["authorization"]["grantDigest"] == digest(
                GRANT_DOMAIN, original
            )

        @settings(
            max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture]
        )
        @given(content=st.binary(max_size=1024))
        def test_arbitrary_finite_effect_bytes_are_observed_and_verified(
            self, tmp_path: Path, content: bytes
        ) -> None:
            with TemporaryDirectory(dir=tmp_path) as directory:
                fixture = make_run(Path(directory), content)
                packet = fixture.produce(content)
                result = fixture.verify(packet, workspace=fixture.broker.workspace)
                assert fixture.target.read_bytes() == content
                assert (
                    result["claim"]["writes"][0]["contentDigest"]
                    == hashlib.sha256(content).hexdigest()
                )
                assert result["authorization"]["status"] == "verified"

        def test_authorized_verification_can_precede_durable_consumer_admission(
            self, run: AuthorizedRun
        ) -> None:
            store = AdmissionStore(run.root / "consumer" / "state.json")
            store.initialize(
                run.observer.public_hex, run.witness.signing_key.public_hex
            )
            policy = AdmissionPolicy(
                run.request.run_id,
                digest("probity-authority-v0", run.broker.authority),
                run.observer.public_hex,
                run.witness.signing_key.public_hex,
                run.witness.signed_head(),
            )
            packet = run.produce()
            verified = run.verify(packet, workspace=run.broker.workspace)
            admitted = store.admit(
                packet, run.broker.history_path, run.witness.state_path, policy
            )
            assert verified["authorization"]["status"] == "verified"
            assert admitted["status"] == "admitted"
            assert admitted["claimDigest"] == digest(
                "probity-claim-v0", packet["claim"]
            )
            assert strict_loads(store.state_path.read_bytes())["admissions"] == [
                admitted
            ]

    class TestFailingCases:
        @pytest.mark.parametrize("field", REQUEST_FIELDS)
        def test_changed_invocation_cannot_reach_native_write(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            value = "/work/other.txt" if field == "target_path" else "other"
            if field == "content_sha256":
                value = "0" * 64
            changed = replace(run.request, **{field: value})
            assert_refused(
                lambda: authorized.write(changed, CONTENT),
                "invocation differs from the expected action",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("content", ["text", bytearray(CONTENT), None, True])
        def test_nonbytes_are_refused_without_an_effect(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, content: Any
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            assert_refused(
                lambda: authorized.write(run.request, content),
                "protected action content must be bytes",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("content", [b"", CONTENT + b"changed", CONTENT[:-1]])
        def test_changed_actual_bytes_fail_before_dispatch(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, content: bytes
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            assert_refused(
                lambda: authorized.write(run.request, content),
                "content digest differs from the authorized action",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("seconds", [-1, 300, 301])
        def test_runtime_checks_validity_against_dispatch_clock(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, seconds: int
        ) -> None:
            authorized = run.authorized(now=NOW + timedelta(seconds=seconds))
            run.broker.begin()
            assert_refused(
                lambda: authorized.write(run.request, CONTENT),
                "grant is not valid at the reference time",
                caplog,
                run=run,
            )

        def test_expired_retry_is_refused_and_does_not_reapply_effect(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            reference = [NOW]
            authorized = AuthorizedBroker(
                run.broker,
                run.grant,
                run.policy,
                run.request,
                clock=lambda: reference[0],
            )
            run.broker.begin()
            authorized.write(run.request, CONTENT)
            reference[0] = NOW + timedelta(seconds=300)
            assert_refused(
                lambda: authorized.write(run.request, CONTENT),
                "grant is not valid at the reference time",
                caplog,
                run=run,
            )
            packet = authorized.seal()
            assert len(run.verify(packet)["claim"]["writes"]) == 1

        def test_invalid_grant_fails_at_runtime_without_an_effect(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.grant["signature"] = "AA=="
            authorized = run.authorized()
            run.broker.begin()
            assert_refused(
                lambda: authorized.write(run.request, CONTENT),
                "grant signature does not verify under the pinned issuer key",
                caplog,
                run=run,
            )

        def test_run_mismatch_is_refused_before_begin(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            request = replace(run.request, run_id="other-run")
            assert_refused(
                lambda: AuthorizedBroker(run.broker, run.grant, run.policy, request),
                "action run differs from the broker interval",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("role", ["observer", "witness"])
        def test_issuer_cannot_be_an_observer_or_witness(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, role: str
        ) -> None:
            issuer = run.observer if role == "observer" else run.witness.signing_key
            policy = GrantPolicy(issuer.public_hex)
            grant = issue_grant(
                run.request,
                issuer,
                issued_at=NOW,
                expires_at=NOW + timedelta(seconds=30),
            )
            assert_refused(
                lambda: AuthorizedBroker(run.broker, grant, policy, run.request),
                "issuer, observer, and witness keys must differ",
                caplog,
                run=run,
            )

        def test_broker_authority_mutation_is_refused_before_write(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            run.broker.authority["intervalId"] = "forged-interval"
            assert_refused(
                lambda: authorized.write(run.request, CONTENT),
                "broker authority changed from its initial commitment",
                caplog,
                run=run,
            )

        def test_preexisting_native_authority_mutation_is_not_recommitted(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.broker.authority["extraAuthority"] = "uncommitted"
            assert_refused(
                lambda: run.authorized(),
                "protected action requires the minimal /work write-file broker profile",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("role", ["observer", "witness"])
        def test_signing_key_mutation_after_configuration(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, role: str
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            if role == "observer":
                run.broker.observer_key = SigningKey.generate()
            else:
                run.witness.signing_key = SigningKey.generate()
            assert_refused(
                lambda: authorized.write(run.request, CONTENT),
                "broker signing keys changed after authorization configuration",
                caplog,
                run=run,
            )

        def test_no_effect_cannot_be_sealed_as_authorized(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            assert_refused(
                authorized.seal,
                "protected action has no completed authorized effect",
                caplog,
                run=run,
            )

        def test_native_failure_does_not_create_successful_authorization_binding(
            self,
            run: AuthorizedRun,
            caplog: pytest.LogCaptureFixture,
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()

            def fail_before_effect(*args: Any, **kwargs: Any) -> None:
                raise OSError("controlled native dispatch failure")

            monkeypatch.setattr(run.broker, "write", fail_before_effect)
            before = run.broker.history_path.read_bytes()
            with pytest.raises(OSError) as caught:
                authorized.write(run.request, CONTENT)
            assert str(caught.value) == "controlled native dispatch failure"
            assert [
                record for record in caplog.records if record.name == LOGGER_NAME
            ] == []
            assert not run.target.exists()
            assert run.broker.history_path.read_bytes() == before
            assert_refused(
                authorized.seal,
                "protected action has no completed authorized effect",
                caplog,
                run=run,
            )

        def test_write_requires_native_begin_before_effect(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            authorized = run.authorized()
            assert_refused(
                lambda: authorized.write(run.request, CONTENT),
                "protected action requires a begun native interval",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("seconds", [-1, 1])
        def test_valid_grant_with_inconsistent_dispatch_clock_refuses_before_effect(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, seconds: int
        ) -> None:
            run.grant = issue_grant(
                run.request,
                run.issuer,
                issued_at=NOW - timedelta(seconds=60),
                expires_at=NOW + timedelta(seconds=240),
            )
            authorized = run.authorized(now=NOW + timedelta(seconds=seconds))
            run.broker.begin()
            assert_refused(
                lambda: authorized.write(run.request, CONTENT),
                "authorization dispatch time is outside the native interval",
                caplog,
                run=run,
            )


def assert_native_refused(
    operation: Callable[[], Any], expected: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Require the preserved native reason and one bounded reader warning."""
    assert_refused(operation, expected, caplog)


class TestVerifyAuthorizedPacket:
    class TestPassingCases:
        def test_record_only_verification_explicitly_omits_current_workspace_check(
            self, run: AuthorizedRun
        ) -> None:
            packet = run.produce()
            run.target.write_bytes(b"later unrelated state")
            result = run.verify(packet)
            assert result["authorization"]["currentWorkspaceCompared"] is False
            assert (
                result["claim"]["writes"][0]["contentDigest"]
                == hashlib.sha256(CONTENT).hexdigest()
            )
            assert result["claim"]["doesNotAssert"] == [
                "reads",
                "transient-writes",
                "file-modes",
                "network-effects",
                "host-operator-independence",
            ]

        def test_historical_reference_time_does_not_rewrite_attested_dispatch_time(
            self, run: AuthorizedRun
        ) -> None:
            packet = run.produce()
            result = run.verify(packet, now=NOW + timedelta(seconds=299))
            assert result["authorization"]["referenceTime"] == "2026-10-01T15:04:59Z"
            assert result["authorization"]["authorizedAt"] == "2026-10-01T15:00:00Z"

        def test_stateless_reader_does_not_claim_consumer_replay_protection(
            self, run: AuthorizedRun
        ) -> None:
            packet = run.produce()
            assert run.verify(packet) == run.verify(packet)
            assert set(run.verify(packet)) == {"authorization", "claim"}

        def test_native_known_gap_remains_visible_after_authorization_verification(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            authorized.write(run.request, CONTENT)
            (run.broker.workspace / "unmediated").write_bytes(b"durable bypass")
            packet = authorized.seal()
            result = run.verify(packet)
            assert result["authorization"]["status"] == "verified"
            assert result["claim"]["coverage"]["noDetectedGap"] is False
            assert result["claim"]["coverage"]["knownGaps"] == [
                "workspace changed outside the broker"
            ]
            assert (
                "observer coverage gap: workspace changed outside the broker"
                in caplog.text
            )

    class TestFailingCases:
        def test_plain_native_packet_cannot_assert_authorization(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.broker.begin()
            run.broker.write(run.request.request_id, run.request.target_path, CONTENT)
            packet = run.broker.seal()
            assert_refused(
                lambda: run.verify(packet),
                "packet has no valid authorization binding",
                caplog,
                run=run,
            )

        def test_valid_unrelated_grant_is_not_accepted_for_existing_packet(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet = run.produce()
            unrelated = issue_grant(
                run.request,
                run.issuer,
                issued_at=NOW - timedelta(seconds=1),
                expires_at=NOW + timedelta(seconds=299),
            )
            assert verify_grant(unrelated, run.request, run.policy, now=NOW)
            assert_refused(
                lambda: run.verify(packet, grant=unrelated),
                "authorization binding differs from the grant or native claim",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("field", ["payload", "keyid", "signature"])
        def test_missing_binding_fields(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            packet = run.produce()
            del packet["authorizationBinding"][field]
            assert_refused(
                lambda: run.verify(packet),
                "packet has no valid authorization binding",
                caplog,
                run=run,
            )

        def test_unknown_binding_member_is_not_ignored(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet = run.produce()
            packet["authorizationBinding"]["override"] = True
            assert_refused(
                lambda: run.verify(packet),
                "packet has no valid authorization binding",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("value", [None, [], True, "binding"])
        def test_malformed_binding_container(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, value: Any
        ) -> None:
            packet = run.produce()
            packet["authorizationBinding"] = value
            assert_refused(
                lambda: run.verify(packet),
                "packet has no valid authorization binding",
                caplog,
                run=run,
            )

        def test_binding_key_cannot_override_consumer_pin(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet = run.produce()
            packet["authorizationBinding"]["keyid"] = SigningKey.generate().public_hex
            assert_refused(
                lambda: run.verify(packet),
                "authorization binding key differs from the pinned observer key",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("signature", ["", "AA==", "!bad", True, None, []])
        def test_invalid_binding_signature(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, signature: Any
        ) -> None:
            packet = run.produce()
            packet["authorizationBinding"]["signature"] = signature
            assert_refused(
                lambda: run.verify(packet),
                "authorization binding signature does not verify under the pinned key",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "field", ["profile", "grantDigest", "claimDigest", "intervalId", "request"]
        )
        def test_observer_signed_binding_semantic_mutation_is_rejected(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            packet = run.produce()
            binding = packet["authorizationBinding"]
            binding["payload"][field] = (
                {"tenant_id": "other"} if field == "request" else "changed"
            )
            binding["signature"] = run.observer.sign(BINDING_DOMAIN, binding["payload"])
            assert_refused(
                lambda: run.verify(packet),
                "authorization binding differs from the grant or native claim",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("payload", [None, True, [], {}, {"profile": PROFILE}])
        def test_malformed_binding_payload(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, payload: Any
        ) -> None:
            packet = run.produce()
            packet["authorizationBinding"]["payload"] = payload
            assert_refused(
                lambda: run.verify(packet),
                "authorization binding payload is malformed",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize(
            "value", [None, True, "2026-10-01T15:00:00.1Z", "2026-13-01T15:00:00Z"]
        )
        def test_invalid_dispatch_timestamp(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, value: Any
        ) -> None:
            packet = run.produce()
            packet["authorizationBinding"]["payload"]["authorizedAt"] = value
            assert_refused(
                lambda: run.verify(packet),
                "authorizedAt must use canonical UTC second precision",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("seconds", [-1, 1])
        def test_signed_dispatch_time_outside_native_interval_is_rejected(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, seconds: int
        ) -> None:
            run.grant = issue_grant(
                run.request,
                run.issuer,
                issued_at=NOW - timedelta(seconds=60),
                expires_at=NOW + timedelta(seconds=240),
            )
            packet = run.produce()
            timestamp = (NOW + timedelta(seconds=seconds)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            bind_packet(run, packet, authorized_at=timestamp)
            assert_refused(
                lambda: run.verify(packet),
                "authorization dispatch time is outside the native interval",
                caplog,
                run=run,
            )

        def test_extra_recorded_effect_is_refused_even_with_valid_binding(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            authorized = run.authorized()
            run.broker.begin()
            authorized.write(run.request, CONTENT)
            run.broker.write("ungranted-request", "/work/extra.txt", b"extra effect")
            packet = authorized.seal()
            assert len(packet["claim"]["writes"]) == 2
            assert_refused(
                lambda: run.verify(packet),
                "protected action requires exactly one recorded effect",
                caplog,
                run=run,
            )

        def test_zero_recorded_effect_is_refused_even_with_valid_binding(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.broker.begin()
            packet = run.broker.seal()
            bind_packet(run, packet)
            assert_refused(
                lambda: run.verify(packet),
                "protected action requires exactly one recorded effect",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("field", ["request_id", "target_path", "content"])
        def test_wrong_observed_effect_is_refused_even_with_observer_signature(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            native = {
                "request_id": run.request.request_id,
                "path": run.request.target_path,
                "content": CONTENT,
            }
            native[{"target_path": "path"}.get(field, field)] = {
                "request_id": "ungranted",
                "target_path": "/work/other.txt",
                "content": b"other bytes",
            }[field]
            run.broker.begin()
            run.broker.write(**native)
            packet = run.broker.seal()
            bind_packet(run, packet)
            assert_refused(
                lambda: run.verify(packet),
                "recorded effect differs from the authorized action",
                caplog,
                run=run,
            )

        @pytest.mark.parametrize("field", ["intervalId", "scope"])
        def test_other_native_authority_is_not_upgraded_by_binding(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, field: str
        ) -> None:
            authority = dict(run.broker.authority)
            authority[field] = "another-run" if field == "intervalId" else "/other"
            run.broker = Broker(
                run.broker.workspace,
                run.broker.history_path,
                authority,
                run.observer,
                run.witness,
            )
            run.broker.begin()
            run.broker.write(
                run.request.request_id, authority["scope"] + "/result.txt", CONTENT
            )
            packet = run.broker.seal()
            bind_packet(run, packet)
            assert_refused(
                lambda: run.verify(packet),
                "native authority differs from the protected action profile",
                caplog,
                run=run,
            )

        def test_changed_current_workspace_fails_when_explicitly_compared(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet = run.produce()
            run.target.write_bytes(b"current bytes no longer match")
            assert_native_refused(
                lambda: run.verify(packet, workspace=run.broker.workspace),
                "current workspace root differs from the claim",
                caplog,
            )

        @pytest.mark.parametrize("role", ["observer", "witness"])
        def test_wrong_native_key_pin_preserves_native_refusal(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture, role: str
        ) -> None:
            packet = run.produce()
            observer_key, witness_key = (
                run.observer.public_hex,
                run.witness.signing_key.public_hex,
            )
            if role == "observer":
                observer_key = SigningKey.generate().public_hex
            else:
                witness_key = SigningKey.generate().public_hex
            assert_native_refused(
                lambda: verify_authorized_packet(
                    run.grant,
                    run.request,
                    run.policy,
                    packet,
                    run.broker.history_path,
                    observer_key,
                    witness_key,
                    now=NOW,
                ),
                "claim key is not the pinned observer key"
                if role == "observer"
                else "checkpoint key is not the pinned witness key",
                caplog,
            )

        def test_native_claim_mutation_preserves_signature_refusal(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet = run.produce()
            packet["claim"]["afterRoot"] = "0" * 64
            assert_native_refused(
                lambda: run.verify(packet),
                "signature does not verify under the pinned key",
                caplog,
            )

        def test_missing_retained_seal_is_not_accepted_as_complete(
            self, run: AuthorizedRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet = run.produce()
            lines = run.broker.history_path.read_bytes().splitlines(keepends=True)
            run.broker.history_path.write_bytes(b"".join(lines[:-1]))
            assert_native_refused(
                lambda: run.verify(packet),
                "history has no final seal",
                caplog,
            )
