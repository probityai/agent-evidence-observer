"""Host admission of a result after authenticated effect and live authority."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import canonical, strict_loads
from probity_observer.ticket_service import verify_ticket_result

from probity_pydantic_recovery.common import deferred, require, sha


def effect(case: dict[str, Any], packet: dict[str, Any]) -> dict[str, Any]:
    """Authenticate the historical effect at its declared historical time."""
    require(packet["postStatus"] == packet["getStatus"] == 200, "historical-http-status")
    candidate = {key: case[key] for key in ("request", "grant", "contentHex")}
    require(packet["postRequestHex"] == canonical(candidate).hex(), "historical-post-binding")
    receipt, readback = (strict_loads(bytes.fromhex(packet[key])) for key in ("postResponseHex", "getResponseHex"))
    return verify_ticket_result(receipt, readback, ActionRequest(**case["request"]), GrantPolicy(**case["policy"]), case["serviceKey"], case["grant"], now=datetime.fromisoformat(case["historicalTime"]))


def admit(case: dict[str, Any], history: bytes, prior: dict[str, Any], live: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Require current host selection before constructing deferred results.

    A spent dispatch grant never creates permission for another POST. This
    profile releases only the authenticated already-committed native result.
    """
    call = deferred(history, case)
    checked = effect(case, prior)
    require(set(current) == {"historySha256", "grant", "serviceKey", "policy", "liveSha256", "clockTime", "targetReady"}, "current-selection-schema")
    require(current["targetReady"] is True, "current-target-not-ready")
    require(current["historySha256"] == sha(history), "current-history-binding")
    require(canonical(current["grant"]) == canonical(case["grant"]), "current-grant-binding")
    require(current["serviceKey"] == case["serviceKey"] and current["policy"] == case["policy"], "current-key-policy-binding")
    require(current["liveSha256"] == sha(canonical(live)), "current-live-binding")
    now = datetime.fromisoformat(current["clockTime"])
    verify_grant(current["grant"], ActionRequest(**case["request"]), GrantPolicy(**current["policy"]), now=now)
    verified = verify_ticket_result(live["receipt"], live, ActionRequest(**case["request"]), GrantPolicy(**current["policy"]), current["serviceKey"], current["grant"], now=now)
    require(verified == checked, "historical-live-effect-join")
    return {"status": "admitted-result-only", "toolCallId": call["tool_call_id"], "historySha256": sha(history), "priorHttpSha256": sha(canonical(prior)), "liveSha256": sha(canonical(live)), "result": checked, "dispatchPermitted": False}
