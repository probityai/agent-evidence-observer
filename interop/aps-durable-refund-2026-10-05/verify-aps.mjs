/** Local refund-record profile. It does not implement PIC or authorize a provider. */
import { readFileSync } from 'node:fs';
import {
  canonicalizeJCS, computeActionRefV2, computePayloadRefV1,
  isExactUtcMilliseconds, parseActionReferenceInputV2, verifyReceiptV1Serialized,
} from 'agent-passport-system';

/** Require host-selected identity, key ID, exact action and payload before effect. */
function verifyNative({ actionRaw, payloadChecked, approvalRaw, policy, now }) {
  if (!isExactUtcMilliseconds(now)) throw new Error('host clock is not exact UTC milliseconds');
  const resolveKey = (signer, keyId) => signer === policy.boundaryIdentity && keyId === policy.keyId
    ? policy.publicKey : undefined;
  const verified = verifyReceiptV1Serialized(approvalRaw, resolveKey, {
    expectedReceiptType: 'aps:policy-decision:v1', boundaryIdentity: policy.boundaryIdentity,
  });
  if (verified.status !== 'valid') throw new Error(`approval_${verified.status}:${verified.errors.join(',')}`);
  // Receipt duplicates are refused by the serialized verifier before this parse.
  const approval = JSON.parse(approvalRaw);
  const action = parseActionReferenceInputV2(actionRaw);
  // This private subprocess receives a parsed payload from the duplicate-rejecting
  // Python boundary. Use that installed entry point for serialized payload input.
  const payload = payloadChecked;
  const payloadRef = computePayloadRefV1(payload);
  const actionRef = computeActionRefV2(action);
  const target = `https://payments.operator.example/v1/payments/${payload.payment_id}/refunds`;
  if (action.agent_id !== policy.workerIdentity || approval.subject_agent !== policy.workerIdentity)
    throw new Error('acting agent differs from host identity');
  if (action.action_type !== 'refund' || action.target !== target ||
      canonicalizeJCS(action.scope_required) !== canonicalizeJCS(['payments:refund']))
    throw new Error('refund action differs from local profile');
  if (payloadRef !== action.payload_ref || actionRef !== approval.action_ref)
    throw new Error('exact action or payload binding differs');
  if (canonicalizeJCS(payload) !== canonicalizeJCS(policy.expectedPayload))
    throw new Error('refund differs from host-selected request');
  if (approval.result.verdict !== 'permit' || approval.result.constraints.length !== 0)
    throw new Error('only unconstrained permit is supported');
  if (now < approval.issued_at || now < action.issued_at || now >= approval.result.valid_until)
    throw new Error('approval outside local dispatch time window');
  return {
    profile: 'probity-aps-refund-record-v0', receiptId: approval.receipt_id,
    actionRef, payloadRef, payloadCanonical: canonicalizeJCS(payload),
    boundaryIdentity: policy.boundaryIdentity, workerIdentity: policy.workerIdentity,
    keyId: policy.keyId, publicKey: policy.publicKey,
    issuedAt: approval.issued_at, validUntil: approval.result.valid_until,
  };
}

try {
  process.stdout.write(JSON.stringify(verifyNative(JSON.parse(readFileSync(0, 'utf8')))));
} catch (error) {
  process.stderr.write(`APS refund refused: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
