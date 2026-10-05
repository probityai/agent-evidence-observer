/** Synthetic APS approval fixtures: no merchant, PIC mapping or provider call. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  buildDecisionRefV1, computeActionRefV2, computePayloadRefV1,
  createActionReferenceInputV2, createReceiptV1, generateKeyPair,
} from 'agent-passport-system';

const sha = value => createHash('sha256').update(value).digest('hex');
const options = JSON.parse(readFileSync(0, 'utf8'));
const boundaryIdentity = 'did:example:refund-boundary';
const workerIdentity = 'did:example:refund-worker';
const boundaryKey = generateKeyPair();
const workerKey = generateKeyPair();
const payload = { payment_id: 'pay_A', amount_minor: 4000, currency: 'EUR' };
const policy = { boundaryIdentity, workerIdentity, keyId: 'approval-1', publicKey: boundaryKey.publicKey,
  expectedPayload: payload };

/** Issue a genuine SDK-signed approval, with explicit action nonce and decision expiry. */
function issue(nonce, validUntil) {
  const action = createActionReferenceInputV2({
    agent_id: workerIdentity, action_type: 'refund',
    target: 'https://payments.operator.example/v1/payments/pay_A/refunds',
    payload_ref: computePayloadRefV1(payload), scope_required: ['payments:refund'],
    issued_at: options.issuedAt, nonce,
  });
  const action_ref = computeActionRefV2(action);
  const delegation_ref = 'sha256:' + sha('synthetic-delegation-leaf');
  const intent = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:action-intent:v1',
    issuer: workerIdentity, subject_agent: workerIdentity, action_ref, delegation_ref,
    issued_at: options.issuedAt, evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  }, [{ signer: workerIdentity, key_id: 'worker-1', private_key: workerKey.privateKey }]);
  const decision_output = {
    profile: 'aps-core-decision-output-v1', verdict: options.verdict ?? 'permit',
    effective_authority_ref: sha('synthetic-effective-authority'), constraints: options.constraints ?? [],
    valid_until: validUntil,
  };
  const { decision_ref } = buildDecisionRefV1({
    action_ref, authority_state: { synthetic: true }, policy_input: { operator_approved: payload },
    decision_context: { run: 'probity-local-refund-record' }, decision_output,
  });
  const approval = createReceiptV1({
    profile: 'aps-receipt-v1', receipt_type: 'aps:policy-decision:v1',
    issuer: boundaryIdentity, subject_agent: workerIdentity, action_ref, delegation_ref, decision_ref,
    issued_at: options.issuedAt, evidence_refs: [], result: decision_output, prev: intent.receipt_id,
  }, [{ signer: boundaryIdentity, key_id: 'approval-1', private_key: boundaryKey.privateKey }]);
  return { actionRaw: JSON.stringify(action), payloadRaw: JSON.stringify(payload),
    approvalRaw: JSON.stringify(approval), policy };
}

const nonce = sha('synthetic-exact-refund-nonce').slice(0, 32);
const first = issue(nonce, options.validUntil);
process.stdout.write(JSON.stringify(options.alternatives ? {
  first, reissued: issue(nonce, options.reissuedValidUntil),
  differentAction: issue(sha('different-native-refund-nonce').slice(0, 32), options.validUntil),
} : first));
