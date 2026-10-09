import { readFileSync } from 'node:fs';
import { verifyPortableProofEnvelope } from '@proofable/sdk';
const proofs = JSON.parse(readFileSync(new URL('./portable-proofs.json', import.meta.url), 'utf8'));
for (const proof of proofs) {
  const result = await verifyPortableProofEnvelope(proof);
  if (!result.valid) { console.error(proof.qHash, result.errors); process.exitCode = 1; }
  else console.log('PASS', proof.qHash, result.signer);
}
