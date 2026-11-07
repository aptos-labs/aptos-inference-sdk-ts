import { verifyRouterDocument as verify, type RouterEvidence } from "./verify.js";

export type { RouterEvidence };
export { VerificationError, type VerificationCategory } from "./error.js";

export function verifyRouterDocument(
  bytes: Uint8Array,
  nonce: Uint8Array,
  repo: string,
  nowSecs: number,
): RouterEvidence {
  return verify(bytes, nonce, repo, nowSecs);
}
