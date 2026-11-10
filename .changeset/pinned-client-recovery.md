---
"@aptos-labs/inference-sdk": patch
"@aptos-labs/inference-verifier": patch
---

Publish usage guides for the SDK and offline verifier. Keep test hooks out of the SDK's public options, recover once from TLS key rotation before sending replayable requests, and apply the configured bearer token to SecureClient application requests. Normalize request headers for compatibility with Undici 7.30.1.

Update the AI SDK to 7, the OpenAI-compatible provider to 3, the OpenAI client to 7, and Zod to 4. Applications using createInferenceAI should use AI SDK 7. Update Vitest and add build, test, and dependency-audit CI checks.
