# Aptos inference SDK

TypeScript client and attestation verifier for the Aptos confidential
inference router.

- `@aptos-labs/inference-verifier` checks one attestation document offline.
  Intel collateral is read from the document.
- `@aptos-labs/inference-sdk` verifies the router, pins the attested TLS key,
  and exposes the OpenAI client surface.

`docs/router-support.md` lists the routes the router serves. Realtime
WebSocket sessions are not implemented.
