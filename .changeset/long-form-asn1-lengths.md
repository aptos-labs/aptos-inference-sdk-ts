---
"@aptos-labs/inference-sdk": minor
"@aptos-labs/inference-verifier": patch
---

Fix verification of Sigstore certificates whose identity fields are 128 bytes or longer. The verifier read DER string lengths as a single byte, so it truncated the signing workflow URI of `aptos-labs/confidential-model-router` releases and rejected them with "certificate workflow does not match".

The SDK now trusts `aptos-labs/confidential-model-router` by default, which is the repository behind the production router. Pass `configRepo: "aptos-labs/confidential-inference-router"` to keep verifying the previous router.
