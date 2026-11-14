# @aptos-labs/inference-sdk

## 0.3.2

### Patch Changes

- 0f0a02e: Stop the OpenAI client from retrying a failed request, refuse request URLs that carry userinfo, and do not follow a symlink when reading the prompt-cache secret. Reject duplicate keys in Sigstore statements and Rekor entries, and select the highest matching TCB level for the TDX module and quoting enclave.
- Updated dependencies [0f0a02e]
  - @aptos-labs/inference-verifier@0.1.4

## 0.3.1

### Patch Changes

- Updated dependencies [ff456ca]
  - @aptos-labs/inference-verifier@0.1.3

## 0.3.0

### Minor Changes

- 00f1837: Add an EHBP transport that encrypts request bodies to the attested HPKE key, including through a relay, and reads the router's usage header.
- 95c57ca: Fix verification of Sigstore certificates whose identity fields are 128 bytes or longer. The verifier read DER string lengths as a single byte, so it truncated the signing workflow URI of `aptos-labs/confidential-model-router` releases and rejected them with "certificate workflow does not match".
  
  The SDK now trusts `aptos-labs/confidential-model-router` by default, which is the repository behind the production router. Pass `configRepo: "aptos-labs/confidential-inference-router"` to keep verifying the previous router.

### Patch Changes

- Updated dependencies [95c57ca]
  - @aptos-labs/inference-verifier@0.1.2

## 0.2.0

### Minor Changes

- 32e4b13: Update the SDK to AI SDK 7, OpenAI 7, Zod 4, and Undici 7.30.1. Applications using `createInferenceAI` should use AI SDK 7 and update structured output schemas to Zod 4.
  
  Fix SDK recovery from TLS pin mismatches, preserve the `PinMismatchError` type, and prevent the transport from replaying requests after unrelated network failures. Add bearer authentication to direct HTTP requests while preserving explicit authorization headers, and support streaming request bodies with the updated Undici client.
  
  Remove test-only hooks from the public SDK options and expand the SDK and verifier documentation with API parameters, verification policy, TLS pinning, session behavior, and error handling.

### Patch Changes

- Updated dependencies [32e4b13]
  - @aptos-labs/inference-verifier@0.1.1
