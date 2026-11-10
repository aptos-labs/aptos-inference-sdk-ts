# @aptos-labs/inference-sdk

## 0.2.0

### Minor Changes

- 32e4b13: Update the SDK to AI SDK 7, OpenAI 7, Zod 4, and Undici 7.30.1. Applications using `createInferenceAI` should use AI SDK 7 and update structured output schemas to Zod 4.
  
  Fix SDK recovery from TLS pin mismatches, preserve the `PinMismatchError` type, and prevent the transport from replaying requests after unrelated network failures. Add bearer authentication to direct HTTP requests while preserving explicit authorization headers, and support streaming request bodies with the updated Undici client.
  
  Remove test-only hooks from the public SDK options and expand the SDK and verifier documentation with API parameters, verification policy, TLS pinning, session behavior, and error handling.

### Patch Changes

- Updated dependencies [32e4b13]
  - @aptos-labs/inference-verifier@0.1.1
