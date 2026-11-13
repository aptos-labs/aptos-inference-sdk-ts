# @aptos-labs/inference-verifier

## 0.1.3

### Patch Changes

- ff456ca: Match go-tdx-guest on Intel revocation and TCB status. CRLs are parsed with `@peculiar/x509`, so revoked PCK and signing certificates listed in v2 Intel CRLs are now rejected. The platform, TDX module, and quoting-enclave TCB levels must each be `UpToDate`; a quoting-enclave `ConfigurationNeeded` is no longer reported as `UpToDate`.

## 0.1.2

### Patch Changes

- 95c57ca: Fix verification of Sigstore certificates whose identity fields are 128 bytes or longer. The verifier read DER string lengths as a single byte, so it truncated the signing workflow URI of `aptos-labs/confidential-model-router` releases and rejected them with "certificate workflow does not match".
  
  The SDK now trusts `aptos-labs/confidential-model-router` by default, which is the repository behind the production router. Pass `configRepo: "aptos-labs/confidential-inference-router"` to keep verifying the previous router.

## 0.1.1

### Patch Changes

- 32e4b13: Update the SDK to AI SDK 7, OpenAI 7, Zod 4, and Undici 7.30.1. Applications using `createInferenceAI` should use AI SDK 7 and update structured output schemas to Zod 4.
  
  Fix SDK recovery from TLS pin mismatches, preserve the `PinMismatchError` type, and prevent the transport from replaying requests after unrelated network failures. Add bearer authentication to direct HTTP requests while preserving explicit authorization headers, and support streaming request bodies with the updated Undici client.
  
  Remove test-only hooks from the public SDK options and expand the SDK and verifier documentation with API parameters, verification policy, TLS pinning, session behavior, and error handling.
