# @aptos-labs/inference-verifier

Offline attestation check for the Aptos inference router.

```ts
import { verifyRouterDocument } from "@aptos-labs/inference-verifier";

const evidence = verifyRouterDocument(bytes, nonce, "owner/repo", nowSecs);
```

`bytes` is one attestation document. `nonce` is the 32 bytes the caller sent to obtain it. `owner/repo` has no `@tag`. `nowSecs` is a Unix timestamp, and certificate expiry is judged against it. The Intel collateral is read from the document. The function does not contact Intel or Sigstore.

The returned evidence includes the attested TLS key, the HPKE key, the measurements, the hardware profile, and the release digest and tag.

A failed check throws `VerificationError`. `error.category` is `envelope`, `encoding`, `dcap`, `tdx`, `provenance`, or `policy`.

`@aptos-labs/inference-sdk` calls this for you. Use this package directly when you already have the document bytes.
