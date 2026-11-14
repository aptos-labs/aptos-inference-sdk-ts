---
"@aptos-labs/inference-sdk": minor
---

Add `releaseDigests` to pin the signed router release. Verification rejects an attested digest that is not on the list, including when the client verifies again after the session is reset. `ReleaseNotPinnedError` carries the digest the router presented.
