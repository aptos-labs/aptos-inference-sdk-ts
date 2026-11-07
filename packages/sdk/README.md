Client for the Aptos confidential inference router.

Verification uses one request to the enclave. Intel collateral comes from
that response. Application traffic is pinned to the attested TLS key.

The default enclave is `https://router.inference.aptoslabs.com`. See
`docs/router-support.md` for which OpenAI routes the router actually serves.
This package does not run in browsers.
