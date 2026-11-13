---
"@aptos-labs/inference-verifier": patch
---

Match go-tdx-guest on Intel revocation and TCB status. CRLs are parsed with `@peculiar/x509`, so revoked PCK and signing certificates listed in v2 Intel CRLs are now rejected. The platform, TDX module, and quoting-enclave TCB levels must each be `UpToDate`; a quoting-enclave `ConfigurationNeeded` is no longer reported as `UpToDate`.
