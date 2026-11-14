---
"@aptos-labs/inference-sdk": patch
"@aptos-labs/inference-verifier": patch
---

Stop the OpenAI client from retrying a failed request, refuse request URLs that carry userinfo, and do not follow a symlink when reading the prompt-cache secret. Reject duplicate keys in Sigstore statements and Rekor entries, and select the highest matching TCB level for the TDX module and quoting enclave.
