# @aptos-labs/inference-sdk

Client for the Aptos confidential inference router.

The first request verifies the router. The client fetches one attestation document from the router, checks it, and sends later requests only on TLS connections that present the attested key. You supply an API key and call the client. You do not fetch the attestation or the Intel collateral yourself.

Requires Node.js 22 or newer. The package is ESM only. It does not run in browsers.

## Install

```sh
npm install @aptos-labs/inference-sdk
```

Inference routes require a bearer token. Pass it as `apiKey`, or set `APTOS_INFERENCE_API_KEY`.

## Chat

```ts
import { InferenceClient } from "@aptos-labs/inference-sdk";

const client = new InferenceClient();

const completion = await client.chat.completions.create({
  model: "glm-5.3",
  messages: [{ role: "user", content: "Hello" }],
});
```

Streaming is the same call with `stream: true`. The router streams chat completions as server-sent events. `client.models.list()` returns the models the router is currently serving.

## What you can set

```ts
new InferenceClient({
  apiKey: process.env.APTOS_INFERENCE_API_KEY,
  enclaveURL: "https://router.inference.aptoslabs.com",
  configRepo: "aptos-labs/confidential-inference-router",
});
```

All three are optional, and those values are the defaults.

`enclaveURL` is an `https` origin. It must not have a path, query, fragment, or user info. Every later request stays on that origin. A redirect is refused.

`configRepo` is `owner/repo`. The client accepts any correctly signed release of that repository. Append `@tag`, as in `owner/repo@v0.0.13`, to require one release. A different release fails verification.

`userCacheSecret` is added to chat completion and completion bodies so the router can keep a prompt cache for the caller. The default is `APTOS_INFERENCE_USER_CACHE_SECRET`, then `~/.aptos-inference/user_cache_secret`. When neither is set, the client creates that file.

## Verification

The first call verifies and opens a session. Further calls reuse it. A session lasts until the attestation collateral expires, or one hour, whichever comes first. The next call then verifies again.

```ts
await client.ready();
const doc = await client.getVerificationDocument();
// doc.securityVerified, doc.releaseDigest, doc.releaseTag, doc.enclaveHost
```

`client.reset()` drops the session. The next call verifies again.

When the router presents a different certificate, the connection fails before the request body is sent. The client verifies once and retries that request once, if the body can be sent again. A stream body is not retried. A second mismatch is returned to the caller.

`SecureClient` is the same session without the OpenAI methods. Its `getVerificationDocument()` is synchronous and throws `NotReadyError` before `ready()`. `InferenceClient.getVerificationDocument()` waits for verification.

## AI SDK

```ts
import { generateText } from "ai";
import { createInferenceAI } from "@aptos-labs/inference-sdk";

const model = await createInferenceAI();
const result = await generateText({
  model: model("glm-5.3"),
  prompt: "Hello",
});
```

`createInferenceAI(apiKey?, options?)` verifies before it returns. `options` takes `enclaveURL`, `configRepo`, and `userCacheSecret`.

## Routes

The router serves:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `GET /v1/models`
- `POST /v1/videos/sync`

`InferenceClient` also exposes the rest of the OpenAI resources, so existing call sites keep their types. Embeddings, audio, images, files, fine-tuning, and moderations are in that group. The router does not serve them. Realtime sessions are not implemented.

## Errors

`OriginError` means the enclave URL or the request URL was rejected, or the attested key did not match the connection. `RedirectRefusedError` means the router sent a redirect. `PinMismatchError` means a different certificate was still present after the one retry. `NotReadyError` means the verification document was read before verification. `SessionClosedError` means `reset()` discarded a verification that was still running.

A failed attestation check throws `VerificationError` from `@aptos-labs/inference-verifier`. `error.category` is `envelope`, `encoding`, `dcap`, `tdx`, `provenance`, or `policy`.
