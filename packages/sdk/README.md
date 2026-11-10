# @aptos-labs/inference-sdk

`@aptos-labs/inference-sdk` is a TypeScript client for the Aptos confidential inference router. It exposes an OpenAI-compatible API and verifies the router's attestation before sending inference requests. Verification uses a document served by the router, including the Intel collateral required to validate its hardware evidence. Subsequent requests use TLS connections pinned to the attested public key.

The package is distributed as an ECMAScript module (ESM) and requires Node.js 22 or later. Browser runtimes are not supported.

## Installation

```sh
npm install @aptos-labs/inference-sdk
```

Inference endpoints require bearer authentication. Configure the token through the `APTOS_INFERENCE_API_KEY` environment variable or the client's `apiKey` option.

## Usage

Create an `InferenceClient` to access the router through OpenAI client methods. Attestation verification runs automatically before the first request.

```ts
import { InferenceClient } from "@aptos-labs/inference-sdk";

const client = new InferenceClient();

const completion = await client.chat.completions.create({
  model: "glm-5.3",
  messages: [{ role: "user", content: "Hello" }],
});
```

To stream a chat completion, include `stream: true` in the request and consume the returned asynchronous iterator. The router delivers streaming responses as server-sent events. Use `client.models.list()` to retrieve the currently available models.

## Configuration

The constructor accepts the following options. Each option is optional; the defaults target the Aptos inference router.

| Option | Description | Default |
| --- | --- | --- |
| `apiKey` | Bearer token for inference requests. | `APTOS_INFERENCE_API_KEY` |
| `enclaveURL` | HTTPS origin of the router. | `https://router.inference.aptoslabs.com` |
| `configRepo` | Trusted source repository, optionally pinned to a release tag. | `aptos-labs/confidential-inference-router` |
| `userCacheSecret` | Secret used to isolate the caller's prompt cache. | `APTOS_INFERENCE_USER_CACHE_SECRET`, then `~/.aptos-inference/user_cache_secret` |

For example, the following configuration makes the default endpoint and repository explicit:

```ts
new InferenceClient({
  apiKey: process.env.APTOS_INFERENCE_API_KEY,
  enclaveURL: "https://router.inference.aptoslabs.com",
  configRepo: "aptos-labs/confidential-inference-router",
});
```

`enclaveURL` must contain only an HTTPS origin, without a non-root path, query, fragment, or user information. All application requests must remain on that origin, and redirects are rejected.

`configRepo` identifies the repository whose signed releases the client trusts. A value such as `owner/repo` accepts releases from that repository when their provenance and measurements pass verification. To require a specific release, append its tag, for example `owner/repo@v0.0.13`. Verification fails if the attested release does not match the configured tag.

For JSON chat completion and completion requests, the SDK adds `userCacheSecret` as the `user_cache_secret` field. An explicit option takes precedence over the environment variable and stored file. If no secret is available, the SDK generates one and saves it to `~/.aptos-inference/user_cache_secret`; if persistence fails, the secret remains unset.

## Verification and sessions

The client establishes a verified session before sending its first application request and reuses that session for subsequent requests. A session expires at the earliest Intel collateral expiry or one hour after verification, whichever occurs first. The next request after expiry triggers a new verification.

Call `ready()` to complete verification explicitly, or use `getVerificationDocument()` to obtain the verified endpoint and release information:

```ts
await client.ready();
const doc = await client.getVerificationDocument();
// doc.securityVerified, doc.releaseDigest, doc.releaseTag, doc.enclaveHost
```

`InferenceClient.getVerificationDocument()` waits for verification to complete before returning the document. Calling `client.reset()` invalidates the cached session and requires verification again before the next request.

If the router presents a different TLS key, the handshake fails before the request body is transmitted. For a replayable body, `SecureClient` discards the session, verifies a fresh attestation, and retries the request once. Stream bodies are not replayed, and a second pin mismatch raises `PinMismatchError`. This recovery applies specifically to TLS pin mismatches; other network failures are returned to the caller. OpenAI API methods additionally follow the OpenAI client's retry policy.

## Direct HTTP requests

Use `SecureClient` for direct HTTP access with the same attestation verification and TLS pinning. Its `fetch()` method accepts an absolute URL on the configured router origin and establishes a verified session automatically when necessary.

```ts
import { SecureClient } from "@aptos-labs/inference-sdk";

const client = new SecureClient();
const response = await client.fetch(
  "https://router.inference.aptoslabs.com/v1/models",
);
```

Application requests include `Authorization: Bearer <apiKey>` when a token is configured, unless an explicit `Authorization` header is provided. Attestation requests do not include the API key.

`SecureClient.getVerificationDocument()` is synchronous and requires an active verified session. Call `ready()` before reading it, or read it after a successful request. It throws `NotReadyError` if verification has not completed or the session has expired.

## Vercel AI SDK

`createInferenceAI` provides an integration with AI SDK 7. Install `ai@7` in the application to use its generation functions; structured output schemas can use Zod 4.

```ts
import { generateText } from "ai";
import { createInferenceAI } from "@aptos-labs/inference-sdk";

const provider = await createInferenceAI();
const result = await generateText({
  model: provider("glm-5.3"),
  prompt: "Hello",
});
```

`createInferenceAI(apiKey?, options?)` completes attestation verification before returning the provider function. The optional second argument accepts `enclaveURL`, `configRepo`, and `userCacheSecret`, with the same defaults as `InferenceClient`.

## Supported endpoints

The router currently implements the following inference endpoints:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `GET /v1/models`
- `POST /v1/videos/sync`

For OpenAI API compatibility, `InferenceClient` also exposes resource groups for embeddings, audio, images, files, fine-tuning, and moderations. Those endpoints are not currently implemented by the router. Realtime WebSocket sessions are also unsupported.

## Error handling

The SDK exports the following error classes for failures in configuration, session management, and transport:

| Error | Condition |
| --- | --- |
| `OriginError` | The endpoint, request URL, or attestation response is rejected; the release does not match a configured tag; or the attestation connection's TLS key does not match the evidence. |
| `RedirectRefusedError` | The router returns a redirect response. |
| `PinMismatchError` | A TLS key mismatch cannot be recovered because the request body is not replayable or the retry also fails its pin check. |
| `NotReadyError` | A verification document is requested without an active verified session. |
| `SessionClosedError` | `reset()` invalidates a verification attempt while it is still in progress. |

`SecureClient` returns these errors directly. OpenAI API methods may wrap transport failures in an OpenAI connection error, with the original error available through `cause`.

Attestation validation failures raise `VerificationError`, exported by `@aptos-labs/inference-verifier`. Its `category` property identifies the verification stage: `envelope`, `encoding`, `dcap`, `tdx`, `provenance`, or `policy`.
