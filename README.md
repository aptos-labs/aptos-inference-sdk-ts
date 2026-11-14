# Aptos inference SDK

TypeScript client for the Aptos confidential inference router. On its first request the client verifies the router. Later traffic is pinned to the attested TLS key, or, with `transport: "ehbp"`, encrypted to the attested HPKE key.

```sh
npm install @aptos-labs/inference-sdk
```

```ts
import { InferenceClient } from "@aptos-labs/inference-sdk";

const client = new InferenceClient();
const completion = await client.chat.completions.create({
  model: "glm-5.3",
  messages: [{ role: "user", content: "Hello" }],
});
```

Set `APTOS_INFERENCE_API_KEY`. Node.js 22 or newer. The client does not run in browsers.

The usage guide that npm publishes is [`packages/sdk/README.md`](packages/sdk/README.md). It covers options, verification, the AI SDK helper, the routes the router serves, and the errors a caller handles.

`@aptos-labs/inference-verifier` is the offline check the client uses. Its entry point is documented in [`packages/verifier/README.md`](packages/verifier/README.md). [`docs/router-support.md`](docs/router-support.md) is the route list.

## Acknowledgements

The attestation and encrypted-transport design in this SDK is inspired by [Tinfoil](https://tinfoil.sh)'s open-source clients, [`tinfoil-js`](https://github.com/tinfoilsh/tinfoil-js) and [`tinfoil-go`](https://github.com/tinfoilsh/tinfoil-go), and by the [Encrypted HTTP Body Protocol](https://github.com/tinfoilsh/encrypted-http-body-protocol). Thank you to the Tinfoil team for publishing that work.
