# Router support

`InferenceClient` exposes the OpenAI resource surface so existing call
sites keep their types. That is an API-compatibility choice. It does not
mean the inference router implements every OpenAI product.

The router accepts:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `GET /v1/models`
- `POST /v1/videos/sync`
- `GET /health`
- `GET /metrics`
- `GET /source`
- `GET /`

Chat completions stream over HTTP server-sent events. The router has no
WebSocket route, so realtime sessions are not implemented.

Embeddings, files, fine-tuning, and moderations are on the client because
they are part of the OpenAI type surface. The router does not serve them.
