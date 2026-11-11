import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, type IncomingHttpHeaders, type Server } from "node:https";

import type { RouterEvidence } from "@aptos-labs/inference-verifier";
import { fetch as undiciFetch, type Dispatcher } from "undici";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { KeyConfigError, OriginError, RedirectRefusedError } from "../src/errors.js";
import {
  acceptRequest,
  decryptResponseStream,
  openResponse,
  parseKeyConfig,
  sealChunks,
  sealRequest,
  sealResponse,
} from "../src/ehbp.js";
import { createTestClient, usageMetrics } from "../src/secure-client.js";
import { selfSigned } from "./certificate.js";

const pair = generateKeyPairSync("x25519");
const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
const secretKey = pair.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
const tls = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const tlsKey = tls.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const tlsCert = selfSigned(tlsKey);
const tlsFingerprint = "11".repeat(32);

let server: Server;
let origin = "";
const hits: { url: string; headers: IncomingHttpHeaders; body: Buffer }[] = [];
let rejectKeys = false;
let failNext = false;

function evidence(): RouterEvidence {
  return {
    tlsPublicKey: tlsFingerprint,
    hpkePublicKey: publicKey.toString("hex"),
    mrtd: "cd".repeat(48),
    rtmrs: ["11".repeat(48), "22".repeat(48), "33".repeat(48), "00".repeat(48)],
    hardware: "small_0d_v011@example",
    releaseDigest: "ee".repeat(32),
    releaseTag: "v0.0.13",
    codeMeasurement: { type: "code", registers: ["aa"] },
    tcbStatus: "UpToDate",
    collateralExpiresAt: Math.floor(Date.now() / 1000) + 3600,
  };
}

function keyConfig(key: Buffer): Buffer {
  const out = Buffer.alloc(41);
  out.writeUInt16BE(0x0020, 1);
  key.copy(out, 3);
  out.writeUInt16BE(4, 35);
  out.writeUInt16BE(0x0001, 37);
  out.writeUInt16BE(0x0002, 39);
  return out;
}

async function fetchThrough(url: URL, agent: Dispatcher): Promise<Uint8Array> {
  const response = await undiciFetch(url, { dispatcher: agent });
  return new Uint8Array(await response.arrayBuffer());
}

function client(options: { relayURL?: string; requestUsageMetrics?: boolean } = {}) {
  return createTestClient(
    {
      enclaveURL: options.relayURL === undefined ? origin : "https://router.inference.aptoslabs.com",
      transport: "ehbp",
      apiKey: "test-key",
      userCacheSecret: "cache-secret",
      requestUsageMetrics: options.requestUsageMetrics === true,
      ...(options.relayURL === undefined ? {} : { relayURL: options.relayURL }),
    },
    { ca: tlsCert, fetchDocument: fetchThrough, verify: () => evidence() },
  );
}

beforeAll(async () => {
  server = createServer({ key: tlsKey, cert: tlsCert }, (request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks);
      const url = request.url ?? "";
      hits.push({ url, headers: request.headers, body });
      if (url.startsWith("/.well-known/hpke-keys")) {
        const key = rejectKeys ? Buffer.alloc(32, 7) : publicKey;
        response.writeHead(200, { "content-type": "application/ohttp-keys" });
        response.end(keyConfig(key));
        return;
      }
      if (url.startsWith("/.well-known/tinfoil-attestation")) {
        response.writeHead(200, { "content-type": "application/json" });
        response.end("{}");
        return;
      }
      if (url === "/v1/bounce") {
        response.writeHead(302, { location: "https://example.com/away" });
        response.end();
        return;
      }
      const encapsulated = request.headers["ehbp-encapsulated-key"];
      if (typeof encapsulated !== "string") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(body);
        return;
      }
      if (failNext) {
        failNext = false;
        response.writeHead(422, { "content-type": "application/problem+json" });
        response.end(JSON.stringify({ type: "urn:ietf:params:ehbp:error:key-config", title: "failed to decrypt request" }));
        return;
      }
      const accepted = acceptRequest(secretKey, Buffer.from(encapsulated, "hex"), body);
      const nonce = randomBytes(32);
      const streaming = Buffer.from(accepted.plaintext).includes('"stream":true') || Buffer.from(accepted.plaintext).includes('"stream": true');
      if (streaming) {
        const frames = sealResponse(accepted.responseSecret, Buffer.from(encapsulated, "hex"), nonce, [Buffer.from("data: hello\n\n"), Buffer.from("data: world\n\n")]);
        response.writeHead(200, {
          "content-type": "text/event-stream",
          trailer: "X-Tinfoil-Usage-Metrics",
          "ehbp-response-nonce": nonce.toString("hex"),
        });
        response.write(frames);
        response.addTrailers({ "X-Tinfoil-Usage-Metrics": "prompt=1,completion=2,total=3,model=glm-5.3,cost_usd=0" });
        response.end();
        return;
      }
      const frame = sealResponse(accepted.responseSecret, Buffer.from(encapsulated, "hex"), nonce, [Buffer.from('{"ok":true}')]);
      response.writeHead(200, {
        "content-type": "application/json",
        "ehbp-response-nonce": nonce.toString("hex"),
        "x-tinfoil-usage-metrics": "prompt=4,completion=5,total=9,model=glm-5.3,cost_usd=0",
      });
      response.end(frame);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  origin = `https://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

describe("EHBP framing", () => {
  it("matches an independent HPKE vector", () => {
    const publicKey = Buffer.from("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b", "hex");
    const ephemeral = Buffer.from("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "hex");
    const secretKey = Buffer.from("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40", "hex");
    const sealed = sealRequest(publicKey, Buffer.from("hello ehbp"), ephemeral);
    expect(Buffer.from(sealed.encapsulatedKey).toString("hex")).toBe("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c");
    expect(Buffer.from(sealed.body).toString("hex")).toBe("0000001af8eb5b7cffaca88b0905fda55ae1d31e2033cb0b4bc9af6d8b56");
    expect(Buffer.from(sealed.responseSecret).toString("hex")).toBe("b78c4355b627be5e9399a7625aca90d41f385328f7c670acd714ac61ec03a3ea");
    const accepted = acceptRequest(secretKey, sealed.encapsulatedKey, sealed.body);
    expect(Buffer.from(accepted.plaintext).toString()).toBe("hello ehbp");
    const nonce = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
    expect(Buffer.from(openResponse(sealed.responseSecret, sealed.encapsulatedKey, nonce, Buffer.from("00000014410e3b5a3086559807da48d99f94ea770181d6d3", "hex"))).toString()).toBe("pong");
  });

  it("round-trips a request and a multi-frame response", () => {
    const sealed = sealChunks(publicKey, [Buffer.from("hello "), Buffer.from("world")]);
    const accepted = acceptRequest(secretKey, sealed.encapsulatedKey, sealed.body);
    expect(Buffer.from(accepted.plaintext).toString()).toBe("hello world");
    const nonce = randomBytes(32);
    const response = sealResponse(accepted.responseSecret, sealed.encapsulatedKey, nonce, [Buffer.from("one"), Buffer.from("two")]);
    expect(Buffer.from(openResponse(sealed.responseSecret, sealed.encapsulatedKey, nonce, response)).toString()).toBe("onetwo");
  });

  it("decrypts a response split across reads", async () => {
    const sealed = sealRequest(publicKey, Buffer.from("ping"));
    const accepted = acceptRequest(secretKey, sealed.encapsulatedKey, sealed.body);
    const nonce = randomBytes(32);
    const response = sealResponse(accepted.responseSecret, sealed.encapsulatedKey, nonce, [Buffer.from("aa"), Buffer.from("bbb")]);
    const split = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(response.subarray(0, 3));
        controller.enqueue(response.subarray(3));
        controller.close();
      },
    });
    const decoded = split.pipeThrough(decryptResponseStream(sealed.responseSecret, sealed.encapsulatedKey, nonce));
    expect(Buffer.from(await new Response(decoded).arrayBuffer()).toString()).toBe("aabbb");
  });

  it("rejects a truncated response and a foreign key", () => {
    const sealed = sealRequest(publicKey, Buffer.from("ping"));
    expect(() => openResponse(sealed.responseSecret, sealed.encapsulatedKey, randomBytes(32), sealed.body.subarray(0, 6))).toThrow(KeyConfigError);
    const other = generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }).subarray(-32);
    const foreign = sealRequest(other, Buffer.from("ping"));
    expect(() => acceptRequest(secretKey, foreign.encapsulatedKey, foreign.body)).toThrow(KeyConfigError);
  });

  it("reads one X25519 key configuration", () => {
    expect(Buffer.from(parseKeyConfig(keyConfig(publicKey))).equals(publicKey)).toBe(true);
    const extra = Buffer.concat([keyConfig(publicKey), Buffer.from([1])]);
    expect(() => parseKeyConfig(extra)).toThrow(KeyConfigError);
  });
});

describe("EHBP client", () => {
  it("encrypts the prompt, returns usage, and keeps the cache secret inside the body", async () => {
    const secure = client({ requestUsageMetrics: true });
    const response = await secure.fetch(`${origin}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", secret: "super-secret-prompt" }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(await usageMetrics(response)).toBe("prompt=4,completion=5,total=9,model=glm-5.3,cost_usd=0");
    const post = hits.filter((hit) => hit.url === "/v1/chat/completions").at(-1);
    if (post === undefined) throw new Error("no post");
    expect(post.body.includes("super-secret-prompt")).toBe(false);
    expect(post.headers["ehbp-encapsulated-key"]).toMatch(/^[0-9a-f]{64}$/);
    expect(post.headers["x-tinfoil-request-usage-metrics"]).toBe("true");
    const accepted = acceptRequest(secretKey, Buffer.from(String(post.headers["ehbp-encapsulated-key"]), "hex"), post.body);
    const plaintext = JSON.parse(Buffer.from(accepted.plaintext).toString()) as { secret: string; user_cache_secret: string };
    expect(plaintext.secret).toBe("super-secret-prompt");
    expect(plaintext.user_cache_secret).toBe("cache-secret");
  });

  it("decrypts a streamed response and reads the usage trailer", async () => {
    const secure = client({ requestUsageMetrics: true });
    const response = await secure.fetch(`${origin}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", stream: true }),
    });
    expect(await response.text()).toBe("data: hello\n\ndata: world\n\n");
    expect(await usageMetrics(response)).toBe("prompt=1,completion=2,total=3,model=glm-5.3,cost_usd=0");
  });

  it("leaves a bodyless request unencrypted", async () => {
    const secure = client();
    const response = await secure.fetch(`${origin}/v1/models`);
    expect(await response.text()).toBe("");
    const get = hits.filter((hit) => hit.url === "/v1/models").at(-1);
    expect(get?.headers["ehbp-encapsulated-key"]).toBeUndefined();
  });

  it("verifies again after a key-config rejection and retries once", async () => {
    failNext = true;
    const seen: string[] = [];
    const secure = createTestClient(
      { enclaveURL: origin, transport: "ehbp", apiKey: "test-key", userCacheSecret: "cache-secret" },
      {
        ca: tlsCert,
        fetchDocument: async (url, agent) => {
          seen.push(url.pathname);
          return fetchThrough(url, agent);
        },
        verify: () => evidence(),
      },
    );
    const response = await secure.fetch(`${origin}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", secret: "retry-prompt" }),
    });
    expect(await response.json()).toEqual({ ok: true });
    expect(seen.filter((path) => path === "/.well-known/tinfoil-attestation")).toHaveLength(2);
  });

  it("refuses a published key that does not match the attestation", async () => {
    rejectKeys = true;
    try {
      const secure = client();
      await expect(secure.ready()).rejects.toBeInstanceOf(KeyConfigError);
    } finally {
      rejectKeys = false;
    }
  });

  it("sends EHBP through the relay and refuses the enclave origin", async () => {
    const secure = client({ relayURL: origin });
    const response = await secure.fetch(`${origin}/v1/models`);
    expect(response.status).toBe(200);
    await response.arrayBuffer();
    await expect(secure.fetch("https://router.inference.aptoslabs.com/v1/models")).rejects.toBeInstanceOf(OriginError);
    expect(secure.getVerificationDocument().enclaveHost).toBe("router.inference.aptoslabs.com");
  });

  it("refuses a redirect and a multipart body", async () => {
    const secure = client();
    await expect(secure.fetch(`${origin}/v1/bounce`)).rejects.toBeInstanceOf(RedirectRefusedError);
    await expect(secure.fetch(`${origin}/v1/chat/completions`, { method: "POST", body: new FormData() })).rejects.toThrow(OriginError);
  });

  it("rejects a relay when transport stays tls", () => {
    expect(() => createTestClient({ enclaveURL: origin, relayURL: origin }, { verify: () => evidence() })).toThrow(OriginError);
  });
});
