import { createHash, generateKeyPairSync } from "node:crypto";
import { createServer, type Server } from "node:https";

import type { RouterEvidence } from "@aptos-labs/inference-verifier";
import { fetch as undiciFetch, type Dispatcher } from "undici";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { OriginError, RedirectRefusedError, SessionClosedError } from "../src/errors.js";
import { parseEnclave } from "../src/origin.js";
import { createTestClient } from "../src/secure-client.js";
import { selfSigned } from "./certificate.js";

const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const keyPem = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const certPem = selfSigned(keyPem);
const fingerprint = createHash("sha256")
  .update(keys.publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");

let server: Server;
let origin = "";
const seen: string[] = [];
const seenHeaders: { path: string; authorization: string | undefined }[] = [];

function evidence(tag = "v0.0.13"): RouterEvidence {
  return {
    tlsPublicKey: fingerprint,
    hpkePublicKey: "ab".repeat(32),
    mrtd: "cd".repeat(48),
    rtmrs: ["11".repeat(48), "22".repeat(48), "33".repeat(48), "00".repeat(48)],
    hardware: "small_0d_v011@example",
    releaseDigest: "ee".repeat(32),
    releaseTag: tag,
    codeMeasurement: { type: "code", registers: ["aa"] },
    tcbStatus: "UpToDate",
    collateralExpiresAt: Math.floor(Date.now() / 1000) + 3600,
  };
}

async function fetchThrough(url: URL, agent: Dispatcher): Promise<Uint8Array> {
  const response = await undiciFetch(url, { dispatcher: agent });
  return new Uint8Array(await response.arrayBuffer());
}

beforeAll(async () => {
  server = createServer({ key: keyPem, cert: certPem }, (request, response) => {
    seen.push(request.url ?? "");
    seenHeaders.push({ path: request.url ?? "", authorization: request.headers.authorization });
    if (request.url === "/v1/bounce") {
      response.writeHead(302, { location: "https://example.com/away" });
      response.end();
      return;
    }
    if (request.url === "/v1/chat/completions") {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(Buffer.concat(chunks));
      });
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  origin = `https://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

describe("enclave URL", () => {
  it("accepts an https origin and rejects anything else", () => {
    expect(parseEnclave("https://router.inference.aptoslabs.com").host).toBe("router.inference.aptoslabs.com");
    expect(() => parseEnclave("http://router.inference.aptoslabs.com")).toThrow(OriginError);
    expect(() => parseEnclave("https://user:pw@router.inference.aptoslabs.com")).toThrow(OriginError);
    expect(() => parseEnclave("https://router.inference.aptoslabs.com/v1")).toThrow(OriginError);
    expect(() => parseEnclave("https://router.inference.aptoslabs.com/?x=1")).toThrow(OriginError);
  });
});

describe("secure client", () => {
  it("uses the attested key and refuses a redirect", async () => {
    const secure = createTestClient(
      { enclaveURL: origin, apiKey: "test", userCacheSecret: "cache-secret" },
      { ca: certPem, fetchDocument: fetchThrough, verify: () => evidence() },
    );
    const response = await secure.fetch(`${origin}/v1/models`);
    expect(response.status).toBe(200);
    expect(secure.getVerificationDocument().tlsPublicKey).toBe(fingerprint);
    await expect(secure.fetch(`${origin}/v1/bounce`)).rejects.toBeInstanceOf(RedirectRefusedError);
    expect(seen.some((url) => url.includes("example.com"))).toBe(false);
  });

  it("keeps the request length correct when it injects the cache secret", async () => {
    const body = JSON.stringify({ model: "m", messages: [] });
    const secure = createTestClient(
      { enclaveURL: origin, apiKey: "test", userCacheSecret: "cache-secret" },
      { ca: certPem, fetchDocument: fetchThrough, verify: () => evidence() },
    );
    const response = await secure.fetch(`${origin}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
      body,
    });
    expect(response.status).toBe(200);
    expect(JSON.parse(await response.text()).user_cache_secret).toBe("cache-secret");
  });

  it("authenticates application requests without sending the key for attestation", async () => {
    const start = seenHeaders.length;
    const secure = createTestClient(
      { enclaveURL: origin, apiKey: "configured-key", userCacheSecret: "cache-secret" },
      { ca: certPem, fetchDocument: fetchThrough, verify: () => evidence() },
    );
    try {
      const response = await secure.fetch(`${origin}/v1/models`);
      await response.text();
      const requests = seenHeaders.slice(start);
      expect(requests).toHaveLength(2);
      expect(requests[0]?.path).toContain("tinfoil-attestation?nonce=");
      expect(requests[0]?.authorization).toBeUndefined();
      expect(requests[1]?.authorization).toBe("Bearer configured-key");

      const override = await secure.fetch(`${origin}/v1/models`, {
        headers: { Authorization: "Bearer explicit-key" },
      });
      await override.text();
      expect(seenHeaders.at(-1)?.authorization).toBe("Bearer explicit-key");
    } finally {
      secure.reset();
    }
  });

  it("uses the API key from the environment for raw fetch", async () => {
    vi.stubEnv("APTOS_INFERENCE_API_KEY", "environment-key");
    const secure = createTestClient(
      { enclaveURL: origin, userCacheSecret: "cache-secret" },
      { ca: certPem, fetchDocument: fetchThrough, verify: () => evidence() },
    );
    try {
      const response = await secure.fetch(`${origin}/v1/models`);
      await response.text();
      expect(seenHeaders.at(-1)?.authorization).toBe("Bearer environment-key");
    } finally {
      secure.reset();
      vi.unstubAllEnvs();
    }
  });

  it("rejects another origin without contacting the enclave", async () => {
    let calls = 0;
    const secure = createTestClient(
      { enclaveURL: origin, apiKey: "test-key", userCacheSecret: "cache-secret" },
      {
        fetchDocument: async () => {
          calls += 1;
          return new Uint8Array();
        },
        verify: () => evidence(),
      },
    );
    await expect(secure.fetch("https://example.com/v1/models")).rejects.toBeInstanceOf(OriginError);
    expect(calls).toBe(0);
  });

  it("does not install a verification reset() discarded", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const secure = createTestClient(
      { enclaveURL: origin, apiKey: "test-key", userCacheSecret: "cache-secret" },
      {
        ca: certPem,
        fetchDocument: async (url, agent) => {
          await gate;
          return fetchThrough(url, agent);
        },
        verify: () => evidence(),
      },
    );
    const pending = secure.ready();
    secure.reset();
    release();
    await expect(pending).rejects.toBeInstanceOf(SessionClosedError);
    expect(() => secure.getVerificationDocument()).toThrow();
  });

  it("rejects a release other than the pinned tag", async () => {
    const secure = createTestClient(
      { enclaveURL: origin, apiKey: "test-key", configRepo: "aptos-labs/confidential-inference-router@v0.0.1", userCacheSecret: "cache-secret" },
      { ca: certPem, fetchDocument: fetchThrough, verify: () => evidence("v0.0.13") },
    );
    await expect(secure.ready()).rejects.toThrow(/v0.0.13/);
  });
});
