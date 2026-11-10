import { createHash, generateKeyPairSync } from "node:crypto";
import { createServer } from "node:https";

import type { RouterEvidence } from "@aptos-labs/inference-verifier";
import { afterEach, describe, expect, it } from "vitest";

import { NotReadyError, PinMismatchError } from "../src/errors.js";
import { createTestClient } from "../src/secure-client.js";
import { pinnedFetch } from "../src/transport.js";
import { selfSigned } from "./certificate.js";

function certificate(name: string) {
  const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const key = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return {
    key,
    cert: selfSigned(key, name),
    fingerprint: createHash("sha256").update(keys.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
  };
}

const first = certificate("first");
const second = certificate("second");
const cleanup: (() => Promise<void>)[] = [];

afterEach(async () => {
  for (const close of cleanup.splice(0)) await close();
});

async function fixture(trustSecond = true) {
  let active = first;
  const state = {
    documentFetches: 0,
    bodies: [] as string[],
    loseResponse: false,
    afterVerification: () => {},
  };
  const server = createServer(first, (request, response) => {
    if (!request.url?.startsWith("/v1/")) {
      response.end("{}");
      return;
    }
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      state.bodies.push(Buffer.concat(chunks).toString());
      if (state.loseResponse) request.socket.destroy();
      else response.end("ok");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  const origin = `https://127.0.0.1:${address.port}`;
  const client = createTestClient(
    { enclaveURL: origin, apiKey: "test-key", userCacheSecret: "test-secret" },
    {
      ca: trustSecond ? first.cert + second.cert : first.cert,
      fetchDocument: async (url, agent) => {
        state.documentFetches += 1;
        const response = await pinnedFetch(agent, url, { method: "GET" });
        return new Uint8Array(await response.arrayBuffer());
      },
      verify: (): RouterEvidence => {
        const tlsPublicKey = active.fingerprint;
        state.afterVerification();
        return {
          tlsPublicKey,
          hpkePublicKey: "ab".repeat(32),
          mrtd: "cd".repeat(48),
          rtmrs: ["11".repeat(48), "22".repeat(48), "33".repeat(48), "00".repeat(48)],
          hardware: "small_0d_v011@test",
          releaseDigest: "ee".repeat(32),
          releaseTag: "v1",
          codeMeasurement: { type: "code", registers: ["aa"] },
          tcbStatus: "UpToDate",
          collateralExpiresAt: Math.floor(Date.now() / 1000) + 3600,
        };
      },
    },
  );
  cleanup.push(async () => {
    client.reset();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  return {
    client,
    state,
    url: `${origin}/v1/test`,
    rotate(next = second) {
      active = next;
      server.setSecureContext(next);
    },
  };
}

describe("TLS key rotation", () => {
  it("reverifies a changed key and sends a replayable body exactly once", async () => {
    const { client, state, url, rotate } = await fixture();
    await client.ready();
    rotate();
    const response = await client.fetch(url, { method: "POST", body: "payload" });
    expect(await response.text()).toBe("ok");
    expect(state.documentFetches).toBe(2);
    expect(state.bodies).toEqual(["payload"]);
    expect(client.getVerificationDocument().tlsPublicKey).toBe(second.fingerprint);
  });

  it("returns PinMismatchError after a second mismatch without sending the body", async () => {
    const { client, state, url, rotate } = await fixture();
    await client.ready();
    rotate();
    state.afterVerification = () => rotate(first);
    await expect(client.fetch(url, { method: "POST", body: "payload" })).rejects.toBeInstanceOf(PinMismatchError);
    expect(state.documentFetches).toBe(2);
    expect(state.bodies).toEqual([]);
    expect(() => client.getVerificationDocument()).toThrow(NotReadyError);
  });

  it("does not retry a stream body after a pin mismatch", async () => {
    const { client, state, url, rotate } = await fixture();
    await client.ready();
    rotate();
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("payload"));
        controller.close();
      },
    });
    await expect(client.fetch(url, { method: "POST", body })).rejects.toBeInstanceOf(PinMismatchError);
    expect(state.documentFetches).toBe(1);
    expect(state.bodies).toEqual([]);
  });

  it("can send a stream body over the verified connection", async () => {
    const { client, state, url } = await fixture();
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("payload"));
        controller.close();
      },
    });
    const response = await client.fetch(url, { method: "POST", body });
    expect(await response.text()).toBe("ok");
    expect(state.bodies).toEqual(["payload"]);
  });

  it("does not retry a request whose response was lost after the body arrived", async () => {
    const { client, state, url } = await fixture();
    state.loseResponse = true;
    await expect(client.fetch(url, { method: "POST", body: "payload" })).rejects.toThrow();
    expect(state.documentFetches).toBe(1);
    expect(state.bodies).toEqual(["payload"]);
  });

  it("does not treat an untrusted certificate as a recoverable pin mismatch", async () => {
    const { client, state, url, rotate } = await fixture(false);
    await client.ready();
    rotate();
    await expect(client.fetch(url)).rejects.toMatchObject({ cause: { code: "DEPTH_ZERO_SELF_SIGNED_CERT" } });
    expect(state.documentFetches).toBe(1);
    expect(state.bodies).toEqual([]);
  });
});
