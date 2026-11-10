import { createHash, timingSafeEqual, X509Certificate } from "node:crypto";
import { checkServerIdentity, type PeerCertificate } from "node:tls";

import { Agent, fetch as undiciFetch, type Dispatcher } from "undici";

import { PinMismatchError } from "./errors.js";

export function spkiFingerprint(certificate: PeerCertificate): string {
  const parsed = new X509Certificate(certificate.raw);
  const spki = parsed.publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("hex");
}

function equalHex(left: string, right: string): boolean {
  const a = Buffer.from(left, "hex");
  const b = Buffer.from(right, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function recordingAgent(ca?: string | Buffer): { agent: Agent; fingerprint: () => string | undefined } {
  let recorded: string | undefined;
  const agent = new Agent({
    connect: {
      rejectUnauthorized: true,
      maxCachedSessions: 0,
      ...(ca === undefined ? {} : { ca }),
      checkServerIdentity(host, cert) {
        const error = checkServerIdentity(host, cert);
        if (error !== undefined) return error;
        const fingerprint = spkiFingerprint(cert);
        if (recorded === undefined) recorded = fingerprint;
        else if (!equalHex(recorded, fingerprint)) return new Error("connection changed certificates");
        return undefined;
      },
    },
  });
  return { agent, fingerprint: () => recorded };
}

export function pinnedAgent(expected: string, ca?: string | Buffer): Agent {
  return new Agent({
    connect: {
      rejectUnauthorized: true,
      maxCachedSessions: 0,
      ...(ca === undefined ? {} : { ca }),
      checkServerIdentity(host, cert) {
        const error = checkServerIdentity(host, cert);
        if (error !== undefined) return error;
        if (!equalHex(spkiFingerprint(cert), expected)) {
          return new PinMismatchError("certificate is not the attested key");
        }
        return undefined;
      },
    },
  });
}

export async function pinnedFetch(agent: Dispatcher, url: URL, init: RequestInit): Promise<Response> {
  const request: Parameters<typeof undiciFetch>[1] = { dispatcher: agent, redirect: "manual" };
  if (init.method !== undefined) request.method = init.method;
  if (init.headers !== undefined) request.headers = init.headers as HeadersInit;
  if (init.body != null) request.body = init.body as never;
  if (init.body instanceof ReadableStream) request.duplex = "half";
  try {
    const response = await undiciFetch(url, request);
    return response as unknown as Response;
  } catch (error) {
    // Undici wraps the TLS callback's error in TypeError("fetch failed").
    // Only this handshake failure proves the request was not sent.
    if (error instanceof Error && error.cause instanceof PinMismatchError) throw error.cause;
    throw error;
  }
}
