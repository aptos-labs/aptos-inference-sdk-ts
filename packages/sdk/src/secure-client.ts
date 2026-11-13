import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import { Readable } from "node:stream";

import { verifyRouterDocument, type RouterEvidence } from "@aptos-labs/inference-verifier";
import { Agent, request as undiciRequest, type Dispatcher } from "undici";

import { injectCacheSecret, resolveCacheSecret } from "./cache-secret.js";
import {
  decryptResponseStream,
  parseKeyConfig,
  sealRequest,
  ENCAPSULATED_KEY,
  KEYS_PATH,
  RESPONSE_NONCE,
  USAGE_REQUEST,
  USAGE_RESPONSE,
} from "./ehbp.js";
import { KeyConfigError, NotReadyError, OriginError, PinMismatchError, RedirectRefusedError, SessionClosedError } from "./errors.js";
import { parseEnclave, sameOrigin, type Enclave } from "./origin.js";
import { pinnedAgent, pinnedFetch, pinnedRequest, recordingAgent } from "./transport.js";

export const DEFAULT_ENCLAVE = "https://router.inference.aptoslabs.com";
export const DEFAULT_REPO = "aptos-labs/confidential-model-router";
const ATTESTATION_PATH = "/.well-known/tinfoil-attestation";
const HOUR_SECONDS = 60 * 60;

export type Transport = "tls" | "ehbp";

export interface SecureClientOptions {
  /** `https` origin of the router. No path, query, fragment, or user info. */
  enclaveURL?: string;
  /** `owner/repo`, or `owner/repo@tag` to require that release. */
  configRepo?: string;
  /** Bearer token. Defaults to `APTOS_INFERENCE_API_KEY`. */
  apiKey?: string;
  /** Prompt-cache secret. Defaults to `APTOS_INFERENCE_USER_CACHE_SECRET`, then `~/.aptos-inference/user_cache_secret`. */
  userCacheSecret?: string;
  /**
   * `tls` pins connections to the attested certificate.
   * `ehbp` encrypts request bodies to the attested HPKE key and can send them through `relayURL`.
   */
  transport?: Transport;
  /** `https` origin that receives EHBP requests. Defaults to `enclaveURL`. */
  relayURL?: string;
  /** Ask the router for `X-Tinfoil-Usage-Metrics` on each request. */
  requestUsageMetrics?: boolean;
}

interface ClientDeps {
  fetchDocument: (url: URL, agent: Dispatcher) => Promise<Uint8Array>;
  verify: typeof verifyRouterDocument;
  ca?: string | Buffer;
  clock: () => number;
}

const clientDeps = new WeakMap<SecureClient, ClientDeps>();
const usageMetricResults = new WeakMap<Response, Promise<string | undefined>>();

export interface TestClientHooks {
  fetchDocument?: ClientDeps["fetchDocument"];
  verify?: ClientDeps["verify"];
  ca?: string | Buffer;
  now?: () => number;
}

export function createTestClient(options: SecureClientOptions, hooks: TestClientHooks): SecureClient {
  const client = new SecureClient(options);
  const current = clientDeps.get(client);
  if (current === undefined) throw new Error("client is not initialized");
  const next: ClientDeps = {
    fetchDocument: hooks.fetchDocument ?? current.fetchDocument,
    verify: hooks.verify ?? current.verify,
    clock: hooks.now ?? current.clock,
  };
  const ca = hooks.ca ?? current.ca;
  if (ca !== undefined) next.ca = ca;
  clientDeps.set(client, next);
  return client;
}

/** Resolves to the router's usage line. For a stream, read the body to completion first. */
export function usageMetrics(response: Response): Promise<string | undefined> {
  return usageMetricResults.get(response) ?? Promise.resolve(response.headers.get(USAGE_RESPONSE) ?? undefined);
}

export interface VerificationDocument {
  schemaVersion: 1;
  configRepo: string;
  enclaveHost: string;
  releaseTag?: string;
  releaseDigest: string;
  codeMeasurement: { type: string; registers: string[] };
  enclaveMeasurement: {
    tlsPublicKeyFingerprint: string;
    hpkePublicKey: string;
    measurement: { type: string; registers: string[] };
  };
  tlsPublicKey: string;
  hpkePublicKey: string;
  hardwareMeasurement: { ID: string; MRTD: string; RTMR0: string };
  codeFingerprint: string;
  enclaveFingerprint: string;
  selectedRouterEndpoint: string;
  securityVerified: boolean;
  verifiedAt: string;
  steps: Record<string, { status: "success" }>;
}

interface SharedSession {
  generation: number;
  evidence: RouterEvidence;
  document: VerificationDocument;
  expiresAt: number;
}

interface TlsSession extends SharedSession {
  kind: "tls";
  agent: Dispatcher;
}

interface EhbpSession extends SharedSession {
  kind: "ehbp";
  hpkePublicKey: Uint8Array;
}

type Session = TlsSession | EhbpSession;

export class SecureClient {
  readonly enclave: Enclave;
  readonly repo: string;
  readonly tag?: string;
  readonly apiKey?: string;
  readonly transport: Transport;
  private readonly relay?: Enclave;
  private readonly requestUsageMetrics: boolean;
  private readonly cacheSecret: string;
  private generation = 0;
  private session: Session | undefined;
  private opening: Promise<Session> | undefined;
  private relayDispatcher: Agent | undefined;

  constructor(options: SecureClientOptions = {}) {
    const parsed = parseConfigRepo(options.configRepo ?? DEFAULT_REPO);
    this.repo = parsed.repo;
    if (parsed.tag !== undefined) this.tag = parsed.tag;
    this.enclave = parseEnclave(options.enclaveURL ?? DEFAULT_ENCLAVE);
    const transport = options.transport ?? "tls";
    if (transport !== "tls" && transport !== "ehbp") throw new OriginError("transport must be tls or ehbp");
    this.transport = transport;
    if (options.relayURL !== undefined) {
      if (transport !== "ehbp") throw new OriginError("relayURL requires transport ehbp");
      this.relay = parseEnclave(options.relayURL);
    }
    this.requestUsageMetrics = options.requestUsageMetrics === true;
    const apiKey = options.apiKey ?? process.env.APTOS_INFERENCE_API_KEY;
    if (apiKey !== undefined) this.apiKey = apiKey;
    this.cacheSecret = resolveCacheSecret(options.userCacheSecret);
    clientDeps.set(this, {
      fetchDocument: defaultFetch,
      verify: verifyRouterDocument,
      clock: Date.now,
    });
  }

  private deps(): ClientDeps {
    const found = clientDeps.get(this);
    if (found === undefined) throw new Error("client is not initialized");
    return found;
  }

  private get requestOrigin(): string {
    return this.relay?.origin ?? this.enclave.origin;
  }

  get baseURL(): string {
    return `${this.requestOrigin}/v1`;
  }

  async ready(): Promise<void> {
    await this.current();
  }

  getVerificationDocument(): VerificationDocument {
    const session = this.session;
    if (session === undefined || this.deps().clock() >= session.expiresAt) {
      throw new NotReadyError("call ready() before reading the verification document");
    }
    return session.document;
  }

  reset(): void {
    this.generation += 1;
    const previous = this.session;
    this.session = undefined;
    this.opening = undefined;
    if (previous?.kind === "tls") void previous.agent.close();
    void this.relayDispatcher?.close();
    this.relayDispatcher = undefined;
  }

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = requestUrl(input);
    sameOrigin(url, this.requestOrigin);
    const replayable = isReplayable(init?.body);
    try {
      return await this.send(url, init);
    } catch (error) {
      if (!replayable || !(error instanceof PinMismatchError)) throw error;
      return await this.send(url, init);
    }
  };

  private async send(url: URL, init?: RequestInit): Promise<Response> {
    const session = await this.current();
    const injected = typeof init?.body === "string" ? injectCacheSecret(init.body, url.pathname, this.cacheSecret) : undefined;
    const headers = new Headers(init?.headers);
    headers.delete("content-length");
    if (this.apiKey !== undefined && !headers.has("authorization")) {
      headers.set("authorization", `Bearer ${this.apiKey}`);
    }
    if (this.requestUsageMetrics) headers.set(USAGE_REQUEST, "true");
    const next: RequestInit = { redirect: "manual", headers };
    if (init?.method !== undefined) next.method = init.method;
    if (init?.signal !== undefined && init.signal !== null) next.signal = init.signal;
    const requestBody = injected ?? init?.body;
    if (requestBody != null) next.body = requestBody;
    if (session.kind === "ehbp") return this.sendEhbp(session, url, next, true);
    if (this.requestUsageMetrics) return this.sendTlsWithTrailers(session, url, next);
    let response: Response;
    try {
      response = await pinnedFetch(session.agent, url, next);
    } catch (error) {
      this.dropMismatchedPin(session, error);
      throw error;
    }
    if (response.status >= 300 && response.status < 400) {
      throw new RedirectRefusedError("the enclave refused to be followed to another URL");
    }
    rememberUsage(response, Promise.resolve(response.headers.get(USAGE_RESPONSE) ?? undefined));
    return response;
  }

  private async sendTlsWithTrailers(session: TlsSession, url: URL, init: RequestInit): Promise<Response> {
    let result: Awaited<ReturnType<typeof pinnedRequest>>;
    try {
      result = await pinnedRequest(session.agent, url, init);
    } catch (error) {
      this.dropMismatchedPin(session, error);
      throw error;
    }
    if (result.statusCode >= 300 && result.statusCode < 400) {
      await result.body.arrayBuffer();
      throw new RedirectRefusedError("the enclave refused to be followed to another URL");
    }
    const usage = usageFrom(result.headers, result.trailers, nodeToWeb(result.body));
    const response = new Response(usage.stream, { status: result.statusCode, headers: headersFrom(result.headers) });
    rememberUsage(response, usage.value);
    return response;
  }

  private dropMismatchedPin(session: TlsSession, error: unknown): void {
    if (error instanceof PinMismatchError && this.session === session) {
      this.session = undefined;
      void session.agent.close();
    }
  }

  private async sendEhbp(session: EhbpSession, url: URL, init: RequestInit, allowKeyRetry: boolean): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.delete(ENCAPSULATED_KEY);
    const plaintext = await bodyBytes(init.body);
    const sealed = plaintext !== null && plaintext.byteLength > 0 ? sealRequest(session.hpkePublicKey, plaintext) : undefined;
    if (sealed !== undefined) headers.set(ENCAPSULATED_KEY, Buffer.from(sealed.encapsulatedKey).toString("hex"));
    const result = await undiciRequest(url, {
      method: init.method ?? "GET",
      headers: headerRecord(headers),
      dispatcher: this.dispatcher(),
      ...(init.signal !== undefined && init.signal !== null ? { signal: init.signal } : {}),
      ...(sealed !== undefined ? { body: Buffer.from(sealed.body) } : {}),
    });
    if (result.statusCode >= 300 && result.statusCode < 400) {
      await result.body.arrayBuffer();
      throw new RedirectRefusedError("the enclave refused to be followed to another URL");
    }
    const nonceHeader = headerValue(result.headers, RESPONSE_NONCE);
    if (nonceHeader !== undefined) {
      try {
        decodeNonce(nonceHeader);
      } catch (error) {
        await result.body.arrayBuffer();
        throw error;
      }
    }
    if (sealed !== undefined && nonceHeader === undefined && result.statusCode === 422 && allowKeyRetry && isReplayable(init.body)) {
      await result.body.arrayBuffer();
      this.invalidate();
      const next = await this.current();
      if (next.kind !== "ehbp") throw new OriginError("the session is no longer an EHBP session");
      return this.sendEhbp(next, url, init, false);
    }
    if (sealed !== undefined && nonceHeader === undefined && result.statusCode >= 200 && result.statusCode < 300) {
      await result.body.arrayBuffer();
      throw new KeyConfigError("encrypted request returned an unencrypted response");
    }
    const responseHeaders = headersFrom(result.headers);
    let stream = nodeToWeb(result.body);
    if (sealed !== undefined && nonceHeader !== undefined) {
      stream = stream.pipeThrough(decryptResponseStream(sealed.responseSecret, sealed.encapsulatedKey, decodeNonce(nonceHeader)));
    }
    const usage = usageFrom(result.headers, result.trailers, stream);
    stream = usage.stream;
    const response = new Response(stream, { status: result.statusCode, headers: responseHeaders });
    rememberUsage(response, usage.value);
    return response;
  }

  private async current(): Promise<Session> {
    const existing = this.session;
    if (existing !== undefined && this.deps().clock() < existing.expiresAt) return existing;
    if (this.opening === undefined) this.opening = this.open(this.generation);
    try {
      return await this.opening;
    } finally {
      this.opening = undefined;
    }
  }

  private async open(generation: number): Promise<Session> {
    if (this.transport === "ehbp") return this.openEhbp(generation);
    return this.openTls(generation);
  }

  private async openTls(generation: number): Promise<Session> {
    const deps = this.deps();
    const recording = recordingAgent(deps.ca);
    let evidence: RouterEvidence;
    try {
      evidence = await this.loadEvidence(generation, recording.agent);
    } catch (error) {
      void recording.agent.close();
      throw error;
    }
    const seen = recording.fingerprint();
    void recording.agent.close();
    if (seen === undefined || seen !== evidence.tlsPublicKey) {
      throw new OriginError("the attestation connection key is not the attested key");
    }
    this.assertGeneration(generation);
    const agent = pinnedAgent(evidence.tlsPublicKey, deps.ca);
    const session: TlsSession = { kind: "tls", agent, ...this.finish(generation, evidence) };
    if (generation !== this.generation) {
      void agent.close();
      throw new SessionClosedError("verification was discarded by reset()");
    }
    this.session = session;
    return session;
  }

  private async openEhbp(generation: number): Promise<Session> {
    const agent = this.dispatcher();
    let evidence: RouterEvidence | undefined;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const loaded = await this.loadEvidence(generation, agent);
      const published = await this.loadPublishedKey(agent);
      this.assertGeneration(generation);
      if (sameKey(published, loaded.hpkePublicKey)) {
        evidence = loaded;
        break;
      }
    }
    if (evidence === undefined) throw new KeyConfigError("the published HPKE key does not match the attestation");
    this.assertGeneration(generation);
    const session: EhbpSession = {
      kind: "ehbp",
      hpkePublicKey: Buffer.from(evidence.hpkePublicKey, "hex"),
      ...this.finish(generation, evidence),
    };
    if (generation !== this.generation) throw new SessionClosedError("verification was discarded by reset()");
    this.session = session;
    return session;
  }

  private finish(generation: number, evidence: RouterEvidence): SharedSession {
    const deps = this.deps();
    return {
      generation,
      evidence,
      document: toDocument(evidence, this.repo, this.enclave),
      expiresAt: Math.min(evidence.collateralExpiresAt * 1000, deps.clock() + HOUR_SECONDS * 1000),
    };
  }

  private async loadEvidence(generation: number, agent: Dispatcher): Promise<RouterEvidence> {
    const nonce = randomBytes(32);
    const url = new URL(ATTESTATION_PATH, this.requestOrigin);
    url.searchParams.set("nonce", nonce.toString("hex"));
    const deps = this.deps();
    let bytes: Uint8Array;
    try {
      bytes = await deps.fetchDocument(url, agent);
    } catch (error) {
      if (generation !== this.generation) throw new SessionClosedError("verification was discarded by reset()");
      throw error;
    }
    this.assertGeneration(generation);
    const evidence = deps.verify(bytes, nonce, this.repo, Math.floor(deps.clock() / 1000));
    if (this.tag !== undefined && evidence.releaseTag !== this.tag) {
      throw new OriginError(`attested release ${evidence.releaseTag} is not ${this.tag}`);
    }
    this.assertGeneration(generation);
    return evidence;
  }

  private async loadPublishedKey(agent: Dispatcher): Promise<Uint8Array> {
    const response = await pinnedFetch(agent, new URL(KEYS_PATH, this.requestOrigin), { method: "GET" });
    if (response.status >= 300 && response.status < 400) {
      throw new RedirectRefusedError("the enclave refused to be followed to another URL");
    }
    if (!response.ok) throw new KeyConfigError(`HPKE key configuration request failed: ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > 1024) throw new KeyConfigError("HPKE key configuration is too large");
    return parseKeyConfig(bytes);
  }

  private dispatcher(): Agent {
    const existing = this.relayDispatcher;
    if (existing !== undefined) return existing;
    const ca = this.deps().ca;
    const agent = new Agent({
      connect: {
        rejectUnauthorized: true,
        ...(ca === undefined ? {} : { ca }),
      },
    });
    this.relayDispatcher = agent;
    return agent;
  }

  private invalidate(): void {
    const previous = this.session;
    this.session = undefined;
    this.opening = undefined;
    if (previous?.kind === "tls") void previous.agent.close();
  }

  private assertGeneration(generation: number): void {
    if (generation !== this.generation) throw new SessionClosedError("verification was discarded by reset()");
  }
}

function parseConfigRepo(value: string): { repo: string; tag?: string } {
  const at = value.lastIndexOf("@");
  if (at < 0) return { repo: value };
  const repo = value.slice(0, at);
  const tag = value.slice(at + 1);
  if (tag.length === 0 || tag.includes("@")) throw new OriginError("configRepo tag is empty");
  return { repo, tag };
}

async function defaultFetch(url: URL, agent: Dispatcher): Promise<Uint8Array> {
  const response = await pinnedFetch(agent, url, { method: "GET" });
  if (!response.ok) throw new OriginError(`attestation request failed: ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > 4 * 1024 * 1024) throw new OriginError("attestation document exceeds 4 MiB");
  return bytes;
}

function toDocument(evidence: RouterEvidence, repo: string, enclave: Enclave): VerificationDocument {
  const code = evidence.codeMeasurement;
  const enclaveMeasurement = {
    type: "https://tinfoil.sh/format/tdx-quote/v1",
    registers: [evidence.mrtd, ...evidence.rtmrs],
  };
  const document: VerificationDocument = {
    schemaVersion: 1,
    configRepo: repo,
    enclaveHost: enclave.host,
    releaseDigest: evidence.releaseDigest,
    codeMeasurement: code,
    enclaveMeasurement: {
      tlsPublicKeyFingerprint: evidence.tlsPublicKey,
      hpkePublicKey: evidence.hpkePublicKey,
      measurement: enclaveMeasurement,
    },
    tlsPublicKey: evidence.tlsPublicKey,
    hpkePublicKey: evidence.hpkePublicKey,
    hardwareMeasurement: {
      ID: evidence.hardware,
      MRTD: evidence.mrtd,
      RTMR0: evidence.rtmrs[0],
    },
    codeFingerprint: createHash("sha256").update(code.type + code.registers.join("")).digest("hex"),
    enclaveFingerprint: createHash("sha256")
      .update(enclaveMeasurement.type + enclaveMeasurement.registers.join(""))
      .digest("hex"),
    selectedRouterEndpoint: enclave.origin,
    securityVerified: true,
    verifiedAt: new Date().toISOString(),
    steps: {
      fetchDigest: { status: "success" },
      verifyCode: { status: "success" },
      verifyEnclave: { status: "success" },
      compareMeasurements: { status: "success" },
    },
  };
  if (evidence.releaseTag !== undefined) document.releaseTag = evidence.releaseTag;
  return document;
}

function requestUrl(input: RequestInfo | URL): URL {
  if (typeof input === "string" || input instanceof URL) return new URL(input);
  return new URL(input.url);
}

function isReplayable(body: BodyInit | null | undefined): boolean {
  if (body === undefined || body === null) return true;
  if (typeof body === "string") return true;
  if (body instanceof URLSearchParams || body instanceof Blob || body instanceof ArrayBuffer) return true;
  if (ArrayBuffer.isView(body)) return true;
  if (typeof FormData !== "undefined" && body instanceof FormData) return true;
  return false;
}

async function bodyBytes(body: BodyInit | null | undefined): Promise<Uint8Array | null> {
  if (body === undefined || body === null) return null;
  if (typeof body === "string") return Buffer.from(body);
  if (body instanceof URLSearchParams) return Buffer.from(body.toString());
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (typeof Blob !== "undefined" && body instanceof Blob) return Buffer.from(await body.arrayBuffer());
  throw new OriginError("EHBP transport cannot encrypt this request body");
}

function sameKey(published: Uint8Array, attestedHex: string): boolean {
  if (!/^[0-9a-fA-F]{64}$/.test(attestedHex)) return false;
  const attested = Buffer.from(attestedHex, "hex");
  return attested.byteLength === published.byteLength && timingSafeEqual(attested, published);
}

function decodeNonce(value: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new KeyConfigError("EHBP response nonce is malformed");
  return Buffer.from(value, "hex");
}

function headerRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

function headerValue(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name];
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value[0];
  return undefined;
}

function headersFrom(raw: IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(raw)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else if (typeof value === "string") {
      headers.append(key, value);
    }
  }
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  return headers;
}

function nodeToWeb(body: Readable): ReadableStream<Uint8Array> {
  const iterator = body[Symbol.asyncIterator]();
  let closed = false;
  return new ReadableStream({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (closed) return;
        if (next.done === true) {
          closed = true;
          controller.close();
          return;
        }
        const chunk = next.value;
        controller.enqueue(chunk instanceof Uint8Array ? new Uint8Array(chunk) : Buffer.from(chunk));
      } catch (error) {
        if (closed) return;
        closed = true;
        controller.error(error);
      }
    },
    async cancel() {
      closed = true;
      body.on("error", () => undefined);
      await iterator.return?.().catch(() => undefined);
      body.destroy();
    },
  });
}

function rememberUsage(response: Response, value: Promise<string | undefined>): void {
  usageMetricResults.set(response, value);
}

function usageFrom(
  headers: IncomingHttpHeaders,
  trailers: Record<string, string>,
  stream: ReadableStream<Uint8Array>,
): { stream: ReadableStream<Uint8Array>; value: Promise<string | undefined> } {
  const immediate = headerValue(headers, USAGE_RESPONSE);
  if (immediate !== undefined) return { stream, value: Promise.resolve(immediate) };
  let resolve: (value: string | undefined) => void = () => undefined;
  const value = new Promise<string | undefined>((done) => {
    resolve = done;
  });
  let settled = false;
  const finish = (): void => {
    if (settled) return;
    settled = true;
    resolve(trailerValue(trailers, USAGE_RESPONSE));
  };
  const reader = stream.getReader();
  const watched = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const next = await reader.read();
        if (next.done) {
          finish();
          controller.close();
          return;
        }
        controller.enqueue(next.value);
      } catch (error) {
        finish();
        controller.error(error);
      }
    },
    cancel(reason) {
      finish();
      return reader.cancel(reason);
    },
  });
  return { stream: watched, value };
}

function trailerValue(trailers: Record<string, string>, name: string): string | undefined {
  for (const [key, value] of Object.entries(trailers)) {
    if (key.toLowerCase() === name && value !== "") return value;
  }
  return undefined;
}
