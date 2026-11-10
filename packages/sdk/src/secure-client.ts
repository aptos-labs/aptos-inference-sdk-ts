import { createHash, randomBytes } from "node:crypto";

import { verifyRouterDocument, type RouterEvidence } from "@aptos-labs/inference-verifier";
import type { Dispatcher } from "undici";

import { injectCacheSecret, resolveCacheSecret } from "./cache-secret.js";
import { NotReadyError, OriginError, RedirectRefusedError, SessionClosedError } from "./errors.js";
import { parseEnclave, sameOrigin, type Enclave } from "./origin.js";
import { isPinMismatch, pinnedAgent, pinnedFetch, recordingAgent } from "./transport.js";

export const DEFAULT_ENCLAVE = "https://router.inference.aptoslabs.com";
export const DEFAULT_REPO = "aptos-labs/confidential-inference-router";
const ATTESTATION_PATH = "/.well-known/tinfoil-attestation";
const HOUR_SECONDS = 60 * 60;

export interface SecureClientOptions {
  /** `https` origin of the router. No path, query, fragment, or user info. */
  enclaveURL?: string;
  /** `owner/repo`, or `owner/repo@tag` to require that release. */
  configRepo?: string;
  /** Bearer token. Defaults to `APTOS_INFERENCE_API_KEY`. */
  apiKey?: string;
  /** Prompt-cache secret. Defaults to `APTOS_INFERENCE_USER_CACHE_SECRET`, then `~/.aptos-inference/user_cache_secret`. */
  userCacheSecret?: string;
}

interface ClientDeps {
  fetchDocument: (url: URL, agent: Dispatcher) => Promise<Uint8Array>;
  verify: typeof verifyRouterDocument;
  ca?: string | Buffer;
  clock: () => number;
}

const clientDeps = new WeakMap<SecureClient, ClientDeps>();

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

interface Session {
  generation: number;
  evidence: RouterEvidence;
  document: VerificationDocument;
  expiresAt: number;
  agent: Dispatcher;
}

export class SecureClient {
  readonly enclave: Enclave;
  readonly repo: string;
  readonly tag?: string;
  readonly apiKey?: string;
  private readonly cacheSecret: string;
  private generation = 0;
  private session: Session | undefined;
  private opening: Promise<Session> | undefined;

  constructor(options: SecureClientOptions = {}) {
    const parsed = parseConfigRepo(options.configRepo ?? DEFAULT_REPO);
    this.repo = parsed.repo;
    if (parsed.tag !== undefined) this.tag = parsed.tag;
    this.enclave = parseEnclave(options.enclaveURL ?? DEFAULT_ENCLAVE);
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

  get baseURL(): string {
    return `${this.enclave.origin}/v1`;
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
    void previous?.agent.close();
  }

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = requestUrl(input);
    sameOrigin(url, this.enclave.origin);
    const replayable = isReplayable(init?.body);
    try {
      return await this.send(url, init);
    } catch (error) {
      if (!replayable || !retryable(error)) throw error;
      this.session = undefined;
      return await this.send(url, init);
    }
  };

  private async send(url: URL, init?: RequestInit): Promise<Response> {
    const session = await this.current();
    const body = typeof init?.body === "string" ? injectCacheSecret(init.body, url.pathname, this.cacheSecret) : undefined;
    const headers = new Headers(init?.headers);
    headers.delete("content-length");
    const next: RequestInit = { redirect: "manual", headers };
    if (init?.method !== undefined) next.method = init.method;
    const requestBody = body ?? init?.body;
    if (requestBody != null) next.body = requestBody;
    const response = await pinnedFetch(session.agent, url, next);
    if (response.status >= 300 && response.status < 400) {
      throw new RedirectRefusedError("the enclave refused to be followed to another URL");
    }
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
    const nonce = randomBytes(32);
    const url = new URL(ATTESTATION_PATH, this.enclave.origin);
    url.searchParams.set("nonce", nonce.toString("hex"));
    const deps = this.deps();
    const recording = recordingAgent(deps.ca);
    let bytes: Uint8Array;
    try {
      bytes = await deps.fetchDocument(url, recording.agent);
    } catch (error) {
      void recording.agent.close();
      if (generation !== this.generation) throw new SessionClosedError("verification was discarded by reset()");
      throw error;
    }
    if (generation !== this.generation) {
      void recording.agent.close();
      throw new SessionClosedError("verification was discarded by reset()");
    }
    const evidence = deps.verify(bytes, nonce, this.repo, Math.floor(deps.clock() / 1000));
    if (this.tag !== undefined && evidence.releaseTag !== this.tag) {
      void recording.agent.close();
      throw new OriginError(`attested release ${evidence.releaseTag} is not ${this.tag}`);
    }
    const seen = recording.fingerprint();
    if (seen === undefined || seen !== evidence.tlsPublicKey) {
      void recording.agent.close();
      throw new OriginError("the attestation connection key is not the attested key");
    }
    if (generation !== this.generation) {
      void recording.agent.close();
      throw new SessionClosedError("verification was discarded by reset()");
    }
    void recording.agent.close();
    const agent = pinnedAgent(evidence.tlsPublicKey, deps.ca);
    const session: Session = {
      generation,
      evidence,
      document: toDocument(evidence, this.repo, this.enclave),
      expiresAt: Math.min(evidence.collateralExpiresAt * 1000, deps.clock() + HOUR_SECONDS * 1000),
      agent,
    };
    if (generation !== this.generation) {
      void agent.close();
      throw new SessionClosedError("verification was discarded by reset()");
    }
    this.session = session;
    return session;
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
  return {
    schemaVersion: 1,
    configRepo: repo,
    enclaveHost: enclave.host,
    releaseTag: evidence.releaseTag,
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

function retryable(error: unknown): boolean {
  if (isPinMismatch(error)) return true;
  if (!(error instanceof Error)) return false;
  const code = "code" in error ? String(error.code) : "";
  return code === "ECONNREFUSED" || code === "ECONNRESET" || code === "UND_ERR_CONNECT_TIMEOUT" || error.message.includes("PIN_MISMATCH");
}
