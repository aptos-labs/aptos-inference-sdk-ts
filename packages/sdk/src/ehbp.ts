import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";

import { KeyConfigError } from "./errors.js";

export const ENCAPSULATED_KEY = "ehbp-encapsulated-key";
export const RESPONSE_NONCE = "ehbp-response-nonce";
export const USAGE_REQUEST = "x-tinfoil-request-usage-metrics";
export const USAGE_RESPONSE = "x-tinfoil-usage-metrics";
export const KEYS_PATH = "/.well-known/hpke-keys";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

const MAX_FRAME = 64 << 20;
const KEM_SUITE = Buffer.from("4b454d0020", "hex");
const HPKE_SUITE = Buffer.from("48504b45002000010002", "hex");
const REQUEST_INFO = Buffer.from("ehbp request");
const EXPORT_CONTEXT = Buffer.from("ehbp response");

export interface SealedRequest {
  encapsulatedKey: Uint8Array;
  responseSecret: Uint8Array;
  body: Uint8Array;
}

export interface AcceptedRequest {
  plaintext: Uint8Array;
  responseSecret: Uint8Array;
}

interface Schedule {
  key: Buffer;
  nonce: Buffer;
  responseSecret: Buffer;
}

/** Reads the single X25519 public key from an `application/ohttp-keys` document. */
export function parseKeyConfig(bytes: Uint8Array): Uint8Array {
  const data = Buffer.from(bytes);
  if (data.length < 1 + 2 + 32 + 2) throw new KeyConfigError("HPKE key configuration is truncated");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const kem = view.getUint16(1);
  if (kem !== 0x0020) throw new KeyConfigError("HPKE key configuration is not X25519");
  const publicKey = data.subarray(3, 35);
  const suitesLength = view.getUint16(35);
  if (data.length !== 37 + suitesLength) throw new KeyConfigError("HPKE key configuration has trailing data");
  if (suitesLength !== 4) throw new KeyConfigError("HPKE key configuration does not advertise one cipher suite");
  const kdf = view.getUint16(37);
  const aead = view.getUint16(39);
  if (kdf !== 0x0001 || aead !== 0x0002) {
    throw new KeyConfigError("HPKE key configuration is not HKDF-SHA256 and AES-256-GCM");
  }
  return new Uint8Array(publicKey);
}

export function sealRequest(publicKey: Uint8Array, plaintext: Uint8Array, ephemeralSecret?: Uint8Array): SealedRequest {
  const chunks = plaintext.byteLength === 0 ? [] : [plaintext];
  return sealChunks(publicKey, chunks, ephemeralSecret);
}

export function sealChunks(publicKey: Uint8Array, chunks: readonly Uint8Array[], ephemeralSecret?: Uint8Array): SealedRequest {
  const schedule = senderSchedule(publicKey, ephemeralSecret);
  const frames = chunks.filter((chunk) => chunk.byteLength > 0).map((chunk, index) => frame(aesSeal(schedule.key, nonceFor(schedule.nonce, index), Buffer.from(chunk))));
  return {
    encapsulatedKey: schedule.encapsulatedKey,
    responseSecret: schedule.responseSecret,
    body: concat(frames),
  };
}

export function acceptRequest(secretKey: Uint8Array, encapsulatedKey: Uint8Array, body: Uint8Array): AcceptedRequest {
  const schedule = recipientSchedule(secretKey, encapsulatedKey);
  return {
    plaintext: openFrames(body, (seq, ciphertext) => aesOpen(schedule.key, nonceFor(schedule.nonce, seq), ciphertext)),
    responseSecret: schedule.responseSecret,
  };
}

export function sealResponse(responseSecret: Uint8Array, encapsulatedKey: Uint8Array, responseNonce: Uint8Array, chunks: readonly Uint8Array[]): Uint8Array {
  const { key, nonce } = responseSchedule(responseSecret, encapsulatedKey, responseNonce);
  const frames = chunks.filter((chunk) => chunk.byteLength > 0).map((chunk, index) => frame(aesSeal(key, nonceFor(nonce, index), Buffer.from(chunk))));
  return concat(frames);
}

export function openResponse(responseSecret: Uint8Array, encapsulatedKey: Uint8Array, responseNonce: Uint8Array, body: Uint8Array): Uint8Array {
  const { key, nonce } = responseSchedule(responseSecret, encapsulatedKey, responseNonce);
  return openFrames(body, (seq, ciphertext) => aesOpen(key, nonceFor(nonce, seq), ciphertext));
}

export function decryptResponseStream(
  responseSecret: Uint8Array,
  encapsulatedKey: Uint8Array,
  responseNonce: Uint8Array,
): TransformStream<Uint8Array, Uint8Array> {
  const { key, nonce } = responseSchedule(responseSecret, encapsulatedKey, responseNonce);
  let pending = Buffer.alloc(0);
  let seq = 0;
  return new TransformStream({
    transform(chunk, controller) {
      pending = pending.length === 0 ? Buffer.from(chunk) : Buffer.concat([pending, Buffer.from(chunk)]);
      while (pending.length >= 4) {
        const length = pending.readUInt32BE(0);
        if (length === 0) {
          pending = pending.subarray(4);
          continue;
        }
        if (length > MAX_FRAME) throw new KeyConfigError("encrypted response frame exceeds 64 MiB");
        if (pending.length < 4 + length) return;
        const ciphertext = pending.subarray(4, 4 + length);
        pending = pending.subarray(4 + length);
        controller.enqueue(aesOpen(key, nonceFor(nonce, seq), ciphertext));
        seq += 1;
      }
    },
    flush() {
      if (pending.length !== 0) throw new KeyConfigError("encrypted response ended inside a frame");
    },
  });
}

function senderSchedule(publicKey: Uint8Array, ephemeralSecret?: Uint8Array): Schedule & { encapsulatedKey: Uint8Array } {
  const remote = publicKeyFromRaw(Buffer.from(publicKey));
  const local = ephemeralSecret === undefined ? generateKeyPairSync("x25519") : { privateKey: privateKeyFromRaw(Buffer.from(ephemeralSecret)), publicKey: createPublicKey(privateKeyFromRaw(Buffer.from(ephemeralSecret))) };
  const encapsulatedKey = rawPublic(local.publicKey);
  const dh = diffieHellman({ privateKey: local.privateKey, publicKey: remote });
  const shared = kemShared(dh, Buffer.concat([encapsulatedKey, rawPublic(remote)]));
  return { encapsulatedKey, ...keySchedule(shared) };
}

function recipientSchedule(secretKey: Uint8Array, encapsulatedKey: Uint8Array): Schedule {
  const local = privateKeyFromRaw(Buffer.from(secretKey));
  const remote = publicKeyFromRaw(Buffer.from(encapsulatedKey));
  const dh = diffieHellman({ privateKey: local, publicKey: remote });
  const shared = kemShared(dh, Buffer.concat([Buffer.from(encapsulatedKey), rawPublic(createPublicKey(local))]));
  return keySchedule(shared);
}

function kemShared(dh: Buffer, kemContext: Buffer): Buffer {
  const prk = labeledExtract(KEM_SUITE, Buffer.alloc(0), Buffer.from("eae_prk"), dh);
  return labeledExpand(KEM_SUITE, prk, Buffer.from("shared_secret"), kemContext, 32);
}

function keySchedule(shared: Buffer): Schedule {
  const pskIdHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), Buffer.from("psk_id_hash"), Buffer.alloc(0));
  const infoHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), Buffer.from("info_hash"), REQUEST_INFO);
  const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(HPKE_SUITE, shared, Buffer.from("secret"), Buffer.alloc(0));
  return {
    key: labeledExpand(HPKE_SUITE, secret, Buffer.from("key"), context, 32),
    nonce: labeledExpand(HPKE_SUITE, secret, Buffer.from("base_nonce"), context, 12),
    responseSecret: hpkeExport(labeledExpand(HPKE_SUITE, secret, Buffer.from("exp"), context, 32)),
  };
}

function hpkeExport(exporterSecret: Buffer): Buffer {
  return labeledExpand(HPKE_SUITE, exporterSecret, Buffer.from("sec"), EXPORT_CONTEXT, 32);
}

function responseSchedule(responseSecret: Uint8Array, encapsulatedKey: Uint8Array, responseNonce: Uint8Array): { key: Buffer; nonce: Buffer } {
  if (responseSecret.byteLength !== 32 || encapsulatedKey.byteLength !== 32 || responseNonce.byteLength !== 32) {
    throw new KeyConfigError("EHBP response key material has the wrong length");
  }
  const salt = Buffer.concat([Buffer.from(encapsulatedKey), Buffer.from(responseNonce)]);
  const prk = extract(salt, Buffer.from(responseSecret));
  return { key: expand(prk, Buffer.from("key"), 32), nonce: expand(prk, Buffer.from("nonce"), 12) };
}

function labeledExtract(suite: Buffer, salt: Buffer, label: Buffer, ikm: Buffer): Buffer {
  return extract(salt, Buffer.concat([Buffer.from("HPKE-v1"), suite, label, ikm]));
}

function labeledExpand(suite: Buffer, prk: Buffer, label: Buffer, info: Buffer, length: number): Buffer {
  const labeled = Buffer.concat([uint16(length), Buffer.from("HPKE-v1"), suite, label, info]);
  return expand(prk, labeled, length);
}

function extract(salt: Buffer, ikm: Buffer): Buffer {
  return createHmac("sha256", salt.byteLength === 0 ? Buffer.alloc(32) : salt).update(ikm).digest();
}

function expand(prk: Buffer, info: Buffer, length: number): Buffer {
  const blocks: Buffer[] = [];
  let previous = Buffer.alloc(0);
  let offset = 0;
  for (let counter = 1; offset < length; counter += 1) {
    previous = createHmac("sha256", prk).update(Buffer.concat([previous, info, Buffer.from([counter])])).digest();
    blocks.push(previous);
    offset += previous.byteLength;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function aesSeal(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function aesOpen(key: Buffer, nonce: Buffer, ciphertext: Buffer): Uint8Array {
  if (ciphertext.byteLength < 16) throw new KeyConfigError("encrypted frame is shorter than its authentication tag");
  const tag = ciphertext.subarray(ciphertext.byteLength - 16);
  const body = ciphertext.subarray(0, ciphertext.byteLength - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  try {
    return new Uint8Array(Buffer.concat([decipher.update(body), decipher.final()]));
  } catch {
    throw new KeyConfigError("encrypted frame failed authentication");
  }
}

function nonceFor(base: Buffer, seq: number): Buffer {
  const nonce = Buffer.from(base);
  let value = BigInt(seq);
  for (let i = 0; i < 8; i += 1) {
    const index = nonce.byteLength - 1 - i;
    nonce[index] = (nonce[index] ?? 0) ^ Number(value & 0xffn);
    value >>= 8n;
  }
  return nonce;
}

function openFrames(body: Uint8Array, open: (seq: number, ciphertext: Buffer) => Uint8Array): Uint8Array {
  const data = Buffer.from(body);
  const parts: Uint8Array[] = [];
  let offset = 0;
  let seq = 0;
  while (offset < data.byteLength) {
    if (offset + 4 > data.byteLength) throw new KeyConfigError("encrypted body ended inside a frame");
    const length = data.readUInt32BE(offset);
    offset += 4;
    if (length === 0) continue;
    if (length > MAX_FRAME) throw new KeyConfigError("encrypted frame exceeds 64 MiB");
    if (offset + length > data.byteLength) throw new KeyConfigError("encrypted body ended inside a frame");
    parts.push(open(seq, data.subarray(offset, offset + length)));
    offset += length;
    seq += 1;
  }
  return concat(parts);
}

function frame(ciphertext: Buffer): Uint8Array {
  const out = Buffer.alloc(4 + ciphertext.byteLength);
  out.writeUInt32BE(ciphertext.byteLength, 0);
  ciphertext.copy(out, 4);
  return out;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = Buffer.alloc(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    Buffer.from(part).copy(out, offset);
    offset += part.byteLength;
  }
  return out;
}

function uint16(value: number): Buffer {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value, 0);
  return out;
}

function rawPublic(key: KeyObject): Buffer {
  const der = key.export({ type: "spki", format: "der" });
  return der.subarray(der.byteLength - 32);
}

function publicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.byteLength !== 32) throw new KeyConfigError("HPKE public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function privateKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.byteLength !== 32) throw new KeyConfigError("HPKE private key must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: "der", type: "pkcs8" });
}
