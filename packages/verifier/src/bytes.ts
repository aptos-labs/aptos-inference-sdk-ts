import { createHash, timingSafeEqual } from "node:crypto";

import { fail } from "./error.js";

export function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

export function hex(data: Uint8Array): string {
  return Buffer.from(data).toString("hex");
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

export function decodeCanonicalBase64(value: string, what: string): Buffer {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    fail("encoding", `${what} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    fail("encoding", `${what} is not canonical base64`);
  }
  return decoded;
}

export function decodeLowerHex(value: string, what: string, bytes: number): Buffer {
  if (value.length !== bytes * 2 || !/^[0-9a-f]+$/.test(value)) {
    fail("encoding", `${what} is not ${bytes} bytes of lowercase hex`);
  }
  return Buffer.from(value, "hex");
}

export function utf8(bytes: Uint8Array, what: string): string {
  const text = Buffer.from(bytes).toString("utf8");
  if (!Buffer.from(text, "utf8").equals(Buffer.from(bytes))) {
    fail("encoding", `${what} is not valid UTF-8`);
  }
  return text;
}

export function rsToDer(signature: Uint8Array): Buffer {
  if (signature.length !== 64) fail("dcap", "ECDSA signature is not 64 bytes");
  const part = (raw: Uint8Array): Buffer => {
    let start = 0;
    while (start < raw.length - 1 && raw[start] === 0) start += 1;
    let body = Buffer.from(raw.subarray(start));
    if ((body[0]! & 0x80) !== 0) body = Buffer.concat([Buffer.from([0]), body]);
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const body = Buffer.concat([
    part(signature.subarray(0, 32)),
    part(signature.subarray(32)),
  ]);
  if (body.length > 127) fail("dcap", "ECDSA signature DER is unexpectedly long");
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

export function p256Spki(xy: Uint8Array): Buffer {
  if (xy.length !== 64) fail("dcap", "P-256 key is not 64 bytes");
  const prefix = Buffer.from(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004",
    "hex",
  );
  return Buffer.concat([prefix, Buffer.from(xy)]);
}

export function zero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}
