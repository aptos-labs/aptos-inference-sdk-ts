import { fail } from "./error.js";

export interface Der {
  tag: number;
  start: number;
  header: number;
  end: number;
  value: Buffer;
}

export function parseDer(bytes: Buffer, at = 0): Der {
  if (at >= bytes.length) fail("encoding", "truncated DER");
  const tag = bytes[at]!;
  if ((tag & 0x1f) === 0x1f) fail("encoding", "long-form DER tags are not accepted");
  let length = bytes[at + 1];
  if (length === undefined) fail("encoding", "truncated DER length");
  let header = 2;
  if (length === 0x80) fail("encoding", "indefinite DER lengths are not accepted");
  if (length > 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 3) fail("encoding", "non-minimal or oversized DER length");
    length = 0;
    for (let i = 0; i < count; i += 1) {
      const byte = bytes[at + 2 + i];
      if (byte === undefined) fail("encoding", "truncated DER length");
      length = (length << 8) | byte;
    }
    if (length < 128) fail("encoding", "non-minimal DER length");
    header = 2 + count;
  }
  const end = at + header + length;
  if (end > bytes.length) fail("encoding", "truncated DER value");
  return { tag, start: at, header, end, value: bytes.subarray(at + header, end) };
}

const UTF8_STRING = 0x0c;
const PRINTABLE_STRING = 0x13;
const IA5_STRING = 0x16;

/**
 * Reads a certificate extension value as text. Fulcio wraps newer identity
 * fields in a DER string and leaves the older ones as raw bytes.
 */
export function decodeAsn1String(bytes: Buffer): string {
  const tag = bytes[0];
  if (tag !== UTF8_STRING && tag !== PRINTABLE_STRING && tag !== IA5_STRING) return bytes.toString("utf8");
  const der = parseDer(bytes);
  if (der.end !== bytes.length) fail("encoding", "trailing bytes after a DER string");
  return der.value.toString("utf8");
}

export function sequence(der: Der): Der[] {
  if (der.tag !== 0x30) fail("encoding", "expected a DER sequence");
  const out: Der[] = [];
  let offset = 0;
  while (offset < der.value.length) {
    const child = parseDer(der.value, offset);
    out.push(child);
    offset = child.end;
  }
  return out;
}

export function encodeOid(oid: string): Buffer {
  const parts = oid.split(".").map((part) => Number(part));
  const first = parts[0];
  const second = parts[1];
  if (first === undefined || second === undefined) fail("encoding", "bad OID");
  const bytes = [first * 40 + second];
  for (const part of parts.slice(2)) {
    const encoded: number[] = [part & 0x7f];
    let rest = part >> 7;
    while (rest > 0) {
      encoded.push((rest & 0x7f) | 0x80);
      rest >>= 7;
    }
    bytes.push(...encoded.reverse());
  }
  return Buffer.from(bytes);
}

export function childByOid(items: Der[], oid: string): Der | undefined {
  const encoded = encodeOid(oid);
  for (const item of items) {
    const [name, value] = sequence(item);
    if (name !== undefined && value !== undefined && name.tag === 0x06 && name.value.equals(encoded)) {
      return value;
    }
  }
  return undefined;
}

export function unwrapOctet(der: Der): Buffer {
  if (der.tag !== 0x04) fail("encoding", "expected a DER octet string");
  return der.value;
}
