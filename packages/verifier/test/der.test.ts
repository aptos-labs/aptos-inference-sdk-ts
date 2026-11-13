import { describe, expect, it } from "vitest";

import { decodeAsn1String } from "../src/der.js";
import { VerificationError } from "../src/error.js";

function utf8String(text: string): Buffer {
  const body = Buffer.from(text, "utf8");
  const length =
    body.length < 0x80
      ? Buffer.from([body.length])
      : body.length < 0x100
        ? Buffer.from([0x81, body.length])
        : Buffer.from([0x82, body.length >> 8, body.length & 0xff]);
  return Buffer.concat([Buffer.from([0x0c]), length, body]);
}

describe("decodeAsn1String", () => {
  it("reads a short-form length", () => {
    expect(decodeAsn1String(utf8String("a".repeat(127)))).toBe("a".repeat(127));
  });

  it("reads the first long-form length", () => {
    expect(decodeAsn1String(utf8String("a".repeat(128)))).toBe("a".repeat(128));
  });

  it("reads a two-byte long-form length", () => {
    expect(decodeAsn1String(utf8String("b".repeat(300)))).toBe("b".repeat(300));
  });

  it("returns an unwrapped extension value as text", () => {
    expect(decodeAsn1String(Buffer.from("https://token.actions.githubusercontent.com"))).toBe(
      "https://token.actions.githubusercontent.com",
    );
  });

  it("rejects bytes after the string", () => {
    const encoded = Buffer.concat([utf8String("abc"), Buffer.from([0x00])]);
    expect(() => decodeAsn1String(encoded)).toThrow(VerificationError);
  });

  it("rejects a length that runs past the value", () => {
    expect(() => decodeAsn1String(Buffer.from([0x0c, 0x05, 0x61, 0x62]))).toThrow(VerificationError);
  });
});
