import { fail, type VerificationCategory } from "./error.js";

interface Cursor {
  text: string;
  i: number;
}

function skip(cursor: Cursor): void {
  while (cursor.i < cursor.text.length && " \n\r\t".includes(cursor.text[cursor.i]!)) {
    cursor.i += 1;
  }
}

function failAt(category: VerificationCategory, message: string): never {
  fail(category, message);
}

function parseValue(cursor: Cursor, category: VerificationCategory): void {
  skip(cursor);
  const ch = cursor.text[cursor.i];
  if (ch === "{") parseObject(cursor, category);
  else if (ch === "[") parseArray(cursor, category);
  else if (ch === '"') parseString(cursor, category);
  else if (ch === "t" || ch === "f" || ch === "n") parseLiteral(cursor, category);
  else if (ch === "-" || (ch !== undefined && ch >= "0" && ch <= "9")) parseNumber(cursor, category);
  else failAt(category, "malformed JSON");
}

function parseObject(cursor: Cursor, category: VerificationCategory): void {
  cursor.i += 1;
  skip(cursor);
  const seen = new Set<string>();
  if (cursor.text[cursor.i] === "}") {
    cursor.i += 1;
    return;
  }
  for (;;) {
    if (cursor.text[cursor.i] !== '"') failAt(category, "JSON object key is not a string");
    const key = parseString(cursor, category);
    if (seen.has(key)) failAt(category, `JSON object has a duplicate key ${key}`);
    seen.add(key);
    skip(cursor);
    if (cursor.text[cursor.i] !== ":") failAt(category, "JSON object is missing a colon");
    cursor.i += 1;
    parseValue(cursor, category);
    skip(cursor);
    const next = cursor.text[cursor.i];
    if (next === ",") {
      cursor.i += 1;
      skip(cursor);
      continue;
    }
    if (next === "}") {
      cursor.i += 1;
      return;
    }
    failAt(category, "JSON object is not closed");
  }
}

function parseArray(cursor: Cursor, category: VerificationCategory): void {
  cursor.i += 1;
  skip(cursor);
  if (cursor.text[cursor.i] === "]") {
    cursor.i += 1;
    return;
  }
  for (;;) {
    parseValue(cursor, category);
    skip(cursor);
    const next = cursor.text[cursor.i];
    if (next === ",") {
      cursor.i += 1;
      skip(cursor);
      continue;
    }
    if (next === "]") {
      cursor.i += 1;
      return;
    }
    failAt(category, "JSON array is not closed");
  }
}

function parseString(cursor: Cursor, category: VerificationCategory): string {
  if (cursor.text[cursor.i] !== '"') failAt(category, "expected a JSON string");
  cursor.i += 1;
  let out = "";
  while (cursor.i < cursor.text.length) {
    const ch = cursor.text[cursor.i]!;
    if (ch === '"') {
      cursor.i += 1;
      return out;
    }
    if (ch === "\\") {
      const esc = cursor.text[cursor.i + 1];
      if (esc === "u") {
        const hex = cursor.text.slice(cursor.i + 2, cursor.i + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) failAt(category, "bad unicode escape");
        const code = Number.parseInt(hex, 16);
        cursor.i += 6;
        if (code >= 0xd800 && code <= 0xdbff) {
          if (cursor.text.slice(cursor.i, cursor.i + 2) !== "\\u") {
            failAt(category, "lone surrogate in JSON string");
          }
          const low = cursor.text.slice(cursor.i + 2, cursor.i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(low)) failAt(category, "bad unicode escape");
          const lowCode = Number.parseInt(low, 16);
          if (lowCode < 0xdc00 || lowCode > 0xdfff) failAt(category, "lone surrogate in JSON string");
          cursor.i += 6;
          out += String.fromCodePoint(0x10000 + ((code - 0xd800) << 10) + (lowCode - 0xdc00));
        } else if (code >= 0xdc00 && code <= 0xdfff) {
          failAt(category, "lone surrogate in JSON string");
        } else {
          out += String.fromCharCode(code);
        }
        continue;
      }
      const simple: Record<string, string> = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      };
      if (esc === undefined || !(esc in simple)) failAt(category, "bad JSON escape");
      out += simple[esc];
      cursor.i += 2;
      continue;
    }
    if (ch < " ") failAt(category, "raw control character in JSON string");
    out += ch;
    cursor.i += 1;
  }
  failAt(category, "unterminated JSON string");
}

function parseLiteral(cursor: Cursor, category: VerificationCategory): void {
  const rest = cursor.text.slice(cursor.i);
  for (const word of ["true", "false", "null"]) {
    if (rest.startsWith(word)) {
      cursor.i += word.length;
      return;
    }
  }
  failAt(category, "bad JSON literal");
}

function parseNumber(cursor: Cursor, category: VerificationCategory): void {
  const start = cursor.i;
  if (cursor.text[cursor.i] === "-") cursor.i += 1;
  if (cursor.text[cursor.i] === "0") {
    cursor.i += 1;
  } else if (cursor.text[cursor.i]! >= "1" && cursor.text[cursor.i]! <= "9") {
    while (cursor.text[cursor.i]! >= "0" && cursor.text[cursor.i]! <= "9") cursor.i += 1;
  } else {
    failAt(category, "bad JSON number");
  }
  if (cursor.text[cursor.i] === ".") {
    cursor.i += 1;
    if (cursor.text[cursor.i]! < "0" || cursor.text[cursor.i]! > "9") failAt(category, "bad JSON number");
    while (cursor.text[cursor.i]! >= "0" && cursor.text[cursor.i]! <= "9") cursor.i += 1;
  }
  if (cursor.text[cursor.i] === "e" || cursor.text[cursor.i] === "E") {
    failAt(category, "JSON numbers with exponents are not accepted");
  }
  const raw = cursor.text.slice(start, cursor.i);
  if (raw.startsWith("-0") || raw.startsWith("00")) failAt(category, "non-canonical JSON number");
  const value = Number(raw);
  if (!Number.isFinite(value)) failAt(category, "JSON number is not finite");
}

export function assertJson(text: string, category: VerificationCategory): unknown {
  const cursor: Cursor = { text, i: 0 };
  parseValue(cursor, category);
  skip(cursor);
  if (cursor.i !== text.length) failAt(category, "trailing data after JSON");
  return JSON.parse(text);
}

export function rawObjectMember(text: string, key: string, category: VerificationCategory): string {
  const cursor: Cursor = { text, i: 0 };
  skip(cursor);
  if (cursor.text[cursor.i] !== "{") fail(category, "expected a JSON object");
  cursor.i += 1;
  skip(cursor);
  let found: string | undefined;
  if (cursor.text[cursor.i] === "}") fail(category, `JSON object has no ${key}`);
  for (;;) {
    const name = parseString(cursor, category);
    skip(cursor);
    if (cursor.text[cursor.i] !== ":") fail(category, "JSON object is missing a colon");
    cursor.i += 1;
    skip(cursor);
    const start = cursor.i;
    parseValue(cursor, category);
    if (name === key) {
      if (found !== undefined) fail(category, `duplicate ${key}`);
      found = text.slice(start, cursor.i);
    }
    skip(cursor);
    const next = cursor.text[cursor.i];
    if (next === ",") {
      cursor.i += 1;
      skip(cursor);
      continue;
    }
    if (next === "}") break;
    fail(category, "JSON object is not closed");
  }
  if (found === undefined) fail(category, `JSON object has no ${key}`);
  return found;
}
