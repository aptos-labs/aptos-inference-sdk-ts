import { fail } from "./error.js";

export interface TdReport {
  teeTcbSvn: Buffer;
  mrSeam: Buffer;
  mrSignerSeam: Buffer;
  seamAttributes: Buffer;
  tdAttributes: Buffer;
  xfam: Buffer;
  mrTd: Buffer;
  mrConfigId: Buffer;
  mrOwner: Buffer;
  mrOwnerConfig: Buffer;
  rtmrs: [Buffer, Buffer, Buffer, Buffer];
  reportData: Buffer;
}

export interface QeReport {
  miscSelect: number;
  attributes: Buffer;
  mrSigner: Buffer;
  isvProdId: number;
  isvSvn: number;
  reportData: Buffer;
  raw: Buffer;
}

export interface ParsedQuote {
  version: number;
  attestationKeyType: number;
  teeType: number;
  qeVendorId: Buffer;
  signed: Buffer;
  td: TdReport;
  signature: Buffer;
  attestationKey: Buffer;
  qeReport: QeReport;
  qeSignature: Buffer;
  qeAuthData: Buffer;
  pckChainPem: Buffer;
}

const TD_REPORT_LEN = 584;
const QE_REPORT_LEN = 384;

function take(buffer: Buffer, offset: number, length: number): Buffer {
  const end = offset + length;
  if (end > buffer.length) fail("dcap", "truncated quote");
  return buffer.subarray(offset, end);
}

function u16(buffer: Buffer, offset: number): number {
  if (offset + 2 > buffer.length) fail("dcap", "truncated quote");
  return buffer.readUInt16LE(offset);
}

function u32(buffer: Buffer, offset: number): number {
  if (offset + 4 > buffer.length) fail("dcap", "truncated quote");
  return buffer.readUInt32LE(offset);
}

export function parseQuote(quote: Buffer): ParsedQuote {
  if (quote.length < 48 + TD_REPORT_LEN + 4) fail("dcap", "quote is too small");
  const version = u16(quote, 0);
  const attestationKeyType = u16(quote, 2);
  const teeType = u32(quote, 4);
  const qeVendorId = take(quote, 12, 16);
  if (version !== 4) fail("tdx", `unsupported quote version ${version}`);
  if (teeType !== 0x81) fail("tdx", "quote is not a TDX quote");
  if (attestationKeyType !== 2) fail("dcap", "unsupported attestation key type");
  const signedLength = 48 + TD_REPORT_LEN;
  const authLength = u32(quote, signedLength);
  const authStart = signedLength + 4;
  if (authLength > 1_048_576 || authStart + authLength > quote.length) {
    fail("dcap", "quote auth data length is wrong");
  }
  const auth = quote.subarray(authStart, authStart + authLength);
  let offset = 0;
  const signature = take(auth, offset, 64);
  offset += 64;
  const attestationKey = take(auth, offset, 64);
  offset += 64;
  const outerType = u16(auth, offset);
  offset += 2;
  const outerSize = u32(auth, offset);
  offset += 4;
  if (outerType !== 6) fail("dcap", `unexpected certification type ${outerType}`);
  if (offset + outerSize !== auth.length) fail("dcap", "certification data length is wrong");
  const body = auth.subarray(offset, offset + outerSize);
  const qeRaw = take(body, 0, QE_REPORT_LEN);
  const qeSignature = take(body, QE_REPORT_LEN, 64);
  let inner = QE_REPORT_LEN + 64;
  const authDataLen = u16(body, inner);
  inner += 2;
  if (authDataLen !== 32) fail("dcap", "QE auth data must be 32 bytes");
  const qeAuthData = take(body, inner, authDataLen);
  inner += authDataLen;
  const certType = u16(body, inner);
  inner += 2;
  const certSize = u32(body, inner);
  inner += 4;
  if (certType !== 5) fail("dcap", `PCK chain type ${certType} is not supported`);
  if (inner + certSize !== body.length) fail("dcap", "PCK chain length is wrong");
  return {
    version,
    attestationKeyType,
    teeType,
    qeVendorId,
    signed: quote.subarray(0, signedLength),
    td: parseTd(quote.subarray(48, signedLength)),
    signature,
    attestationKey,
    qeReport: parseQe(qeRaw),
    qeSignature,
    qeAuthData,
    pckChainPem: body.subarray(inner),
  };
}

function parseTd(body: Buffer): TdReport {
  let offset = 0;
  const next = (length: number): Buffer => {
    const value = body.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const teeTcbSvn = next(16);
  const mrSeam = next(48);
  const mrSignerSeam = next(48);
  const seamAttributes = next(8);
  const tdAttributes = next(8);
  const xfam = next(8);
  const mrTd = next(48);
  const mrConfigId = next(48);
  const mrOwner = next(48);
  const mrOwnerConfig = next(48);
  const rtmrs = [next(48), next(48), next(48), next(48)] as [Buffer, Buffer, Buffer, Buffer];
  const reportData = next(64);
  if (offset !== body.length) fail("dcap", "TD report length is wrong");
  return {
    teeTcbSvn, mrSeam, mrSignerSeam, seamAttributes, tdAttributes, xfam, mrTd,
    mrConfigId, mrOwner, mrOwnerConfig, rtmrs, reportData,
  };
}

function parseQe(raw: Buffer): QeReport {
  return {
    raw,
    miscSelect: raw.readUInt32LE(16),
    attributes: raw.subarray(48, 64),
    mrSigner: raw.subarray(128, 160),
    isvProdId: raw.readUInt16LE(256),
    isvSvn: raw.readUInt16LE(258),
    reportData: raw.subarray(320, 384),
  };
}
