import { createPublicKey, verify, X509Certificate, type KeyObject } from "node:crypto";

import { X509Certificate as AsnCertificate, X509Crl } from "@peculiar/x509";

import { decodeCanonicalBase64, equalBytes, p256Spki, rsToDer, sha256, zero } from "./bytes.js";
import { childByOid, encodeOid, parseDer, sequence, unwrapOctet } from "./der.js";
import type { CollateralEntry } from "./document.js";
import { INTEL_PCS_V1 } from "./document.js";
import { fail } from "./error.js";
import { assertJson, rawObjectMember } from "./json.js";
import { INTEL_SGX_ROOT_CA_DER } from "./intel-root.js";
import { parseQuote, type ParsedQuote, type QeReport, type TdReport } from "./quote.js";

export interface DcapResult {
  quote: ParsedQuote;
  tcbStatus: string;
  advisoryIds: string[];
  evalDataNumber: number;
  collateralExpiresAt: number;
}

interface TcbComponent {
  svn: number;
}
interface TcbLevel {
  sgx: number[];
  tdx: number[];
  pce: number;
  status: string;
  date: string;
  advisories: string[];
}
interface ModuleLevel {
  isvsvn: number;
  status: string;
  date: string;
  advisories: string[];
}
interface ModuleIdentity {
  id: string;
  mrsigner: Buffer;
  attributes: Buffer;
  attributesMask: Buffer;
  levels: ModuleLevel[];
}
interface TcbInfo {
  id: string;
  version: number;
  issue: number;
  next: number;
  fmspc: Buffer;
  eval: number;
  module: { mrsigner: Buffer; attributes: Buffer; attributesMask: Buffer };
  identities: ModuleIdentity[];
  levels: TcbLevel[];
}
interface QeIdentity {
  id: string;
  version: number;
  issue: number;
  next: number;
  miscselect: number;
  miscselectMask: number;
  attributes: Buffer;
  attributesMask: Buffer;
  mrsigner: Buffer;
  isvProdId: number;
  levels: ModuleLevel[];
}

const INTEL_VENDOR = Buffer.from("939a7233f79c4ca9940a0db3957f0607", "hex");

export function verifyDcap(
  quoteBytes: Buffer,
  collateral: CollateralEntry[],
  now: number,
  rootDer: Buffer = INTEL_SGX_ROOT_CA_DER,
): DcapResult {
  const quote = parseQuote(quoteBytes);
  if (!quote.qeVendorId.equals(INTEL_VENDOR)) fail("dcap", "unexpected QE vendor");
  const root = new X509Certificate(rootDer);
  const pcs = loadPcs(collateral);
  const rootCrl = readCrl(pcs.rootCrl, root.publicKey, root, now);
  const pckCerts = pemCerts(quote.pckChainPem);
  if (pckCerts.length < 2) fail("dcap", "PCK chain is too short");
  const pckIssuer = pckCerts[1]!;
  const pckCrl = readCrl(pcs.pckCrl, pckIssuer.publicKey, pckIssuer, now);
  checkChain(pckCerts, root, now, [rootCrl, pckCrl]);
  const tcbCerts = pemCerts(Buffer.from(pcs.tcbChain));
  checkChain(tcbCerts, root, now, [rootCrl, pckCrl]);
  const tcbRaw = pcs.tcbBody;
  const tcbSigned = Buffer.from(rawObjectMember(tcbRaw, "tcbInfo", "dcap"));
  const tcbSignature = decodeHexSignature(JSON.parse(rawObjectMember(tcbRaw, "signature", "dcap")) as string);
  verifySigned(tcbCerts[0]!, tcbSigned, tcbSignature);
  const tcb = parseTcb(JSON.parse(tcbSigned.toString("utf8")) as Record<string, unknown>);
  if (now < tcb.issue) fail("dcap", "TCB info is not yet valid");
  if (now > tcb.next) fail("dcap", "TCB info has expired");

  const qeCerts = pemCerts(Buffer.from(pcs.qeChain));
  const sameChain = certsEqual(qeCerts, tcbCerts);
  if (!sameChain) checkChain(qeCerts, root, now, [rootCrl, pckCrl]);
  const qeRaw = pcs.qeBody;
  const qeSigned = Buffer.from(rawObjectMember(qeRaw, "enclaveIdentity", "dcap"));
  const qeSignature = decodeHexSignature(JSON.parse(rawObjectMember(qeRaw, "signature", "dcap")) as string);
  verifySigned(qeCerts[0]!, qeSigned, qeSignature);
  const qe = parseQeIdentity(JSON.parse(qeSigned.toString("utf8")) as Record<string, unknown>);
  if (now < qe.issue) fail("dcap", "QE identity is not yet valid");
  if (now > qe.next) fail("dcap", "QE identity has expired");
  if (qe.id !== "TD_QE" || (qe.version !== 2 && qe.version !== 3)) {
    fail("dcap", "QE identity is not TD_QE");
  }

  const pck = pckCerts[0]!;
  const platform = readPck(pck.raw);
  if (!platform.fmspc.equals(tcb.fmspc)) fail("dcap", "FMSPC mismatch");
  verifyRaw(pck.publicKey, quote.qeReport.raw, quote.qeSignature);
  const bound = sha256(Buffer.concat([quote.attestationKey, quote.qeAuthData]));
  if (!quote.qeReport.reportData.subarray(0, 32).equals(bound)) fail("dcap", "QE report data mismatch");
  const qeLevel = matchQe(quote.qeReport, qe);
  verifyRaw(createPublicKey({ key: p256Spki(quote.attestationKey), format: "der", type: "spki" }), quote.signed, quote.signature);

  if (tcb.version < 3 || tcb.id !== "TDX") fail("dcap", "TCB info is not TDX");
  const platformLevels = evaluateTdx(tcb, platform.cpuSvn, platform.pceSvn, quote.td.teeTcbSvn);
  verifyModule(tcb, quote.td);
  const advisories = [...new Set([...platformLevels, qeLevel].flatMap((level) => level.advisories))];
  return {
    quote,
    tcbStatus: "UpToDate",
    advisoryIds: advisories,
    evalDataNumber: tcb.eval,
    collateralExpiresAt: Math.min(tcb.next, qe.next),
  };
}

function loadPcs(entries: CollateralEntry[]): {
  tcbBody: string; tcbChain: string; qeBody: string; qeChain: string; pckCrl: Buffer; rootCrl: Buffer;
} {
  const entry = entries.find((item) => item.role === "endorsement" && item.format === INTEL_PCS_V1 && item.subjects.includes("cpu"));
  if (entry === undefined) fail("dcap", "missing Intel PCS collateral");
  const responses = entry.data.responses;
  if (!Array.isArray(responses)) fail("dcap", "Intel collateral has no responses");
  let tcbBody: string | undefined;
  let tcbChain: string | undefined;
  let qeBody: string | undefined;
  let qeChain: string | undefined;
  let pckCrl: Buffer | undefined;
  let rootCrl: Buffer | undefined;
  for (const response of responses) {
    if (response === null || typeof response !== "object") fail("dcap", "bad PCS response");
    const record = response as Record<string, unknown>;
    const url = record.url;
    const body = record.body_base64;
    if (typeof url !== "string" || typeof body !== "string") fail("dcap", "bad PCS response");
    const bytes = decodeCanonicalBase64(body, url);
    const kind = classify(url);
    if (kind === "pckcrl") {
      pckCrl = bytes;
      tcbChain ??= undefined;
      const chain = header(record.headers, ["SGX-PCK-CRL-Issuer-Chain"]);
      void chain;
      continue;
    }
    if (kind === "tcb") {
      tcbBody = bytes.toString("utf8");
      tcbChain = header(record.headers, ["SGX-TCB-Info-Issuer-Chain", "TCB-Info-Issuer-Chain"]);
    } else if (kind === "qe") {
      qeBody = bytes.toString("utf8");
      qeChain = header(record.headers, ["SGX-Enclave-Identity-Issuer-Chain"]);
    } else if (kind === "rootcrl") {
      rootCrl = bytes;
    } else {
      fail("dcap", `unrecognized PCS response ${url}`);
    }
  }
  // The loop above stores the PCK CRL issuer only to require the header.
  for (const response of responses) {
    const record = response as Record<string, unknown>;
    if (classify(String(record.url)) === "pckcrl") {
      header(record.headers, ["SGX-PCK-CRL-Issuer-Chain"]);
    }
  }
  if (tcbBody === undefined || tcbChain === undefined || qeBody === undefined || qeChain === undefined || pckCrl === undefined || rootCrl === undefined) {
    fail("dcap", "Intel collateral is incomplete");
  }
  assertJson(tcbBody, "dcap");
  assertJson(qeBody, "dcap");
  return { tcbBody, tcbChain, qeBody, qeChain, pckCrl, rootCrl };
}

function classify(url: string): "pckcrl" | "tcb" | "qe" | "rootcrl" | "other" {
  const rest = url.split("://")[1]?.split(/[?#]/)[0]?.replace(/\/+$/, "");
  const path = rest?.slice(rest.indexOf("/") + 1);
  if (path === undefined) return "other";
  if (path.endsWith("/pckcrl")) return "pckcrl";
  if (path.endsWith("/tcb")) return "tcb";
  if (path.endsWith("/qe/identity")) return "qe";
  if (path.endsWith(".der") || path.endsWith("/rootcacrl")) return "rootcrl";
  return "other";
}

function header(headers: unknown, names: string[]): string {
  if (headers === null || typeof headers !== "object") fail("dcap", "PCS response has no headers");
  for (const [key, value] of Object.entries(headers)) {
    if (!names.some((name) => name.toLowerCase() === key.toLowerCase())) continue;
    const first = Array.isArray(value) ? value[0] : value;
    if (typeof first !== "string" || first.length === 0) fail("dcap", `empty ${names[0]} header`);
    return percentDecode(first);
  }
  fail("dcap", `missing ${names[0]} header`);
}

function percentDecode(value: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] === "%") {
      const hex = value.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) fail("dcap", "bad percent-encoding");
      bytes.push(Number.parseInt(hex, 16));
      i += 2;
    } else {
      bytes.push(value.charCodeAt(i));
    }
  }
  return Buffer.from(bytes).toString("utf8");
}

interface Crl {
  issuer: X509Certificate;
  serials: bigint[];
}

export function readCrl(bytes: Buffer, key: KeyObject, issuer: X509Certificate, now: number): Crl {
  const top = parseDer(bytes);
  if (top.end !== bytes.length) fail("dcap", "trailing bytes after the CRL");
  const outer = sequence(top);
  const tbs = outer[0];
  const signature = outer[2];
  if (outer.length !== 3 || tbs === undefined || signature === undefined || signature.tag !== 0x03) {
    fail("dcap", "malformed CRL");
  }
  if (signature.value[0] !== 0) fail("dcap", "CRL signature has unused bits");
  const signed = bytes.subarray(top.header + tbs.start, top.header + tbs.end);
  if (!verify("sha256", signed, key, signature.value.subarray(1))) fail("dcap", "CRL signature is invalid");
  let crl: X509Crl;
  try {
    crl = new X509Crl(new Uint8Array(bytes));
  } catch {
    fail("dcap", "malformed CRL");
  }
  if (crl.issuer !== new AsnCertificate(issuer.raw).subject) fail("dcap", "CRL issuer does not match the signer");
  if (crl.thisUpdate.getTime() / 1000 > now) fail("dcap", "CRL is not yet valid");
  const nextUpdate = crl.nextUpdate;
  if (nextUpdate === undefined) fail("dcap", "CRL has no nextUpdate");
  if (now > nextUpdate.getTime() / 1000) fail("dcap", "CRL has expired");
  const serials = crl.entries.map((entry) => BigInt(`0x${entry.serialNumber}`));
  return { issuer, serials };
}

function pemCerts(pem: Buffer): X509Certificate[] {
  const text = pem.toString("utf8");
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (blocks === null || blocks.length === 0) fail("dcap", "certificate chain is not PEM");
  const leftover = text
    .replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g, "")
    .replace(/[\s\0]/g, "");
  if (leftover.length > 0) fail("dcap", "PEM chain has extra content");
  return blocks.map((block) => new X509Certificate(block));
}

export function checkChain(certs: X509Certificate[], root: X509Certificate, now: number, crls: Crl[]): void {
  const chain = certs[certs.length - 1]?.publicKey.equals(root.publicKey) ? certs.slice(0, -1) : certs;
  const anchors = [...chain, root];
  for (let i = 0; i < chain.length; i += 1) {
    const cert = chain[i]!;
    const issuer = anchors[i + 1]!;
    if (!cert.verify(issuer.publicKey) || !cert.checkIssued(issuer)) fail("dcap", "certificate chain is invalid");
    const from = Date.parse(cert.validFrom) / 1000;
    const to = Date.parse(cert.validTo) / 1000;
    if (now < from || now >= to) fail("dcap", "certificate is outside its validity");
    const crl = crls.find((item) => item.issuer.raw.equals(issuer.raw) || item.issuer.publicKey.equals(issuer.publicKey));
    if (crl === undefined) fail("dcap", "no CRL covers a certificate issuer");
    const serial = BigInt(`0x${cert.serialNumber}`);
    if (crl.serials.includes(serial)) fail("dcap", "certificate is revoked");
  }
}

function certsEqual(left: X509Certificate[], right: X509Certificate[]): boolean {
  return left.length === right.length && left.every((cert, index) => cert.raw.equals(right[index]!.raw));
}

function verifySigned(cert: X509Certificate, payload: Buffer, signature: Buffer): void {
  if (!verify("sha256", payload, cert.publicKey, rsToDer(signature))) {
    fail("dcap", "Intel signature is invalid");
  }
}

function verifyRaw(key: KeyObject, payload: Buffer, signature: Buffer): void {
  if (!verify("sha256", payload, key, rsToDer(signature))) fail("dcap", "quote signature is invalid");
}

function decodeHexSignature(value: string): Buffer {
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length !== 128) fail("dcap", "Intel signature is not 64 bytes of hex");
  return Buffer.from(value, "hex");
}

function parseTcb(info: Record<string, unknown>): TcbInfo {
  const levels = Array.isArray(info.tcbLevels) ? info.tcbLevels.map(parseLevel) : [];
  levels.sort((a, b) => compareLevels(a, b));
  const module = object(info.tdxModule);
  const identities = Array.isArray(info.tdxModuleIdentities) ? info.tdxModuleIdentities.map(parseIdentity) : [];
  return {
    id: string(info.id),
    version: number(info.version),
    issue: time(string(info.issueDate)),
    next: time(string(info.nextUpdate)),
    fmspc: Buffer.from(string(info.fmspc), "hex"),
    eval: number(info.tcbEvaluationDataNumber),
    module: {
      mrsigner: hexBuf(string(module.mrsigner), 48),
      attributes: hexBuf(string(module.attributes), 8),
      attributesMask: hexBuf(string(module.attributesMask), 8),
    },
    identities,
    levels,
  };
}

function parseIdentity(value: unknown): ModuleIdentity {
  const record = object(value);
  const levels = Array.isArray(record.tcbLevels) ? record.tcbLevels.map((level) => {
    const item = object(level);
    const tcb = object(item.tcb);
    return {
      isvsvn: number(tcb.isvsvn),
      status: string(item.tcbStatus),
      date: string(item.tcbDate),
      advisories: advisories(item.advisoryIDs),
    };
  }) : [];
  return {
    id: string(record.id),
    mrsigner: hexBuf(string(record.mrsigner), 48),
    attributes: hexBuf(string(record.attributes), 8),
    attributesMask: hexBuf(string(record.attributesMask), 8),
    levels,
  };
}

function parseLevel(value: unknown): TcbLevel {
  const record = object(value);
  const tcb = object(record.tcb);
  return {
    sgx: components(tcb.sgxtcbcomponents),
    tdx: components(tcb.tdxtcbcomponents),
    pce: number(tcb.pcesvn),
    status: string(record.tcbStatus),
    date: string(record.tcbDate),
    advisories: advisories(record.advisoryIDs),
  };
}

function parseQeIdentity(info: Record<string, unknown>): QeIdentity {
  const levels = Array.isArray(info.tcbLevels) ? info.tcbLevels.map((level) => {
    const item = object(level);
    return {
      isvsvn: number(object(item.tcb).isvsvn),
      status: string(item.tcbStatus),
      date: string(item.tcbDate),
      advisories: advisories(item.advisoryIDs),
    };
  }) : [];
  return {
    id: string(info.id),
    version: number(info.version),
    issue: time(string(info.issueDate)),
    next: time(string(info.nextUpdate)),
    miscselect: hexBuf(string(info.miscselect), 4).readUInt32LE(),
    miscselectMask: hexBuf(string(info.miscselectMask), 4).readUInt32LE(),
    attributes: hexBuf(string(info.attributes), 16),
    attributesMask: hexBuf(string(info.attributesMask), 16),
    mrsigner: hexBuf(string(info.mrsigner), 32),
    isvProdId: number(info.isvprodid),
    levels,
  };
}

function components(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => number(object(item).svn));
}

function advisories(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) fail("dcap", "bad advisory IDs");
  return value as string[];
}

function compareLevels(a: TcbLevel, b: TcbLevel): number {
  return compareBytes(b.sgx, a.sgx) || b.pce - a.pce || compareBytes(b.tdx, a.tdx);
}

function compareBytes(left: number[], right: number[]): number {
  const count = Math.min(left.length, right.length);
  for (let i = 0; i < count; i += 1) {
    if (left[i] !== right[i]) return left[i]! - right[i]!;
  }
  return left.length - right.length;
}

// Matches go-tdx-guest: the platform level and the TDX module level must each
// be UpToDate on their own; statuses are not converged.
export function evaluateTdx(tcb: TcbInfo, cpu: Buffer, pce: number, tee: Buffer): Array<TcbLevel | ModuleLevel> {
  const level = tcb.levels.find((candidate) => meets(candidate, cpu, pce, tee));
  if (level === undefined) fail("dcap", "no matching TCB level");
  requireUpToDate("TCB", level.status);
  const module = matchModule(tcb, tee);
  if (module === undefined) return [level];
  requireUpToDate("TDX module TCB", module.status);
  return [level, module];
}

function requireUpToDate(component: string, status: string): void {
  if (status !== "UpToDate") fail("tdx", `${component} status is not UpToDate, found ${status}`);
}

function meets(level: TcbLevel, cpu: Buffer, pce: number, tee: Buffer): boolean {
  if (pce < level.pce || level.sgx.length !== cpu.length) return false;
  if (cpu.some((byte, index) => byte < level.sgx[index]!)) return false;
  if (level.tdx.length !== tee.length) return false;
  const skip = tee[1]! > 0 ? 2 : 0;
  return !tee.some((byte, index) => index >= skip && byte < level.tdx[index]!);
}

// Intel publishes levels in descending isvsvn order, but a signed document is not
// required to. The level that applies is the highest threshold the report still meets.
function highestSvn(levels: readonly ModuleLevel[], svn: number): ModuleLevel | undefined {
  let match: ModuleLevel | undefined;
  for (const level of levels) {
    if (svn < level.isvsvn) continue;
    if (match === undefined || level.isvsvn > match.isvsvn) match = level;
  }
  return match;
}

function matchModule(tcb: TcbInfo, tee: Buffer): ModuleLevel | undefined {
  if (tee[1] === 0) return undefined;
  const wanted = `TDX_${tee[1]!.toString(16).padStart(2, "0")}`.toUpperCase();
  const identity = tcb.identities.find((item) => item.id.toUpperCase() === wanted);
  if (identity === undefined) fail("dcap", `missing TDX module identity ${wanted}`);
  const level = highestSvn(identity.levels, tee[0]!);
  if (level === undefined) fail("dcap", "TDX module SVN is below the published minimum");
  return level;
}

function verifyModule(tcb: TcbInfo, td: TdReport): void {
  let expected = tcb.module;
  const version = td.teeTcbSvn[1] ?? 0;
  if (version > 0) {
    const wanted = `TDX_${version.toString(16).padStart(2, "0")}`.toUpperCase();
    const identity = tcb.identities.find((item) => item.id.toUpperCase() === wanted);
    if (identity === undefined) fail("dcap", "missing TDX module identity");
    expected = identity;
  }
  if (!td.mrSignerSeam.equals(expected.mrsigner)) fail("dcap", "TDX module signer mismatch");
  for (let i = 0; i < 8; i += 1) {
    const mask = expected.attributesMask[i]!;
    if ((td.seamAttributes[i]! & mask) !== (expected.attributes[i]! & mask)) {
      fail("dcap", "TDX module attributes mismatch");
    }
    if ((td.seamAttributes[i]! & ~mask & 0xff) !== 0) fail("dcap", "TDX module attributes outside the mask");
  }
}

export function matchQe(report: QeReport, identity: QeIdentity): ModuleLevel {
  if (!report.mrSigner.equals(identity.mrsigner)) fail("dcap", "QE signer mismatch");
  if ((report.attributes[0]! & 0x02) !== 0) fail("dcap", "QE debug mode is enabled");
  if (report.isvProdId !== identity.isvProdId) fail("dcap", "QE product id mismatch");
  if ((report.miscSelect & identity.miscselectMask) !== (identity.miscselect & identity.miscselectMask)) {
    fail("dcap", "QE miscselect mismatch");
  }
  for (let i = 0; i < 16; i += 1) {
    const mask = identity.attributesMask[i]!;
    if ((report.attributes[i]! & mask) !== (identity.attributes[i]! & mask)) fail("dcap", "QE attributes mismatch");
  }
  const level = highestSvn(identity.levels, report.isvSvn);
  if (level === undefined) fail("dcap", "QE SVN is below the published minimum");
  requireUpToDate("QE identity TCB", level.status);
  return level;
}

function readPck(der: Buffer): { fmspc: Buffer; cpuSvn: Buffer; pceSvn: number } {
  const cert = sequence(parseDer(der));
  const tbs = cert[0];
  if (tbs === undefined) fail("dcap", "bad PCK certificate");
  const fields = sequence(tbs);
  const extensions = fields.find((field) => field.tag === 0xa3);
  if (extensions === undefined) fail("dcap", "PCK certificate has no SGX extension");
  const extensionList = sequence(parseDer(extensions.value));
  const sgx = extensionList.find((item) => {
    const [oid] = sequence(item);
    return oid?.tag === 0x06 && oid.value.equals(encodeOid("1.2.840.113741.1.13.1"));
  });
  if (sgx === undefined) fail("dcap", "PCK certificate has no SGX extension");
  const octet = sequence(sgx).find((part) => part.tag === 0x04);
  if (octet === undefined) fail("dcap", "SGX extension is empty");
  const entries = sequence(parseDer(unwrapOctet(octet)));
  const fmspc = childByOid(entries, "1.2.840.113741.1.13.1.4");
  const tcb = childByOid(entries, "1.2.840.113741.1.13.1.2");
  if (fmspc === undefined || tcb === undefined) fail("dcap", "PCK certificate is missing FMSPC");
  const tcbEntries = sequence(tcb.tag === 0x04 ? parseDer(unwrapOctet(tcb)) : tcb);
  const cpu = childByOid(tcbEntries, "1.2.840.113741.1.13.1.2.18");
  const pce = childByOid(tcbEntries, "1.2.840.113741.1.13.1.2.17");
  if (cpu === undefined || pce === undefined || fmspc.value.length !== 6 || cpu.value.length !== 16) {
    fail("dcap", "PCK TCB extension is malformed");
  }
  const pceBytes = pce.value;
  const pceSvn = pceBytes.length === 1 ? pceBytes[0]! : pceBytes.length === 2 ? pceBytes.readUInt16BE() : NaN;
  if (!Number.isInteger(pceSvn)) fail("dcap", "PCE SVN is malformed");
  return { fmspc: fmspc.value, cpuSvn: cpu.value, pceSvn };
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("dcap", "expected an object");
  return value as Record<string, unknown>;
}

function string(value: unknown): string {
  if (typeof value !== "string") fail("dcap", "expected a string");
  return value;
}

function number(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) fail("dcap", "expected an integer");
  return value;
}

function hexBuf(value: string, length: number): Buffer {
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length !== length * 2) fail("dcap", "bad hex field");
  return Buffer.from(value, "hex");
}

function time(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail("dcap", "bad timestamp");
  return parsed / 1000;
}

export function reportDataMatches(quote: ParsedQuote, expected: Buffer): void {
  if (!equalBytes(quote.td.reportData, expected)) fail("dcap", "quote report data mismatch");
}

export function launchInputsAreZero(td: TdReport): void {
  for (const [name, value] of [
    ["MR_CONFIG_ID", td.mrConfigId],
    ["MR_OWNER", td.mrOwner],
    ["MR_OWNER_CONFIG", td.mrOwnerConfig],
  ] as const) {
    if (!zero(value)) fail("tdx", `${name} must be zero`);
  }
}
