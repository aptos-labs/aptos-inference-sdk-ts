import { createPublicKey, verify, X509Certificate, type KeyObject } from "node:crypto";

import { decodeCanonicalBase64, sha256 } from "./bytes.js";
import { decodeAsn1String, parseDer, sequence } from "./der.js";
import { fail } from "./error.js";
import { assertJson } from "./json.js";
import trustedRootJson from "./trusted_root.json" with { type: "json" };

const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const TAG_PREFIX = "refs/tags/";
const PREDICATE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";
const HARDWARE_PREDICATE = "https://tinfoil.sh/predicate/hardware-measurements/v1";

interface TrustRoot {
  tlogs: Array<{
    publicKey: { rawBytes: string; keyDetails: string; validFor: { start?: string; end?: string } };
    logId: { keyId: string };
  }>;
  certificateAuthorities: Array<{
    certChain: { certificates: Array<{ rawBytes: string }> };
    validFor: { start?: string; end?: string };
  }>;
}

const trustedRoot = trustedRootJson as TrustRoot;

export interface CodeProof {
  tag: string;
  digest: string;
  snp: string;
  rtmr1: string;
  rtmr2: string;
}

export interface HardwareEntry {
  name: string;
  mrtd: string;
  rtmr0: string;
}

export interface SigstoreRoots {
  trustedRoot: TrustRoot;
}

export function verifyCode(
  bundle: unknown,
  repo: string,
  tag: string | undefined,
  digest: string,
  roots: SigstoreRoots = { trustedRoot },
): CodeProof {
  const statement = verifyBundle(bundle, repo, tag, digest, roots);
  if (statement.predicateType !== PREDICATE) fail("provenance", "unsupported code predicate");
  const predicate = object(statement.predicate);
  const tdx = object(predicate.tdx_measurement);
  return {
    tag: statement.tag,
    digest,
    snp: register(predicate.snp_measurement, "SNP"),
    rtmr1: register(tdx.rtmr1, "RTMR1"),
    rtmr2: register(tdx.rtmr2, "RTMR2"),
  };
}

export function verifyHardware(
  bundle: unknown,
  repo: string,
  digest: string,
  roots: SigstoreRoots = { trustedRoot },
): HardwareEntry[] {
  const statement = verifyBundle(bundle, repo, undefined, digest, roots);
  if (statement.predicateType !== HARDWARE_PREDICATE) fail("provenance", "unsupported hardware predicate");
  const entries = object(statement.predicate);
  const measurements = Object.entries(entries).map(([name, value]) => {
    const record = object(value);
    return {
      name: `${name}@${digest}`,
      mrtd: register(record.mrtd, "MRTD"),
      rtmr0: register(record.rtmr0, "RTMR0"),
    };
  });
  if (measurements.length === 0) fail("provenance", "hardware catalog is empty");
  return measurements;
}

interface Statement {
  predicateType: string;
  predicate: unknown;
  tag: string;
}

function verifyBundle(
  bundle: unknown,
  repo: string,
  tag: string | undefined,
  digest: string,
  roots: SigstoreRoots,
): Statement {
  const record = object(bundle);
  if (record.verificationMaterial !== undefined) {
    const material = object(record.verificationMaterial);
    if ("x509CertificateChain" in material) fail("provenance", "legacy bundle format");
  }
  const envelope = object(record.dsseEnvelope);
  const payloadType = string(envelope.payloadType);
  if (payloadType !== "application/vnd.in-toto+json") fail("provenance", "unexpected DSSE payload type");
  const payload = decodeCanonicalBase64(string(envelope.payload), "DSSE payload");
  const statement = object(assertJson(payload.toString("utf8"), "provenance"));
  const signatures = envelope.signatures;
  if (!Array.isArray(signatures) || signatures.length !== 1) fail("provenance", "expected one DSSE signature");
  const signature = decodeCanonicalBase64(string(object(signatures[0]).sig), "DSSE signature");
  const certificate = leafCertificate(record);
  const pae = Buffer.concat([
    Buffer.from("DSSEv1 "),
    Buffer.from(String(Buffer.byteLength(payloadType))),
    Buffer.from(" "),
    Buffer.from(payloadType),
    Buffer.from(" "),
    Buffer.from(String(payload.length)),
    Buffer.from(" "),
    payload,
  ]);
  if (!verify("sha256", pae, certificate.publicKey, signature)) fail("provenance", "DSSE signature is invalid");
  const identity = verifyFulcio(certificate, roots.trustedRoot);
  checkIdentity(identity, repo, tag);
  const integrated = verifyRekor(record, certificate.raw, signature, payload, identity.notBefore, identity.notAfter, roots.trustedRoot);
  if (integrated < identity.notBefore || integrated > identity.notAfter) {
    fail("provenance", "Rekor time is outside the certificate validity");
  }
  const subjects = statement.subject;
  if (!Array.isArray(subjects) || subjects.length === 0) fail("provenance", "statement has no subject");
  const subjectDigest = object(object(subjects[0]).digest).sha256;
  if (typeof subjectDigest !== "string" || subjectDigest.toLowerCase() !== digest) {
    fail("provenance", "subject digest mismatch");
  }
  return {
    predicateType: string(statement.predicateType),
    predicate: statement.predicate,
    tag: identity.ref.slice(TAG_PREFIX.length),
  };
}

interface Identity {
  issuer: string;
  repository: string;
  workflow: string;
  runner: string;
  ref: string;
  commit: string;
  notBefore: number;
  notAfter: number;
}

function leafCertificate(bundle: Record<string, unknown>): X509Certificate {
  const raw = object(object(bundle.verificationMaterial).certificate).rawBytes;
  return new X509Certificate(decodeCanonicalBase64(string(raw), "signing certificate"));
}

function verifyFulcio(leaf: X509Certificate, root: TrustRoot): Identity {
  if (!hasKeyUsage(leaf.raw, 0x80) || !hasCodeSigning(leaf.raw)) {
    fail("provenance", "certificate cannot sign code");
  }
  const notBefore = Date.parse(leaf.validFrom) / 1000;
  const notAfter = Date.parse(leaf.validTo) / 1000;
  let matched = false;
  for (const authority of root.certificateAuthorities) {
    const start = authority.validFor.start === undefined ? undefined : Date.parse(authority.validFor.start) / 1000;
    const end = authority.validFor.end === undefined ? undefined : Date.parse(authority.validFor.end) / 1000;
    if ((start !== undefined && notBefore < start) || (end !== undefined && notBefore > end)) continue;
    const certs = authority.certChain.certificates.map((item) => new X509Certificate(Buffer.from(item.rawBytes, "base64")));
    for (const issuer of certs) {
      if (leaf.verify(issuer.publicKey) && leaf.checkIssued(issuer)) {
        verifyAuthority(certs, issuer);
        matched = true;
      }
    }
  }
  if (!matched) fail("provenance", "certificate is not signed by a trusted Fulcio authority");
  return { ...readIdentity(leaf), notBefore, notAfter };
}

function verifyAuthority(certs: X509Certificate[], issuer: X509Certificate): void {
  const start = certs.indexOf(issuer);
  for (let i = start; i < certs.length - 1; i += 1) {
    const cert = certs[i]!;
    const parent = certs[i + 1]!;
    if (!cert.verify(parent.publicKey)) fail("provenance", "Fulcio chain is invalid");
  }
  const last = certs[certs.length - 1]!;
  if (!last.verify(last.publicKey)) fail("provenance", "Fulcio chain does not end at a root");
}

function readIdentity(cert: X509Certificate): Omit<Identity, "notBefore" | "notAfter"> {
  const values = new Map<string, string>();
  // Extensions are read from the DER so the values are the ones Fulcio signed.
  for (const [oid, value] of certificateExtensions(cert.raw)) values.set(oid, value);
  const issuer = values.get("1.3.6.1.4.1.57264.1.8") ?? values.get("1.3.6.1.4.1.57264.1.1") ?? "";
  let repository = values.get("1.3.6.1.4.1.57264.1.5") ?? "";
  if (repository.length === 0) {
    repository = (values.get("1.3.6.1.4.1.57264.1.12") ?? "").replace(/^https:\/\/github\.com\//, "");
  }
  const workflow = values.get("1.3.6.1.4.1.57264.1.9") ?? "";
  if (issuer.length === 0 || repository.length === 0 || workflow.length === 0) {
    fail("provenance", "certificate is missing a Fulcio identity extension");
  }
  return {
    issuer,
    repository,
    workflow,
    runner: values.get("1.3.6.1.4.1.57264.1.11") ?? "",
    ref: values.get("1.3.6.1.4.1.57264.1.14") ?? "",
    commit: values.get("1.3.6.1.4.1.57264.1.13") ?? "",
  };
}

function extensionValue(der: Buffer, oid: string): Buffer | undefined {
  const tbs = sequence(parseDer(der))[0];
  if (tbs === undefined) return undefined;
  const extensions = sequence(tbs).find((field) => field.tag === 0xa3);
  if (extensions === undefined) return undefined;
  for (const extension of sequence(parseDer(extensions.value))) {
    const parts = sequence(extension);
    if (parts[0] !== undefined && decodeOid(parts[0].value) === oid) {
      return parts.find((part) => part.tag === 0x04)?.value;
    }
  }
  return undefined;
}

function hasKeyUsage(der: Buffer, bit: number): boolean {
  const value = extensionValue(der, "2.5.29.15");
  if (value === undefined || value[0] !== 0x03) return false;
  const unused = value[2] ?? 8;
  const data = value[3] ?? 0;
  return unused < 8 && (data & bit) !== 0;
}

function hasCodeSigning(der: Buffer): boolean {
  const value = extensionValue(der, "2.5.29.37");
  return value?.includes(Buffer.from("2b06010505070303", "hex")) ?? false;
}

function certificateExtensions(der: Buffer): Array<[string, string]> {
  const tbs = sequence(parseDer(der))[0];
  if (tbs === undefined) return [];
  const fields = sequence(tbs);
  const extensions = fields.find((field) => field.tag === 0xa3);
  if (extensions === undefined) return [];
  const list = sequence(parseDer(extensions.value));
  const out: Array<[string, string]> = [];
  for (const extension of list) {
    const parts = sequence(extension);
    const oid = parts[0];
    const value = parts.find((part) => part.tag === 0x04);
    if (oid === undefined || value === undefined) continue;
    out.push([decodeOid(oid.value), decodeAsn1String(value.value)]);
  }
  return out;
}

function decodeOid(bytes: Buffer): string {
  const first = bytes[0] ?? 0;
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (const byte of bytes.subarray(1)) {
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

function checkIdentity(identity: Omit<Identity, "notBefore" | "notAfter">, repo: string, tag: string | undefined): void {
  if (identity.issuer !== GITHUB_ISSUER) fail("provenance", "certificate is not from GitHub Actions");
  if (identity.repository !== repo) fail("provenance", "certificate repository does not match");
  const workflow = new RegExp(
    `^https://github\\.com/${escapeRegex(repo)}/\\.github/workflows/[^/@]+@refs/tags/[^@]+$`,
  );
  if (!workflow.test(identity.workflow)) fail("provenance", "certificate workflow does not match");
  if (identity.runner !== "github-hosted") fail("provenance", "build did not run on a GitHub-hosted runner");
  if (!/^refs\/tags\/[^@]+$/.test(identity.ref)) fail("provenance", "build ref is not a tag");
  if (tag !== undefined && identity.ref !== `${TAG_PREFIX}${tag}`) fail("provenance", "build ref does not match the tag");
  if (!/^[0-9a-f]{40}$/.test(identity.commit)) fail("provenance", "source digest is not a commit SHA");
}

function verifyRekor(
  bundle: Record<string, unknown>,
  certificate: Buffer,
  signature: Buffer,
  payload: Buffer,
  notBefore: number,
  notAfter: number,
  root: TrustRoot,
): number {
  const entries = object(bundle.verificationMaterial).tlogEntries;
  if (!Array.isArray(entries) || entries.length !== 1) fail("provenance", "expected one Rekor entry");
  const entry = object(entries[0]);
  const integrated = integer(entry.integratedTime);
  if (integrated < notBefore || integrated > notAfter) fail("provenance", "integrated time is outside the certificate");
  const body = decodeCanonicalBase64(string(entry.canonicalizedBody), "Rekor body");
  const parsed = object(assertJson(body.toString("utf8"), "provenance"));
  const kind = object(entry.kindVersion);
  if (parsed.kind !== kind.kind || parsed.apiVersion !== kind.version) fail("provenance", "Rekor kind does not match");
  const spec = object(parsed.spec);
  const logged = object((spec.signatures as unknown[])?.[0]);
  const loggedCert = new X509Certificate(Buffer.from(decodeCanonicalBase64(string(logged.verifier), "verifier").toString("utf8")));
  if (!loggedCert.raw.equals(certificate)) fail("provenance", "Rekor certificate does not match the bundle");
  const loggedSig = decodeCanonicalBase64(string(logged.signature), "Rekor signature");
  if (!loggedSig.equals(signature)) fail("provenance", "Rekor signature does not match the bundle");
  const hash = object(spec.payloadHash);
  if (hash.algorithm !== "sha256" || hash.value !== sha256(payload).toString("hex")) {
    fail("provenance", "Rekor payload hash does not match");
  }
  const logId = string(object(entry.logId).keyId);
  const key = rekorKey(root, logId, integrated);
  const setPayload = `{"body":${JSON.stringify(string(entry.canonicalizedBody))},"integratedTime":${integrated},"logID":"${Buffer.from(logId, "base64").toString("hex")}","logIndex":${integer(entry.logIndex)}}`;
  const set = decodeCanonicalBase64(string(object(entry.inclusionPromise).signedEntryTimestamp), "SET");
  if (!verify("sha256", Buffer.from(setPayload), key, set)) fail("provenance", "signed entry timestamp is invalid");
  const proof = object(object(entry.inclusionProof));
  const checkpoint = verifyCheckpoint(string(object(proof.checkpoint).envelope), key);
  const rootHash = decodeCanonicalBase64(string(proof.rootHash), "root hash");
  if (!rootHash.equals(checkpoint)) fail("provenance", "inclusion root does not match the checkpoint");
  const index = integer(proof.logIndex);
  const size = integer(proof.treeSize);
  const hashes = (proof.hashes as unknown[]).map((item) => decodeCanonicalBase64(string(item), "proof hash"));
  const leaf = sha256(Buffer.concat([Buffer.from([0]), body]));
  if (!inclusionRoot(index, leaf, size, hashes).equals(rootHash)) fail("provenance", "inclusion proof is invalid");
  return integrated;
}

function rekorKey(root: TrustRoot, logId: string, at: number): KeyObject {
  for (const log of root.tlogs) {
    if (log.logId.keyId !== logId) continue;
    const start = log.publicKey.validFor.start === undefined ? undefined : Date.parse(log.publicKey.validFor.start) / 1000;
    const end = log.publicKey.validFor.end === undefined ? undefined : Date.parse(log.publicKey.validFor.end) / 1000;
    if ((start !== undefined && at < start) || (end !== undefined && at > end)) continue;
    return createPublicKey({ key: Buffer.from(log.publicKey.rawBytes, "base64"), format: "der", type: "spki" });
  }
  fail("provenance", "no Rekor key for this log");
}

function verifyCheckpoint(envelope: string, key: KeyObject): Buffer {
  const [note, signatures] = splitOnce(envelope.trim(), "\n\n");
  if (signatures === undefined) fail("provenance", "checkpoint has no signature");
  const lines = note.split("\n");
  const origin = lines[0];
  const size = lines[1];
  const hash = lines[2];
  if (origin === undefined || size === undefined || hash === undefined) fail("provenance", "bad checkpoint");
  const other = lines.slice(3).map((line) => `${line}\n`).join("");
  const message = `${origin}\n${size}\n${hash}\n${other}`;
  for (const line of signatures.split("\n")) {
    if (line.trim().length === 0) continue;
    if (!line.startsWith("—")) fail("provenance", "bad checkpoint signature");
    const parts = line.split(" ");
    const raw = Buffer.from(parts[2] ?? "", "base64");
    if (raw.length <= 4) continue;
    if (verify("sha256", Buffer.from(message), key, raw.subarray(4))) return Buffer.from(hash, "base64");
  }
  fail("provenance", "checkpoint signature is invalid");
}

function inclusionRoot(index: number, leaf: Buffer, size: number, proof: Buffer[]): Buffer {
  if (index < 0 || index >= size) fail("provenance", "inclusion index is outside the tree");
  const inner = bitLength(index ^ (size - 1));
  const border = bitCount(Math.floor(index / 2 ** inner));
  if (proof.length !== inner + border) fail("provenance", "inclusion proof has the wrong size");
  let hash = leaf;
  for (let i = 0; i < inner; i += 1) {
    const sibling = proof[i]!;
    hash = ((index >> i) & 1) === 0 ? node(hash, sibling) : node(sibling, hash);
  }
  for (const sibling of proof.slice(inner)) hash = node(sibling, hash);
  return hash;
}

function node(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([Buffer.from([1]), left, right]));
}

function bitLength(value: number): number {
  if (value <= 0) return 0;
  return Math.floor(Math.log2(value)) + 1;
}

function bitCount(value: number): number {
  let count = 0;
  let rest = value;
  while (rest > 0) {
    count += rest & 1;
    rest >>>= 1;
  }
  return count;
}

function integer(value: unknown): number {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 0) fail("provenance", "expected an unsigned integer");
  return parsed;
}

function splitOnce(value: string, separator: string): [string, string | undefined] {
  const index = value.indexOf(separator);
  if (index < 0) return [value, undefined];
  return [value.slice(0, index), value.slice(index + separator.length)];
}

function register(value: unknown, name: string): string {
  const length = name === "SNP" ? 96 : 96;
  if (typeof value !== "string" || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    fail("provenance", `${name} is malformed`);
  }
  return value;
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("provenance", "expected an object");
  return value as Record<string, unknown>;
}

function string(value: unknown): string {
  if (typeof value !== "string") fail("provenance", "expected a string");
  return value;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
