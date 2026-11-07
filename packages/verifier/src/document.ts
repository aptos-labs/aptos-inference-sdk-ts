import { decodeCanonicalBase64, decodeLowerHex, sha256 } from "./bytes.js";
import { fail } from "./error.js";
import { assertJson } from "./json.js";

export const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
const ATTESTATION_V3 = "https://tinfoil.sh/predicate/attestation/v3";
const REPORT_DATA_V1 = "https://tinfoil.sh/report-data/v1";
const CRYPTO_MATERIAL_V1 = "https://tinfoil.sh/crypto-material/v1";
const DEVICE_EVIDENCE_V1 = "https://tinfoil.sh/device-evidence/v1";
export const TDX_QUOTE_V1 = "https://tinfoil.sh/format/tdx-quote/v1";
export const TLS_KEY_FORMAT = "https://tinfoil.sh/key/spki-fp-sha256/v1";
export const HPKE_KEY_FORMAT = "https://tinfoil.sh/key/x25519-hpke/v1";
export const INTEL_PCS_V1 = "https://tinfoil.sh/collateral/intel-pcs/v1";
export const SIGSTORE_CODE_V1 = "https://tinfoil.sh/collateral/sigstore-code/v1";
export const SIGSTORE_HARDWARE_V1 =
  "https://inference.aptoslabs.com/collateral/sigstore-hardware-measurements/v1";

export interface CollateralEntry {
  id: string;
  role: string;
  format: string;
  subjects: string[];
  data: Record<string, unknown>;
}

export interface CheckedDocument {
  cpuFormat: string;
  quote: Buffer;
  cryptoMaterial: Buffer;
  deviceEvidence: Buffer;
  tlsPublicKey: string;
  hpkePublicKey: string;
  deviceCount: number;
  collateral: CollateralEntry[];
  reportData: Buffer;
}

function object(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("envelope", `${what} is not an object`);
  }
  return value as Record<string, unknown>;
}

function stringField(source: Record<string, unknown>, key: string, what: string): string {
  const value = source[key];
  if (typeof value !== "string") fail("envelope", `${what}.${key} is not a string`);
  return value;
}

function only(source: Record<string, unknown>, keys: string[], what: string): void {
  for (const key of Object.keys(source)) {
    if (!keys.includes(key)) fail("envelope", `${what} has unknown field ${key}`);
  }
}

export function isValidRepo(repo: string): boolean {
  const parts = repo.split("/");
  if (parts.length !== 2) return false;
  return parts.every(
    (part) => part.length > 0 && /^[A-Za-z0-9._-]+$/.test(part),
  );
}

export function checkDocument(bytes: Uint8Array, nonce: Uint8Array): CheckedDocument {
  if (bytes.length > MAX_DOCUMENT_BYTES) fail("envelope", "document exceeds 4 MiB");
  if (nonce.length !== 32) fail("envelope", "nonce must be 32 bytes");
  const text = Buffer.from(bytes).toString("utf8");
  if (!Buffer.from(text, "utf8").equals(Buffer.from(bytes))) {
    fail("encoding", "document is not valid UTF-8");
  }
  const raw = object(assertJson(text, "encoding"), "document");
  only(raw, ["format", "challenge", "cpu_evidence", "crypto_material", "device_evidence", "collateral"], "document");
  if (raw.format !== ATTESTATION_V3) fail("envelope", "unsupported attestation format");

  const challenge = object(raw.challenge, "challenge");
  only(challenge, ["nonce", "report_data", "report_data_algorithm"], "challenge");
  if (challenge.report_data_algorithm !== REPORT_DATA_V1) {
    fail("envelope", "unsupported report data algorithm");
  }
  const nonceHex = stringField(challenge, "nonce", "challenge");
  if (nonceHex !== Buffer.from(nonce).toString("hex")) fail("envelope", "nonce mismatch");
  decodeLowerHex(nonceHex, "challenge.nonce", 32);
  const claimedReport = decodeLowerHex(
    stringField(challenge, "report_data", "challenge"),
    "challenge.report_data",
    64,
  );

  const cpu = object(raw.cpu_evidence, "cpu_evidence");
  only(cpu, ["format", "report_base64", "endorsed"], "cpu_evidence");
  const endorsed = object(cpu.endorsed, "cpu_evidence.endorsed");
  only(endorsed, ["crypto_material_hash", "device_evidence_hash"], "cpu_evidence.endorsed");
  const crypto = decodeCanonicalBase64(stringField(raw, "crypto_material", "document"), "crypto_material");
  const devices = decodeCanonicalBase64(
    stringField(raw, "device_evidence", "document"),
    "device_evidence",
  );
  const cryptoHash = sha256(crypto);
  const deviceHash = sha256(devices);
  if (hexOf(cryptoHash) !== stringField(endorsed, "crypto_material_hash", "endorsed")) {
    fail("envelope", "crypto_material hash mismatch");
  }
  if (hexOf(deviceHash) !== stringField(endorsed, "device_evidence_hash", "endorsed")) {
    fail("envelope", "device_evidence hash mismatch");
  }
  const report = reportData(nonce, cryptoHash, deviceHash);
  if (!report.equals(claimedReport)) fail("envelope", "report data mismatch");

  const cryptoJson = object(assertJson(crypto.toString("utf8"), "encoding"), "crypto_material");
  only(cryptoJson, ["format", "items"], "crypto_material");
  if (cryptoJson.format !== CRYPTO_MATERIAL_V1) fail("envelope", "unsupported crypto material format");
  if (!Array.isArray(cryptoJson.items)) fail("envelope", "crypto_material.items is not an array");
  const keys = new Map<string, { format: string; data: string }>();
  for (const item of cryptoJson.items) {
    const record = object(item, "crypto_material item");
    only(record, ["id", "format", "data"], "crypto_material item");
    const id = stringField(record, "id", "crypto_material item");
    if (keys.has(id)) fail("envelope", `duplicate crypto_material id ${id}`);
    keys.set(id, {
      format: stringField(record, "format", "crypto_material item"),
      data: stringField(record, "data", "crypto_material item"),
    });
  }
  const tls = requiredKey(keys, "tls", TLS_KEY_FORMAT);
  const hpke = requiredKey(keys, "hpke", HPKE_KEY_FORMAT);

  const deviceJson = object(assertJson(devices.toString("utf8"), "encoding"), "device_evidence");
  only(deviceJson, ["format", "items"], "device_evidence");
  if (deviceJson.format !== DEVICE_EVIDENCE_V1) fail("envelope", "unsupported device evidence format");
  if (!Array.isArray(deviceJson.items)) fail("envelope", "device_evidence.items is not an array");

  const collateral = parseCollateral(raw.collateral);
  return {
    cpuFormat: stringField(cpu, "format", "cpu_evidence"),
    quote: decodeCanonicalBase64(stringField(cpu, "report_base64", "cpu_evidence"), "quote"),
    cryptoMaterial: crypto,
    deviceEvidence: devices,
    tlsPublicKey: tls,
    hpkePublicKey: hpke,
    deviceCount: deviceJson.items.length,
    collateral,
    reportData: report,
  };
}

function requiredKey(
  keys: Map<string, { format: string; data: string }>,
  id: string,
  format: string,
): string {
  const item = keys.get(id);
  if (item === undefined || item.format !== format) fail("policy", `missing ${id} key`);
  return decodeLowerHex(item.data, id, 32).toString("hex");
}

function parseCollateral(value: unknown): CollateralEntry[] {
  if (!Array.isArray(value)) fail("envelope", "collateral is not an array");
  const seen = new Set<string>();
  return value.map((entry) => {
    const record = object(entry, "collateral");
    only(record, ["id", "role", "format", "subjects", "data"], "collateral");
    const id = stringField(record, "id", "collateral");
    if (seen.has(id)) fail("envelope", `duplicate collateral id ${id}`);
    seen.add(id);
    const role = stringField(record, "role", "collateral");
    if (role !== "endorsement" && role !== "reference-values") {
      fail("envelope", `unknown collateral role ${role}`);
    }
    const subjects = record.subjects ?? [];
    if (!Array.isArray(subjects) || subjects.some((subject) => typeof subject !== "string")) {
      fail("envelope", "collateral subjects are not strings");
    }
    return {
      id,
      role,
      format: stringField(record, "format", "collateral"),
      subjects: subjects as string[],
      data: object(record.data, "collateral data"),
    };
  });
}

function reportData(nonce: Uint8Array, cryptoHash: Buffer, deviceHash: Buffer): Buffer {
  const hash = sha256(
    Buffer.concat([Buffer.from(REPORT_DATA_V1), Buffer.from(nonce), cryptoHash, deviceHash]),
  );
  return Buffer.concat([hash, Buffer.alloc(32)]);
}

function hexOf(value: Buffer): string {
  return value.toString("hex");
}
