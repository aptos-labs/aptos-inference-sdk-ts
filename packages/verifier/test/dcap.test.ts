import { webcrypto, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  Extension,
  X509CertificateGenerator,
  X509CrlGenerator,
  type X509CrlEntryParams,
} from "@peculiar/x509";
import { describe, expect, it } from "vitest";

import { checkChain, evaluateTdx, matchQe, readCrl } from "../src/dcap.js";
import { VerificationError } from "../src/error.js";
import type { QeReport } from "../src/quote.js";

interface PcsResponse {
  url: string;
  headers: Record<string, string[] | string>;
  body_base64: string;
}

const corpus = JSON.parse(
  readFileSync(new URL("./corpus/router-v0.0.175-aptos.3.json", import.meta.url), "utf8"),
) as { collateral: Array<{ format: string; data: { responses: PcsResponse[] } }> };
const responses = corpus.collateral.find((entry) => entry.format.includes("intel-pcs"))!.data.responses;
const corpusNow = Date.parse("2026-11-12T07:37:00Z") / 1000;

function response(match: (url: string) => boolean): PcsResponse {
  return responses.find((item) => match(item.url))!;
}

function issuerChain(item: PcsResponse, name: string): X509Certificate[] {
  const value = Object.entries(item.headers).find(([key]) => key.toLowerCase() === name.toLowerCase())![1];
  const pem = decodeURIComponent(Array.isArray(value) ? value[0]! : value);
  return pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)!.map((block) => new X509Certificate(block));
}

describe("Intel CRLs", () => {
  it("reads every revoked serial from the v2 PCK CRL", () => {
    const pck = response((url) => url.includes("/pckcrl"));
    const issuer = issuerChain(pck, "SGX-PCK-CRL-Issuer-Chain")[0]!;
    const crl = readCrl(Buffer.from(pck.body_base64, "base64"), issuer.publicKey, issuer, corpusNow);
    expect(crl.serials).toHaveLength(57);
    expect(crl.serials).toContain(BigInt("0x6fc34e5023e728923435d61aa4b83c618166ad35"));
  });

  it("reads the empty root CA CRL", () => {
    const root = response((url) => url.endsWith("IntelSGXRootCA.der"));
    const rootCa = issuerChain(response((url) => url.includes("/pckcrl")), "SGX-PCK-CRL-Issuer-Chain").at(-1)!;
    const crl = readCrl(Buffer.from(root.body_base64, "base64"), rootCa.publicKey, rootCa, corpusNow);
    expect(crl.serials).toEqual([]);
  });
});

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const now = Math.floor(Date.now() / 1000);
const day = 24 * 60 * 60 * 1000;

async function keys(): Promise<CryptoKeyPair> {
  return (await webcrypto.subtle.generateKey(algorithm, false, ["sign", "verify"])) as CryptoKeyPair;
}

async function fixture() {
  const caKeys = await keys();
  const leafKeys = await keys();
  const ca = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Test PCK Platform CA",
    notBefore: new Date(Date.now() - day),
    notAfter: new Date(Date.now() + day),
    keys: caKeys,
    signingAlgorithm: algorithm,
  });
  const leaf = await X509CertificateGenerator.create({
    serialNumber: "1a2b3c4d",
    subject: "CN=Test PCK Certificate",
    issuer: ca.subject,
    notBefore: new Date(Date.now() - day),
    notAfter: new Date(Date.now() + day),
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: algorithm,
  });
  return {
    caKeys,
    ca: new X509Certificate(Buffer.from(ca.rawData)),
    caName: ca.subject,
    leaf: new X509Certificate(Buffer.from(leaf.rawData)),
  };
}

async function crlDer(
  issuer: string,
  signingKey: CryptoKey,
  entries: X509CrlEntryParams[],
  nextUpdate = new Date(Date.now() + day),
): Promise<Buffer> {
  const crlNumber = new Extension("2.5.29.20", false, new Uint8Array([0x02, 0x01, 0x01]));
  const crl = await X509CrlGenerator.create({
    issuer,
    thisUpdate: new Date(Date.now() - day),
    nextUpdate,
    entries,
    extensions: [crlNumber],
    signingKey,
    signingAlgorithm: algorithm,
  });
  return Buffer.from(crl.rawData);
}

function expectFailure(run: () => unknown, message: string): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as VerificationError).message).toContain(message);
    return;
  }
  throw new Error(`expected failure: ${message}`);
}

describe("CRL revocation", () => {
  it("rejects a certificate listed in a v2 CRL with extensions", async () => {
    const { caKeys, ca, caName, leaf } = await fixture();
    const der = await crlDer(caName, caKeys.privateKey, [
      { serialNumber: "0f", revocationDate: new Date(Date.now() - day) },
      { serialNumber: "1a2b3c4d", revocationDate: new Date(Date.now() - day) },
    ]);
    const crl = readCrl(der, ca.publicKey, ca, now);
    expect(crl.serials).toEqual([0x0fn, 0x1a2b3c4dn]);
    expectFailure(() => checkChain([leaf], ca, now, [crl]), "certificate is revoked");
  });

  it("accepts a certificate the CRL does not list", async () => {
    const { caKeys, ca, caName, leaf } = await fixture();
    const der = await crlDer(caName, caKeys.privateKey, [{ serialNumber: "0f", revocationDate: new Date(Date.now() - day) }]);
    expect(() => checkChain([leaf], ca, now, [readCrl(der, ca.publicKey, ca, now)])).not.toThrow();
  });

  it("accepts a CRL with extensions and no entries", async () => {
    const { caKeys, ca, caName, leaf } = await fixture();
    const crl = readCrl(await crlDer(caName, caKeys.privateKey, []), ca.publicKey, ca, now);
    expect(crl.serials).toEqual([]);
    expect(() => checkChain([leaf], ca, now, [crl])).not.toThrow();
  });

  it("rejects bytes after the CRL", async () => {
    const { caKeys, ca, caName } = await fixture();
    const der = Buffer.concat([await crlDer(caName, caKeys.privateKey, []), Buffer.from([0x00])]);
    expectFailure(() => readCrl(der, ca.publicKey, ca, now), "trailing bytes after the CRL");
  });

  it("rejects an expired CRL", async () => {
    const { caKeys, ca, caName } = await fixture();
    const der = await crlDer(caName, caKeys.privateKey, [], new Date(Date.now() - 1000));
    expectFailure(() => readCrl(der, ca.publicKey, ca, now), "CRL has expired");
  });

  it("rejects a CRL signed by another key", async () => {
    const { ca, caName } = await fixture();
    const other = await keys();
    const der = await crlDer(caName, other.privateKey, []);
    expectFailure(() => readCrl(der, ca.publicKey, ca, now), "CRL signature is invalid");
  });

  it("rejects a CRL naming another issuer", async () => {
    const { caKeys, ca } = await fixture();
    const der = await crlDer("CN=Another CA", caKeys.privateKey, []);
    expectFailure(() => readCrl(der, ca.publicKey, ca, now), "CRL issuer does not match the signer");
  });
});

type TcbInfo = Parameters<typeof evaluateTdx>[0];
type QeIdentity = Parameters<typeof matchQe>[1];

function tcbInfo(platformStatus: string, moduleStatus = "UpToDate"): TcbInfo {
  return {
    id: "TDX",
    version: 3,
    issue: 0,
    next: 0,
    fmspc: Buffer.alloc(6),
    eval: 0,
    module: { mrsigner: Buffer.alloc(48), attributes: Buffer.alloc(8), attributesMask: Buffer.alloc(8) },
    identities: [
      {
        id: "TDX_03",
        mrsigner: Buffer.alloc(48),
        attributes: Buffer.alloc(8),
        attributesMask: Buffer.alloc(8),
        levels: [{ isvsvn: 0, status: moduleStatus, date: "2026-01-01T00:00:00Z", advisories: ["INTEL-SA-2"] }],
      },
    ],
    levels: [
      {
        sgx: Array(16).fill(0),
        tdx: Array(16).fill(0),
        pce: 0,
        status: platformStatus,
        date: "2026-01-01T00:00:00Z",
        advisories: ["INTEL-SA-1"],
      },
    ],
  };
}

const cpuSvn = Buffer.alloc(16);
const legacyTee = Buffer.alloc(16);
const moduleTee = Buffer.from([0x00, 0x03, ...Array(14).fill(0)]);

describe("TCB status", () => {
  it("accepts UpToDate platform and module levels", () => {
    const levels = evaluateTdx(tcbInfo("UpToDate"), cpuSvn, 0, moduleTee);
    expect(levels.flatMap((level) => level.advisories)).toEqual(["INTEL-SA-1", "INTEL-SA-2"]);
  });

  for (const status of ["SWHardeningNeeded", "ConfigurationNeeded", "OutOfDate", "Revoked"]) {
    it(`rejects a ${status} platform level`, () => {
      expectFailure(() => evaluateTdx(tcbInfo(status), cpuSvn, 0, legacyTee), `TCB status is not UpToDate, found ${status}`);
    });
  }

  it("rejects an OutOfDate TDX module level", () => {
    expectFailure(
      () => evaluateTdx(tcbInfo("UpToDate", "OutOfDate"), cpuSvn, 0, moduleTee),
      "TDX module TCB status is not UpToDate, found OutOfDate",
    );
  });

  function qe(status: string): { identity: QeIdentity; report: QeReport } {
    const mrsigner = Buffer.alloc(32, 0x01);
    return {
      identity: {
        id: "TD_QE",
        version: 2,
        issue: 0,
        next: 0,
        miscselect: 0,
        miscselectMask: 0,
        attributes: Buffer.alloc(16),
        attributesMask: Buffer.alloc(16),
        mrsigner,
        isvProdId: 2,
        levels: [{ isvsvn: 4, status, date: "2026-01-01T00:00:00Z", advisories: [] }],
      },
      report: {
        miscSelect: 0,
        attributes: Buffer.alloc(16),
        mrSigner: mrsigner,
        isvProdId: 2,
        isvSvn: 4,
        reportData: Buffer.alloc(64),
        raw: Buffer.alloc(384),
      },
    };
  }

  it("accepts an UpToDate quoting enclave", () => {
    const { identity, report } = qe("UpToDate");
    expect(matchQe(report, identity).status).toBe("UpToDate");
  });

  for (const status of ["ConfigurationNeeded", "OutOfDateConfigurationNeeded", "OutOfDate", "Revoked"]) {
    it(`rejects a ${status} quoting enclave`, () => {
      const { identity, report } = qe(status);
      expectFailure(() => matchQe(report, identity), `QE identity TCB status is not UpToDate, found ${status}`);
    });
  }
});
