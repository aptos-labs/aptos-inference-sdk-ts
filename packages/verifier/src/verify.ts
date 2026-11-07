import { verifyDcap, launchInputsAreZero, reportDataMatches } from "./dcap.js";
import {
  checkDocument,
  isValidRepo,
  SIGSTORE_CODE_V1,
  SIGSTORE_HARDWARE_V1,
  TDX_QUOTE_V1,
} from "./document.js";
import { fail } from "./error.js";
import { appraiseTdx } from "./policy.js";
import { INTEL_SGX_ROOT_CA_DER } from "./intel-root.js";
import { verifyCode, verifyHardware, type SigstoreRoots } from "./sigstore.js";

const HARDWARE_REPO = "tinfoilsh/hardware-measurements";
const PROFILES = ["small_0d_v011"];

export interface RouterEvidence {
  tlsPublicKey: string;
  hpkePublicKey: string;
  mrtd: string;
  rtmrs: [string, string, string, string];
  hardware: string;
  releaseDigest: string;
  releaseTag: string;
  codeMeasurement: { type: string; registers: string[] };
  tcbStatus: string;
  collateralExpiresAt: number;
}

export interface VerifyOptions {
  rootDer?: Buffer;
  sigstore?: SigstoreRoots;
}

export function verifyRouterDocument(
  bytes: Uint8Array,
  nonce: Uint8Array,
  repo: string,
  nowSecs: number,
  options: VerifyOptions = {},
): RouterEvidence {
  if (!isValidRepo(repo)) fail("policy", "trusted repository must be owner/name");
  const document = checkDocument(bytes, nonce);
  if (document.cpuFormat !== TDX_QUOTE_V1) fail("policy", "expected a TDX quote");
  if (document.deviceCount !== 0) fail("policy", "the router carries no device evidence");
  const dcap = verifyDcap(document.quote, document.collateral, nowSecs, options.rootDer ?? INTEL_SGX_ROOT_CA_DER);
  reportDataMatches(dcap.quote, document.reportData);
  launchInputsAreZero(dcap.quote.td);
  if (dcap.tcbStatus !== "UpToDate") fail("tdx", `TCB status ${dcap.tcbStatus} is not UpToDate`);
  appraiseTdx(dcap.quote.td, dcap.quote.version, dcap.quote.qeVendorId, dcap.evalDataNumber);
  const code = verifyCodeBundle(document.collateral, repo, options.sigstore);
  const quote = dcap.quote.td;
  if (code.rtmr1 !== quote.rtmrs[1]!.toString("hex") || code.rtmr2 !== quote.rtmrs[2]!.toString("hex")) {
    fail("provenance", "code measurements do not match the quote");
  }
  const hardware = matchHardware(document.collateral, quote.mrTd.toString("hex"), quote.rtmrs[0]!.toString("hex"), options.sigstore);
  return {
    tlsPublicKey: document.tlsPublicKey,
    hpkePublicKey: document.hpkePublicKey,
    mrtd: quote.mrTd.toString("hex"),
    rtmrs: quote.rtmrs.map((value) => value.toString("hex")) as [string, string, string, string],
    hardware,
    releaseDigest: code.digest,
    releaseTag: code.tag,
    codeMeasurement: {
      type: "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
      registers: [code.snp, code.rtmr1, code.rtmr2],
    },
    tcbStatus: dcap.tcbStatus,
    collateralExpiresAt: dcap.collateralExpiresAt,
  };
}

function verifyCodeBundle(collateral: ReturnType<typeof checkDocument>["collateral"], repo: string, roots?: SigstoreRoots) {
  const entry = collateral.find((item) => item.role === "reference-values" && item.format === SIGSTORE_CODE_V1);
  if (entry === undefined) fail("provenance", "missing code provenance");
  const claimed = string(entry.data.repo);
  if (claimed !== repo) fail("provenance", `collateral names ${claimed}, not ${repo}`);
  const tag = string(entry.data.tag);
  const digest = string(entry.data.digest);
  return verifyCode(entry.data.sigstore_bundle, repo, tag.length === 0 ? undefined : tag, digest, roots);
}

function matchHardware(
  collateral: ReturnType<typeof checkDocument>["collateral"],
  mrtd: string,
  rtmr0: string,
  roots?: SigstoreRoots,
): string {
  const entry = collateral.find((item) => item.role === "reference-values" && item.format === SIGSTORE_HARDWARE_V1);
  if (entry === undefined) fail("provenance", "missing hardware measurements");
  if (entry.data.repo !== HARDWARE_REPO) fail("provenance", "unexpected hardware catalog publisher");
  const digest = string(entry.data.digest);
  const measurements = verifyHardware(entry.data.sigstore_bundle, HARDWARE_REPO, digest, roots);
  const match = measurements.find((item) => {
    const profile = item.name.split("@")[0] ?? "";
    return PROFILES.includes(profile) && item.mrtd === mrtd && item.rtmr0 === rtmr0;
  });
  if (match === undefined) fail("policy", "firmware matches no accepted router profile");
  return match.name;
}

function string(value: unknown): string {
  if (typeof value !== "string") fail("provenance", "collateral field is not a string");
  return value;
}
