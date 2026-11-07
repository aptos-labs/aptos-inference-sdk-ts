import { zero } from "./bytes.js";
import { fail } from "./error.js";
import type { TdReport } from "./quote.js";

const MINIMUM_EVAL = 19;
const MINIMUM_SVN = [3, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const TD_ATTRIBUTES = Buffer.from("0000001000000000", "hex");
const XFAM = Buffer.from("e702060000000000", "hex");
const MRSEAMS = new Set([
  "476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c",
  "7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d",
  "d0d80c085166ba78ccc69af268e5753cf0f3394523cb4ff7c50b08d9265c82489c099c377be6a400e4d2b57da924012c",
  "489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72",
  "fca4ff221293807e3d247416299ca39a236872df4eb414567ca96072d3fde7dead740f807eefe2f7d938499c03cc8aba",
  "aef4ed3e686fe6cf44c9a8d1cc63105443b558ac4f40c282abf78271e9a4586c50408c8584c7b43fd21edb736700ba5f",
]);

export function appraiseTdx(td: TdReport, version: number, vendor: Buffer, evalData: number): void {
  if (version !== 4) fail("tdx", `unsupported TDX quote version ${version}`);
  if (!vendor.equals(Buffer.from("939a7233f79c4ca9940a0db3957f0607", "hex"))) {
    fail("tdx", "unexpected QE vendor ID");
  }
  if (evalData < MINIMUM_EVAL) fail("tdx", `TCB evaluation data number ${evalData} is below ${MINIMUM_EVAL}`);
  for (let i = 0; i < MINIMUM_SVN.length; i += 1) {
    if (td.teeTcbSvn[i]! < MINIMUM_SVN[i]!) {
      fail("tdx", `TEE TCB SVN component ${i} is below the minimum`);
    }
  }
  if (!MRSEAMS.has(td.mrSeam.toString("hex"))) fail("tdx", "TDX module measurement is not accepted");
  if (!td.tdAttributes.equals(TD_ATTRIBUTES)) fail("tdx", "TD_ATTRIBUTES mismatch");
  if (!td.xfam.equals(XFAM)) fail("tdx", "XFAM mismatch");
  if (!zero(td.rtmrs[3]!)) fail("tdx", "RTMR3 must be zero");
}
