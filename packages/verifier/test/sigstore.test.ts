import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { VerificationError } from "../src/error.js";
import { verifyCode } from "../src/sigstore.js";
import { verifyRouterDocument } from "../src/verify.js";

describe("provenance JSON", () => {
  it("rejects a DSSE statement with a duplicate key before checking its signature", () => {
    const payload = Buffer.from('{"subject":[],"subject":[]}').toString("base64");
    const bundle = {
      dsseEnvelope: {
        payloadType: "application/vnd.in-toto+json",
        payload,
        signatures: [{ sig: Buffer.from([1, 2, 3]).toString("base64") }],
      },
    };
    expectFailure(
      () => verifyCode(bundle, "aptos-labs/confidential-model-router", undefined, "ab".repeat(32)),
      "JSON object has a duplicate key subject",
    );
  });

  it("rejects a Rekor entry with a duplicate key", () => {
    const document = JSON.parse(
      readFileSync(new URL("./corpus/router-v0.0.13.json", import.meta.url), "utf8"),
    ) as {
      collateral: Array<{ data: { sigstore_bundle?: { verificationMaterial: { tlogEntries: Array<{ canonicalizedBody: string }> } } } }>;
    };
    const entry = document.collateral[1]!.data.sigstore_bundle!.verificationMaterial.tlogEntries[0]!;
    const body = Buffer.from(entry.canonicalizedBody, "base64").toString("utf8");
    entry.canonicalizedBody = Buffer.from(body.replace('{"apiVersion":', '{"apiVersion":"0.0.1","apiVersion":')).toString("base64");
    expectFailure(
      () => verifyRouterDocument(
        Buffer.from(JSON.stringify(document)),
        Buffer.alloc(32, 0x11),
        "aptos-labs/confidential-inference-router",
        Date.parse("2026-11-07T00:54:16Z") / 1000,
      ),
      "JSON object has a duplicate key apiVersion",
    );
  });
});

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
