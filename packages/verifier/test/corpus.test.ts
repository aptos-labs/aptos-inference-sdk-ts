import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { VerificationError } from "../src/error.js";
import { verifyRouterDocument } from "../src/verify.js";

const document = readFileSync(new URL("./corpus/router-v0.0.13.json", import.meta.url));
const nonce = Buffer.alloc(32, 0x11);
const repo = "aptos-labs/confidential-inference-router";
const now = Date.parse("2026-11-07T00:54:16Z") / 1000;

describe("router corpus", () => {
  it("accepts the captured v0.0.13 document", () => {
    const evidence = verifyRouterDocument(document, nonce, repo, now);
    expect(evidence.tcbStatus).toBe("UpToDate");
    expect(evidence.releaseTag).toBe("v0.0.13");
    expect(evidence.releaseDigest).toBe(
      "bed70f58ec1c97a0b829aae6832086bee624ee90b597b33f0c446e842ea38512",
    );
    expect(evidence.hardware).toBe(
      "small_0d_v011@d80f92482bfffc1033d2e4b88c0df6e1090e8825d91d43715beb06742ec6a96b",
    );
    expect(evidence.tlsPublicKey).toBe(
      "301bc674c8254dbaba3645a7dbcc50f74d777fd467750ecb09e45d6d821edf04",
    );
    expect(evidence.hpkePublicKey).toBe(
      "9d40a6f1274a8626b293be002ab3310e0f625aa6da538ac243f94d7ad39beb34",
    );
  });

  it("rejects a different nonce before trusting the quote", () => {
    expectCategory(() => verifyRouterDocument(document, Buffer.alloc(32, 0x22), repo, now), "envelope");
  });

  it("rejects a flipped quote byte as a DCAP failure", () => {
    const parsed = JSON.parse(document.toString("utf8")) as { cpu_evidence: { report_base64: string } };
    const quote = Buffer.from(parsed.cpu_evidence.report_base64, "base64");
    quote[80] ^= 0x01;
    parsed.cpu_evidence.report_base64 = quote.toString("base64");
    expectCategory(() => verifyRouterDocument(Buffer.from(JSON.stringify(parsed)), nonce, repo, now), "dcap");
  });

  it("rejects another repository", () => {
    expectCategory(() => verifyRouterDocument(document, nonce, "aptos-labs/other", now), "provenance");
  });

  it("rejects collateral that is past nextUpdate", () => {
    expectCategory(() => verifyRouterDocument(document, nonce, repo, now + 40 * 24 * 60 * 60), "dcap");
  });

  it("rejects a re-serialized TCB info", () => {
    const parsed = JSON.parse(document.toString("utf8")) as {
      collateral: Array<{ data: { responses: Array<{ url: string; body_base64: string }> } }>;
    };
    const response = parsed.collateral[0]!.data.responses.find((item) => item.url.includes("/tcb?"));
    const text = Buffer.from(response!.body_base64, "base64").toString("utf8");
    response!.body_base64 = Buffer.from(text.replace('"tcbInfo":{', '"tcbInfo":{ ')).toString("base64");
    expectCategory(() => verifyRouterDocument(Buffer.from(JSON.stringify(parsed)), nonce, repo, now), "dcap");
  });

  it("rejects an owner/repo@tag passed to the verifier", () => {
    expectCategory(() => verifyRouterDocument(document, nonce, `${repo}@v0.0.13`, now), "policy");
  });
});

function expectCategory(run: () => void, category: string): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as VerificationError).category).toBe(category);
    return;
  }
  throw new Error(`expected ${category}`);
}
