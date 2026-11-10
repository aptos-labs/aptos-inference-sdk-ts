import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function selfSigned(pkcs8: string, name = "127.0.0.1"): string {
  const dir = mkdtempSync(join(tmpdir(), "inference-sdk-"));
  try {
    const keyPath = join(dir, "key.pem");
    const certPath = join(dir, "cert.pem");
    writeFileSync(keyPath, pkcs8);
    execFileSync("openssl", [
      "req", "-new", "-x509", "-key", keyPath, "-out", certPath, "-days", "1",
      "-subj", `/CN=${name}`, "-addext", "subjectAltName=IP:127.0.0.1",
    ]);
    return readFileSync(certPath, "utf8");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
