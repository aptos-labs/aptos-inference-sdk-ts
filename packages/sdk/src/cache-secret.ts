import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const FIELD = "user_cache_secret";
const PATHS = ["/chat/completions", "/completions", "/responses"];

export function resolveCacheSecret(explicit?: string): string {
  if (explicit !== undefined && explicit !== "") return explicit;
  const fromEnv = process.env.APTOS_INFERENCE_USER_CACHE_SECRET;
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  try {
    const dir = join(homedir(), ".aptos-inference");
    const path = join(dir, "user_cache_secret");
    try {
      const existing = readFileSync(path, "utf8").trim();
      if (existing !== "") return existing;
    } catch {
      // generated below
    }
    mkdirSync(dir, { recursive: true });
    const secret = randomBytes(32).toString("hex");
    const temporary = `${path}.${process.pid}.tmp`;
    writeFileSync(temporary, `${secret}\n`, { mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
    return secret;
  } catch {
    return "";
  }
}

export function injectCacheSecret(body: string, pathname: string, secret: string): string | undefined {
  if (secret === "" || !PATHS.some((path) => pathname.endsWith(path))) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  if (Object.prototype.hasOwnProperty.call(parsed, FIELD)) return undefined;
  const end = body.lastIndexOf("}");
  if (end < 0) return undefined;
  const field = `${JSON.stringify(FIELD)}:${JSON.stringify(secret)}`;
  const separator = Object.keys(parsed).length > 0 ? "," : "";
  return body.slice(0, end) + separator + field + body.slice(end);
}
