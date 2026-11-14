import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
      const existing = readRegularFile(path).trim();
      if (existing !== "") return existing;
    } catch {
      // generated below
    }
    mkdirSync(dir, { recursive: true });
    const secret = randomBytes(32).toString("hex");
    const temporary = `${path}.${process.pid}.tmp`;
    const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      writeFileSync(fd, `${secret}\n`);
    } finally {
      closeSync(fd);
    }
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
    return secret;
  } catch {
    return "";
  }
}

function readRegularFile(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
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
