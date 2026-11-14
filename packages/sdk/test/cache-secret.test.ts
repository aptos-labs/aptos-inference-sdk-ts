import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveCacheSecret } from "../src/cache-secret.js";

describe("cache secret file", () => {
  let home: string;

  afterEach(() => {
    vi.unstubAllEnvs();
    if (home !== undefined) rmSync(home, { recursive: true, force: true });
  });

  function stubHome(): string {
    home = mkdtempSync(join(tmpdir(), "inference-sdk-home-"));
    vi.stubEnv("HOME", home);
    vi.stubEnv("APTOS_INFERENCE_USER_CACHE_SECRET", "");
    return join(home, ".aptos-inference");
  }

  it("reads a regular file", () => {
    const dir = stubHome();
    mkdirSync(dir);
    writeFileSync(join(dir, "user_cache_secret"), "stored-secret\n", { mode: 0o600 });
    expect(resolveCacheSecret()).toBe("stored-secret");
  });

  it("does not follow a symlink to the secret file", () => {
    const dir = stubHome();
    mkdirSync(dir);
    const target = join(home, "other-secret");
    writeFileSync(target, "leaked-from-symlink-target\n");
    symlinkSync(target, join(dir, "user_cache_secret"));
    const secret = resolveCacheSecret();
    expect(secret).not.toBe("leaked-from-symlink-target");
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(readFileSync(join(dir, "user_cache_secret"), "utf8").trim()).toBe(secret);
  });
});
