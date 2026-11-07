import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@aptos-labs/inference-verifier": fileURLToPath(
        new URL("../verifier/src/index.ts", import.meta.url),
      ),
    },
  },
  test: { environment: "node", fileParallelism: false },
});
