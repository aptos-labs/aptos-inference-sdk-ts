import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import type { LanguageModel } from "ai";

import { SecureClient, type SecureClientOptions } from "./secure-client.js";

export async function createInferenceAI(
  apiKey?: string,
  options: Omit<SecureClientOptions, "apiKey"> = {},
): Promise<(model: string) => LanguageModel> {
  const clientOptions: SecureClientOptions = { ...options };
  if (apiKey !== undefined) clientOptions.apiKey = apiKey;
  const secure = new SecureClient(clientOptions);
  await secure.ready();
  const provider = createOpenAICompatible({
    name: "aptos-inference",
    apiKey: secure.apiKey ?? "not-set",
    baseURL: secure.baseURL,
    fetch: secure.fetch as unknown as typeof fetch,
  });
  return (model) => provider.languageModel(model);
}
