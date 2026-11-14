import { generateText, NoObjectGeneratedError, Output, streamText } from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { createInferenceAI } from "../src/ai.js";
import { InferenceClient } from "../src/client.js";

// Exercise the real provider libraries against the SDK's transport interface.
// The local TLS tests cover the SecureClient implementation separately.
const transport = vi.hoisted(() => ({
  ready: vi.fn<() => Promise<void>>(),
  fetch: vi.fn<typeof fetch>(),
}));

vi.mock("../src/secure-client.js", () => ({
  SecureClient: class {
    apiKey = "test-key";
    baseURL = "https://router.inference.aptoslabs.com/v1";
    ready = transport.ready;
    fetch = transport.fetch;
  },
}));

function completion(content: string): Response {
  return Response.json({
    id: "test-completion",
    object: "chat.completion",
    created: 1,
    model: "test-model",
    choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  });
}

beforeEach(() => {
  vi.resetAllMocks();
  // The provider uses JSON mode; these tests check client-side schema validation.
  vi.stubGlobal("AI_SDK_LOG_WARNINGS", false);
  transport.ready.mockResolvedValue(undefined);
  transport.fetch.mockImplementation(async () => completion("Hello"));
});

afterEach(() => vi.unstubAllGlobals());

describe("provider compatibility", () => {
  it("routes OpenAI chat completions through the secure transport", async () => {
    const client = new InferenceClient({ apiKey: "test-key" });
    const result = await client.chat.completions.create({
      model: "test-model",
      messages: [{ role: "user", content: "Hello" }],
    });
    expect(result.choices[0]?.message.content).toBe("Hello");
    expect(transport.fetch).toHaveBeenCalledOnce();
    const [url, init] = transport.fetch.mock.calls[0]!;
    expect(String(url)).toBe("https://router.inference.aptoslabs.com/v1/chat/completions");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer test-key");
  });

  it("does not retry a chat completion after the connection fails", async () => {
    transport.fetch.mockRejectedValue(new TypeError("fetch failed"));
    const client = new InferenceClient({ apiKey: "test-key" });
    await expect(client.chat.completions.create({
      model: "test-model",
      messages: [{ role: "user", content: "Hello" }],
    })).rejects.toThrow();
    expect(transport.fetch).toHaveBeenCalledOnce();
  });

  it("verifies before returning an AI SDK model and generates text", async () => {
    const provider = await createInferenceAI("test-key");
    expect(transport.ready).toHaveBeenCalledOnce();
    expect(transport.fetch).not.toHaveBeenCalled();
    const result = await generateText({ model: provider("test-model"), prompt: "Hello" });
    expect(result.text).toBe("Hello");
    expect(transport.fetch).toHaveBeenCalledOnce();
  });

  it("validates AI SDK structured output with a Zod 4 schema", async () => {
    transport.fetch.mockImplementation(async () => completion('{"answer":"Hello"}'));
    const provider = await createInferenceAI("test-key");
    const result = await generateText({
      model: provider("test-model"),
      prompt: "Reply with an answer object",
      output: Output.object({ schema: z.object({ answer: z.string() }) }),
    });
    expect(result.output).toEqual({ answer: "Hello" });
  });

  it("rejects structured output that does not match its Zod 4 schema", async () => {
    transport.fetch.mockImplementation(async () => completion('{"answer":123}'));
    const provider = await createInferenceAI("test-key");
    await expect(generateText({
      model: provider("test-model"),
      prompt: "Reply with an answer object",
      output: Output.object({ schema: z.object({ answer: z.string() }) }),
    })).rejects.toBeInstanceOf(NoObjectGeneratedError);
  });

  it("streams AI SDK text over the secure transport", async () => {
    const chunks = [
      { choices: [{ index: 0, delta: { role: "assistant", content: "Hello" }, finish_reason: null }] },
      { choices: [{ index: 0, delta: {}, finish_reason: "stop" }] },
    ];
    const body = chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("") + "data: [DONE]\n\n";
    transport.fetch.mockImplementation(async () => new Response(body, {
      headers: { "content-type": "text/event-stream" },
    }));
    const provider = await createInferenceAI("test-key");
    const result = streamText({ model: provider("test-model"), prompt: "Hello" });
    let text = "";
    for await (const part of result.textStream) text += part;
    expect(text).toBe("Hello");
    expect(transport.fetch).toHaveBeenCalledOnce();
  });
});
