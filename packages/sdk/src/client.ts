import OpenAI from "openai";

import { SecureClient, type SecureClientOptions, type VerificationDocument } from "./secure-client.js";

export class InferenceClient {
  private readonly secure: SecureClient;
  private readonly openai: OpenAI;
  readonly chat: OpenAI["chat"];
  readonly completions: OpenAI["completions"];
  readonly embeddings: OpenAI["embeddings"];
  readonly audio: OpenAI["audio"];
  readonly images: OpenAI["images"];
  readonly files: OpenAI["files"];
  readonly models: OpenAI["models"];
  readonly moderations: OpenAI["moderations"];
  readonly beta: OpenAI["beta"];
  readonly fineTuning: OpenAI["fineTuning"];

  constructor(options: SecureClientOptions = {}) {
    this.secure = new SecureClient(options);
    this.openai = new OpenAI({
      apiKey: this.secure.apiKey ?? "not-set",
      baseURL: this.secure.baseURL,
      fetch: this.secure.fetch as unknown as NonNullable<ConstructorParameters<typeof OpenAI>[0]>["fetch"],
    });
    this.chat = this.openai.chat;
    this.completions = this.openai.completions;
    this.embeddings = this.openai.embeddings;
    this.audio = this.openai.audio;
    this.images = this.openai.images;
    this.files = this.openai.files;
    this.models = this.openai.models;
    this.moderations = this.openai.moderations;
    this.beta = this.openai.beta;
    this.fineTuning = this.openai.fineTuning;
  }

  ready(): Promise<void> {
    return this.secure.ready();
  }

  async getVerificationDocument(): Promise<VerificationDocument> {
    await this.ready();
    return this.secure.getVerificationDocument();
  }

  reset(): void {
    this.secure.reset();
  }
}
