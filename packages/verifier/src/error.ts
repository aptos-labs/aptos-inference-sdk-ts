export type VerificationCategory =
  | "envelope"
  | "encoding"
  | "dcap"
  | "tdx"
  | "provenance"
  | "policy";

export class VerificationError extends Error {
  readonly category: VerificationCategory;

  constructor(category: VerificationCategory, message: string) {
    super(message);
    this.name = "VerificationError";
    this.category = category;
  }
}

export function fail(category: VerificationCategory, message: string): never {
  throw new VerificationError(category, message);
}
