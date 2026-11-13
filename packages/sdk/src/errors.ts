export class SdkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class OriginError extends SdkError {}
export class RedirectRefusedError extends SdkError {}
export class PinMismatchError extends SdkError {}
export class NotReadyError extends SdkError {}
export class SessionClosedError extends SdkError {}
export class KeyConfigError extends SdkError {}
