import { OriginError } from "./errors.js";

export interface Enclave {
  origin: string;
  host: string;
}

export function parseEnclave(value: string): Enclave {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OriginError("enclave URL is not a URL");
  }
  if (url.protocol !== "https:") throw new OriginError("enclave URL must be https");
  if (url.username !== "" || url.password !== "") throw new OriginError("enclave URL must not carry userinfo");
  if (url.pathname !== "/" && url.pathname !== "") throw new OriginError("enclave URL must not have a path");
  if (url.search !== "" || url.hash !== "") throw new OriginError("enclave URL must not have a query or fragment");
  return { origin: url.origin, host: url.host };
}

export function sameOrigin(target: URL, origin: string): void {
  if (target.username !== "" || target.password !== "") {
    throw new OriginError("request URL must not carry userinfo");
  }
  if (target.protocol !== "https:" || target.origin !== origin) {
    throw new OriginError("request URL is not the verified origin");
  }
}
