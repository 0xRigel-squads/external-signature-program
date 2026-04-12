import { decode as decodeCbor } from "cbor-x";

import { expectLength, toBytes } from "./bytes.js";
import { createClientDataJsonReconstructionParams } from "./clientDataJson.js";
import { invariant } from "./errors.js";
import type { WebAuthnData } from "./types.js";
import { AuthType } from "./types.js";

const P256_HALF_ORDER =
  0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n;
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

interface ParsedClientDataJson {
  type: string;
  origin: string;
  crossOrigin?: boolean;
  other_keys_can_be_added_here?: string;
}

export interface RegistrationWebAuthnData extends WebAuthnData {
  /** Raw credential id (`rawId`) for allowCredentials on later authentication. */
  publicKeyUncompressed: Uint8Array;
  credentialId: Uint8Array;
}

/**
 * Parses `navigator.credentials.create` output into SDK WebAuthn fields.
 * Note: some password managers may not provide a DER signature in attestation.
 */
export function parseRegistrationCredential(
  credential: PublicKeyCredential,
): RegistrationWebAuthnData {
  const response = credential.response as AuthenticatorAttestationResponse & {
    getPublicKey?: () => ArrayBuffer | null;
  };
  const attestationObject = new Uint8Array(response.attestationObject);
  const decoded = decodeCbor(attestationObject) as {
    authData?: Uint8Array;
    attStmt?: { sig?: Uint8Array };
  };
  const authData = toBytes(decoded.authData ?? new Uint8Array());
  const signatureDer = toBytes(decoded.attStmt?.sig ?? new Uint8Array());
  const clientDataJson = new Uint8Array(response.clientDataJSON);
  const publicKeySpki = response.getPublicKey?.();
  invariant(publicKeySpki != null, "browser did not expose credential public key");
  const { compressed, uncompressed } = decodeSpkiP256PublicKey(
    new Uint8Array(publicKeySpki),
  );

  return {
    credentialId: new Uint8Array(credential.rawId),
    publicKey: compressed,
    publicKeyUncompressed: uncompressed,
    signature: signatureDer,
    authData,
    clientDataJson,
    clientDataJsonReconstructionParams: parseClientDataJsonReconstructionParams(clientDataJson),
  };
}

/** Parses `navigator.credentials.get` output into SDK WebAuthn fields. */
export function parseAuthenticationCredential(input: {
  credential: PublicKeyCredential;
  compressedPublicKey: Uint8Array;
}): WebAuthnData {
  const response = input.credential.response as AuthenticatorAssertionResponse;
  return {
    publicKey: expectLength(input.compressedPublicKey, 33, "compressed public key"),
    signature: new Uint8Array(response.signature),
    authData: new Uint8Array(response.authenticatorData),
    clientDataJson: new Uint8Array(response.clientDataJSON),
    clientDataJsonReconstructionParams: parseClientDataJsonReconstructionParams(
      new Uint8Array(response.clientDataJSON),
    ),
  };
}

/** Extracts compressed/uncompressed P-256 key from SPKI bytes. */
export function decodeSpkiP256PublicKey(publicKeySpki: Uint8Array): {
  compressed: Uint8Array;
  uncompressed: Uint8Array;
} {
  for (let index = 0; index <= publicKeySpki.length - 65; index += 1) {
    if (publicKeySpki[index] !== 0x04) continue;
    const uncompressed = publicKeySpki.slice(index + 1, index + 65);
    const x = uncompressed.slice(0, 32);
    const y = uncompressed.slice(32, 64);
    const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
    return {
      compressed: Uint8Array.of(prefix, ...x),
      uncompressed,
    };
  }

  throw new Error("failed to find uncompressed P-256 public key in SPKI bytes");
}

/** Converts DER ECDSA signature to 64-byte compact `(r || s)` with low-s normalization. */
export function parseDerSignatureToCompact(signatureDer: Uint8Array): Uint8Array {
  const bytes = toBytes(signatureDer);
  let offset = 0;
  invariant(bytes[offset++] === 0x30, "expected DER sequence");
  const sequenceLength = readDerLength(bytes, offset);
  offset = sequenceLength.nextOffset;
  invariant(sequenceLength.length <= bytes.length - offset, "invalid DER sequence length");

  invariant(bytes[offset++] === 0x02, "expected DER integer for r");
  const rLength = readDerLength(bytes, offset);
  offset = rLength.nextOffset;
  const r = bytes.slice(offset, offset + rLength.length);
  offset += rLength.length;

  invariant(bytes[offset++] === 0x02, "expected DER integer for s");
  const sLength = readDerLength(bytes, offset);
  offset = sLength.nextOffset;
  const s = bytes.slice(offset, offset + sLength.length);

  const rValue = derIntegerToBigInt(r);
  let sValue = derIntegerToBigInt(s);
  if (sValue > P256_HALF_ORDER) {
    sValue = P256_ORDER - sValue;
  }

  return Uint8Array.of(...bigIntTo32Bytes(rValue), ...bigIntTo32Bytes(sValue));
}

/** Parses compact reconstruction params from browser-provided `clientDataJSON`. */
export function parseClientDataJsonReconstructionParams(
  clientDataJson: Uint8Array,
) {
  const json = JSON.parse(new TextDecoder().decode(clientDataJson)) as ParsedClientDataJson;
  const url = new URL(json.origin);
  return createClientDataJsonReconstructionParams({
    authType: json.type === "webauthn.create" ? AuthType.Create : AuthType.Get,
    crossOrigin: json.crossOrigin ?? false,
    isHttp: url.protocol === "http:",
    hasGoogleExtra: typeof json.other_keys_can_be_added_here === "string",
    port: url.port === "" ? null : Number(url.port),
  });
}

/** Base64url (no padding) encoding helper. */
export function toBase64Url(bytes: Uint8Array): string {
  const string = Array.from(bytes, (value) => String.fromCharCode(value)).join("");
  return btoa(string).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/** Base64url (no padding) decoding helper. */
export function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const decoded = atob(normalized + padding);
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
}

/** String helper for storing/transmitting credential ids. */
export function credentialIdToString(credentialId: Uint8Array): string {
  return toBase64Url(credentialId);
}

function readDerLength(bytes: Uint8Array, offset: number): {
  length: number;
  nextOffset: number;
} {
  const first = bytes[offset];
  if (first < 0x80) {
    return { length: first, nextOffset: offset + 1 };
  }

  const lengthBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < lengthBytes; i += 1) {
    length = (length << 8) | bytes[offset + 1 + i];
  }
  return { length, nextOffset: offset + 1 + lengthBytes };
}

function derIntegerToBigInt(bytes: Uint8Array): bigint {
  let normalized = bytes;
  while (normalized.length > 0 && normalized[0] === 0x00) {
    normalized = normalized.slice(1);
  }
  const hex = Array.from(normalized, (value) => value.toString(16).padStart(2, "0")).join("");
  return BigInt(`0x${hex || "0"}`);
}

function bigIntTo32Bytes(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, "0");
  return Uint8Array.from(hex.match(/.{1,2}/g)!.map((part) => Number.parseInt(part, 16)));
}
