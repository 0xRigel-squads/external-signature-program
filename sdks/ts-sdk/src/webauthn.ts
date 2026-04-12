import { decode as decodeCbor } from "cbor-x";

import { expectLength, toBytes } from "./bytes.js";
import {
  GOOGLE_CLIENT_DATA_JSON_EXTRA_VALUE,
  createClientDataJsonReconstructionParams,
} from "./clientDataJson.js";
import { decodeBase64Url, encodeBase64Url } from "./crypto.js";
import { ExternalSignatureSdkError, invariant } from "./errors.js";
import type { ClientDataJsonReconstructionParams, WebAuthnData } from "./types.js";
import { AuthType } from "./types.js";

const P256_HALF_ORDER =
  0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n;
const P256_ORDER =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const EC_PUBLIC_KEY_OID = Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
const PRIME256V1_OID = Uint8Array.of(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07);
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;
const FLAG_EXTENSION_DATA = 0x80;
const COSE_KEY_KTY = 1;
const COSE_KEY_ALG = 3;
const COSE_KEY_CRV = -1;
const COSE_KEY_X = -2;
const COSE_KEY_Y = -3;
const COSE_KTY_EC2 = 2;
const COSE_ALG_ES256 = -7;
const COSE_CRV_P256 = 1;

interface ParsedClientDataJson {
  type: string;
  origin: string;
  crossOrigin?: boolean;
  other_keys_can_be_added_here?: string;
}

interface ParsedAttestedCredentialData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  publicKey: Uint8Array;
  publicKeyUncompressed: Uint8Array;
}

export interface RegistrationWebAuthnData extends WebAuthnData {
  /** Raw credential id (`rawId`) for allowCredentials on later authentication. */
  publicKeyUncompressed: Uint8Array;
  credentialId: Uint8Array;
}

/**
 * Parses `navigator.credentials.create` output into SDK WebAuthn fields.
 * Falls back to parsing attested credential data when `getPublicKey()` is unavailable.
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
  invariant(
    signatureDer.length > 0,
    "registration attestation is missing attStmt.sig DER signature",
  );

  const attestedCredential = parseAttestedCredentialData(authData);
  const clientDataJson = new Uint8Array(response.clientDataJSON);
  const publicKeySpki = response.getPublicKey?.();

  let publicKey = attestedCredential.publicKey;
  let publicKeyUncompressed = attestedCredential.publicKeyUncompressed;

  if (publicKeySpki != null) {
    const spkiKey = decodeSpkiP256PublicKey(new Uint8Array(publicKeySpki));
    invariant(
      bytesEqual(spkiKey.compressed, attestedCredential.publicKey),
      "browser-exposed public key does not match attested credential data",
    );
    invariant(
      bytesEqual(spkiKey.uncompressed, attestedCredential.publicKeyUncompressed),
      "browser-exposed uncompressed public key does not match attested credential data",
    );
    publicKey = spkiKey.compressed;
    publicKeyUncompressed = spkiKey.uncompressed;
  }

  return {
    credentialId: attestedCredential.credentialId,
    publicKey,
    publicKeyUncompressed,
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
  const bytes = toBytes(publicKeySpki);
  const spki = readDerElement(bytes, 0, 0x30, "SPKI");
  invariant(spki.nextOffset === bytes.length, "SPKI contains trailing bytes");

  const algorithmIdentifier = readDerElement(
    bytes,
    spki.valueOffset,
    0x30,
    "SPKI algorithm identifier",
  );
  const subjectPublicKey = readDerElement(
    bytes,
    algorithmIdentifier.nextOffset,
    0x03,
    "SPKI subjectPublicKey",
  );
  invariant(
    subjectPublicKey.nextOffset === spki.nextOffset,
    "SPKI contains unexpected fields after subjectPublicKey",
  );

  const algorithmOid = readDerElement(
    bytes,
    algorithmIdentifier.valueOffset,
    0x06,
    "SPKI algorithm OID",
  );
  const curveOid = readDerElement(
    bytes,
    algorithmOid.nextOffset,
    0x06,
    "SPKI curve OID",
  );
  invariant(
    curveOid.nextOffset === algorithmIdentifier.nextOffset,
    "SPKI algorithm identifier contains unexpected trailing bytes",
  );

  const algorithmOidValue = bytes.slice(algorithmOid.valueOffset, algorithmOid.nextOffset);
  const curveOidValue = bytes.slice(curveOid.valueOffset, curveOid.nextOffset);
  invariant(
    bytesEqual(algorithmOidValue, EC_PUBLIC_KEY_OID),
    "SPKI algorithm OID must be id-ecPublicKey (1.2.840.10045.2.1)",
  );
  invariant(
    bytesEqual(curveOidValue, PRIME256V1_OID),
    "SPKI curve OID must be prime256v1/P-256 (1.2.840.10045.3.1.7)",
  );

  const bitString = bytes.slice(subjectPublicKey.valueOffset, subjectPublicKey.nextOffset);
  invariant(bitString.length > 0, "SPKI subjectPublicKey BIT STRING must not be empty");
  invariant(bitString[0] === 0x00, "SPKI subjectPublicKey BIT STRING must use zero unused bits");
  const encodedPoint = bitString.slice(1);
  invariant(
    encodedPoint.length === 65,
    "SPKI subjectPublicKey must contain a 65-byte uncompressed EC point",
  );
  invariant(
    encodedPoint[0] === 0x04,
    "SPKI subjectPublicKey must be uncompressed EC point format (0x04)",
  );

  const uncompressed = encodedPoint.slice(1);
  const x = uncompressed.slice(0, 32);
  const y = uncompressed.slice(32, 64);
  const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
  return {
    compressed: Uint8Array.of(prefix, ...x),
    uncompressed,
  };
}

/** Converts DER ECDSA signature to 64-byte compact `(r || s)` with low-s normalization. */
export function parseDerSignatureToCompact(signatureDer: Uint8Array): Uint8Array {
  try {
    const bytes = toBytes(signatureDer);
    let offset = 0;
    invariant(bytes.length >= 2, "DER signature is too short");
    invariant(bytes[offset++] === 0x30, "DER signature must start with sequence tag (0x30)");

    const sequenceLength = readDerLength(bytes, offset);
    offset = sequenceLength.nextOffset;
    invariant(
      sequenceLength.length === bytes.length - offset,
      "DER sequence length does not match payload size",
    );

    const { value: rValue, nextOffset: afterR } = readDerInteger(bytes, offset, "r");
    const { value: sValueRaw, nextOffset: afterS } = readDerInteger(bytes, afterR, "s");
    invariant(afterS === bytes.length, "DER signature contains trailing bytes");

    let sValue = sValueRaw;
    if (sValue > P256_HALF_ORDER) {
      sValue = P256_ORDER - sValue;
    }

    return Uint8Array.of(...bigIntTo32Bytes(rValue), ...bigIntTo32Bytes(sValue));
  } catch (error) {
    if (error instanceof ExternalSignatureSdkError) {
      throw new ExternalSignatureSdkError(
        `invalid DER-encoded ECDSA signature: ${error.message}`,
      );
    }
    throw new ExternalSignatureSdkError(
      `failed to parse DER-encoded ECDSA signature: ${String(error)}`,
    );
  }
}

/** Parses compact reconstruction params from browser-provided `clientDataJSON`. */
export function parseClientDataJsonReconstructionParams(
  clientDataJson: Uint8Array,
): ClientDataJsonReconstructionParams {
  try {
    const json = JSON.parse(new TextDecoder().decode(clientDataJson)) as ParsedClientDataJson;
    invariant(
      json.type === "webauthn.create" || json.type === "webauthn.get",
      "clientDataJSON type must be either 'webauthn.create' or 'webauthn.get'",
    );
    invariant(
      json.crossOrigin == null || typeof json.crossOrigin === "boolean",
      "clientDataJSON crossOrigin must be a boolean when present",
    );
    invariant(
      json.other_keys_can_be_added_here == null ||
        json.other_keys_can_be_added_here === GOOGLE_CLIENT_DATA_JSON_EXTRA_VALUE,
      "clientDataJSON other_keys_can_be_added_here must match the canonical Google value",
    );
    const url = new URL(json.origin);
    invariant(url.protocol === "http:" || url.protocol === "https:", "origin must use http or https");
    invariant(url.hostname.length > 0, "origin must include a hostname");

    let port: number | null = null;
    if (url.port !== "") {
      const parsedPort = Number(url.port);
      invariant(Number.isInteger(parsedPort), "origin port must be an integer");
      invariant(parsedPort >= 1 && parsedPort <= 65535, "origin port must be in range 1..65535");
      port = parsedPort;
    }

    return createClientDataJsonReconstructionParams({
      authType: json.type === "webauthn.create" ? AuthType.Create : AuthType.Get,
      crossOrigin: json.crossOrigin ?? false,
      isHttp: url.protocol === "http:",
      hasGoogleExtra: typeof json.other_keys_can_be_added_here === "string",
      port,
    });
  } catch (error) {
    if (error instanceof ExternalSignatureSdkError) {
      throw new ExternalSignatureSdkError(
        `invalid clientDataJSON reconstruction parameters: ${error.message}`,
      );
    }
    throw new ExternalSignatureSdkError(`failed to parse clientDataJSON: ${String(error)}`);
  }
}

/** Base64url (no padding) encoding helper. */
export function toBase64Url(bytes: Uint8Array): string {
  return encodeBase64Url(bytes);
}

/** Base64url (no padding) decoding helper. */
export function fromBase64Url(value: string): Uint8Array {
  try {
    return decodeBase64Url(value);
  } catch (error) {
    throw new ExternalSignatureSdkError(`invalid base64url input: ${String(error)}`);
  }
}

/** String helper for storing/transmitting credential ids. */
export function credentialIdToString(credentialId: Uint8Array): string {
  return toBase64Url(credentialId);
}

function parseAttestedCredentialData(authData: Uint8Array): ParsedAttestedCredentialData {
  invariant(authData.length >= 37, "registration authData is too short");

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = new DataView(authData.buffer, authData.byteOffset, authData.byteLength)
    .getUint32(33, false);
  invariant(
    (flags & FLAG_ATTESTED_CREDENTIAL_DATA) !== 0,
    "registration authData is missing attested credential data",
  );

  let offset = 37;
  invariant(offset + 18 <= authData.length, "registration authData is truncated before credential metadata");
  const aaguid = authData.slice(offset, offset + 16);
  offset += 16;

  const credentialIdLength =
    (authData[offset] << 8) | authData[offset + 1];
  offset += 2;
  invariant(
    offset + credentialIdLength <= authData.length,
    "registration authData credential id exceeds payload length",
  );
  const credentialId = authData.slice(offset, offset + credentialIdLength);
  offset += credentialIdLength;

  const cosePublicKeyEnd = skipCborItem(authData, offset);
  invariant(cosePublicKeyEnd <= authData.length, "registration authData public key exceeds payload length");
  if ((flags & FLAG_EXTENSION_DATA) === 0) {
    invariant(
      cosePublicKeyEnd === authData.length,
      "registration authData has unexpected trailing bytes after credential public key",
    );
  }
  const cosePublicKey = authData.slice(offset, cosePublicKeyEnd);
  const { compressed, uncompressed } = decodeCoseP256PublicKey(cosePublicKey);

  return {
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credentialId,
    publicKey: compressed,
    publicKeyUncompressed: uncompressed,
  };
}

function decodeCoseP256PublicKey(cosePublicKey: Uint8Array): {
  compressed: Uint8Array;
  uncompressed: Uint8Array;
} {
  const decoded = decodeCbor(cosePublicKey);
  invariant(decoded instanceof Map, "credential public key COSE payload must be a CBOR map");

  const kty = decoded.get(COSE_KEY_KTY);
  const alg = decoded.get(COSE_KEY_ALG);
  const crv = decoded.get(COSE_KEY_CRV);
  invariant(kty === COSE_KTY_EC2, "credential public key must use COSE EC2 key type");
  invariant(alg === COSE_ALG_ES256, "credential public key must use ES256 algorithm");
  invariant(crv === COSE_CRV_P256, "credential public key must use P-256 curve");

  const x = expectLength(getCoseByteString(decoded, COSE_KEY_X, "x coordinate"), 32, "x coordinate");
  const y = expectLength(getCoseByteString(decoded, COSE_KEY_Y, "y coordinate"), 32, "y coordinate");
  const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
  return {
    compressed: Uint8Array.of(prefix, ...x),
    uncompressed: concatCoordinates(x, y),
  };
}

function getCoseByteString(map: Map<unknown, unknown>, key: number, label: string): Uint8Array {
  const value = map.get(key);
  invariant(value instanceof Uint8Array, `credential public key ${label} must be a byte string`);
  return value;
}

function concatCoordinates(x: Uint8Array, y: Uint8Array): Uint8Array {
  const out = new Uint8Array(64);
  out.set(x, 0);
  out.set(y, 32);
  return out;
}

function skipCborItem(bytes: Uint8Array, offset: number): number {
  invariant(offset < bytes.length, "invalid CBOR payload");
  const initialByte = bytes[offset++];
  const majorType = initialByte >> 5;
  const additionalInfo = initialByte & 0x1f;

  if (majorType <= 1) {
    return readCborArgument(bytes, offset, additionalInfo).nextOffset;
  }

  if (majorType === 2 || majorType === 3) {
    const lengthInfo = readCborArgument(bytes, offset, additionalInfo);
    const nextOffset = lengthInfo.nextOffset + lengthInfo.value;
    invariant(nextOffset <= bytes.length, "CBOR byte/string length exceeds payload");
    return nextOffset;
  }

  if (majorType === 4) {
    const lengthInfo = readCborArgument(bytes, offset, additionalInfo);
    let nextOffset = lengthInfo.nextOffset;
    for (let i = 0; i < lengthInfo.value; i += 1) {
      nextOffset = skipCborItem(bytes, nextOffset);
    }
    return nextOffset;
  }

  if (majorType === 5) {
    const lengthInfo = readCborArgument(bytes, offset, additionalInfo);
    let nextOffset = lengthInfo.nextOffset;
    for (let i = 0; i < lengthInfo.value; i += 1) {
      nextOffset = skipCborItem(bytes, nextOffset);
      nextOffset = skipCborItem(bytes, nextOffset);
    }
    return nextOffset;
  }

  if (majorType === 6) {
    return skipCborItem(bytes, readCborArgument(bytes, offset, additionalInfo).nextOffset);
  }

  if (additionalInfo < 24) {
    return offset;
  }
  if (additionalInfo === 24) {
    invariant(offset + 1 <= bytes.length, "CBOR simple value exceeds payload");
    return offset + 1;
  }
  if (additionalInfo === 25) {
    invariant(offset + 2 <= bytes.length, "CBOR simple value exceeds payload");
    return offset + 2;
  }
  if (additionalInfo === 26) {
    invariant(offset + 4 <= bytes.length, "CBOR simple value exceeds payload");
    return offset + 4;
  }
  if (additionalInfo === 27) {
    invariant(offset + 8 <= bytes.length, "CBOR simple value exceeds payload");
    return offset + 8;
  }

  throw new ExternalSignatureSdkError("indefinite-length CBOR items are not supported");
}

function readCborArgument(
  bytes: Uint8Array,
  offset: number,
  additionalInfo: number,
): { value: number; nextOffset: number } {
  if (additionalInfo < 24) {
    return { value: additionalInfo, nextOffset: offset };
  }

  if (additionalInfo === 24) {
    invariant(offset + 1 <= bytes.length, "CBOR length exceeds payload");
    return { value: bytes[offset], nextOffset: offset + 1 };
  }

  if (additionalInfo === 25) {
    invariant(offset + 2 <= bytes.length, "CBOR length exceeds payload");
    return {
      value: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, false),
      nextOffset: offset + 2,
    };
  }

  if (additionalInfo === 26) {
    invariant(offset + 4 <= bytes.length, "CBOR length exceeds payload");
    return {
      value: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false),
      nextOffset: offset + 4,
    };
  }

  if (additionalInfo === 27) {
    invariant(offset + 8 <= bytes.length, "CBOR length exceeds payload");
    const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(
      offset,
      false,
    );
    invariant(value <= BigInt(Number.MAX_SAFE_INTEGER), "CBOR length exceeds supported range");
    return { value: Number(value), nextOffset: offset + 8 };
  }

  throw new ExternalSignatureSdkError("indefinite-length CBOR items are not supported");
}

function readDerLength(bytes: Uint8Array, offset: number): {
  length: number;
  nextOffset: number;
} {
  invariant(offset < bytes.length, "invalid DER length field");
  const first = bytes[offset];
  if (first < 0x80) {
    return { length: first, nextOffset: offset + 1 };
  }

  const lengthBytes = first & 0x7f;
  invariant(lengthBytes > 0, "invalid DER length field");
  invariant(lengthBytes <= 4, "DER length field is too large");
  invariant(offset + 1 + lengthBytes <= bytes.length, "invalid DER length field");
  invariant(bytes[offset + 1] !== 0x00, "DER length field must use minimal encoding");
  let length = 0;
  for (let i = 0; i < lengthBytes; i += 1) {
    length = (length << 8) | bytes[offset + 1 + i];
  }
  invariant(length >= 0x80, "DER long-form length must not encode short-form values");
  return { length, nextOffset: offset + 1 + lengthBytes };
}

function readDerInteger(
  bytes: Uint8Array,
  offset: number,
  label: string,
): { value: bigint; nextOffset: number } {
  invariant(offset < bytes.length, `missing DER integer for ${label}`);
  invariant(bytes[offset++] === 0x02, `expected DER integer for ${label}`);
  const integerLength = readDerLength(bytes, offset);
  offset = integerLength.nextOffset;
  invariant(integerLength.length > 0, `DER integer for ${label} must not be empty`);
  invariant(
    offset + integerLength.length <= bytes.length,
    `DER integer length for ${label} exceeds payload`,
  );
  const integerBytes = bytes.slice(offset, offset + integerLength.length);
  assertCanonicalDerInteger(integerBytes, label);
  const value = derIntegerToBigInt(integerBytes);
  invariant(value >= 1n && value < P256_ORDER, `${label} must be in range [1, n-1]`);
  return { value, nextOffset: offset + integerLength.length };
}

function assertCanonicalDerInteger(bytes: Uint8Array, label: string): void {
  invariant(bytes.length > 0, `DER integer for ${label} must not be empty`);
  invariant((bytes[0] & 0x80) === 0, `DER integer for ${label} must be positive`);
  if (bytes.length > 1 && bytes[0] === 0x00) {
    invariant((bytes[1] & 0x80) === 0x80, `DER integer for ${label} has non-canonical leading zero`);
  }
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
  invariant(value >= 0n && value < P256_ORDER, "signature integer must be in range [0, n)");
  const hex = value.toString(16).padStart(64, "0");
  invariant(hex.length <= 64, "signature integer does not fit into 32 bytes");
  return Uint8Array.from(hex.match(/.{1,2}/g)!.map((part) => Number.parseInt(part, 16)));
}

function readDerElement(
  bytes: Uint8Array,
  offset: number,
  expectedTag: number,
  label: string,
): { valueOffset: number; nextOffset: number } {
  invariant(offset < bytes.length, `${label} is missing`);
  invariant(bytes[offset] === expectedTag, `${label} has invalid DER tag`);
  const lengthField = readDerLength(bytes, offset + 1);
  const valueOffset = lengthField.nextOffset;
  const nextOffset = valueOffset + lengthField.length;
  invariant(nextOffset <= bytes.length, `${label} length exceeds payload`);
  return { valueOffset, nextOffset };
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}
