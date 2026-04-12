import { concatBytes, utf8 } from "./bytes.js";
import { encodeBase64Url } from "./crypto.js";
import type {
  ClientDataJsonReconstructionParams,
  CreateClientDataJsonReconstructionParamsInput,
} from "./types.js";
import { AuthType } from "./types.js";

const TYPE_CREATE = 0x00;
const TYPE_GET = 0x10;
const FLAG_CROSS_ORIGIN = 0x01;
const FLAG_HTTP_ORIGIN = 0x02;
const FLAG_GOOGLE_EXTRA = 0x04;

/** Packs WebAuthn clientDataJSON reconstruction metadata into compact params. */
export function createClientDataJsonReconstructionParams(
  input: CreateClientDataJsonReconstructionParamsInput,
): ClientDataJsonReconstructionParams {
  let typeAndFlags = input.authType === AuthType.Get ? TYPE_GET : TYPE_CREATE;
  if (input.crossOrigin) typeAndFlags |= FLAG_CROSS_ORIGIN;
  if (input.isHttp) typeAndFlags |= FLAG_HTTP_ORIGIN;
  if (input.hasGoogleExtra) typeAndFlags |= FLAG_GOOGLE_EXTRA;
  return {
    typeAndFlags,
    port: input.port ?? null,
  };
}

/** Reads the auth type from packed reconstruction params. */
export function getAuthType(params: ClientDataJsonReconstructionParams): AuthType {
  return (params.typeAndFlags & 0xf0) === TYPE_GET ? AuthType.Get : AuthType.Create;
}

/**
 * Reconstructs the exact `clientDataJSON` byte template expected by the program.
 * This must match the signed browser payload byte-for-byte.
 */
export function reconstructClientDataJson(
  params: ClientDataJsonReconstructionParams,
  rpId: string,
  challenge: Uint8Array,
): Uint8Array {
  const challengeBase64Url = encodeBase64Url(challenge);
  const protocol = (params.typeAndFlags & FLAG_HTTP_ORIGIN) !== 0 ? "http://" : "https://";
  const type = getAuthType(params) === AuthType.Get ? "webauthn.get" : "webauthn.create";
  const origin =
    params.port == null ? `${protocol}${rpId}` : `${protocol}${rpId}:${params.port}`;
  const crossOrigin = (params.typeAndFlags & FLAG_CROSS_ORIGIN) !== 0 ? "true" : "false";

  const base = [
    "{\"type\":\"",
    type,
    "\",\"challenge\":\"",
    challengeBase64Url,
    "\",\"origin\":\"",
    origin,
    "\",\"crossOrigin\":",
    crossOrigin,
  ];

  const googleExtra =
    (params.typeAndFlags & FLAG_GOOGLE_EXTRA) !== 0
      ? [
          ",\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\"",
        ]
      : [];

  return concatBytes(utf8(base.join("")), utf8(googleExtra.join("")), utf8("}"));
}
