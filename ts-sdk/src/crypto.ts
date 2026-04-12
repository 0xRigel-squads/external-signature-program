import { sha256 } from "@noble/hashes/sha256";
import { base64urlnopad } from "@scure/base";

import type { BytesLike } from "./types.js";
import { toBytes } from "./bytes.js";

export function sha256Bytes(data: BytesLike): Uint8Array {
  return Uint8Array.from(sha256(toBytes(data)));
}

export function encodeBase64Url(data: BytesLike): string {
  return base64urlnopad.encode(toBytes(data));
}
