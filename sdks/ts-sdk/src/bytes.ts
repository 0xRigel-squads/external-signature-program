import { ExternalSignatureSdkError, invariant } from "./errors.js";
import type { BytesLike } from "./types.js";

export function toBytes(value: BytesLike): Uint8Array {
  return value instanceof Uint8Array ? value : Uint8Array.from(value);
}

export function expectLength(value: BytesLike, length: number, label: string): Uint8Array {
  const bytes = toBytes(value);
  invariant(bytes.length === length, `${label} must be exactly ${length} bytes`);
  return bytes;
}

export function expectMaxLength(value: BytesLike, length: number, label: string): Uint8Array {
  const bytes = toBytes(value);
  invariant(bytes.length <= length, `${label} must be at most ${length} bytes`);
  return bytes;
}

export function toLittleEndianU16(value: number): Uint8Array {
  invariant(Number.isInteger(value) && value >= 0 && value <= 0xffff, "u16 out of range");
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

export function toLittleEndianU64(value: bigint | number): Uint8Array {
  if (typeof value === "number") {
    invariant(Number.isSafeInteger(value), "u64 input number must be a safe integer");
  }
  const big = typeof value === "bigint" ? value : BigInt(value);
  invariant(big >= 0n && big <= 0xffff_ffff_ffff_ffffn, "u64 out of range");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, big, true);
  return out;
}

export function concatBytes(...parts: BytesLike[]): Uint8Array {
  const normalized = parts.map(toBytes);
  const length = normalized.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of normalized) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function truncateSlot(slot: number | bigint): number {
  if (typeof slot === "number") {
    invariant(Number.isSafeInteger(slot), "slot must be a safe integer");
  }
  const big = typeof slot === "bigint" ? slot : BigInt(slot);
  invariant(big >= 0n, "slot must be non-negative");
  return Number(big % 1000n);
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new ExternalSignatureSdkError(message);
  }
}
