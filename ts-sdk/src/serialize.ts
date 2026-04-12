import { AccountMeta, PublicKey, TransactionInstruction, TransactionMessage } from "@solana/web3.js";
import { base58 } from "@scure/base";

import {
  assert,
  concatBytes,
  expectLength,
  expectMaxLength,
  toLittleEndianU16,
  toLittleEndianU64,
  utf8,
} from "./bytes.js";
import { ExternalSignatureSdkError } from "./errors.js";
import type {
  ClientDataJsonReconstructionParams,
  SessionKey,
  WebAuthnData,
} from "./types.js";

export interface CompiledInstructionWire {
  programIdIndex: number;
  accountsIndices: Uint8Array;
  /** Raw instruction data bytes (not base58 text). */
  data: Uint8Array;
}

export interface CompiledExecutionPayload {
  accountMetas: AccountMeta[];
  compiledInstructions: CompiledInstructionWire[];
}

export function serializeOptionU16(value: number | null): Uint8Array {
  if (value == null) {
    return Uint8Array.of(0);
  }
  return concatBytes(Uint8Array.of(1), toLittleEndianU16(value));
}

export function serializeClientDataJsonReconstructionParams(
  params: ClientDataJsonReconstructionParams,
): Uint8Array {
  return concatBytes(Uint8Array.of(params.typeAndFlags), serializeOptionU16(params.port));
}

export function serializeSmallVecU8(bytes: Uint8Array, label: string): Uint8Array {
  const normalized = expectMaxLength(bytes, 0xff, label);
  return concatBytes(Uint8Array.of(normalized.length), normalized);
}

export function serializeSmallVecU16(bytes: Uint8Array, label: string): Uint8Array {
  const normalized = expectMaxLength(bytes, 0xffff, label);
  return concatBytes(toLittleEndianU16(normalized.length), normalized);
}

export function serializeSessionKey(sessionKey: SessionKey): Uint8Array {
  return concatBytes(
    expectLength(sessionKey.key, 32, "session key"),
    toLittleEndianU64(sessionKey.expiration),
  );
}

export function serializeP256RawVerificationData(webauthnData: WebAuthnData): Uint8Array {
  return concatBytes(
    expectLength(webauthnData.publicKey, 33, "compressed public key"),
    serializeClientDataJsonReconstructionParams(
      webauthnData.clientDataJsonReconstructionParams,
    ),
  );
}

export function serializeP256RawInitializationData(
  rpId: Uint8Array,
  webauthnData: WebAuthnData,
): Uint8Array {
  return concatBytes(
    serializeSmallVecU8(expectMaxLength(rpId, 0xff, "rp id"), "rp id"),
    expectLength(webauthnData.publicKey, 33, "compressed public key"),
    serializeClientDataJsonReconstructionParams(
      webauthnData.clientDataJsonReconstructionParams,
    ),
  );
}

export function serializeCompiledInstruction(instruction: CompiledInstructionWire): Uint8Array {
  return concatBytes(
    Uint8Array.of(instruction.programIdIndex),
    serializeSmallVecU8(
      expectMaxLength(instruction.accountsIndices, 0xff, "compiled instruction accounts"),
      "compiled instruction accounts",
    ),
    serializeSmallVecU16(
      expectMaxLength(instruction.data, 0xffff, "compiled instruction data"),
      "compiled instruction data",
    ),
  );
}

export function serializeCompiledInstructions(
  instructions: CompiledInstructionWire[],
): Uint8Array {
  assert(instructions.length <= 0xff, "too many compiled instructions");
  return concatBytes(
    Uint8Array.of(instructions.length),
    ...instructions.map(serializeCompiledInstruction),
  );
}

export function compileInstructionsForExecution(
  instructions: TransactionInstruction[],
  payerKey: PublicKey,
): CompiledExecutionPayload {
  const message = new TransactionMessage({
    payerKey,
    recentBlockhash: PublicKey.default.toBase58(),
    instructions,
  }).compileToLegacyMessage();

  const header = message.header;
  const accountKeys = message.accountKeys;
  const writableSignedEnd =
    header.numRequiredSignatures - header.numReadonlySignedAccounts;
  const signedEnd = header.numRequiredSignatures;
  const writableUnsignedEnd = accountKeys.length - header.numReadonlyUnsignedAccounts;

  const accountMetas = accountKeys.map((pubkey, index) => {
    const isSigner = index < signedEnd;
    const isWritable = isSigner ? index < writableSignedEnd : index < writableUnsignedEnd;
    return { pubkey, isSigner, isWritable };
  });

  const compiledInstructions = message.instructions.map((instruction) => ({
    programIdIndex: instruction.programIdIndex,
    accountsIndices: Uint8Array.from(instruction.accounts),
    // web3 legacy compiled instructions may expose data as base58 string.
    // Always normalize to raw bytes for program-compatible serialization.
    data:
      typeof instruction.data === "string"
        ? base58.decode(instruction.data)
        : Uint8Array.from(instruction.data),
  }));

  return { accountMetas, compiledInstructions };
}

export function serializeInitializeAccountArgs(input: {
  truncatedSlot: number;
  signatureScheme: number;
  initializationData: Uint8Array;
  sessionKey?: SessionKey | null;
}): Uint8Array {
  return concatBytes(
    toLittleEndianU16(input.truncatedSlot),
    Uint8Array.of(input.signatureScheme),
    serializeSmallVecU8(input.initializationData, "initialization data"),
    input.sessionKey == null
      ? Uint8Array.of(0)
      : concatBytes(Uint8Array.of(1), serializeSessionKey(input.sessionKey)),
  );
}

export function serializeExecuteInstructionArgs(input: {
  signatureScheme: number;
  signerExecutionScheme: number;
  truncatedSlot: number;
  extraVerificationData: Uint8Array;
  compiledInstructions: CompiledInstructionWire[];
}): Uint8Array {
  return concatBytes(
    Uint8Array.of(input.signatureScheme),
    Uint8Array.of(input.signerExecutionScheme),
    toLittleEndianU16(input.truncatedSlot),
    serializeSmallVecU8(input.extraVerificationData, "verification data"),
    serializeCompiledInstructions(input.compiledInstructions),
  );
}

export function serializeRefreshSessionKeyArgs(input: {
  truncatedSlot: number;
  signatureScheme: number;
  verificationData: Uint8Array;
  sessionKey: SessionKey;
}): Uint8Array {
  return concatBytes(
    toLittleEndianU16(input.truncatedSlot),
    Uint8Array.of(input.signatureScheme),
    serializeSmallVecU8(input.verificationData, "verification data"),
    serializeSessionKey(input.sessionKey),
  );
}

export function serializeExecuteInstructionsSessionedArgs(input: {
  signatureScheme: number;
  signerExecutionScheme: number;
  compiledInstructions: CompiledInstructionWire[];
}): Uint8Array {
  return concatBytes(
    Uint8Array.of(input.signatureScheme),
    Uint8Array.of(input.signerExecutionScheme),
    serializeCompiledInstructions(input.compiledInstructions),
  );
}

export function serializeAccountMetaList(accountMetas: AccountMeta[]): Uint8Array {
  assert(accountMetas.length <= 0xff, "too many execution accounts");
  return concatBytes(
    Uint8Array.of(accountMetas.length),
    ...accountMetas.map((meta) =>
      concatBytes(
        meta.pubkey.toBytes(),
        Uint8Array.of(meta.isSigner ? 1 : 0),
        Uint8Array.of(meta.isWritable ? 1 : 0),
      ),
    ),
  );
}

export function requireAsciiLabel(label: string): Uint8Array {
  try {
    return utf8(label);
  } catch (error) {
    throw new ExternalSignatureSdkError(
      `failed to serialize ascii label ${label}: ${String(error)}`,
    );
  }
}
