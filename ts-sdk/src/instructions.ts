import { Buffer } from "buffer";
import {
  AccountMeta,
  PublicKey,
  TransactionInstruction,
} from "@solana/web3.js";

import {
  INSTRUCTIONS_SYSVAR_ID,
  PROGRAM_ID,
  SECP256R1_PROGRAM_ID,
  SLOT_HASHES_SYSVAR_ID,
  SYSTEM_PROGRAM_ID,
} from "./constants.js";
import { concatBytes, expectLength, truncateSlot, utf8 } from "./bytes.js";
import { reconstructClientDataJson } from "./clientDataJson.js";
import { createExecuteInstructionsChallenge, createInitializePasskeyChallenge, createRefreshSessionKeyChallenge } from "./challenges.js";
import { sha256Bytes } from "./crypto.js";
import {
  compileInstructionsForExecution,
  serializeExecuteInstructionsSessionedArgs,
  serializeExecuteInstructionArgs,
  serializeInitializeAccountArgs,
  serializeP256RawInitializationData,
  serializeP256RawVerificationData,
  serializeRefreshSessionKeyArgs,
} from "./serialize.js";
import type {
  InitializePasskeyResult,
  SessionKey,
  WebAuthnData,
  WrappedInstructionResult,
} from "./types.js";
import { SignatureScheme, SignerExecutionScheme } from "./types.js";
import { derivePasskeyAccount } from "./pda.js";
import { parseDerSignatureToCompact } from "./webauthn.js";

/** Input for passkey account initialization wrapper. */
export interface InitializePasskeyAccountInput {
  webauthnData: WebAuthnData;
  rpId: string | Uint8Array;
  payer: PublicKey;
  truncatedSlot: number | bigint;
  recentSlotHash: Uint8Array;
  sessionKey?: SessionKey | null;
}

/** Input for authenticated wrapped execution (non-sessioned). */
export interface ExecuteInstructionsInput {
  webauthnData: WebAuthnData;
  passkeyAccount: PublicKey;
  nonceSigner: PublicKey;
  truncatedSlot: number | bigint;
  recentSlotHash: Uint8Array;
  instructions: TransactionInstruction[];
  signerExecutionScheme?: SignerExecutionScheme;
}

/** Input for sessioned wrapped execution. */
export interface ExecuteInstructionsSessionedInput {
  passkeyAccount: PublicKey;
  sessionSigner: PublicKey;
  instructions: TransactionInstruction[];
  signerExecutionScheme?: SignerExecutionScheme;
}

/** Input for session-key refresh wrapper. */
export interface RefreshSessionKeyInput {
  webauthnData: WebAuthnData;
  passkeyAccount: PublicKey;
  nonceSigner: PublicKey;
  truncatedSlot: number | bigint;
  recentSlotHash: Uint8Array;
  sessionKey: SessionKey;
}

/** Input for constructing secp256r1 precompile instruction. */
export interface Secp256r1InstructionInput {
  /** DER-encoded ECDSA signature from WebAuthn assertion/attestation. */
  signature: Uint8Array;
  /** Precompile message (typically authData || sha256(clientDataJson)). */
  message: Uint8Array;
  /** Compressed secp256r1 public key (33-byte SEC1). */
  publicKey: Uint8Array;
  instructionIndex?: number;
}

/**
 * Creates the secp256r1 precompile instruction.
 * Include this immediately before authenticated program instructions.
 */
export function createSecp256r1Instruction(
  input: Secp256r1InstructionInput,
): TransactionInstruction {
  const signature = parseDerSignatureToCompact(input.signature);
  const message = input.message;
  const publicKey = expectLength(input.publicKey, 33, "compressed public key");
  const dataStart = 2 + 14;
  const publicKeyOffset = dataStart;
  const signatureOffset = publicKeyOffset + publicKey.length;
  const messageOffset = signatureOffset + signature.length;
  const data = concatBytes(
    Uint8Array.of(1),
    Uint8Array.of(0),
    new Uint8Array([signatureOffset & 0xff, (signatureOffset >> 8) & 0xff]),
    Uint8Array.of(0xff, 0xff),
    new Uint8Array([publicKeyOffset & 0xff, (publicKeyOffset >> 8) & 0xff]),
    Uint8Array.of(0xff, 0xff),
    new Uint8Array([messageOffset & 0xff, (messageOffset >> 8) & 0xff]),
    new Uint8Array([message.length & 0xff, (message.length >> 8) & 0xff]),
    Uint8Array.of(0xff, 0xff),
    publicKey,
    signature,
    message,
  );

  return new TransactionInstruction({
    programId: SECP256R1_PROGRAM_ID,
    keys: [],
    data: Buffer.from(data),
  });
}

/** Builds initialize-account wrapper and matching challenge/precompile message. */
export function buildInitializePasskeyAccount(
  input: InitializePasskeyAccountInput,
): InitializePasskeyResult {
  const [passkeyAccount] = derivePasskeyAccount(input.webauthnData.publicKey);
  const rpIdBytes = typeof input.rpId === "string" ? utf8(input.rpId) : input.rpId;
  const initializationData = serializeP256RawInitializationData(rpIdBytes, input.webauthnData);
  const args = serializeInitializeAccountArgs({
    truncatedSlot: truncateSlot(input.truncatedSlot),
    signatureScheme: SignatureScheme.P256Webauthn,
    initializationData,
    sessionKey: input.sessionKey,
  });
  const instruction = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: passkeyAccount, isSigner: false, isWritable: true },
      { pubkey: input.payer, isSigner: true, isWritable: true },
      { pubkey: INSTRUCTIONS_SYSVAR_ID, isSigner: false, isWritable: false },
      { pubkey: SLOT_HASHES_SYSVAR_ID, isSigner: false, isWritable: false },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(concatBytes(Uint8Array.of(0), args)),
  });

  const { challenge, challengeBase64Url } = createInitializePasskeyChallenge({
    payer: input.payer,
    recentSlotHash: input.recentSlotHash,
    sessionKey: input.sessionKey,
  });
  const precompileMessage = buildPrecompileMessage(
    input.webauthnData.clientDataJson,
    input.webauthnData.authData,
  );

  return {
    passkeyAccount,
    instruction,
    challenge,
    challengeBase64Url,
    precompileMessage,
  };
}

/**
 * Builds execute-instructions wrapper and matching challenge/precompile message.
 * Defaults to `SignerExecutionScheme.ExecutionAccount` if not provided.
 */
export function buildExecuteInstructions(
  input: ExecuteInstructionsInput,
): WrappedInstructionResult {
  const compiled = compileInstructionsForExecution(input.instructions, input.nonceSigner);
  const verificationData = serializeP256RawVerificationData(input.webauthnData);
  const args = serializeExecuteInstructionArgs({
    signatureScheme: SignatureScheme.P256Webauthn,
    signerExecutionScheme:
      input.signerExecutionScheme ?? SignerExecutionScheme.ExecutionAccount,
    truncatedSlot: truncateSlot(input.truncatedSlot),
    extraVerificationData: verificationData,
    compiledInstructions: compiled.compiledInstructions,
  });

  const instruction = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: input.passkeyAccount, isSigner: false, isWritable: true },
      { pubkey: INSTRUCTIONS_SYSVAR_ID, isSigner: false, isWritable: false },
      { pubkey: SLOT_HASHES_SYSVAR_ID, isSigner: false, isWritable: false },
      { pubkey: input.nonceSigner, isSigner: true, isWritable: true },
      ...compiled.accountMetas.map(toAccountMetaArg),
    ],
    data: Buffer.from(concatBytes(Uint8Array.of(1), args)),
  });

  const { challenge, challengeBase64Url } = createExecuteInstructionsChallenge({
    nonceSigner: input.nonceSigner,
    recentSlotHash: input.recentSlotHash,
    instructions: input.instructions,
  });

  return {
    instruction,
    challenge,
    challengeBase64Url,
    precompileMessage: buildPrecompileMessage(
      input.webauthnData.clientDataJson,
      input.webauthnData.authData,
    ),
  };
}

/**
 * Builds sessioned execute-instructions wrapper.
 * Defaults to `SignerExecutionScheme.ExecutionAccount` if not provided.
 */
export function buildExecuteInstructionsSessioned(
  input: ExecuteInstructionsSessionedInput,
): TransactionInstruction {
  const compiled = compileInstructionsForExecution(input.instructions, input.sessionSigner);
  const args = serializeExecuteInstructionsSessionedArgs({
    signatureScheme: SignatureScheme.P256Webauthn,
    signerExecutionScheme:
      input.signerExecutionScheme ?? SignerExecutionScheme.ExecutionAccount,
    compiledInstructions: compiled.compiledInstructions,
  });

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: input.passkeyAccount, isSigner: false, isWritable: true },
      { pubkey: input.sessionSigner, isSigner: true, isWritable: false },
      ...compiled.accountMetas.map(toAccountMetaArg),
    ],
    data: Buffer.from(concatBytes(Uint8Array.of(3), args)),
  });
}

/** Builds refresh-session-key wrapper and matching challenge/precompile message. */
export function buildRefreshSessionKey(
  input: RefreshSessionKeyInput,
): WrappedInstructionResult {
  const verificationData = serializeP256RawVerificationData(input.webauthnData);
  const args = serializeRefreshSessionKeyArgs({
    truncatedSlot: truncateSlot(input.truncatedSlot),
    signatureScheme: SignatureScheme.P256Webauthn,
    verificationData,
    sessionKey: input.sessionKey,
  });

  const instruction = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: input.passkeyAccount, isSigner: false, isWritable: true },
      { pubkey: INSTRUCTIONS_SYSVAR_ID, isSigner: false, isWritable: false },
      { pubkey: SLOT_HASHES_SYSVAR_ID, isSigner: false, isWritable: false },
      { pubkey: input.nonceSigner, isSigner: true, isWritable: true },
    ],
    data: Buffer.from(concatBytes(Uint8Array.of(2), args)),
  });

  const { challenge, challengeBase64Url } = createRefreshSessionKeyChallenge({
    nonceSigner: input.nonceSigner,
    recentSlotHash: input.recentSlotHash,
    sessionKey: input.sessionKey,
  });

  return {
    instruction,
    challenge,
    challengeBase64Url,
    precompileMessage: buildPrecompileMessage(
      input.webauthnData.clientDataJson,
      input.webauthnData.authData,
    ),
  };
}

/** Builds the precompile message: `authData || sha256(clientDataJson)`. */
export function buildPrecompileMessage(
  clientDataJson: Uint8Array,
  authData: Uint8Array,
): Uint8Array {
  return concatBytes(authData, sha256Bytes(clientDataJson));
}

/** Reconstructs the expected `clientDataJSON` bytes for a given challenge. */
export function reconstructClientDataJsonForChallenge(input: {
  rpId: string;
  challenge: Uint8Array;
  webauthnData: WebAuthnData;
}): Uint8Array {
  return reconstructClientDataJson(
    input.webauthnData.clientDataJsonReconstructionParams,
    input.rpId,
    input.challenge,
  );
}

function toAccountMetaArg(meta: AccountMeta): AccountMeta {
  return {
    pubkey: meta.pubkey,
    isSigner: meta.isSigner,
    isWritable: meta.isWritable,
  };
}
