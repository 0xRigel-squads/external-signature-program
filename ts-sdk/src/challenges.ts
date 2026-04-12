import { PublicKey, TransactionInstruction } from "@solana/web3.js";

import { concatBytes, expectLength, truncateSlot, utf8 } from "./bytes.js";
import { encodeBase64Url, sha256Bytes } from "./crypto.js";
import {
  compileInstructionsForExecution,
  serializeAccountMetaList,
  serializeCompiledInstructions,
  serializeSessionKey,
} from "./serialize.js";
import type { SessionKey } from "./types.js";

export interface ChallengeResult {
  /** Raw 32-byte challenge hash used in WebAuthn challenge field. */
  challenge: Uint8Array;
  /** URL-safe base64 (no padding) form of `challenge`. */
  challengeBase64Url: string;
}

/** Builds challenge payload/hash for passkey initialization. */
export function createInitializePasskeyChallenge(input: {
  payer: PublicKey;
  recentSlotHash: Uint8Array;
  sessionKey?: SessionKey | null;
}): ChallengeResult {
  const challenge = sha256Bytes(
    concatBytes(
      expectLength(input.recentSlotHash, 32, "recent slot hash"),
      input.payer.toBytes(),
      utf8("initialize_passkey"),
      input.sessionKey == null ? new Uint8Array() : serializeSessionKey(input.sessionKey),
    ),
  );

  return { challenge, challengeBase64Url: encodeBase64Url(challenge) };
}

/** Builds challenge payload/hash for authenticated wrapped execution. */
export function createExecuteInstructionsChallenge(input: {
  nonceSigner: PublicKey;
  recentSlotHash: Uint8Array;
  instructions: TransactionInstruction[];
}): ChallengeResult {
  const compiled = compileInstructionsForExecution(input.instructions, input.nonceSigner);
  const challenge = sha256Bytes(
    concatBytes(
      expectLength(input.recentSlotHash, 32, "recent slot hash"),
      input.nonceSigner.toBytes(),
      utf8("execute_instructions"),
      serializeAccountMetaList(compiled.accountMetas),
      serializeCompiledInstructions(compiled.compiledInstructions),
    ),
  );

  return { challenge, challengeBase64Url: encodeBase64Url(challenge) };
}

/** Builds challenge payload/hash for session-key refresh. */
export function createRefreshSessionKeyChallenge(input: {
  nonceSigner: PublicKey;
  recentSlotHash: Uint8Array;
  sessionKey: SessionKey;
}): ChallengeResult {
  const challenge = sha256Bytes(
    concatBytes(
      expectLength(input.recentSlotHash, 32, "recent slot hash"),
      input.nonceSigner.toBytes(),
      utf8("refresh_session_key"),
      serializeSessionKey(input.sessionKey),
    ),
  );

  return { challenge, challengeBase64Url: encodeBase64Url(challenge) };
}

/** Truncates slot to the modulo-1000 format expected by the on-chain program. */
export function truncateSlotForValidator(slot: number | bigint): number {
  return truncateSlot(slot);
}
