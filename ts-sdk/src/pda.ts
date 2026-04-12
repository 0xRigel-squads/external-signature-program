import { Buffer } from "buffer";
import { PublicKey } from "@solana/web3.js";

import { PROGRAM_ID } from "./constants.js";
import { expectLength } from "./bytes.js";
import { sha256Bytes } from "./crypto.js";

/** Derives passkey account PDA from compressed secp256r1 public key (33 bytes). */
export function derivePasskeyAccount(publicKey: Uint8Array): [PublicKey, number] {
  const publicKeyHash = sha256Bytes(expectLength(publicKey, 33, "compressed public key"));
  return PublicKey.findProgramAddressSync([Buffer.from("passkey"), publicKeyHash], PROGRAM_ID);
}

/** Derives execution account PDA from passkey account PDA. */
export function deriveExecutionAccount(passkeyAccount: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [passkeyAccount.toBytes(), Buffer.from("execution_account")],
    PROGRAM_ID,
  );
}
