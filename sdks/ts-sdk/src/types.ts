import { PublicKey, TransactionInstruction } from "@solana/web3.js";

/** WebAuthn ceremony type encoded into reconstruction params. */
export enum AuthType {
  Create = "create",
  Get = "get",
}

/** Program-level signature scheme discriminator. */
export enum SignatureScheme {
  P256Webauthn = 0,
}

/**
 * Selects which account is used as CPI signer during wrapped execution.
 * - ExecutionAccount: signer PDA derived from external account.
 * - ExternalAccount: the passkey account itself is the signer.
 */
export enum SignerExecutionScheme {
  ExecutionAccount = 0,
  ExternalAccount = 1,
}

export type BytesLike = Uint8Array | number[];

/** Compact params used to reconstruct `clientDataJSON` on-chain. */
export interface ClientDataJsonReconstructionParams {
  typeAndFlags: number;
  port: number | null;
}

/** Inputs for constructing compact `clientDataJSON` reconstruction params. */
export interface CreateClientDataJsonReconstructionParamsInput {
  authType: AuthType;
  crossOrigin: boolean;
  includeCrossOrigin?: boolean;
  isHttp: boolean;
  hasGoogleExtra: boolean;
  port?: number | null;
}

/**
 * Minimal WebAuthn payload required by the program wrapper.
 * `signature` must be DER-encoded ECDSA for precompile construction.
 */
export interface WebAuthnData {
  publicKey: Uint8Array;
  signature: Uint8Array;
  authData: Uint8Array;
  clientDataJson: Uint8Array;
  clientDataJsonReconstructionParams: ClientDataJsonReconstructionParams;
}

/** Session signer key + relative expiration (seconds) for refresh requests. */
export interface SessionKey {
  key: Uint8Array;
  expiration: bigint | number;
}

/** Return type for authenticated wrapper builders. */
export interface WrappedInstructionResult {
  instruction: TransactionInstruction;
  challenge: Uint8Array;
  challengeBase64Url: string;
  precompileMessage: Uint8Array;
}

/** Initialization result includes the derived passkey account PDA. */
export interface InitializePasskeyResult extends WrappedInstructionResult {
  passkeyAccount: PublicKey;
}
