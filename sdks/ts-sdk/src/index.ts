export { PublicKey, TransactionInstruction } from "@solana/web3.js";

export {
  createExecuteInstructionsChallenge,
  createInitializePasskeyChallenge,
  createRefreshSessionKeyChallenge,
  truncateSlotForValidator,
} from "./challenges.js";
export {
  buildExecuteInstructions,
  buildExecuteInstructionsSessioned,
  buildInitializePasskeyAccount,
  buildPrecompileMessage,
  buildRefreshSessionKey,
  createSecp256r1Instruction,
  reconstructClientDataJsonForChallenge,
} from "./instructions.js";
export {
  GOOGLE_CLIENT_DATA_JSON_EXTRA_VALUE,
  createClientDataJsonReconstructionParams,
  reconstructClientDataJson,
} from "./clientDataJson.js";
export { PROGRAM_ID, INSTRUCTIONS_SYSVAR_ID, SLOT_HASHES_SYSVAR_ID } from "./constants.js";
export { deriveExecutionAccount, derivePasskeyAccount } from "./pda.js";
export { ExternalSignatureSdkError } from "./errors.js";
export { truncateSlot } from "./bytes.js";
export {
  AuthType,
  SignatureScheme,
  SignerExecutionScheme,
} from "./types.js";
export type {
  ExecuteInstructionsInput,
  ExecuteInstructionsSessionedInput,
  InitializePasskeyAccountInput,
  RefreshSessionKeyInput,
  Secp256r1InstructionInput,
} from "./instructions.js";
export type {
  ClientDataJsonReconstructionParams,
  CreateClientDataJsonReconstructionParamsInput,
  InitializePasskeyResult,
  SessionKey,
  WebAuthnData,
  WrappedInstructionResult,
} from "./types.js";
