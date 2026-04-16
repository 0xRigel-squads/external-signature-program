# External Signature Program - TypeScript SDK

TypeScript SDK for constructing byte-compatible instructions and challenges for the External Signature Program.

## What this SDK does

- Derives passkey and execution PDAs.
- Builds wrapped program instructions:
  - initialize passkey account
  - execute instructions
  - execute instructions (sessioned)
  - refresh session key
- Builds matching challenge payloads (`Uint8Array` and base64url string).
- Builds the secp256r1 precompile instruction required before authenticated calls.
- Parses browser WebAuthn payloads into SDK-friendly structures.

## What this SDK does not do

- It does not call `navigator.credentials.create/get` for you.
- It does not send transactions for you.
- It does not manage RPC nonce/slot-hash fetching for you.

Use it as a deterministic serialization/wrapping layer around your own WebAuthn + transaction flow.

The package now has two entrypoints:

- `external-signature-ts-sdk`: Node-safe instruction builders, challenge helpers, PDA helpers, constants, and shared types.
- `external-signature-ts-sdk/webauthn`: browser/WebAuthn parsing helpers and related browser-facing types.

## Installation

```bash
npm install external-signature-ts-sdk
```

## Core flow

For authenticated (non-sessioned) execution:

1. Build or parse `WebAuthnData` (from a browser assertion).
2. Build wrapped instruction (`buildExecuteInstructions`).
3. Build precompile instruction (`createSecp256r1Instruction`) using `wrapped.precompileMessage`.
4. Send transaction with `[precompileIx, wrapped.instruction]` in that order.

For sessioned execution:

1. First set a session key (`buildRefreshSessionKey` + precompile).
2. Later execute with `buildExecuteInstructionsSessioned` (no precompile needed).

## Minimal example

```ts
import {
  PublicKey,
  SignerExecutionScheme,
  buildExecuteInstructions,
  createSecp256r1Instruction,
} from "external-signature-ts-sdk";
import { parseAuthenticationCredential } from "external-signature-ts-sdk/webauthn";

// Browser-origin credential from navigator.credentials.get(...)
const credential: PublicKeyCredential = /* ... */;
const compressedPublicKey = new Uint8Array(33); // from registration

const webauthnData = parseAuthenticationCredential({
  credential,
  compressedPublicKey,
});

const passkeyAccount = new PublicKey("...");
const nonceSigner = new PublicKey("...");
const recentSlotHash = new Uint8Array(32);

const wrapped = buildExecuteInstructions({
  webauthnData,
  passkeyAccount,
  nonceSigner,
  truncatedSlot: 123,
  recentSlotHash,
  instructions: [],
  signerExecutionScheme: SignerExecutionScheme.ExecutionAccount,
});

const precompileIx = createSecp256r1Instruction({
  signature: webauthnData.signature, // DER ECDSA signature
  publicKey: webauthnData.publicKey, // compressed 33-byte key
  message: wrapped.precompileMessage,
});

// send transaction: [precompileIx, wrapped.instruction]
```

## Gotchas

- `createSecp256r1Instruction` expects a DER signature and converts it internally to compact form.
- `publicKey` for `createSecp256r1Instruction` must be compressed SEC1 (33 bytes), not SPKI.
- `createSecp256r1Instruction` validates precompile message length (`<= 65535` bytes).
- `truncatedSlot` is modulo-1000; use `truncateSlotForValidator(...)`.
- For wrapped authenticated calls, include the secp256r1 precompile instruction immediately before the program instruction.
- DER signatures are validated strictly (canonical DER, full payload consumption, `r/s` range checks).
- `parseClientDataJsonReconstructionParams` accepts only `webauthn.create` or `webauthn.get` and validates `origin` (http/https + valid port).

## Validation behavior

These checks were tightened as correctness hardening. Wire format and instruction/challenge encoding are unchanged.

- `decodeSpkiP256PublicKey` now validates DER/SPKI structure and requires `id-ecPublicKey` + `prime256v1` and a 65-byte uncompressed EC point.
- `truncateSlot` and `toLittleEndianU64` reject non-integer numeric inputs (`NaN`, infinities, fractional values) with `ExternalSignatureSdkError`.
- `parseClientDataJsonReconstructionParams` requires `crossOrigin` to be boolean (when present).
- `parseClientDataJsonReconstructionParams` only accepts `other_keys_can_be_added_here` when it exactly matches `GOOGLE_CLIENT_DATA_JSON_EXTRA_VALUE`.
- `parseRegistrationCredential` fails fast when `attStmt.sig` is missing/empty.

## Compatibility notes

- **Breaking**:
  - `Secp256r1InstructionInput.instructionIndex` was removed. The TS SDK only supports the canonical inline precompile payload layout.
  - Browser/WebAuthn helpers now live under `external-signature-ts-sdk/webauthn` so the root entrypoint remains Node-safe.
- **Non-breaking**:
  - `fromBase64Url`/`toBase64Url` now use runtime-safe base64url utilities (Node + browser compatible).
  - Additional builder input interfaces are exported from the package entrypoint for stronger consumer typing.
  - Error paths for malformed DER and malformed `clientDataJSON` now fail fast with `ExternalSignatureSdkError`.
  - `parseRegistrationCredential` falls back to attested credential data when `getPublicKey()` is unavailable and validates it against `getPublicKey()` when both are present.

## Root exports

- `derivePasskeyAccount`
- `deriveExecutionAccount`
- `buildInitializePasskeyAccount`
- `buildExecuteInstructions`
- `buildExecuteInstructionsSessioned`
- `buildRefreshSessionKey`
- `createSecp256r1Instruction`
- `createInitializePasskeyChallenge`
- `createExecuteInstructionsChallenge`
- `createRefreshSessionKeyChallenge`
- `reconstructClientDataJson`
- `GOOGLE_CLIENT_DATA_JSON_EXTRA_VALUE`

## WebAuthn exports

- `parseRegistrationCredential`
- `parseAuthenticationCredential`
- `RegistrationWebAuthnData`
- `decodeSpkiP256PublicKey`
- `parseClientDataJsonReconstructionParams`
- `parseDerSignatureToCompact`
- `toBase64Url`
- `fromBase64Url`
