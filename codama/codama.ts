import {
    accountNode,
    arrayTypeNode,
    bytesTypeNode,
    constantDiscriminatorNode,
    constantPdaSeedNodeFromString,
    constantValueNode,
    createFromRoot,
    definedTypeLinkNode,
    definedTypeNode,
    enumEmptyVariantTypeNode,
    enumTypeNode,
    errorNode,
    fixedSizeTypeNode,
    instructionAccountNode,
    instructionArgumentNode,
    instructionNode,
    instructionRemainingAccountsNode,
    numberTypeNode,
    numberValueNode,
    optionTypeNode,
    pdaNode,
    prefixedCountNode,
    programNode,
    publicKeyTypeNode,
    publicKeyValueNode,
    rootNode,
    sizePrefixTypeNode,
    structFieldTypeNode,
    structTypeNode,
    variablePdaSeedNode,
} from "codama";
import path from "path";
import fs from "fs";

// ============================================================================
// External Signature Program — Codama IDL
// ============================================================================
//
// Program ID: ExtSgUPtP3JyKUysFw2S5fpL5fWfUPzGUQLd2bTwftXN
//
// Instructions (discriminator = first byte):
//   0 — initializeExternalAccount
//   1 — executeInstructions
//   2 — refreshSessionKey
//   3 — executeInstructionsSessioned
//
// ============================================================================

const root = rootNode(
    programNode({
        name: "externalSignatureProgram",
        publicKey: "ExtSgUPtP3JyKUysFw2S5fpL5fWfUPzGUQLd2bTwftXN",
        version: "0.1.0",
        origin: "native",

        // ====================================================================
        // Accounts
        // ====================================================================
        accounts: [
            // P256WebauthnAccountData — the on-chain account layout
            // Layout: AccountHeader (4) + RpIdInformation (65) +
            //         CompressedP256PublicKey (33) + padding (2) +
            //         SessionKey (40) + counter (8) = 152 bytes
            accountNode({
                name: "p256WebauthnAccount",
                size: 152,
                discriminators: [
                    // version=1, scheme=0 (P256Webauthn)
                    constantDiscriminatorNode(
                        constantValueNode(numberTypeNode("u8"), numberValueNode(1)),
                        0
                    ),
                ],
                data: structTypeNode([
                    // --- AccountHeader (4 bytes) ---
                    structFieldTypeNode({
                        name: "version",
                        type: numberTypeNode("u8"),
                        defaultValue: numberValueNode(1),
                        defaultValueStrategy: "omitted",
                    }),
                    structFieldTypeNode({
                        name: "scheme",
                        type: numberTypeNode("u8"),
                        defaultValue: numberValueNode(0),
                        defaultValueStrategy: "omitted",
                    }),
                    structFieldTypeNode({
                        name: "reserved",
                        type: fixedSizeTypeNode(bytesTypeNode(), 2),
                        defaultValue: numberValueNode(0),
                        defaultValueStrategy: "omitted",
                    }),
                    // --- RpIdInformation (65 bytes) ---
                    structFieldTypeNode({
                        name: "rpIdLen",
                        type: numberTypeNode("u8"),
                    }),
                    structFieldTypeNode({
                        name: "rpId",
                        type: fixedSizeTypeNode(bytesTypeNode(), 32),
                        docs: ["Relying party ID, padded to 32 bytes"],
                    }),
                    structFieldTypeNode({
                        name: "rpIdHash",
                        type: fixedSizeTypeNode(bytesTypeNode(), 32),
                        docs: ["SHA-256 hash of the relying party ID"],
                    }),
                    // --- CompressedP256PublicKey (33 bytes) ---
                    structFieldTypeNode({
                        name: "publicKeyX",
                        type: fixedSizeTypeNode(bytesTypeNode(), 32),
                        docs: ["X coordinate of the P256 public key"],
                    }),
                    structFieldTypeNode({
                        name: "publicKeyYParity",
                        type: numberTypeNode("u8"),
                        docs: ["Y parity byte (0x02 or 0x03)"],
                    }),
                    // --- Padding (2 bytes) ---
                    structFieldTypeNode({
                        name: "padding",
                        type: fixedSizeTypeNode(bytesTypeNode(), 2),
                        defaultValue: numberValueNode(0),
                        defaultValueStrategy: "omitted",
                    }),
                    // --- SessionKey (40 bytes) ---
                    structFieldTypeNode({
                        name: "sessionKeyPublicKey",
                        type: publicKeyTypeNode(),
                        docs: ["Ed25519 public key of the session key (zeroed if none)"],
                    }),
                    structFieldTypeNode({
                        name: "sessionKeyExpiration",
                        type: numberTypeNode("u64"),
                        docs: ["Unix timestamp when the session key expires"],
                    }),
                    // --- Counter (8 bytes) ---
                    structFieldTypeNode({
                        name: "counter",
                        type: numberTypeNode("u64"),
                        docs: [
                            "WebAuthn signature counter for replay protection.",
                            "Must be monotonically increasing.",
                        ],
                    }),
                ]),
            }),
        ],

        // ====================================================================
        // Instructions
        // ====================================================================
        instructions: [
            // ----------------------------------------------------------------
            // 0 — Initialize External Account
            // ----------------------------------------------------------------
            // Accounts: [externally_signed_account, rent_payer,
            //            instructions_sysvar, slothashes_sysvar,
            //            system_program, ...remaining]
            // Data (borsh): TruncatedSlot(u16), signature_scheme(u8),
            //               initialization_data(SmallVec<u8,u8>),
            //               session_key(Option<SessionKey>)
            instructionNode({
                name: "initializeExternalAccount",
                docs: [
                    "Initializes a new externally-signed account with WebAuthn/P256 credentials.",
                    "A secp256r1 precompile instruction must precede this instruction in the transaction.",
                ],
                optionalAccountStrategy: "omitted",
                accounts: [
                    instructionAccountNode({
                        name: "externallySignedAccount",
                        isSigner: false,
                        isWritable: true,
                        docs: ["The PDA to be created, derived from hash of compressed public key."],
                    }),
                    instructionAccountNode({
                        name: "rentPayer",
                        isSigner: true,
                        isWritable: true,
                        docs: ["The account paying for rent and transaction fees."],
                    }),
                    instructionAccountNode({
                        name: "instructionsSysvar",
                        isSigner: false,
                        isWritable: false,
                        defaultValue: publicKeyValueNode(
                            "Sysvar1nstructions1111111111111111111111111",
                            "splInstructions"
                        ),
                        docs: ["Instructions sysvar for precompile signature introspection."],
                    }),
                    instructionAccountNode({
                        name: "slotHashesSysvar",
                        isSigner: false,
                        isWritable: false,
                        defaultValue: publicKeyValueNode(
                            "SysvarS1otHashes111111111111111111111111111",
                            "splSlotHashes"
                        ),
                        docs: ["SlotHashes sysvar for nonce validation."],
                    }),
                    instructionAccountNode({
                        name: "systemProgram",
                        isSigner: false,
                        isWritable: false,
                        defaultValue: publicKeyValueNode(
                            "11111111111111111111111111111111",
                            "systemProgram"
                        ),
                        docs: ["System Program for account creation."],
                    }),
                ],
                arguments: [
                    instructionArgumentNode({
                        name: "discriminator",
                        type: numberTypeNode("u8"),
                        defaultValue: numberValueNode(0),
                        defaultValueStrategy: "omitted",
                    }),
                    instructionArgumentNode({
                        name: "slothash",
                        type: numberTypeNode("u16"),
                        docs: [
                            "Truncated slot (last 3 digits of slot height, mod 1000).",
                            "Used as nonce — must match a recent slot hash (within 150 slots).",
                        ],
                    }),
                    instructionArgumentNode({
                        name: "signatureScheme",
                        type: definedTypeLinkNode("signatureScheme"),
                        docs: ["The signature scheme (currently only P256Webauthn = 0)."],
                    }),
                    instructionArgumentNode({
                        name: "initializationData",
                        type: sizePrefixTypeNode(
                            bytesTypeNode(),
                            numberTypeNode("u8")
                        ),
                        docs: [
                            "Scheme-specific initialization data as SmallVec<u8, u8>.",
                            "For P256Webauthn: borsh-serialized P256RawInitializationData",
                            "(rp_id: SmallVec<u8,u8>, public_key: [u8;33],",
                            " client_data_json_reconstruction_params: ClientDataJsonReconstructionParams).",
                        ],
                    }),
                    instructionArgumentNode({
                        name: "sessionKey",
                        type: optionTypeNode(
                            definedTypeLinkNode("sessionKey"),
                            { prefix: numberTypeNode("u8") }
                        ),
                        docs: [
                            "Optional session key. If provided, its expiration must not exceed",
                            "3 months from the current Clock timestamp.",
                        ],
                    }),
                ],
                discriminators: [
                    constantDiscriminatorNode(
                        constantValueNode(numberTypeNode("u8"), numberValueNode(0))
                    ),
                ],
            }),

            // ----------------------------------------------------------------
            // 1 — Execute Instructions
            // ----------------------------------------------------------------
            // Accounts: [externally_signed_account, instructions_sysvar,
            //            slothashes_sysvar, nonce_signer,
            //            ...instruction_execution_accounts]
            // Data (borsh): signature_scheme(u8), signer_execution_scheme(u8),
            //               slothash(TruncatedSlot/u16),
            //               extra_verification_data(SmallVec<u8,u8>),
            //               instructions(SmallVec<u8, CompiledInstruction>)
            instructionNode({
                name: "executeInstructions",
                docs: [
                    "Executes a batch of compiled instructions authenticated by a direct P256 signature.",
                    "A secp256r1 precompile instruction must precede this instruction in the transaction.",
                    "Includes reentrancy protection (cannot CPI back to this program).",
                ],
                optionalAccountStrategy: "omitted",
                accounts: [
                    instructionAccountNode({
                        name: "externallySignedAccount",
                        isSigner: false,
                        isWritable: true,
                        docs: ["The externally-signed PDA that authorizes the instructions."],
                    }),
                    instructionAccountNode({
                        name: "instructionsSysvar",
                        isSigner: false,
                        isWritable: false,
                        defaultValue: publicKeyValueNode(
                            "Sysvar1nstructions1111111111111111111111111",
                            "splInstructions"
                        ),
                        docs: ["Instructions sysvar for precompile signature verification."],
                    }),
                    instructionAccountNode({
                        name: "slotHashesSysvar",
                        isSigner: false,
                        isWritable: false,
                        defaultValue: publicKeyValueNode(
                            "SysvarS1otHashes111111111111111111111111111",
                            "splSlotHashes"
                        ),
                        docs: ["SlotHashes sysvar for nonce validation."],
                    }),
                    instructionAccountNode({
                        name: "nonceSigner",
                        isSigner: true,
                        isWritable: false,
                        docs: ["The signer providing the nonce signature for replay protection."],
                    }),
                ],
                arguments: [
                    instructionArgumentNode({
                        name: "discriminator",
                        type: numberTypeNode("u8"),
                        defaultValue: numberValueNode(1),
                        defaultValueStrategy: "omitted",
                    }),
                    instructionArgumentNode({
                        name: "signatureScheme",
                        type: definedTypeLinkNode("signatureScheme"),
                    }),
                    instructionArgumentNode({
                        name: "signerExecutionScheme",
                        type: definedTypeLinkNode("signerExecutionScheme"),
                        docs: [
                            "Determines which account signs CPI calls:",
                            "ExecutionAccount (0) = derived PDA, ExternalAccount (1) = the ESA itself.",
                        ],
                    }),
                    instructionArgumentNode({
                        name: "slothash",
                        type: numberTypeNode("u16"),
                        docs: ["Truncated slot for nonce validation (mod 1000)."],
                    }),
                    instructionArgumentNode({
                        name: "extraVerificationData",
                        type: sizePrefixTypeNode(
                            bytesTypeNode(),
                            numberTypeNode("u8")
                        ),
                        docs: [
                            "Scheme-specific verification data as SmallVec<u8, u8>.",
                            "For P256Webauthn: borsh-serialized P256RawVerificationData",
                            "(public_key: [u8;33], client_data_json_reconstruction_params).",
                        ],
                    }),
                    instructionArgumentNode({
                        name: "instructions",
                        type: arrayTypeNode(
                            definedTypeLinkNode("compiledInstruction"),
                            prefixedCountNode(numberTypeNode("u8"))
                        ),
                        docs: [
                            "SmallVec<u8, CompiledInstruction> — compiled instructions to execute via CPI.",
                            "Account indices reference the remaining accounts.",
                        ],
                    }),
                ],
                discriminators: [
                    constantDiscriminatorNode(
                        constantValueNode(numberTypeNode("u8"), numberValueNode(1))
                    ),
                ],
                remainingAccounts: [
                    instructionRemainingAccountsNode({
                        isOptional: false,
                        isSigner: false,
                        isWritable: false,
                        docs: [
                            "Accounts referenced by the compiled instructions.",
                            "The execution account (derived PDA or ESA itself, based on",
                            "signerExecutionScheme) should be included here when needed.",
                        ],
                    }),
                ],
            }),

            // ----------------------------------------------------------------
            // 2 — Refresh Session Key
            // ----------------------------------------------------------------
            // Accounts: [externally_signed_account, instructions_sysvar,
            //            slothashes_sysvar, nonce_signer, ...remaining]
            // Data (borsh): slothash(u16), signature_scheme(u8),
            //               verification_data(SmallVec<u8,u8>),
            //               session_key(SessionKey)
            instructionNode({
                name: "refreshSessionKey",
                docs: [
                    "Refreshes the session key on an externally-signed account.",
                    "Requires a fresh P256 signature. The new expiration is calculated as",
                    "Clock::unix_timestamp + session_key.expiration (treated as a duration).",
                ],
                optionalAccountStrategy: "omitted",
                accounts: [
                    instructionAccountNode({
                        name: "externallySignedAccount",
                        isSigner: false,
                        isWritable: true,
                        docs: ["The externally-signed PDA whose session key is being refreshed."],
                    }),
                    instructionAccountNode({
                        name: "instructionsSysvar",
                        isSigner: false,
                        isWritable: false,
                        defaultValue: publicKeyValueNode(
                            "Sysvar1nstructions1111111111111111111111111",
                            "splInstructions"
                        ),
                    }),
                    instructionAccountNode({
                        name: "slotHashesSysvar",
                        isSigner: false,
                        isWritable: false,
                        defaultValue: publicKeyValueNode(
                            "SysvarS1otHashes111111111111111111111111111",
                            "splSlotHashes"
                        ),
                    }),
                    instructionAccountNode({
                        name: "nonceSigner",
                        isSigner: true,
                        isWritable: false,
                        docs: ["The signer providing the nonce signature."],
                    }),
                ],
                arguments: [
                    instructionArgumentNode({
                        name: "discriminator",
                        type: numberTypeNode("u8"),
                        defaultValue: numberValueNode(2),
                        defaultValueStrategy: "omitted",
                    }),
                    instructionArgumentNode({
                        name: "slothash",
                        type: numberTypeNode("u16"),
                        docs: ["Truncated slot for nonce validation (mod 1000)."],
                    }),
                    instructionArgumentNode({
                        name: "signatureScheme",
                        type: definedTypeLinkNode("signatureScheme"),
                    }),
                    instructionArgumentNode({
                        name: "verificationData",
                        type: sizePrefixTypeNode(
                            bytesTypeNode(),
                            numberTypeNode("u8")
                        ),
                        docs: [
                            "Scheme-specific verification data as SmallVec<u8, u8>.",
                            "For P256Webauthn: borsh-serialized P256RawVerificationData.",
                        ],
                    }),
                    instructionArgumentNode({
                        name: "sessionKey",
                        type: definedTypeLinkNode("sessionKey"),
                        docs: [
                            "The new session key. The expiration field is treated as a",
                            "duration (seconds) — the program adds it to Clock::unix_timestamp.",
                        ],
                    }),
                ],
                discriminators: [
                    constantDiscriminatorNode(
                        constantValueNode(numberTypeNode("u8"), numberValueNode(2))
                    ),
                ],
            }),

            // ----------------------------------------------------------------
            // 3 — Execute Instructions (Sessioned)
            // ----------------------------------------------------------------
            // Accounts: [externally_signed_account, session_signer,
            //            ...instruction_execution_accounts]
            // Data (borsh): signature_scheme(u8), signer_execution_scheme(u8),
            //               instructions(SmallVec<u8, CompiledInstruction>)
            instructionNode({
                name: "executeInstructionsSessioned",
                docs: [
                    "Executes compiled instructions using an active session key.",
                    "No precompile signature required — the session key signer authorizes execution.",
                    "Validates session key against the account and checks expiration.",
                    "Includes reentrancy protection.",
                ],
                optionalAccountStrategy: "omitted",
                accounts: [
                    instructionAccountNode({
                        name: "externallySignedAccount",
                        isSigner: false,
                        isWritable: true,
                        docs: ["The externally-signed PDA that authorizes the instructions."],
                    }),
                    instructionAccountNode({
                        name: "sessionSigner",
                        isSigner: true,
                        isWritable: false,
                        docs: ["The session key signer — must match the key stored on the account."],
                    }),
                ],
                arguments: [
                    instructionArgumentNode({
                        name: "discriminator",
                        type: numberTypeNode("u8"),
                        defaultValue: numberValueNode(3),
                        defaultValueStrategy: "omitted",
                    }),
                    instructionArgumentNode({
                        name: "signatureScheme",
                        type: definedTypeLinkNode("signatureScheme"),
                    }),
                    instructionArgumentNode({
                        name: "signerExecutionScheme",
                        type: definedTypeLinkNode("signerExecutionScheme"),
                        docs: [
                            "ExecutionAccount (0) = derived PDA signs,",
                            "ExternalAccount (1) = ESA itself signs.",
                        ],
                    }),
                    instructionArgumentNode({
                        name: "instructions",
                        type: arrayTypeNode(
                            definedTypeLinkNode("compiledInstruction"),
                            prefixedCountNode(numberTypeNode("u8"))
                        ),
                        docs: [
                            "SmallVec<u8, CompiledInstruction> — compiled instructions to execute.",
                        ],
                    }),
                ],
                discriminators: [
                    constantDiscriminatorNode(
                        constantValueNode(numberTypeNode("u8"), numberValueNode(3))
                    ),
                ],
                remainingAccounts: [
                    instructionRemainingAccountsNode({
                        isOptional: false,
                        isSigner: false,
                        isWritable: false,
                        docs: ["Accounts referenced by the compiled instructions."],
                    }),
                ],
            }),
        ],

        // ====================================================================
        // Defined Types
        // ====================================================================
        definedTypes: [
            // SignatureScheme enum
            definedTypeNode({
                name: "signatureScheme",
                type: enumTypeNode([
                    enumEmptyVariantTypeNode("p256Webauthn"),
                ]),
                docs: [
                    "The signature verification scheme.",
                    "Currently only P256Webauthn (0) is supported.",
                ],
            }),

            // SignerExecutionScheme enum
            definedTypeNode({
                name: "signerExecutionScheme",
                type: enumTypeNode([
                    enumEmptyVariantTypeNode("executionAccount"),
                    enumEmptyVariantTypeNode("externalAccount"),
                ]),
                docs: [
                    "Determines which account signs CPI calls.",
                    "ExecutionAccount: a derived PDA (ESA key + 'execution_account').",
                    "ExternalAccount: the externally-signed account itself.",
                ],
            }),

            // SessionKey struct (borsh-serialized in instruction data)
            definedTypeNode({
                name: "sessionKey",
                type: structTypeNode([
                    structFieldTypeNode({
                        name: "key",
                        type: publicKeyTypeNode(),
                        docs: ["Ed25519 public key of the session key."],
                    }),
                    structFieldTypeNode({
                        name: "expiration",
                        type: numberTypeNode("u64"),
                        docs: [
                            "For initialization/refresh: duration in seconds to add to current timestamp.",
                            "On-chain: absolute unix timestamp of expiration.",
                            "Max 3 months (7,776,000 seconds) from current time.",
                        ],
                    }),
                ]),
                docs: ["An ephemeral session key with an expiration."],
            }),

            // CompiledInstruction struct (borsh-serialized)
            definedTypeNode({
                name: "compiledInstruction",
                type: structTypeNode([
                    structFieldTypeNode({
                        name: "programIdIndex",
                        type: numberTypeNode("u8"),
                        docs: ["Index into the remaining accounts for the program to invoke."],
                    }),
                    structFieldTypeNode({
                        name: "accountsIndices",
                        type: arrayTypeNode(
                            numberTypeNode("u8"),
                            prefixedCountNode(numberTypeNode("u8"))
                        ),
                        docs: [
                            "SmallVec<u8, u8> — indices into remaining accounts for this instruction.",
                        ],
                    }),
                    structFieldTypeNode({
                        name: "data",
                        type: arrayTypeNode(
                            numberTypeNode("u8"),
                            prefixedCountNode(numberTypeNode("u16"))
                        ),
                        docs: [
                            "SmallVec<u16, u8> — the instruction data (u16 length prefix).",
                        ],
                    }),
                ]),
                docs: [
                    "A compiled instruction that references accounts by index into the",
                    "remaining accounts array. Uses SmallVec (u8/u16 length prefixes).",
                ],
            }),

            // ClientDataJsonReconstructionParams
            definedTypeNode({
                name: "clientDataJsonReconstructionParams",
                type: structTypeNode([
                    structFieldTypeNode({
                        name: "typeAndFlags",
                        type: numberTypeNode("u8"),
                        docs: [
                            "Packed byte: high nibble = auth type (0x00=create, 0x10=get),",
                            "low nibble = flags (0x01=crossOrigin, 0x02=http, 0x04=googleExtra).",
                        ],
                    }),
                    structFieldTypeNode({
                        name: "port",
                        type: optionTypeNode(
                            numberTypeNode("u16"),
                            { prefix: numberTypeNode("u8") }
                        ),
                        docs: ["Optional port number for the origin URL."],
                    }),
                ]),
                docs: [
                    "Minimal representation for reconstructing the WebAuthn clientDataJSON.",
                    "Used in both initialization and verification data.",
                ],
            }),

            // P256RawInitializationData — what goes inside initializationData bytes
            definedTypeNode({
                name: "p256RawInitializationData",
                type: structTypeNode([
                    structFieldTypeNode({
                        name: "rpId",
                        type: arrayTypeNode(
                            numberTypeNode("u8"),
                            prefixedCountNode(numberTypeNode("u8"))
                        ),
                        docs: [
                            "SmallVec<u8, u8> — relying party ID (max 32 bytes, no quote chars).",
                        ],
                    }),
                    structFieldTypeNode({
                        name: "publicKey",
                        type: fixedSizeTypeNode(bytesTypeNode(), 33),
                        docs: [
                            "Compressed P256 public key: [y_parity(1) | x(32)].",
                        ],
                    }),
                    structFieldTypeNode({
                        name: "clientDataJsonReconstructionParams",
                        type: definedTypeLinkNode("clientDataJsonReconstructionParams"),
                    }),
                ]),
                docs: [
                    "P256 WebAuthn initialization data.",
                    "Borsh-serialized inside the initializationData SmallVec bytes.",
                ],
            }),

            // P256RawVerificationData — what goes inside extraVerificationData bytes
            definedTypeNode({
                name: "p256RawVerificationData",
                type: structTypeNode([
                    structFieldTypeNode({
                        name: "publicKey",
                        type: fixedSizeTypeNode(bytesTypeNode(), 33),
                        docs: ["Compressed P256 public key: [y_parity(1) | x(32)]."],
                    }),
                    structFieldTypeNode({
                        name: "clientDataJsonReconstructionParams",
                        type: definedTypeLinkNode("clientDataJsonReconstructionParams"),
                    }),
                ]),
                docs: [
                    "P256 WebAuthn verification data.",
                    "Borsh-serialized inside the extraVerificationData / verificationData SmallVec bytes.",
                ],
            }),
        ],

        // ====================================================================
        // Errors
        // ====================================================================
        errors: [
            // Nonce errors (0-4)
            errorNode({ name: "invalidSlothashIndex", code: 0, message: "Invalid slothash index" }),
            errorNode({ name: "invalidTruncatedSlot", code: 1, message: "Invalid truncated slot" }),
            errorNode({ name: "expiredSlothash", code: 2, message: "Expired slothash" }),
            errorNode({ name: "missingNonceSignature", code: 3, message: "Missing nonce signature" }),
            errorNode({ name: "cpiNotAllowed", code: 4, message: "CPI not allowed" }),

            // Introspection errors (5-9)
            errorNode({ name: "invalidInstructionSysvarAccount", code: 5, message: "Invalid instruction sysvar account" }),
            errorNode({ name: "invalidPrecompileId", code: 6, message: "Invalid precompile id" }),
            errorNode({ name: "invalidNumPrecompileSignatures", code: 7, message: "Invalid number of precompile signatures" }),
            errorNode({ name: "invalidSignatureIndex", code: 8, message: "Invalid signature index" }),
            errorNode({ name: "invalidSignatureOffset", code: 9, message: "Invalid signature offset" }),

            // Serialization errors (10-13)
            errorNode({ name: "errorInitializingHeader", code: 10, message: "Error initializing header" }),
            errorNode({ name: "errorDeserializingHeader", code: 11, message: "Error deserializing header" }),
            errorNode({ name: "errorInitializingAccountData", code: 12, message: "Error initializing account data" }),
            errorNode({ name: "errorDeserializingAccountData", code: 13, message: "Error deserializing account data" }),

            // Execution errors (14-19)
            errorNode({ name: "invalidExtraVerificationDataArgs", code: 14, message: "Invalid extra verification data args" }),
            errorNode({ name: "invalidExecutionArgs", code: 15, message: "Invalid execution args" }),
            errorNode({ name: "sessionSignerNotASigner", code: 16, message: "Session signer is not a signer" }),
            errorNode({ name: "invalidSessionKey", code: 17, message: "Invalid session key" }),
            errorNode({ name: "sessionKeyExpired", code: 18, message: "Session key expired" }),
            errorNode({ name: "invalidSessionKeyExpiration", code: 19, message: "Invalid session key expiration" }),

            // Signature scheme errors (20)
            errorNode({ name: "invalidSignatureScheme", code: 20, message: "Invalid signature scheme" }),

            // Signer execution errors (21-22)
            errorNode({ name: "invalidSignerExecutionScheme", code: 21, message: "Invalid signer execution scheme" }),
            errorNode({ name: "signerExecutionAccountNotASigner", code: 22, message: "Signer execution account is not a signer" }),

            // P256 WebAuthn errors (23-31)
            errorNode({ name: "p256RelyingPartTooLong", code: 23, message: "Relying party ID too long. Max length is 32 bytes" }),
            errorNode({ name: "p256RelyingPartIncludeQuotes", code: 24, message: "Relying party does not get to include quotes" }),
            errorNode({ name: "p256RelyingPartyMismatch", code: 25, message: "Relying party mismatch" }),
            errorNode({ name: "p256ClientDataHashMismatch", code: 26, message: "Client data hash mismatch" }),
            errorNode({ name: "p256AccountNotWritable", code: 27, message: "Account is not writable" }),
            errorNode({ name: "p256InvalidAlgorithm", code: 28, message: "Invalid passkey Algorithm" }),
            errorNode({ name: "p256InvalidPublicKeyEncoding", code: 29, message: "Invalid public key encoding" }),
            errorNode({ name: "p256PublicKeyMismatch", code: 30, message: "Public key mismatch" }),
            errorNode({ name: "p256UserNotVerified", code: 31, message: "User not verified" }),
            errorNode({ name: "p256UserNotPresent", code: 32, message: "User not present" }),
        ],

        // ====================================================================
        // PDAs
        // ====================================================================
        pdas: [
            pdaNode({
                name: "externallySignedAccount",
                seeds: [
                    constantPdaSeedNodeFromString("utf8", "passkey"),
                    variablePdaSeedNode(
                        "hashedPublicKey",
                        fixedSizeTypeNode(bytesTypeNode(), 32),
                        [
                            "SHA-256 hash of the compressed P256 public key (33 bytes -> 32 bytes).",
                            "Hash is required because PDA seeds are limited to 32 bytes each.",
                        ]
                    ),
                ],
            }),
            pdaNode({
                name: "executionAccount",
                seeds: [
                    variablePdaSeedNode(
                        "externallySignedAccountKey",
                        publicKeyTypeNode(),
                        ["The public key of the parent externally-signed account."]
                    ),
                    constantPdaSeedNodeFromString("utf8", "execution_account"),
                ],
            }),
        ],
    })
);

// ============================================================================
// Export / Write IDL
// ============================================================================
const codama = createFromRoot(root);

// Write the IDL JSON to disk for reference
const idlJson = JSON.stringify(root, null, 2);
const outputPath = path.join(__dirname, "..", "idl.json");
fs.writeFileSync(outputPath, idlJson);
console.log(`Codama IDL written to ${outputPath}`);

// Export for programmatic use
export { root, codama };
