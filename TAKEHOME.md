# Protocol Engineer Take-Home Assignment

## Overview

Welcome! This take-home assignment is designed to assess your ability to work with Solana programs and implement cryptographic signature schemes. The goal is to implement a native secp256r1 signature scheme within the existing external signature program.

**Time Expectation:** 4-6 hours. This may be an ambitious scope - it's perfectly acceptable to submit after 4-6 hours regardless of completion state. Document what you accomplished and what remains.

## Background

This program currently supports P256 WebAuthn signatures (passkeys), which use the secp256r1 curve with WebAuthn attestation data. Your task is to implement a simpler, native secp256r1 signature scheme that leverages the same Solana secp256r1 precompile but without the WebAuthn overhead.

Both schemes share the same underlying elliptic curve (secp256r1/P-256) and use the same precompile (`Secp256r1SigVerify1111111111111111111111111`), making this an ideal complementary signature scheme.

## Objectives

### Primary Goal
Implement a native secp256r1 signature scheme that:
1. Uses the existing secp256r1 precompile (already used by P256 WebAuthn)
2. Follows the program's architectural patterns and trait implementations
3. Leverages zerocopy serialization/deserialization (bytemuck) for efficient on-chain data handling
4. Integrates with the existing instruction handlers

### Testing Requirement
Your implementation must include **at minimum**:
- One passing unit test demonstrating successful signature verification
- One failing unit test demonstrating proper error handling

Use the same testing framework and patterns found in `tests/p256/`.

### Documentation Requirement
Document any challenges, design decisions, or potential issues encountered during implementation, along with proposed solutions.

## Getting Started

### Prerequisites
- Rust toolchain with Solana tooling installed
- Familiarity with Solana program development
- Understanding of ECDSA signatures and secp256r1 curve

### Building and Testing
```bash
# Build the program
cargo build-sbf

# Run tests
cargo test-sbf

```

## Architecture Overview

### Key Files to Understand

1. **Signature Schemes Enum** (`src/state/externally_signed_account/schemes.rs`)
   - Defines available signature schemes

2. **Trait Definition** (`src/state/externally_signed_account/traits.rs`)
   - `ExternallySignedAccountData` trait that all schemes must implement
   - Core interface for signature verification and account management

3. **P256 WebAuthn Implementation** (Reference)
   - `src/state/p256_webauthn/` - Full implementation to use as reference
   - `src/state/p256_webauthn/trait_impl.rs` - Main trait implementation
   - Shows how to use the secp256r1 precompile

4. **Precompile Utilities** (`src/utils/precompiles.rs`)
   - `Secp256r1Precompile` - Already implemented and ready to use
   - `PrecompileParser` - Helper for parsing precompile instruction data
   - `SignatureOffsets` - Zerocopy struct for signature location data

5. **Test Framework** (`tests/p256/`)
   - Existing test patterns and utilities
   - Use as reference for your own tests

### Core Requirements

Your implementation must:
- Use **zerocopy serialization** via `bytemuck` (Pod + Zeroable traits)
- Use **fixed-size structs** for on-chain storage
- Use **compressed public keys** (33 bytes format)
- Follow existing patterns for PDA derivation and session key management
- Handle proper memory alignment and padding

## Implementation Approach

You'll need to:

1. **Design your account data structure** - What fields are necessary? How should they be laid out in memory?

2. **Implement the trait** - The `ExternallySignedAccountData` trait defines the interface. Study how P256 WebAuthn implements it.

3. **Wire it into the program** - Update enums, instruction handlers, and any other integration points.

4. **Write tests** - At minimum one passing and one failing test using the patterns in `tests/p256/`.

The P256 WebAuthn implementation serves as your primary reference. Study how it:
- Structures account data
- Implements trait methods
- Uses the precompile
- Derives PDAs
- Handles session keys

## Evaluation Criteria

We'll evaluate your submission based on correctness of the implementation, code quality and adherence to existing patterns, quality of tests, and clarity of communication in your documentation about design decisions and challenges encountered.

## Deliverables

1. **Implementation** (as much as completed in 4-6 hours)
   - Source files for your secp256r1 scheme
   - Integration points (enums, instruction handlers, etc.)
   - At minimum: one passing test and one failing test

2. **Documentation** (IMPORTANT)
   - A `NOTES.md` file documenting:
     - What you accomplished
     - What remains incomplete (if applicable)
     - Design decisions you made and why
     - Challenges or issues encountered
     - Solutions or workarounds implemented
     - Any assumptions you made
     - What you would do differently with more time

## Resources

- **P256 WebAuthn implementation** (`src/state/p256_webauthn/`) - Your primary reference
- **Trait definition** (`src/state/externally_signed_account/traits.rs`) - The interface to implement
- **Precompile utilities** (`src/utils/precompiles.rs`) - Ready-to-use helpers
- **Test framework** (`tests/p256/`) - Patterns for your own tests
- **Documentation** (`docs/`) - Additional context on the program

## Submission

Please submit:
1. Your implementation (source code at whatever completion state)
2. `NOTES.md` with your documentation and reflections
3. Test output (even if tests don't fully pass)

**Remember:** It's perfectly acceptable to submit an incomplete implementation after 4-6 hours. We're interested in your thought process, problem-solving approach, and ability to work with existing codebases as much as the final result.

Good luck! We're excited to see your approach.
