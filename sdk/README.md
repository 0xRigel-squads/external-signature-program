# External Signature Program - Rust SDK

A Rust SDK for building instructions to interact with the External Signature Program, which enables passkey-based authentication on Solana.

## Features

- **PDA Derivation**: Helper functions to derive passkey accounts and execution accounts
- **Instruction Builders**: Easy-to-use builders for all program instructions
  - Initialize passkey accounts
  - Execute instructions with passkey authentication
  - Refresh session keys
  - Create secp256r1 precompile verification instructions

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
external-signature-sdk = { path = "./sdk" }
```

## Usage

### Deriving PDAs

```rust
use external_signature_sdk::pda::{derive_passkey_account, derive_execution_account};

// Derive passkey account from compressed public key (33 bytes)
let (passkey_account, bump) = derive_passkey_account(&public_key)?;

// Derive execution account from passkey account
let (execution_account, bump) = derive_execution_account(&passkey_account)?;
```

### Initialize a Passkey Account

```rust
use external_signature_sdk::{
    instructions::initialize_passkey_account,
    types::WebAuthnData,
};

let webauthn_data = WebAuthnData {
    public_key: compressed_public_key, // 33 bytes
    signature: signature_bytes,
    auth_data: authenticator_data,
    client_data_json: client_data,
    client_data_json_reconstruction_params: params,
};

let rp_id = b"www.example.com";
let slot_hash = get_slot_hash();

let (passkey_account, init_ix) = initialize_passkey_account(
    &webauthn_data,
    rp_id,
    &payer,
    slot_hash,
)?;

// Create precompile verification instruction
let precompile_ix = create_secp256r1_instruction(
    &signature,
    &message,
    &uncompressed_public_key, // 64 bytes for precompile
    None,
)?;

// Send transaction with [precompile_ix, init_ix]
```

### Execute Instructions

```rust
use external_signature_sdk::instructions::execute_instructions;

let instructions = vec![
    // Your instructions here
    memo_instruction,
    transfer_instruction,
];

let additional_accounts = vec![
    // Additional account metas required by your instructions
];

let execute_ix = execute_instructions(
    &webauthn_data,
    &passkey_account,
    &payer,
    slot_hash,
    instructions,
    additional_accounts,
)?;

// Send transaction with [precompile_ix, execute_ix]
```

### Refresh Session Key

```rust
use external_signature_sdk::instructions::refresh_session_key;
use external_signature_program::state::SessionKey;

let session_key = SessionKey {
    key: session_pubkey.to_bytes(),
    expiration: 900, // seconds
};

let refresh_ix = refresh_session_key(
    &webauthn_data,
    &passkey_account,
    &payer,
    slot_hash,
    session_key,
)?;

// Send transaction with [precompile_ix, refresh_ix]
```

## Important Notes

### Public Key Formats

- **Compressed keys (33 bytes)**: Used for account initialization and verification data
  - Format: `[parity_byte (1 byte)] + [x_coordinate (32 bytes)]`
- **Uncompressed keys (64 bytes)**: Used for secp256r1 precompile instruction
  - Format: `[x_coordinate (32 bytes)] + [y_coordinate (32 bytes)]`

### Instruction Order

Always include the secp256r1 precompile verification instruction **before** any instruction that requires signature verification in the same transaction.

## Modules

- `error`: SDK error types
- `instructions`: Instruction builders for all program operations
- `pda`: PDA derivation helpers
- `types`: Common types used throughout the SDK

## License

MIT
