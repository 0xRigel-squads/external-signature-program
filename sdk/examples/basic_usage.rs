use external_signature_sdk::{
    instructions::{
        create_secp256r1_instruction, execute_instructions, initialize_passkey_account,
        refresh_session_key,
    },
    pda::{derive_execution_account, derive_passkey_account},
    types::{AuthType, WebAuthnData},
    TruncatedSlot,
};
use external_signature_program::state::SessionKey;
use solana_program::instruction::Instruction;
use solana_pubkey::Pubkey;

fn main() {
    println!("External Signature Program SDK Examples");
    println!("========================================\n");

    // Example 1: Derive passkey account PDA
    println!("Example 1: Derive Passkey Account PDA");
    let compressed_public_key = [0x02u8; 33]; // Example compressed public key
    let (passkey_account, bump) = derive_passkey_account(&compressed_public_key).unwrap();
    println!("  Passkey Account: {}", passkey_account);
    println!("  Bump: {}\n", bump);

    // Example 2: Derive execution account PDA
    println!("Example 2: Derive Execution Account PDA");
    let (execution_account, bump) = derive_execution_account(&passkey_account).unwrap();
    println!("  Execution Account: {}", execution_account);
    println!("  Bump: {}\n", bump);

    // Example 3: Initialize a passkey account
    println!("Example 3: Initialize Passkey Account");
    let webauthn_data = WebAuthnData::new(
        compressed_public_key,
        vec![0u8; 64], // signature
        vec![0u8; 37], // auth_data
        vec![],        // client_data_json
        AuthType::Create,
        false, // cross_origin
        false, // is_http
        false, // has_google_extra
        None,  // port
    );

    let rp_id = b"example.com";
    let payer = Pubkey::new_unique();
    let slot_hash = TruncatedSlot(0);

    let (account_pubkey, init_ix) =
        initialize_passkey_account(&webauthn_data, rp_id, &payer, slot_hash).unwrap();

    println!("  Account to initialize: {}", account_pubkey);
    println!("  Instruction data length: {} bytes", init_ix.data.len());
    println!("  Number of accounts: {}\n", init_ix.accounts.len());

    // Example 4: Create secp256r1 precompile instruction
    println!("Example 4: Create Secp256r1 Precompile Instruction");
    let uncompressed_public_key = [0x04u8; 64]; // Uncompressed public key for precompile
    let signature = [0u8; 64];
    let message = b"example message to verify";

    let precompile_ix =
        create_secp256r1_instruction(&signature, message, &uncompressed_public_key, None).unwrap();

    println!("  Precompile instruction created");
    println!("  Instruction data length: {} bytes\n", precompile_ix.data.len());

    // Example 5: Execute instructions
    println!("Example 5: Execute Instructions with Passkey");
    let memo_ix = Instruction {
        program_id: Pubkey::new_unique(),
        accounts: vec![],
        data: b"Hello from passkey!".to_vec(),
    };

    let execute_ix = execute_instructions(
        &webauthn_data,
        &passkey_account,
        &payer,
        slot_hash,
        vec![memo_ix],
        vec![],
    )
    .unwrap();

    println!("  Execute instruction created");
    println!("  Instruction data length: {} bytes", execute_ix.data.len());
    println!("  Number of accounts: {}\n", execute_ix.accounts.len());

    // Example 6: Refresh session key
    println!("Example 6: Refresh Session Key");
    let session_key = SessionKey {
        key: Pubkey::new_unique().to_bytes(),
        expiration: 900, // 15 minutes
    };

    let refresh_ix =
        refresh_session_key(&webauthn_data, &passkey_account, &payer, slot_hash, session_key)
            .unwrap();

    println!("  Refresh session key instruction created");
    println!("  Instruction data length: {} bytes", refresh_ix.data.len());
    println!("  Number of accounts: {}", refresh_ix.accounts.len());
}
