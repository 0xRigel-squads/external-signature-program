use std::fs;

use borsh::to_vec;
use external_signature_program::{
    instructions::initialize_external_account::InitializeAccountArgs,
    state::{P256NativeRawInitializationData, P256RawInitializationData, SignatureScheme},
    utils::{nonce::TruncatedSlot, SmallVec, SLOT_HASHES_ID},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use pinocchio::sysvars::instructions::INSTRUCTIONS_ID;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program::ID as SYSTEM_PROGRAM_ID,
};

use crate::p256::utils::{
    parser::parse_webauthn_fixture, secp256r1_instruction::new_secp256r1_instruction,
};

/// Returns a tuple containing:
/// 1. The pubkey of the initialized account
/// 2. A vector of instructions (precompile verification, transfer, and initialization)
pub fn initialize_passkey_account(
    fixture_path: &str,
    payer: &Pubkey,
    slot_num: &TruncatedSlot,
    program_id: &Pubkey,
) -> Result<(Pubkey, Vec<u8>, Vec<Instruction>), Box<dyn std::error::Error>> {
    // Read and parse the WebAuthn fixture
    let json_data = fs::read_to_string(fixture_path)?;
    let webauthn_data = parse_webauthn_fixture(&json_data)?;

    // println!("WebAuthn data: {:#?}", webauthn_data);
    // println!("Client data json: {:#?}", general_purpose::URL_SAFE_NO_PAD.encode(&webauthn_data.client_data_json));
    // println!("Auth data: {:#?}", general_purpose::URL_SAFE_NO_PAD.encode(&webauthn_data.auth_data));
    // println!("Signature: {:#?}", general_purpose::URL_SAFE_NO_PAD.encode(&webauthn_data.signature));
    // println!("Sig Length: {:#?}", webauthn_data.signature.len());
    // Prepare message for secp256r1 verification
    let mut message = webauthn_data.auth_data.clone();
    let client_data_hash = solana_nostd_sha256::hashv(&[&webauthn_data.client_data_json]);
    message.extend_from_slice(&client_data_hash);

    // Get the public key from the fixture data
    let public_key = webauthn_data.public_key.unwrap();
    println!("public key lengthg {}", public_key.len());
    // Create secp256r1 verification instruction
    let precompile_ix =
        new_secp256r1_instruction(&webauthn_data.signature, &message, &public_key, None)?;

    // Calculate public key hash
    let public_key_hash = solana_nostd_sha256::hashv(&[&public_key]);

    // RP ID for the passkey (relay party identifier)
    let rp_id = b"www.passkeys-debugger.io";

    // Define the seeds for the passkey account
    let seeds: [&[u8]; 2] = [b"passkey", public_key_hash.as_slice()];

    // Find the program-derived address for the account
    let (account_to_initialize, _account_bump) =
        Pubkey::try_find_program_address(&seeds, program_id).unwrap();

    // Construct the initialization instruction data
    let p256_webauthn_args = P256RawInitializationData {
        rp_id: SmallVec::<u8, u8>::try_from(rp_id.to_vec()).unwrap(),
        public_key: public_key.as_slice().try_into().unwrap(),
        client_data_json_reconstruction_params: webauthn_data
            .client_data_json_reconstruction_params
            .into(),
    };

    let initialize_args = InitializeAccountArgs {
        slothash: slot_num.clone(),
        signature_scheme: SignatureScheme::P256Webauthn.into(),
        initialization_data: SmallVec::<u8, u8>::try_from(to_vec(&p256_webauthn_args).unwrap())
            .unwrap(),
        session_key: None,
    };

    let mut instruction_data = Vec::with_capacity(1 + 1 + public_key.len() + 1 + rp_id.len());
    instruction_data.push(0); // instruction discriminator
    instruction_data.extend_from_slice(&to_vec(&initialize_args).unwrap());

    // Create the account initialization instruction
    let initialize_account_ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(account_to_initialize, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(Pubkey::new_from_array(INSTRUCTIONS_ID), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    };

    // Combine all instructions into a Vec
    let instructions = vec![precompile_ix, initialize_account_ix];

    Ok((account_to_initialize, public_key, instructions))
}

/// Returns a tuple containing:
/// 1. The pubkey of the initialized account
/// 2. A vector of instructions (precompile verification, transfer, and initialization)
pub fn initialize_native_account(
    p256_keypair: &SigningKey,
    p256_signature: &Signature,
    message: &[u8],
    payer: &Pubkey,
    slot_num: &TruncatedSlot,
    program_id: &Pubkey,
) -> Result<(Pubkey, Vec<u8>, Vec<Instruction>), Box<dyn std::error::Error>> {
    // Prepare message for secp256r1 verification
    let p256_public_key = VerifyingKey::from(p256_keypair)
        .to_encoded_point(true)
        .to_bytes();

    let der_signature = p256_signature.to_der();

    let precompile_ix =
        new_secp256r1_instruction(der_signature.as_bytes(), message, &p256_public_key, None)
            .unwrap();

    // Calculate public key hash
    let public_key_hash = solana_nostd_sha256::hashv(&[&p256_public_key]);

    let seeds: [&[u8]; 2] = [b"native", public_key_hash.as_slice()];

    // Find the program-derived address for the account
    let (account_to_initialize, _account_bump) =
        Pubkey::try_find_program_address(&seeds, program_id)
            .expect("failed to find program address");

    println!("found pubkey address");
    let sized_pubkey_bytes = {
        let tmp = p256_public_key.clone().into_vec();
        let tmp: [u8; 33] = tmp.try_into().expect("failed to convert vec into array");
        tmp
    };

    // Construct the initialization instruction data
    let p256_args = P256NativeRawInitializationData {
        public_key: sized_pubkey_bytes,
    };

    let initialize_args = InitializeAccountArgs {
        slothash: slot_num.clone(),
        signature_scheme: SignatureScheme::P256Native.into(),
        initialization_data: SmallVec::<u8, u8>::try_from(
            to_vec(&p256_args).expect("failed to convert args to vec"),
        )
        .expect("failed to create smallvec from args"),
        session_key: None,
    };

    let mut instruction_data = Vec::new();
    instruction_data.push(0); // instruction discriminator
    instruction_data.extend_from_slice(&to_vec(&initialize_args).expect("failed to extend slice"));

    // // Create the account initialization instruction
    let initialize_account_ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(account_to_initialize, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(Pubkey::new_from_array(INSTRUCTIONS_ID), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    };

    let instructions = vec![precompile_ix, initialize_account_ix];

    Ok((account_to_initialize, p256_public_key.into(), instructions))
}

/// Returns a tuple containing:
/// 1. The pubkey of the initialized account
/// 2. A vector of instructions (precompile verification, transfer, and initialization)
pub fn initialize_multiple_native_accounts(
    keypairs: &[&SigningKey],
    signatures: &[&Signature],
    message: &[u8],
    payer: &Pubkey,
    slot_num: &TruncatedSlot,
    program_id: &Pubkey,
) -> Result<(Pubkey, Vec<u8>, Vec<Instruction>), Box<dyn std::error::Error>> {
    // Prepare message for secp256r1 verification
    let p256_public_key = VerifyingKey::from(p256_keypair)
        .to_encoded_point(true)
        .to_bytes();

    let der_signature = p256_signature.to_der();

    let precompile_ix =
        new_secp256r1_instruction(der_signature.as_bytes(), message, &p256_public_key, None)
            .unwrap();

    // Calculate public key hash
    let public_key_hash = solana_nostd_sha256::hashv(&[&p256_public_key]);

    let seeds: [&[u8]; 2] = [b"native", public_key_hash.as_slice()];

    // Find the program-derived address for the account
    let (account_to_initialize, _account_bump) =
        Pubkey::try_find_program_address(&seeds, program_id)
            .expect("failed to find program address");

    println!("found pubkey address");
    let sized_pubkey_bytes = {
        let tmp = p256_public_key.clone().into_vec();
        let tmp: [u8; 33] = tmp.try_into().expect("failed to convert vec into array");
        tmp
    };

    // Construct the initialization instruction data
    let p256_args = P256NativeRawInitializationData {
        public_key: sized_pubkey_bytes,
    };

    let initialize_args = InitializeAccountArgs {
        slothash: slot_num.clone(),
        signature_scheme: SignatureScheme::P256Native.into(),
        initialization_data: SmallVec::<u8, u8>::try_from(
            to_vec(&p256_args).expect("failed to convert args to vec"),
        )
        .expect("failed to create smallvec from args"),
        session_key: None,
    };

    let mut instruction_data = Vec::new();
    instruction_data.push(0); // instruction discriminator
    instruction_data.extend_from_slice(&to_vec(&initialize_args).expect("failed to extend slice"));

    // // Create the account initialization instruction
    let initialize_account_ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(account_to_initialize, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(Pubkey::new_from_array(INSTRUCTIONS_ID), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    };

    let instructions = vec![precompile_ix, initialize_account_ix];

    Ok((account_to_initialize, p256_public_key.into(), instructions))
}
