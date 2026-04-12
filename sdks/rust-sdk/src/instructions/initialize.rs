use crate::{pda::derive_passkey_account, types::WebAuthnData, Result, SdkError, PROGRAM_ID};
use borsh::to_vec;
use external_signature_program::{
    instructions::initialize_external_account::InitializeAccountArgs,
    state::{P256RawInitializationData, SignatureScheme},
    utils::{nonce::TruncatedSlot, SmallVec, SLOT_HASHES_ID},
};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program::ID as SYSTEM_PROGRAM_ID,
};
use std::str::FromStr;

/// Builds an initialize passkey account instruction
///
/// # Arguments
/// * `webauthn_data` - The WebAuthn credential data
/// * `rp_id` - Relying party identifier (e.g., "www.example.com")
/// * `payer` - The account that will pay for the account creation
/// * `slot_hash` - Current slot hash for replay protection
///
/// # Returns
/// Tuple of (passkey_account_pubkey, instruction)
pub fn initialize_passkey_account(
    webauthn_data: &WebAuthnData,
    rp_id: &[u8],
    payer: &Pubkey,
    slot_hash: TruncatedSlot,
) -> Result<(Pubkey, Instruction)> {
    // Derive the passkey account PDA
    let (account_to_initialize, _bump) = derive_passkey_account(&webauthn_data.public_key)?;

    // Construct the P256 initialization data
    let p256_webauthn_args = P256RawInitializationData {
        rp_id: SmallVec::<u8, u8>::try_from(rp_id.to_vec())
            .map_err(|_| SdkError::InvalidRpId("RP ID too long".to_string()))?,
        public_key: webauthn_data.public_key,
        client_data_json_reconstruction_params: webauthn_data
            .client_data_json_reconstruction_params
            .clone()
            .into(),
    };

    let initialize_args = InitializeAccountArgs {
        slothash: slot_hash,
        signature_scheme: SignatureScheme::P256Webauthn.into(),
        initialization_data: SmallVec::<u8, u8>::try_from(to_vec(&p256_webauthn_args)?).map_err(
            |_| SdkError::SerializationError("Initialization data too large".to_string()),
        )?,
        session_key: None,
    };

    // Build instruction data
    let mut instruction_data = vec![0]; // discriminator
    instruction_data.extend_from_slice(&to_vec(&initialize_args)?);

    // Build the instruction
    let instruction = Instruction {
        program_id: Pubkey::new_from_array(PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(account_to_initialize, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(
                Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap(),
                false,
            ),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    };

    Ok((account_to_initialize, instruction))
}

/// Builds an initialize passkey account instruction with a session key
///
/// # Arguments
/// * `webauthn_data` - The WebAuthn credential data
/// * `rp_id` - Relying party identifier (e.g., "www.example.com")
/// * `payer` - The account that will pay for the account creation
/// * `slot_hash` - Current slot hash for replay protection
/// * `session_key` - Session key configuration
///
/// # Returns
/// Tuple of (passkey_account_pubkey, instruction)
pub fn initialize_passkey_account_with_session(
    webauthn_data: &WebAuthnData,
    rp_id: &[u8],
    payer: &Pubkey,
    slot_hash: TruncatedSlot,
    session_key: external_signature_program::state::SessionKey,
) -> Result<(Pubkey, Instruction)> {
    // Derive the passkey account PDA
    let (account_to_initialize, _bump) = derive_passkey_account(&webauthn_data.public_key)?;

    // Construct the P256 initialization data
    let p256_webauthn_args = P256RawInitializationData {
        rp_id: SmallVec::<u8, u8>::try_from(rp_id.to_vec())
            .map_err(|_| SdkError::InvalidRpId("RP ID too long".to_string()))?,
        public_key: webauthn_data.public_key,
        client_data_json_reconstruction_params: webauthn_data
            .client_data_json_reconstruction_params
            .clone()
            .into(),
    };

    let initialize_args = InitializeAccountArgs {
        slothash: slot_hash,
        signature_scheme: SignatureScheme::P256Webauthn.into(),
        initialization_data: SmallVec::<u8, u8>::try_from(to_vec(&p256_webauthn_args)?).map_err(
            |_| SdkError::SerializationError("Initialization data too large".to_string()),
        )?,
        session_key: Some(session_key),
    };

    // Build instruction data
    let mut instruction_data = vec![0]; // discriminator
    instruction_data.extend_from_slice(&to_vec(&initialize_args)?);

    // Build the instruction
    let instruction = Instruction {
        program_id: Pubkey::new_from_array(PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(account_to_initialize, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(
                Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap(),
                false,
            ),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: instruction_data,
    };

    Ok((account_to_initialize, instruction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthType;

    #[test]
    fn test_initialize_passkey_account() {
        use crate::TruncatedSlot;

        let webauthn_data = WebAuthnData::new(
            [1u8; 33],
            vec![0u8; 64],
            vec![0u8; 37],
            vec![],
            AuthType::Create,
            false,
            false,
            false,
            None,
        );

        let rp_id = b"example.com";
        let payer = Pubkey::new_unique();
        let slot_hash = TruncatedSlot(0);

        let result = initialize_passkey_account(&webauthn_data, rp_id, &payer, slot_hash);
        assert!(result.is_ok());
    }
}
