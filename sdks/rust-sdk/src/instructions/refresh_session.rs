use crate::{types::WebAuthnData, Result, SdkError, PROGRAM_ID};
use borsh::to_vec;
use external_signature_program::{
    instructions::refresh_session_key::RefreshSessionKeyArgs,
    state::{P256RawVerificationData, SessionKey},
    utils::{nonce::TruncatedSlot, SmallVec, SLOT_HASHES_ID},
};
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::str::FromStr;

/// Builds a refresh session key instruction
///
/// # Arguments
/// * `webauthn_data` - The WebAuthn authentication data
/// * `passkey_account` - The passkey account to update
/// * `payer` - The transaction fee payer
/// * `slot_hash` - Current slot hash for replay protection
/// * `session_key` - New session key configuration
///
/// # Returns
/// The refresh session key instruction
pub fn refresh_session_key(
    webauthn_data: &WebAuthnData,
    passkey_account: &Pubkey,
    payer: &Pubkey,
    slot_hash: TruncatedSlot,
    session_key: SessionKey,
) -> Result<Instruction> {
    // Prepare verification data
    let verification_data = P256RawVerificationData {
        public_key: webauthn_data.public_key,
        client_data_json_reconstruction_params: webauthn_data
            .client_data_json_reconstruction_params
            .clone(),
    };

    // Build instruction arguments
    let external_sig_ix_data = RefreshSessionKeyArgs {
        signature_scheme: 0, // P256Webauthn
        verification_data: SmallVec::<u8, u8>::try_from(to_vec(&verification_data)?)
            .map_err(|_| SdkError::SerializationError("Verification data too large".to_string()))?,
        session_key,
        slothash: slot_hash,
    };

    // Serialize instruction data
    let mut serialized_ix_data = vec![2]; // discriminator
    borsh::to_writer(&mut serialized_ix_data, &external_sig_ix_data)?;

    // Build the instruction
    Ok(Instruction {
        program_id: Pubkey::new_from_array(PROGRAM_ID),
        accounts: vec![
            AccountMeta::new(*passkey_account, false),
            AccountMeta::new_readonly(
                Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap(),
                false,
            ),
            AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
            AccountMeta::new(*payer, true),
        ],
        data: serialized_ix_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthType;

    #[test]
    fn test_refresh_session_key() {
        use crate::TruncatedSlot;

        let webauthn_data = WebAuthnData::new(
            [1u8; 33],
            vec![0u8; 64],
            vec![0u8; 37],
            vec![],
            AuthType::Get,
            false,
            false,
            false,
            None,
        );

        let passkey_account = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let slot_hash = TruncatedSlot(0);
        let session_key = SessionKey {
            key: [0u8; 32],
            expiration: 1000,
        };

        let result = refresh_session_key(
            &webauthn_data,
            &passkey_account,
            &payer,
            slot_hash,
            session_key,
        );
        assert!(result.is_ok());
    }
}
