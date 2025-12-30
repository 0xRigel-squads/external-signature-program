use crate::{types::WebAuthnData, Result, SdkError, PROGRAM_ID};
use borsh::to_vec;
use external_signature_program::{
    instructions::execute_instructions::ExecutableInstructionArgs,
    state::P256RawVerificationData,
    utils::{
        instructions::CompiledInstruction as ExternalCompiledInstruction,
        nonce::TruncatedSlot, SmallVec, SLOT_HASHES_ID,
    },
};
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const INSTRUCTIONS_SYSVAR: [u8; 32] = [
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161,
    253, 68, 227, 219, 217, 138, 0, 0, 0, 0,
];

/// Builds an execute instructions instruction for passkey authentication
///
/// # Arguments
/// * `webauthn_data` - The WebAuthn authentication data
/// * `passkey_account` - The passkey account to authenticate with
/// * `payer` - The transaction fee payer
/// * `slot_hash` - Current slot hash for replay protection
/// * `instructions` - Instructions to execute
/// * `additional_accounts` - Additional accounts needed by the instructions
///
/// # Returns
/// The execute instruction
pub fn execute_instructions(
    webauthn_data: &WebAuthnData,
    passkey_account: &Pubkey,
    payer: &Pubkey,
    slot_hash: TruncatedSlot,
    instructions: Vec<Instruction>,
    additional_accounts: Vec<AccountMeta>,
) -> Result<Instruction> {
    // Prepare verification data
    let extra_verification_data = P256RawVerificationData {
        public_key: webauthn_data.public_key,
        client_data_json_reconstruction_params: webauthn_data
            .client_data_json_reconstruction_params
            .clone(),
    };

    // Convert instructions to compiled format
    let compiled_instructions = compile_instructions(&instructions, &additional_accounts)?;

    // Build instruction arguments
    let external_sig_ix_data = ExecutableInstructionArgs {
        signature_scheme: 0, // P256Webauthn
        signer_execution_scheme: 0, // DirectSigner
        extra_verification_data: SmallVec::<u8, u8>::try_from(to_vec(&extra_verification_data)?)
            .map_err(|_| SdkError::SerializationError("Verification data too large".to_string()))?,
        instructions: compiled_instructions,
        slothash: slot_hash,
    };

    // Serialize instruction data
    let mut serialized_ix_data = vec![1]; // discriminator
    borsh::to_writer(&mut serialized_ix_data, &external_sig_ix_data)?;

    // Build account metas
    let mut accounts = vec![
        AccountMeta::new(*passkey_account, false),
        AccountMeta::new_readonly(Pubkey::new_from_array(INSTRUCTIONS_SYSVAR), false),
        AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
        AccountMeta::new(*payer, true),
    ];
    accounts.extend(additional_accounts);

    Ok(Instruction {
        program_id: Pubkey::new_from_array(PROGRAM_ID),
        accounts,
        data: serialized_ix_data,
    })
}

/// Helper function to compile Solana instructions into the format expected by the program
fn compile_instructions(
    instructions: &[Instruction],
    account_metas: &[AccountMeta],
) -> Result<SmallVec<u8, ExternalCompiledInstruction>> {
    // Build account key list
    let mut account_keys: Vec<Pubkey> = Vec::new();
    for meta in account_metas {
        if !account_keys.contains(&meta.pubkey) {
            account_keys.push(meta.pubkey);
        }
    }

    // Compile each instruction
    let compiled: Vec<ExternalCompiledInstruction> = instructions
        .iter()
        .map(|ix| {
            // Find program ID index
            let program_id_index = account_keys
                .iter()
                .position(|k| k == &ix.program_id)
                .unwrap_or_else(|| {
                    account_keys.push(ix.program_id);
                    account_keys.len() - 1
                }) as u8;

            // Build account indices
            let accounts_indices: Vec<u8> = ix
                .accounts
                .iter()
                .map(|meta| {
                    account_keys
                        .iter()
                        .position(|k| k == &meta.pubkey)
                        .unwrap_or_else(|| {
                            account_keys.push(meta.pubkey);
                            account_keys.len() - 1
                        }) as u8
                })
                .collect();

            ExternalCompiledInstruction {
                program_id_index,
                accounts_indices: SmallVec::<u8, u8>::try_from(accounts_indices)
                    .expect("Too many accounts"),
                data: SmallVec::<u16, u8>::try_from(ix.data.clone()).expect("Instruction data too large"),
            }
        })
        .collect();

    SmallVec::<u8, ExternalCompiledInstruction>::try_from(compiled)
        .map_err(|_| SdkError::SerializationError("Too many instructions".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthType;

    #[test]
    fn test_execute_instructions() {
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

        let memo_ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: b"test memo".to_vec(),
        };

        let result = execute_instructions(
            &webauthn_data,
            &passkey_account,
            &payer,
            slot_hash,
            vec![memo_ix],
            vec![],
        );

        assert!(result.is_ok());
    }
}
