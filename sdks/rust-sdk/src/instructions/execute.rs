use crate::{types::WebAuthnData, Result, SdkError, PROGRAM_ID};
use borsh::to_vec;
use external_signature_program::{
    instructions::execute_instructions::ExecutableInstructionArgs,
    state::{P256RawVerificationData, SignerExecutionScheme},
    utils::{
        instructions::CompiledInstruction as ExternalCompiledInstruction, nonce::TruncatedSlot,
        SmallVec, SLOT_HASHES_ID,
    },
};
use solana_message::VersionedMessage;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::str::FromStr;

pub(crate) struct CompiledExecutionPayload {
    pub account_metas: Vec<AccountMeta>,
    pub instructions: SmallVec<u8, ExternalCompiledInstruction>,
}

/// Builds an execute instructions instruction for passkey authentication.
pub fn execute_instructions(
    webauthn_data: &WebAuthnData,
    passkey_account: &Pubkey,
    nonce_signer: &Pubkey,
    slot_hash: TruncatedSlot,
    instructions: Vec<Instruction>,
    signer_execution_scheme: SignerExecutionScheme,
) -> Result<Instruction> {
    let extra_verification_data = P256RawVerificationData {
        public_key: webauthn_data.public_key,
        client_data_json_reconstruction_params: webauthn_data
            .client_data_json_reconstruction_params
            .clone(),
    };

    let compiled = compile_instructions_for_execution(&instructions, nonce_signer)?;

    let external_sig_ix_data = ExecutableInstructionArgs {
        signature_scheme: 0, // P256Webauthn
        signer_execution_scheme: signer_execution_scheme as u8,
        extra_verification_data: SmallVec::<u8, u8>::try_from(to_vec(&extra_verification_data)?)
            .map_err(|_| SdkError::SerializationError("Verification data too large".to_string()))?,
        instructions: compiled.instructions,
        slothash: slot_hash,
    };

    let mut serialized_ix_data = vec![1]; // discriminator
    borsh::to_writer(&mut serialized_ix_data, &external_sig_ix_data)?;

    let mut accounts = vec![
        AccountMeta::new(*passkey_account, false),
        AccountMeta::new_readonly(
            Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap(),
            false,
        ),
        AccountMeta::new_readonly(Pubkey::new_from_array(SLOT_HASHES_ID), false),
        AccountMeta::new(*nonce_signer, true),
    ];
    accounts.extend(compiled.account_metas);

    Ok(Instruction {
        program_id: Pubkey::new_from_array(PROGRAM_ID),
        accounts,
        data: serialized_ix_data,
    })
}

pub(crate) fn compile_instructions_for_execution(
    instructions: &[Instruction],
    payer: &Pubkey,
) -> Result<CompiledExecutionPayload> {
    let message = VersionedMessage::Legacy(solana_message::legacy::Message::new(
        instructions,
        Some(payer),
    ));
    let compiled_instructions = message.instructions();

    let header = message.header();
    let account_keys = message.static_account_keys();
    let writable_signed_end = header.num_required_signatures - header.num_readonly_signed_accounts;
    let signed_end = header.num_required_signatures;
    let writable_unsigned_end = account_keys.len() - header.num_readonly_unsigned_accounts as usize;

    let mut account_metas = Vec::with_capacity(account_keys.len());
    for (index, key) in account_keys.iter().enumerate() {
        let is_signer = index < signed_end as usize;
        let is_writable = if is_signer {
            index < writable_signed_end as usize
        } else {
            index < writable_unsigned_end
        };
        account_metas.push(AccountMeta {
            pubkey: *key,
            is_signer,
            is_writable,
        });
    }

    let mut normalized = Vec::with_capacity(compiled_instructions.len());
    for instruction in compiled_instructions {
        let accounts_indices =
            SmallVec::<u8, u8>::try_from(instruction.accounts.clone()).map_err(|_| {
                SdkError::SerializationError("Too many instruction accounts".to_string())
            })?;
        let data = SmallVec::<u16, u8>::try_from(instruction.data.clone())
            .map_err(|_| SdkError::SerializationError("Instruction data too large".to_string()))?;

        normalized.push(ExternalCompiledInstruction {
            program_id_index: instruction.program_id_index,
            accounts_indices,
            data,
        });
    }
    let compiled = SmallVec::<u8, ExternalCompiledInstruction>::try_from(normalized)
        .map_err(|_| SdkError::SerializationError("Too many instructions".to_string()))?;

    Ok(CompiledExecutionPayload {
        account_metas,
        instructions: compiled,
    })
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
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            vec![0u8; 37],
            vec![],
            AuthType::Get,
            false,
            false,
            false,
            None,
        );

        let passkey_account = Pubkey::new_unique();
        let nonce_signer = Pubkey::new_unique();
        let slot_hash = TruncatedSlot(0);

        let memo_ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: b"test memo".to_vec(),
        };

        let result = execute_instructions(
            &webauthn_data,
            &passkey_account,
            &nonce_signer,
            slot_hash,
            vec![memo_ix],
            SignerExecutionScheme::ExecutionAccount,
        );

        assert!(result.is_ok());
    }
}
