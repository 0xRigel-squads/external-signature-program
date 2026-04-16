use crate::{Result, PROGRAM_ID};
use external_signature_program::{
    instructions::execute_instructions_sessioned::ExecutableInstructionSessionedArgs,
    state::SignerExecutionScheme,
};
use solana_program::instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use super::execute::compile_instructions_for_execution;

/// Builds a sessioned execute instructions instruction.
pub fn execute_instructions_sessioned(
    passkey_account: &Pubkey,
    session_signer: &Pubkey,
    instructions: Vec<Instruction>,
    signer_execution_scheme: SignerExecutionScheme,
) -> Result<Instruction> {
    let compiled = compile_instructions_for_execution(&instructions, session_signer)?;

    let args = ExecutableInstructionSessionedArgs {
        signature_scheme: 0, // P256Webauthn
        signer_execution_scheme: signer_execution_scheme as u8,
        instructions: compiled.instructions,
    };

    let mut data = vec![3]; // discriminator
    borsh::to_writer(&mut data, &args)?;

    let mut accounts = vec![
        AccountMeta::new(*passkey_account, false),
        AccountMeta::new_readonly(*session_signer, true),
    ];
    accounts.extend(compiled.account_metas);

    Ok(Instruction {
        program_id: Pubkey::new_from_array(PROGRAM_ID),
        accounts,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_instructions_sessioned() {
        let passkey_account = Pubkey::new_unique();
        let session_signer = Pubkey::new_unique();
        let memo_ix = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![],
            data: b"sessioned".to_vec(),
        };

        let result = execute_instructions_sessioned(
            &passkey_account,
            &session_signer,
            vec![memo_ix],
            SignerExecutionScheme::ExecutionAccount,
        );

        assert!(result.is_ok());
    }
}
