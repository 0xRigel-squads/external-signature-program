use crate::{Result, SdkError, PROGRAM_ID};
use solana_pubkey::Pubkey;

/// Derives the passkey account PDA from a compressed public key
pub fn derive_passkey_account(public_key: &[u8; 33]) -> Result<(Pubkey, u8)> {
    let public_key_hash = solana_nostd_sha256::hashv(&[public_key]);

    Pubkey::try_find_program_address(
        &[b"passkey", public_key_hash.as_slice()],
        &Pubkey::new_from_array(PROGRAM_ID),
    )
    .ok_or(SdkError::PdaDerivationFailed)
}

/// Derives the execution account PDA from a passkey account
pub fn derive_execution_account(passkey_account: &Pubkey) -> Result<(Pubkey, u8)> {
    Pubkey::try_find_program_address(
        &[passkey_account.as_ref(), b"execution_account"],
        &Pubkey::new_from_array(PROGRAM_ID),
    )
    .ok_or(SdkError::PdaDerivationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_passkey_account() {
        let public_key = [1u8; 33];
        let result = derive_passkey_account(&public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_execution_account() {
        let passkey_account = Pubkey::new_unique();
        let result = derive_execution_account(&passkey_account);
        assert!(result.is_ok());
    }
}
