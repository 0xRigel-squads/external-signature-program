use crate::{Result, SdkError};
use solana_program::instruction::Instruction;
use solana_pubkey::Pubkey;

const SECP256R1_PROGRAM_ID: [u8; 32] = [
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
];

/// Creates a secp256r1 precompile verification instruction
///
/// This instruction must be included in the same transaction before any
/// instruction that requires signature verification.
///
/// Note: The public_key should be uncompressed (64 bytes) for the precompile,
/// even though the program stores compressed keys.
pub fn create_secp256r1_instruction(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8; 64],
    instruction_index: Option<u8>,
) -> Result<Instruction> {
    if signature.len() != 64 {
        return Err(SdkError::InvalidSignatureLength);
    }

    let eth_address = construct_eth_address(public_key);
    let mut instruction_data = vec![1]; // instruction discriminator for signature verification

    // Add signature offset (u16 LE)
    let sig_offset = 1 + 1 + 1 + 20 + 1 + 32 + 4;
    instruction_data.extend_from_slice(&(sig_offset as u16).to_le_bytes());

    // Add signature instruction index
    instruction_data.push(instruction_index.unwrap_or(u8::MAX));

    // Add Ethereum address (20 bytes)
    instruction_data.extend_from_slice(&eth_address);

    // Add message offset (u16 LE)
    let msg_offset = sig_offset + 64;
    instruction_data.extend_from_slice(&(msg_offset as u16).to_le_bytes());

    // Add message size (u16 LE)
    instruction_data.extend_from_slice(&(message.len() as u16).to_le_bytes());

    // Add message instruction index
    instruction_data.push(instruction_index.unwrap_or(u8::MAX));

    // Add reserved byte
    instruction_data.push(0);

    // Add signature (r: 32 bytes, s: 32 bytes)
    instruction_data.extend_from_slice(signature);

    // Add message data
    instruction_data.extend_from_slice(message);

    Ok(Instruction {
        program_id: Pubkey::new_from_array(SECP256R1_PROGRAM_ID),
        accounts: vec![],
        data: instruction_data,
    })
}

/// Constructs an Ethereum-style address from a P-256 public key
fn construct_eth_address(public_key: &[u8; 64]) -> [u8; 20] {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(public_key);
    let hash = hasher.finalize();

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_secp256r1_instruction() {
        let signature = [0u8; 64];
        let message = b"test message";
        let public_key = [0u8; 64];

        let result = create_secp256r1_instruction(&signature, message, &public_key, None);
        assert!(result.is_ok());
    }
}
