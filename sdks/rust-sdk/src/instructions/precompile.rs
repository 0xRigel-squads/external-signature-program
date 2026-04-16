use bytemuck::bytes_of;
use openssl::{bn::BigNum, ecdsa::EcdsaSig};
use solana_program::instruction::Instruction;
use solana_secp256r1_program::{
    id, Secp256r1SignatureOffsets, COMPRESSED_PUBKEY_SERIALIZED_SIZE, DATA_START, SECP256R1_ORDER,
    SIGNATURE_SERIALIZED_SIZE,
};

use crate::{Result, SdkError};

const FIELD_SIZE: usize = 32;
const SECP256R1_HALF_ORDER: [u8; FIELD_SIZE] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// Creates a secp256r1 precompile verification instruction.
///
/// `signature_der` must be a DER-encoded ECDSA signature from WebAuthn.
/// `public_key` must be compressed secp256r1 (33 bytes).
pub fn create_secp256r1_instruction(
    signature_der: &[u8],
    message: &[u8],
    public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
    public_key_offset: Option<(u8, u16)>,
) -> Result<Instruction> {
    if message.len() > u16::MAX as usize {
        return Err(SdkError::MessageTooLarge);
    }

    let signature = parse_der_signature_to_compact(signature_der)?;

    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len()),
    );

    let num_signatures: u8 = 1;
    let (public_key_instruction_index, public_key_offset) = match public_key_offset {
        Some((ix, offset)) => (ix as u16, offset as usize),
        None => (u16::MAX, DATA_START),
    };
    let signature_offset = match public_key_instruction_index {
        u16::MAX => public_key_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE),
        _ => DATA_START,
    };
    let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

    instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

    let offsets = Secp256r1SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: u16::MAX,
        public_key_offset: public_key_offset as u16,
        public_key_instruction_index,
        message_data_offset: message_data_offset as u16,
        message_data_size: message.len() as u16,
        message_instruction_index: u16::MAX,
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));
    if public_key_instruction_index == u16::MAX {
        instruction_data.extend_from_slice(public_key);
    }
    instruction_data.extend_from_slice(&signature);
    instruction_data.extend_from_slice(message);

    Ok(Instruction {
        program_id: id(),
        accounts: vec![],
        data: instruction_data,
    })
}

fn parse_der_signature_to_compact(signature_der: &[u8]) -> Result<[u8; SIGNATURE_SERIALIZED_SIZE]> {
    let ecdsa_sig =
        EcdsaSig::from_der(signature_der).map_err(|_| SdkError::InvalidSignatureFormat)?;
    let r = ecdsa_sig.r().to_vec();
    let s = ecdsa_sig.s().to_vec();

    let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];

    let mut padded_r = [0u8; FIELD_SIZE];
    let mut padded_s = [0u8; FIELD_SIZE];
    if r.len() > FIELD_SIZE || s.len() > FIELD_SIZE {
        return Err(SdkError::InvalidSignatureFormat);
    }
    padded_r[FIELD_SIZE.saturating_sub(r.len())..].copy_from_slice(&r);
    padded_s[FIELD_SIZE.saturating_sub(s.len())..].copy_from_slice(&s);

    signature[..FIELD_SIZE].copy_from_slice(&padded_r);
    signature[FIELD_SIZE..].copy_from_slice(&padded_s);

    let s_bignum = BigNum::from_slice(&s).map_err(|_| SdkError::InvalidSignatureFormat)?;
    let half_order =
        BigNum::from_slice(&SECP256R1_HALF_ORDER).map_err(|_| SdkError::InvalidSignatureFormat)?;
    let order =
        BigNum::from_slice(&SECP256R1_ORDER).map_err(|_| SdkError::InvalidSignatureFormat)?;
    if s_bignum > half_order {
        let mut new_s = BigNum::new().map_err(|_| SdkError::InvalidSignatureFormat)?;
        new_s
            .checked_sub(&order, &s_bignum)
            .map_err(|_| SdkError::InvalidSignatureFormat)?;
        let new_s_bytes = new_s.to_vec();
        if new_s_bytes.len() > FIELD_SIZE {
            return Err(SdkError::InvalidSignatureFormat);
        }

        let mut new_padded_s = [0u8; FIELD_SIZE];
        new_padded_s[FIELD_SIZE.saturating_sub(new_s_bytes.len())..].copy_from_slice(&new_s_bytes);
        signature[FIELD_SIZE..].copy_from_slice(&new_padded_s);
    }

    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_secp256r1_instruction_with_der_signature() {
        let signature = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let message = b"test message";
        let public_key = [0x02u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE];

        let result = create_secp256r1_instruction(&signature, message, &public_key, None).unwrap();
        assert_eq!(result.program_id, id());
        assert_eq!(result.data[0], 1);
        assert_eq!(result.data[1], 0);
    }
}
