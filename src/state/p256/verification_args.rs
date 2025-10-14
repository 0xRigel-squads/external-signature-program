use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::program_error::ProgramError;

use crate::state::CompressedP256PublicKey;

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256NativeRawVerificationData {
    pub public_key: [u8; 33],
}

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256NativeParsedVerificationData {
    pub public_key: CompressedP256PublicKey,
}

impl TryFrom<P256NativeRawVerificationData> for P256NativeParsedVerificationData {
    type Error = ProgramError;

    fn try_from(data: P256NativeRawVerificationData) -> Result<Self, ProgramError> {
        Ok(Self {
            public_key: CompressedP256PublicKey::new(&data.public_key),
        })
    }
}
