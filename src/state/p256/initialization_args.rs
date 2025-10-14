use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::program_error::ProgramError;

use crate::{
    // errors::ExternalSignatureProgramError,
    state::CompressedP256PublicKey,
};

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct P256NativeRawInitializationData {
    pub public_key: [u8; 33],
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy)]
#[repr(C)]
pub struct P256NativeParsedInitializationData {
    pub public_key: CompressedP256PublicKey,
}

impl TryFrom<P256NativeRawInitializationData> for P256NativeParsedInitializationData {
    type Error = ProgramError;

    fn try_from(data: P256NativeRawInitializationData) -> Result<Self, ProgramError> {
        Ok(Self {
            public_key: CompressedP256PublicKey::new(&data.public_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_p256_raw_initialization_data() {
        let data = P256NativeRawInitializationData {
            public_key: [0u8; 33],
        };
        assert!(P256NativeParsedInitializationData::try_from(data).is_ok());
    }
}
