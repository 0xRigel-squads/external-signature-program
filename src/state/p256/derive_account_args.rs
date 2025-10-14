use super::{P256NativeParsedInitializationData, P256NativeParsedVerificationData};
pub struct P256NativeDeriveAccountArgs {
    pub public_key: [u8; 33],
}

impl<'a> From<&'a P256NativeParsedInitializationData> for P256NativeDeriveAccountArgs {
    fn from(data: &'a P256NativeParsedInitializationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}

impl<'a> From<&'a P256NativeParsedVerificationData> for P256NativeDeriveAccountArgs {
    fn from(data: &'a P256NativeParsedVerificationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}
