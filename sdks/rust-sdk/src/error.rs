use thiserror::Error;

#[derive(Error, Debug)]
pub enum SdkError {
    #[error("Invalid secp256r1 signature format")]
    InvalidSignatureFormat,

    #[error("Invalid signature length")]
    InvalidSignatureLength,

    #[error("Message too large for secp256r1 precompile")]
    MessageTooLarge,

    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("PDA derivation failed")]
    PdaDerivationFailed,

    #[error("Invalid RP ID: {0}")]
    InvalidRpId(String),

    #[error("Borsh serialization error: {0}")]
    BorshError(#[from] std::io::Error),
}
