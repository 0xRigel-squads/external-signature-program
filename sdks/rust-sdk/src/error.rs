use thiserror::Error;

#[derive(Error, Debug)]
pub enum SdkError {
    #[error("Invalid public key length: expected 64 bytes")]
    InvalidPublicKeyLength,

    #[error("Invalid signature length")]
    InvalidSignatureLength,

    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("PDA derivation failed")]
    PdaDerivationFailed,

    #[error("Invalid RP ID: {0}")]
    InvalidRpId(String),

    #[error("Borsh serialization error: {0}")]
    BorshError(#[from] std::io::Error),
}
