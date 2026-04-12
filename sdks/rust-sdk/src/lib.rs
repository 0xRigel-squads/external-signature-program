pub mod error;
pub mod instructions;
pub mod pda;
pub mod types;

pub use error::SdkError;
pub use external_signature_program::utils::nonce::TruncatedSlot;
pub use external_signature_program::ID as PROGRAM_ID;

pub type Result<T> = std::result::Result<T, SdkError>;
