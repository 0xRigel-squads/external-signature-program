use bytemuck::{Pod, Zeroable};

use crate::state::{AccountHeader, CompressedP256PublicKey, SessionKey};

/// P-256 (secp256r1) account data
#[derive(Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub struct P256NativeAccountData {
    /// Exists here purely for alignment
    _header: AccountHeader,

    /// P-256 public key (compressed)
    pub public_key: CompressedP256PublicKey,

    /// Padding to ensure alignment
    pub padding: [u8; 3],

    /// Session key
    pub session_key: SessionKey,
}
