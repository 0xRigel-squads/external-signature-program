use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct CompressedP256PublicKey {
    pub x: [u8; 32],
    pub y_parity: u8,
}

impl CompressedP256PublicKey {
    pub fn new(public_key: &[u8]) -> Self {
        Self {
            x: public_key[1..33].try_into().unwrap(),
            y_parity: public_key[0],
        }
    }
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = self.y_parity;
        bytes[1..33].copy_from_slice(&self.x);
        bytes
    }
}
