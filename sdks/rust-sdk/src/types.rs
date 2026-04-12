pub use external_signature_program::utils::signatures::{
    AuthType, ClientDataJsonReconstructionParams,
};

/// WebAuthn authentication data parsed from a fixture or credential
#[derive(Debug, Clone)]
pub struct WebAuthnData {
    /// Compressed P-256 public key (33 bytes: 1 byte parity + 32 bytes x-coordinate)
    pub public_key: [u8; 33],
    pub signature: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}

/// Session key configuration
#[derive(Debug, Clone, Copy)]
pub struct SessionKeyConfig {
    pub key: [u8; 32],
    pub expiration: u64,
}

impl WebAuthnData {
    /// Creates a new WebAuthnData with simple ClientDataJsonReconstructionParams
    pub fn new(
        public_key: [u8; 33],
        signature: Vec<u8>,
        auth_data: Vec<u8>,
        client_data_json: Vec<u8>,
        auth_type: AuthType,
        cross_origin: bool,
        is_http: bool,
        has_google_extra: bool,
        port: Option<u16>,
    ) -> Self {
        Self {
            public_key,
            signature,
            auth_data,
            client_data_json,
            client_data_json_reconstruction_params: ClientDataJsonReconstructionParams::new(
                auth_type,
                cross_origin,
                is_http,
                has_google_extra,
                port,
            ),
        }
    }
}
