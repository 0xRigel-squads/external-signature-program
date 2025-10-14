use pinocchio::{
    account_info::{AccountInfo, Ref},
    program_error::ProgramError,
    pubkey::try_find_program_address,
    sysvars::{clock::Clock, instructions::Instructions, Sysvar},
};

use crate::{
    errors::ExternalSignatureProgramError,
    state::{
        ExternallySignedAccountData, SessionKey, SignatureScheme, SESSION_KEY_EXPIRATION_LIMIT,
    },
    utils::{hash, PrecompileParser, Secp256r1Precompile},
};

use super::{
    AccountSeeds, P256NativeAccountData, P256NativeDeriveAccountArgs,
    P256NativeParsedInitializationData, P256NativeParsedVerificationData,
    P256NativeRawInitializationData, P256NativeRawVerificationData,
};

impl ExternallySignedAccountData for P256NativeAccountData {
    type AccountSeeds = AccountSeeds;
    type DeriveAccountArgs = P256NativeDeriveAccountArgs;
    type RawInitializationData = P256NativeRawInitializationData;
    type RawVerificationData = P256NativeRawVerificationData;
    type ParsedInitializationData = P256NativeParsedInitializationData;
    type ParsedVerificationData = P256NativeParsedVerificationData;

    fn version() -> u8 {
        1
    }

    fn scheme() -> u8 {
        SignatureScheme::P256Native as u8
    }

    fn size() -> usize {
        core::mem::size_of::<P256NativeAccountData>()
    }

    fn get_initialization_payload() -> &'static [u8] {
        b"initialize_native"
    }

    fn initialize_account(
        &mut self,
        args: &Self::ParsedInitializationData,
        session_key: Option<SessionKey>,
    ) -> Result<(), ProgramError> {
        // Set fields from initialization data
        self.public_key = args.public_key;

        // Set session key if provided
        if let Some(session_key) = session_key {
            // Check that the session key is not above the expiration limit
            if session_key.expiration
                > Clock::get()?.unix_timestamp as u64 + SESSION_KEY_EXPIRATION_LIMIT
            {
                return Err(ExternalSignatureProgramError::InvalidSessionKeyExpiration.into());
            }

            self.session_key = session_key;
        }

        Ok(())
    }

    /// Derives a new account from the public key
    fn derive_account(args: Self::DeriveAccountArgs) -> Result<Self::AccountSeeds, ProgramError> {
        // Since the limit for seeds is 32 bytes per seed, we hash the public key
        let public_key_hash = hash(&args.public_key);
        let (derived_key, bump) =
            try_find_program_address(&[b"native", &public_key_hash], &crate::ID).unwrap();

        Ok(AccountSeeds {
            key: derived_key,
            bump,
            seed_native: b"native",
            seed_public_key_hash: public_key_hash,
        })
    }

    /// Derive the account seeds from the account data
    fn derive_existing_account(&self) -> Result<Self::AccountSeeds, ProgramError> {
        let seeds = Self::derive_account(Self::DeriveAccountArgs {
            public_key: self.public_key.to_bytes(),
        })?;

        Ok(seeds)
    }

    /// Check the account based on the parsed verification data
    fn check_account(
        &self,
        account_info: &AccountInfo,
        _args: &Self::ParsedVerificationData,
    ) -> Result<Self::AccountSeeds, ProgramError> {
        let derive_args = Self::DeriveAccountArgs {
            public_key: self.public_key.to_bytes(),
        };

        // Check that the account matches the seeds
        let account_seeds = Self::derive_account(derive_args)?;
        if account_seeds.key.ne(account_info.key()) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        Ok(account_seeds)
    }

    /// Verifies an instruction execution payload
    fn verify_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        _extra_verification_data: &Self::ParsedVerificationData,
        _payload: &[u8],
    ) -> Result<(), ProgramError> {
        // Load the ix at index 0
        let precompile_instruction = instructions_sysvar_account.load_instruction_at(0)?;

        // Initialize the precompile parser
        let parser = PrecompileParser::<Secp256r1Precompile>::new(
            &precompile_instruction,
            &instructions_sysvar_account,
        )?;

        // parser.get_signature_payload(index)

        // Check that there is only one signature
        let num_signatures = parser.num_signatures();
        if num_signatures != 1 {
            return Err(ExternalSignatureProgramError::InvalidNumPrecompileSignatures.into());
        }

        // Get the 0th signature payload
        let signature_payload = parser.get_signature_payload(0)?;

        // Check the payloads pubkey matches the account data
        let payload_pubkey = signature_payload.public_key;
        if payload_pubkey != self.public_key.to_bytes() {
            return Err(ExternalSignatureProgramError::P256PublicKeyMismatch.into());
        }

        Ok(())
    }

    /// Verifies an initialization payload
    fn verify_initialization_payload<'a>(
        &mut self,
        instructions_sysvar_account: &Instructions<Ref<'a, [u8]>>,
        initialization_data: &Self::ParsedInitializationData,
        payload: &[u8],
    ) -> Result<(), ProgramError> {
        let verification_args = Self::ParsedVerificationData {
            public_key: initialization_data.public_key,
        };

        self.verify_payload(instructions_sysvar_account, &verification_args, payload)?;
        Ok(())
    }

    /// Validates a session key
    fn is_valid_session_key(&self, signer: &AccountInfo) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        // Check that the signer is a signer
        if !signer.is_signer() {
            return Err(ExternalSignatureProgramError::SessionSignerNotASigner.into());
        }
        // Check that the signer is the session key
        if self.session_key.key != *signer.key() {
            return Err(ExternalSignatureProgramError::InvalidSessionKey.into());
        }
        // Check that the session key is not expired
        if self.session_key.expiration < clock.unix_timestamp as u64 {
            return Err(ExternalSignatureProgramError::SessionKeyExpired.into());
        }
        Ok(())
    }

    /// Updates the session key
    fn update_session_key(&mut self, session_key: SessionKey) -> Result<(), ProgramError> {
        // Check that the session key is not above the expiration limit
        if session_key.expiration
            > Clock::get()?.unix_timestamp as u64 + SESSION_KEY_EXPIRATION_LIMIT
        {
            return Err(ExternalSignatureProgramError::InvalidSessionKeyExpiration.into());
        }

        self.session_key = session_key;

        Ok(())
    }
}
