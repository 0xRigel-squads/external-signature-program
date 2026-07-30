use crate::p256::utils::svm::get_valid_slothash;
use crate::p256::utils::{
    initialization::initialize_passkey_account,
    parser::parse_webauthn_fixture,
    svm::{create_and_send_svm_transaction, initialize_svm},
};
use solana_keypair::Keypair;
use solana_signer::{EncodableKey, Signer};
use std::fs;

fn test_creation_from_fixture(path: &str) {
    let payer = Keypair::read_from_file(
        "tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json",
    )
    .unwrap();
    let (mut svm, program_id) = initialize_svm(vec![payer.pubkey()]);

    let (_hash, truncated_slot) = get_valid_slothash(&svm);
    // Get the passkey account and instructions from our abstracted function
    let (_account_pubkey, _public_key, instructions) =
        initialize_passkey_account(path, &payer.pubkey(), &truncated_slot, &program_id).unwrap();

    // Create and submit the transaction
    create_and_send_svm_transaction(&mut svm, instructions, &payer.pubkey(), vec![&payer]).unwrap();
}

#[cfg(test)]
mod test_initialization {
    use super::*;

    #[test]
    fn test_chrome_creation() {
        test_creation_from_fixture("tests/p256/fixtures/chrome/creation.json");
    }

    #[test]
    fn test_ios_crossplatform_creation() {
        test_creation_from_fixture("tests/p256/fixtures/ios-crossplatform/creation.json");
    }

    #[test]
    fn test_yubikey_creation() {
        test_creation_from_fixture("tests/p256/fixtures/yubikey/creation.json");
    }

    #[test]
    fn test_one_password_creation() {
        test_creation_from_fixture("tests/p256/fixtures/one-password/creation.json");
    }

    #[test]
    fn test_nordpass_creation_without_cross_origin() {
        let path = "tests/p256/fixtures/nordpass/creation.json";
        let json_data = fs::read_to_string(path).unwrap();
        let webauthn_data = parse_webauthn_fixture(&json_data).unwrap();
        assert!(webauthn_data
            .client_data_json_reconstruction_params
            .omits_cross_origin());

        test_creation_from_fixture(path);
    }
}
