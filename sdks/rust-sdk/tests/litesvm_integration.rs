use std::{
    fs,
    path::PathBuf,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose, Engine as _};
use external_signature_program::{
    state::{P256WebauthnAccountData, SessionKey},
    utils::signatures::{AuthType, ClientDataJsonReconstructionParams},
    ID as PROGRAM_ID,
};
use external_signature_sdk::{
    instructions::{
        create_secp256r1_instruction, execute_instructions, initialize_passkey_account,
        refresh_session_key,
    },
    pda::derive_execution_account,
    types::{SignerExecutionScheme, WebAuthnData},
    TruncatedSlot,
};
use litesvm::LiteSVM;
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program::{
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    native_token::LAMPORTS_PER_SOL,
};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_slot_hashes::{SlotHash, SlotHashes};
use solana_transaction::Transaction;

const TEST_KEYPAIR_PATH: &str =
    "../../tests/p256/keypairs/sinf1bu1CMQaMzeDoysAU7dAp2gs5j2V3vM9W5ZXAyB.json";
const CHROME_CREATION_PATH: &str = "../../tests/p256/fixtures/chrome/creation.json";
const CHROME_AUTH_PATH: &str = "../../tests/p256/fixtures/chrome/authentication.json";
const CHROME_SESSION_AUTH_PATH: &str =
    "../../tests/p256/fixtures/chrome/session_key_authentication.json";
const RP_ID: &str = "www.passkeys-debugger.io";
const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const TESTING_SESSION_KEY: SessionKey = SessionKey {
    key: Pubkey::from_str_const("sesfSDjioiWGpxqSoHSfMGrQe3wAyEBDSAL3niVecdC").to_bytes(),
    expiration: 900,
};

#[derive(Debug)]
struct ParsedFixture {
    signature: Vec<u8>,
    public_key: Option<[u8; 33]>,
    auth_data: Vec<u8>,
    client_data_json: Vec<u8>,
    params: ClientDataJsonReconstructionParams,
}

#[test]
fn sdk_executes_end_to_end_against_litesvm() {
    let payer = load_keypair(TEST_KEYPAIR_PATH);
    let mut svm = initialize_svm(&payer.pubkey());
    let (_, truncated_slot) = get_valid_slothash(&svm);

    let creation = parse_webauthn_fixture(CHROME_CREATION_PATH);
    let registration_key = creation
        .public_key
        .expect("creation fixture must include public key");

    let init_data = WebAuthnData {
        public_key: registration_key,
        signature: creation.signature.clone(),
        auth_data: creation.auth_data.clone(),
        client_data_json: creation.client_data_json.clone(),
        client_data_json_reconstruction_params: creation.params,
    };
    let (passkey_account, initialize_ix) = initialize_passkey_account(
        &init_data,
        RP_ID.as_bytes(),
        &payer.pubkey(),
        truncated_slot.clone(),
    )
    .expect("initialize instruction");
    let initialize_precompile_ix = create_secp256r1_instruction(
        &init_data.signature,
        &build_precompile_message(&init_data.auth_data, &init_data.client_data_json),
        &init_data.public_key,
        None,
    )
    .expect("initialize precompile");
    send_transaction(
        &mut svm,
        vec![initialize_precompile_ix, initialize_ix],
        &payer,
    );
    assert!(svm.get_account(&passkey_account).is_some());

    let (execution_account, _) = derive_execution_account(&passkey_account).expect("execution pda");
    svm.airdrop(&execution_account, LAMPORTS_PER_SOL).unwrap();

    let auth = parse_webauthn_fixture(CHROME_AUTH_PATH);
    let auth_data = WebAuthnData {
        public_key: registration_key,
        signature: auth.signature,
        auth_data: auth.auth_data,
        client_data_json: auth.client_data_json,
        client_data_json_reconstruction_params: auth.params,
    };
    let execute_ix = execute_instructions(
        &auth_data,
        &passkey_account,
        &payer.pubkey(),
        truncated_slot.clone(),
        vec![
            create_memo_instruction(payer.pubkey()),
            create_system_transfer_instruction(execution_account, payer.pubkey()),
        ],
        SignerExecutionScheme::ExecutionAccount,
    )
    .expect("execute instruction");
    let execute_precompile_ix = create_secp256r1_instruction(
        &auth_data.signature,
        &build_precompile_message(&auth_data.auth_data, &auth_data.client_data_json),
        &auth_data.public_key,
        None,
    )
    .expect("execute precompile");
    send_transaction(&mut svm, vec![execute_precompile_ix, execute_ix], &payer);

    let session_auth = parse_webauthn_fixture(CHROME_SESSION_AUTH_PATH);
    let refresh_data = WebAuthnData {
        public_key: registration_key,
        signature: session_auth.signature,
        auth_data: session_auth.auth_data,
        client_data_json: session_auth.client_data_json,
        client_data_json_reconstruction_params: session_auth.params,
    };
    let refresh_ix = refresh_session_key(
        &refresh_data,
        &passkey_account,
        &payer.pubkey(),
        truncated_slot.clone(),
        TESTING_SESSION_KEY,
    )
    .expect("refresh session key instruction");
    let refresh_precompile_ix = create_secp256r1_instruction(
        &refresh_data.signature,
        &build_precompile_message(&refresh_data.auth_data, &refresh_data.client_data_json),
        &refresh_data.public_key,
        None,
    )
    .expect("refresh precompile");
    send_transaction(&mut svm, vec![refresh_precompile_ix, refresh_ix], &payer);

    let account = svm
        .get_account(&passkey_account)
        .expect("passkey account should exist");
    let account_data: &P256WebauthnAccountData = bytemuck::from_bytes(&account.data);
    assert_eq!(account_data.session_key.key, TESTING_SESSION_KEY.key);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expected_expiration = now + TESTING_SESSION_KEY.expiration;
    assert_eq!(account_data.session_key.expiration, expected_expiration);
}

fn load_keypair(path: &str) -> Keypair {
    let path = manifest_path(path);
    let keypair_bytes: Vec<u8> =
        serde_json::from_str(&fs::read_to_string(path).expect("read keypair fixture"))
            .expect("parse keypair fixture");
    Keypair::from_bytes(&keypair_bytes).expect("keypair fixture bytes")
}

fn send_transaction(svm: &mut LiteSVM, instructions: Vec<Instruction>, payer: &Keypair) {
    let blockhash = svm.latest_blockhash();
    let message = Message::new_with_blockhash(&instructions, Some(&payer.pubkey()), &blockhash);
    let tx = Transaction::new(&[payer], message, blockhash);
    svm.send_transaction(tx).unwrap();
}

fn initialize_svm(airdrop_key: &Pubkey) -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.airdrop(airdrop_key, 10 * LAMPORTS_PER_SOL).unwrap();
    svm.add_program_from_file(
        Pubkey::new_from_array(PROGRAM_ID),
        &manifest_path("../../target/deploy/external_signature_program.so"),
    )
    .unwrap();
    set_slothash_sysvar(&mut svm);
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    svm.set_sysvar::<Clock>(&clock);
    svm
}

fn set_slothash_sysvar(svm: &mut LiteSVM) {
    let mut slothashes: Vec<SlotHash> = Vec::new();
    for i in 0..512u64 {
        let slot_bytes = i.to_le_bytes();
        let hash_result = Sha256::digest(slot_bytes);
        let hash_bytes: [u8; 32] = hash_result.into();
        slothashes.push((i, Hash::from(hash_bytes)));
    }
    svm.set_sysvar(&SlotHashes::new(&slothashes));
}

fn get_valid_slothash(svm: &LiteSVM) -> ([u8; 32], TruncatedSlot) {
    let slothashes = svm.get_sysvar::<SlotHashes>();
    let slot = slothashes[42];
    let truncated_slot = TruncatedSlot((slot.0 % 1000) as u16);
    (slot.1.to_bytes(), truncated_slot)
}

fn create_memo_instruction(signer: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::from_str(MEMO_PROGRAM_ID).unwrap(),
        accounts: vec![AccountMeta::new(signer, true)],
        data: vec![],
    }
}

fn create_system_transfer_instruction(execution_account: Pubkey, to: Pubkey) -> Instruction {
    let mut instruction =
        solana_program::system_instruction::transfer(&execution_account, &to, 1_000_000_000);
    instruction
        .accounts
        .iter_mut()
        .find(|account_meta| account_meta.pubkey == execution_account)
        .unwrap()
        .is_signer = false;
    instruction
}

fn build_precompile_message(auth_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let mut message = auth_data.to_vec();
    let client_data_hash = solana_nostd_sha256::hashv(&[client_data_json]);
    message.extend_from_slice(&client_data_hash);
    message
}

fn parse_webauthn_fixture(path: &str) -> ParsedFixture {
    let data: JsonValue = serde_json::from_str(
        &fs::read_to_string(manifest_path(path)).expect("read webauthn fixture"),
    )
    .expect("parse webauthn fixture json");

    let signature = match data["response"]["attestationObject"].as_str() {
        Some(attestation_object) => parse_signature_from_attestation_object(attestation_object),
        None => general_purpose::URL_SAFE_NO_PAD
            .decode(data["response"]["signature"].as_str().expect("signature"))
            .expect("decode signature"),
    };

    let compressed_public_key = data["response"]["publicKey"].as_str().map(|public_key| {
        let (x, y) = decode_ec_public_key(public_key);
        let y_parity = y[y.len() - 1] & 1;
        let mut compressed_key = vec![0x02 + y_parity];
        compressed_key.extend_from_slice(&x);
        compressed_key
            .try_into()
            .expect("compressed secp256r1 public key must be 33 bytes")
    });

    let auth_data = general_purpose::URL_SAFE_NO_PAD
        .decode(
            data["response"]["authenticatorData"]
                .as_str()
                .expect("authenticatorData"),
        )
        .expect("decode authenticatorData");
    let client_data_json = general_purpose::URL_SAFE_NO_PAD
        .decode(
            data["response"]["clientDataJSON"]
                .as_str()
                .expect("clientDataJSON"),
        )
        .expect("decode clientDataJSON");

    let client_data_json_value: JsonValue =
        serde_json::from_slice(&client_data_json).expect("parse clientDataJSON");
    let auth_type = match client_data_json_value["type"].as_str() {
        Some("webauthn.create") => AuthType::Create,
        Some("webauthn.get") => AuthType::Get,
        _ => panic!("invalid auth type in fixture"),
    };
    let cross_origin = client_data_json_value["crossOrigin"]
        .as_bool()
        .unwrap_or(false);
    let is_http = client_data_json_value["origin"]
        .as_str()
        .expect("origin")
        .starts_with("http://");
    let has_google_extra = client_data_json_value["other_keys_can_be_added_here"]
        .as_str()
        .is_some();
    let port = client_data_json_value["origin"]
        .as_str()
        .and_then(|origin| {
            origin
                .split("://")
                .nth(1)
                .and_then(|host| host.split(':').nth(1))
                .and_then(|value| value.parse::<u16>().ok())
        });
    let params = ClientDataJsonReconstructionParams::new(
        auth_type,
        cross_origin,
        is_http,
        has_google_extra,
        port,
    );

    ParsedFixture {
        signature,
        public_key: compressed_public_key,
        auth_data,
        client_data_json,
        params,
    }
}

fn parse_signature_from_attestation_object(attestation_object: &str) -> Vec<u8> {
    let attestation_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(attestation_object)
        .expect("decode attestation object");
    let value: CborValue = serde_cbor::from_slice(&attestation_bytes).expect("parse CBOR");

    if let CborValue::Map(map) = value {
        for (key, val) in map {
            if let CborValue::Text(key_str) = key {
                if key_str == "attStmt" {
                    if let CborValue::Map(att_stmt) = val {
                        for (stmt_key, stmt_val) in att_stmt {
                            if let CborValue::Text(stmt_key_str) = stmt_key {
                                if stmt_key_str == "sig" {
                                    if let CborValue::Bytes(sig_bytes) = stmt_val {
                                        return sig_bytes;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    panic!("signature not found in attestationObject");
}

fn decode_ec_public_key(public_key: &str) -> (Vec<u8>, Vec<u8>) {
    let key_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(public_key)
        .expect("decode public key");

    for i in 0..key_bytes.len().saturating_sub(64) {
        if key_bytes[i] == 0x04 {
            let x = key_bytes[i + 1..i + 33].to_vec();
            let y = key_bytes[i + 33..i + 65].to_vec();
            return (x, y);
        }
    }

    panic!("could not locate ec coordinates in public key");
}

fn manifest_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}
