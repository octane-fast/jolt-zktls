use guest::PublicInputs;
use jolt_sdk::PrivateInput;
use serde::Deserialize;
use std::path::PathBuf;
use tracing::info;

// ─── Test case deserialization ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TestCase {
    name: String,
    params: TestParams,
    records: Vec<TestRecord>,
}

#[derive(Debug, Deserialize)]
struct TestParams {
    #[serde(rename = "capturedPrivKeys")]
    captured_priv_keys: std::collections::HashMap<String, String>,
    #[serde(rename = "negotiatedCipherSuite")]
    negotiated_cipher_suite: String,
    #[serde(rename = "handshakeMsgs")]
    handshake_msgs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TestRecord {
    ciphertext: String,
    #[serde(rename = "recordNumber")]
    record_number: u32,
    direction: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    #[serde(rename = "plaintextHex")]
    plaintext_hex: String,
    algorithm: String,
}

fn load_test_cases() -> TestCase {
    let candidates = [
        PathBuf::from("../test/test_cases.json"),
        PathBuf::from("../../test/test_cases.json"),
        PathBuf::from("tls/test/test_cases.json"),
    ];

    for p in &candidates {
        if p.exists() {
            let data = std::fs::read_to_string(p).unwrap();
            return serde_json::from_str(&data).unwrap();
        }
    }

    panic!("test_cases.json not found. Run: npx tsx test/generate-test-cases.ts");
}

// ─── Main ──────────────────────────────────────────────────────────

pub fn main() {
    tracing_subscriber::fmt::init();

    let tc = load_test_cases();
    info!("Test case: {}", tc.name);
    info!("Cipher: {}", tc.params.negotiated_cipher_suite);
    info!("Records: {}", tc.records.len());

    // Build KeyDerivationParams-like data for serialization
    let captured_priv_keys: Vec<(String, Vec<u8>)> = tc
        .params
        .captured_priv_keys
        .iter()
        .map(|(alg, h)| (alg.clone(), hex::decode(h).unwrap()))
        .collect();

    let handshake_msgs: Vec<Vec<u8>> = tc
        .params
        .handshake_msgs
        .iter()
        .map(|h| hex::decode(h).unwrap())
        .collect();

    // ── Compile & preprocess ──────────────────────────────────────
    info!("Compiling guest...");
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_prove_decrypt(target_dir);

    info!("Preprocessing...");
    let shared = guest::preprocess_shared_prove_decrypt(&mut program)
        .expect("shared preprocessing failed");
    let prover_pp = guest::preprocess_prover_prove_decrypt(shared.clone());
    let blindfold_setup = prover_pp.blindfold_setup();
    let verifier_pp = guest::preprocess_verifier_prove_decrypt(
        shared,
        prover_pp.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );

    let prove_fn = guest::build_prover_prove_decrypt(program, prover_pp);
    let verify_fn = guest::build_verifier_prove_decrypt(verifier_pp);

    // ── Prove & verify each record ────────────────────────────────
    for (i, tr) in tc.records.iter().enumerate() {
        let ciphertext = hex::decode(&tr.ciphertext).unwrap();
        let direction: u8 = match tr.direction.as_str() {
            "ServerToClient" => 0,
            "ClientToServer" => 1,
            _ => panic!("Unknown direction: {}", tr.direction),
        };
        let expected_plaintext = hex::decode(&tr.expected.plaintext_hex).unwrap();

        let public = PublicInputs {
            cipher_suite: tc.params.negotiated_cipher_suite.clone(),
            handshake_msgs: handshake_msgs.clone(),
            ciphertext,
            record_number: tr.record_number,
            direction,
            expected_plaintext,
        };

        info!("Record {} ({}): proving decryption...", i, tr.direction);

        // Prove!
        let (output, proof, io_device) =
            prove_fn(public.clone(), PrivateInput::new(captured_priv_keys.clone()));
        info!("  Proof generated");

        // Verify!
        let is_valid = verify_fn(public, output.clone(), io_device.panic, proof);
        info!("  Proof valid: {}", is_valid);

        if io_device.panic {
            info!(
                "  ❌ Record {}: guest panicked (decryption or assertion failed)",
                i
            );
        } else if !is_valid {
            info!("  ❌ Record {}: proof verification failed", i);
        } else {
            info!(
                "  ✅ Record {}: proof valid, plaintext {} bytes ({})",
                i, output.len(), tr.expected.algorithm
            );
        }
    }

    info!("Done.");
}
