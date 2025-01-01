/// Integration test: reads a session captured by the C++ TLS recorder
/// (with keylog-derived traffic keys) and verifies Rust decryption.

use serde::Deserialize;
use std::path::PathBuf;
use tls_decrypt_rs::decrypt::decrypt_with_key;
use tls_decrypt_rs::{Direction, RawRecord};

#[derive(Debug, Deserialize)]
struct Session {
    params: SessionParams,
    records: Vec<SessionRecord>,
}

#[derive(Debug, Deserialize)]
struct SessionParams {
    #[serde(rename = "serverTrafficKey")]
    server_traffic_key: Option<String>, // hex
    #[serde(rename = "serverTrafficIv")]
    server_traffic_iv: Option<String>, // hex
    #[serde(rename = "clientTrafficKey")]
    client_traffic_key: Option<String>, // hex
    #[serde(rename = "clientTrafficIv")]
    client_traffic_iv: Option<String>, // hex
}

#[derive(Debug, Deserialize)]
struct SessionRecord {
    ciphertext: String, // hex
    #[serde(rename = "recordNumber")]
    record_number: u32,
    direction: String,
}

fn load_session() -> Session {
    let candidates = [
        PathBuf::from("../../octane-accelerator/session.json"),
        PathBuf::from("../octane-accelerator/session.json"),
        PathBuf::from("session.json"),
    ];

    for p in &candidates {
        if p.exists() {
            let data = std::fs::read_to_string(p).unwrap();
            return serde_json::from_str(&data).unwrap();
        }
    }
    panic!("session.json not found. Run: cd octane-accelerator && make test-tls-record HOST=example.com");
}

#[test]
fn decrypt_cpp_recorder_session() {
    let session = load_session();

    let server_key = hex::decode(
        session.params.server_traffic_key
            .as_deref()
            .expect("session missing serverTrafficKey"),
    ).unwrap();
    let server_iv = hex::decode(
        session.params.server_traffic_iv
            .as_deref()
            .expect("session missing serverTrafficIv"),
    ).unwrap();
    let client_key = hex::decode(
        session.params.client_traffic_key
            .as_deref()
            .expect("session missing clientTrafficKey"),
    ).unwrap();
    let client_iv = hex::decode(
        session.params.client_traffic_iv
            .as_deref()
            .expect("session missing clientTrafficIv"),
    ).unwrap();

    eprintln!("\n  🧪 Rust test: C++ TLS recorder session");
    eprintln!("  Records: {}\n", session.records.len());

    let mut passed = 0;
    let mut failed = 0;

    for (i, rec) in session.records.iter().enumerate() {
        let ciphertext = hex::decode(&rec.ciphertext).unwrap();
        let direction = match rec.direction.as_str() {
            "ServerToClient" => Direction::ServerToClient,
            "ClientToServer" => Direction::ClientToServer,
            _ => panic!("Unknown direction: {}", rec.direction),
        };

        let (enc_key, fixed_iv) = match direction {
            Direction::ServerToClient => (&server_key, &server_iv),
            Direction::ClientToServer => (&client_key, &client_iv),
        };

        let raw = RawRecord {
            ciphertext,
            record_number: rec.record_number,
            direction,
        };

        match decrypt_with_key(&raw, enc_key, fixed_iv) {
            Ok(result) => {
                let pt_hex = hex::encode(&result.plaintext);
                let preview = String::from_utf8_lossy(&result.plaintext);
                let preview_clean: String = preview.chars().take(60).collect();
                eprintln!(
                    "  ✅ Record {} ({}): {} — {}",
                    i, rec.direction, result.algorithm, preview_clean
                );
                passed += 1;
            }
            Err(e) => {
                eprintln!("  ❌ Record {} ({}): {}", i, rec.direction, e);
                failed += 1;
            }
        }
    }

    eprintln!("\n  {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "{} records failed to decrypt", failed);
}
