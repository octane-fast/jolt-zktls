use tls_decrypt_rs::{
    decrypt_record, derive_keys_from_handshake,
    Direction, KeyDerivationParams, RawRecord,
};

fn main() {
    println!("tls-decrypt-rs — TLS 1.3 AEAD record decryption\n");

    // ── Example: full derivation + decryption ──
    // To use with real data, populate KeyDerivationParams with:
    //   - captured_priv_keys: the client's ephemeral X25519 private key
    //   - negotiated_cipher_suite: e.g. "TLS_CHACHA20_POLY1305_SHA256"
    //   - handshake_msgs: raw handshake messages [ClientHello, ServerHello, ...]
    //
    // The TypeScript implementation captures these via a crypto wrapper.
    // Export them as hex and feed them here.

    let params = KeyDerivationParams {
        captured_priv_keys: vec![
            // ("X25519", hex::decode("...").unwrap()),
        ],
        negotiated_cipher_suite: String::new(), // e.g. "TLS_CHACHA20_POLY1305_SHA256"
        handshake_msgs: vec![
            // hex::decode("ClientHello...").unwrap(),
            // hex::decode("ServerHello...").unwrap(),
        ],
    };

    // Example record (ciphertext hex from a captured session)
    let example_ct = hex::decode(
        "86bf42499432b08f27141cd09075bb1cbabca06528f953fdb5600d13eca022a6",
    )
    .unwrap();

    let records = vec![RawRecord {
        ciphertext: example_ct,
        record_number: 1,
        direction: Direction::ServerToClient,
    }];

    // Step 1: Derive keys (for display)
    match derive_keys_from_handshake(&params) {
        Ok(derived) => {
            println!("  ✅ Key derivation succeeded");
            println!("  Server enc key : {}", hex::encode(&derived.server_enc_key));
            println!("  Server IV      : {}", hex::encode(&derived.server_iv));
            println!("  Shared secret  : {}", hex::encode(&derived.shared_secret));

            // Step 2: Decrypt each record (derives keys internally, same as TypeScript)
            for (i, rec) in records.iter().enumerate() {
                match decrypt_record(rec, &params) {
                    Ok(result) => {
                        println!("\n  ── Record {} ({}) ──", i + 1, rec.direction.label());
                        println!("  Algorithm : {}", result.algorithm);
                        println!("  Nonce     : {}", hex::encode(&result.nonce));
                        println!("  Plaintext : {}", hex::encode(&result.plaintext));
                        if let Ok(text) = std::str::from_utf8(&result.plaintext) {
                            let preview: String = text.chars().take(80).collect();
                            println!("  → \"{}\"", preview.replace('\r', "\\r").replace('\n', "\\n"));
                        }
                    }
                    Err(e) => println!("  ⚠️  Decrypt failed: {}", e),
                }
            }
        }
        Err(e) => {
            println!("  ⚠️  Key derivation skipped (no params): {}", e);
            println!("\n  To use, populate KeyDerivationParams with:");
            println!("    - captured_priv_keys: client X25519 private key");
            println!("    - negotiated_cipher_suite: TLS_CHACHA20_POLY1305_SHA256");
            println!("    - handshake_msgs: [ClientHello, ServerHello, ...]");
        }
    }

    // ── Standalone decrypt with explicit key/IV ──
    // If you already have the derived keys (e.g. from the TypeScript tool):
    //
    // let server_enc_key = hex::decode("75aac5f5...").unwrap();
    // let server_iv = hex::decode("c6da6377...").unwrap();
    // let rec = RawRecord { ciphertext: ..., record_number: 1, direction: Direction::ServerToClient };
    // let result = decrypt_record(&rec, &server_enc_key, &server_iv).unwrap();
}
