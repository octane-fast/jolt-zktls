#![cfg_attr(feature = "guest", no_std)]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use jolt::PrivateInput;
use serde::{Deserialize, Serialize};
use tls_decrypt_rs::{decrypt_record, Direction, KeyDerivationParams, RawRecord};

/// Public inputs visible to both prover and verifier.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicInputs {
    pub cipher_suite: String,
    pub handshake_msgs: Vec<Vec<u8>>,
    pub ciphertext: Vec<u8>,
    pub record_number: u32,
    pub direction: u8,
    pub expected_plaintext: Vec<u8>,
}

/// Proves that a TLS 1.3 AEAD decryption is correct.
///
/// - `public`: all non-secret TLS session data (visible to verifier)
/// - `private_keys`: captured client private keys (hidden via BlindFold)
///
/// Returns: raw plaintext application data.
#[jolt::provable(stack_size = 131072, heap_size = 262144, max_trace_length = 2097152, max_input_size = 8192)]
fn prove_decrypt(
    public: PublicInputs,
    private_keys: PrivateInput<Vec<(String, Vec<u8>)>>,
) -> Vec<u8> {
    let captured_priv_keys = (*private_keys).clone();

    let params = KeyDerivationParams {
        captured_priv_keys,
        negotiated_cipher_suite: public.cipher_suite,
        handshake_msgs: public.handshake_msgs,
    };

    let direction = match public.direction {
        0 => Direction::ServerToClient,
        1 => Direction::ClientToServer,
        _ => panic!("bad direction"),
    };

    let rec = RawRecord {
        ciphertext: public.ciphertext,
        record_number: public.record_number,
        direction,
    };

    let result = decrypt_record(&rec, &params).expect("decryption failed");

    assert_eq!(
        result.plaintext, public.expected_plaintext,
        "plaintext mismatch"
    );

    result.plaintext
}
