/**
 * lib.rs — Jolt zkTLS prover library with C FFI.
 *
 * Compiled into the Octane Accelerator binary. Provides:
 *   - jolt_init():  compile + preprocess (expensive, call once)
 *   - jolt_prove(): prove TLS decryption (fast per-record after init)
 *
 * All data is passed as JSON strings for simplicity.
 */

use guest::PublicInputs;
use jolt_sdk::PrivateInput;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

// ─── Session deserialization ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Session {
    name: String,
    params: SessionParams,
    records: Vec<SessionRecord>,
}

#[derive(Debug, Deserialize)]
struct SessionParams {
    #[serde(rename = "capturedPrivKeys")]
    captured_priv_keys: std::collections::HashMap<String, String>,
    #[serde(rename = "negotiatedCipherSuite")]
    negotiated_cipher_suite: String,
    #[serde(rename = "handshakeMsgs")]
    handshake_msgs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SessionRecord {
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

// ─── Output types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct RecordResult {
    index: usize,
    direction: String,
    algorithm: String,
    plaintext_hex: String,
    plaintext_bytes: usize,
    proof_valid: bool,
}

#[derive(Serialize)]
struct ProveOutput {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cipher_suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<RecordResult>>,
}

// ─── Global prover state ───────────────────────────────────────────

// The closure returned by build_prover_prove_decrypt returns:
//   (Vec<u8>, jolt_sdk::RV64IMACProof, jolt_sdk::JoltDevice)
// It's Send + Sync (explicit in the macro output).
type ProveFn = Box<
    dyn Fn(
            PublicInputs,
            PrivateInput<Vec<(String, Vec<u8>)>>,
        ) -> (
            Vec<u8>,
            jolt_sdk::RV64IMACProof,
            jolt_sdk::JoltDevice,
        )
        + Send
        + Sync,
>;

static PROVER_STATE: Mutex<Option<ProveFn>> = Mutex::new(None);

// ─── Core implementation ───────────────────────────────────────────

fn do_init(target_dir: &str) -> Result<(), String> {
    let mut program = guest::compile_prove_decrypt(target_dir);

    let shared = guest::preprocess_shared_prove_decrypt(&mut program)
        .map_err(|e| format!("shared preprocessing failed: {:?}", e))?;

    let prover_pp = guest::preprocess_prover_prove_decrypt(shared.clone());
    let blindfold_setup = prover_pp.blindfold_setup();
    let verifier_pp = guest::preprocess_verifier_prove_decrypt(
        shared,
        prover_pp.generators.to_verifier_setup(),
        Some(blindfold_setup),
    );

    let _verify_fn = guest::build_verifier_prove_decrypt(verifier_pp);
    let prove_fn = guest::build_prover_prove_decrypt(program, prover_pp);

    let mut state = PROVER_STATE
        .lock()
        .map_err(|e| format!("lock poisoned: {}", e))?;
    *state = Some(Box::new(prove_fn));

    Ok(())
}

fn err_json(msg: &str, name: Option<&str>, cipher: Option<&str>) -> String {
    serde_json::to_string(&ProveOutput {
        ok: false,
        error: Some(msg.to_string()),
        name: name.map(|s| s.to_string()),
        cipher_suite: cipher.map(|s| s.to_string()),
        records: None,
    })
    .unwrap()
}

fn do_prove(session_json: &str) -> String {
    let session: Session = match serde_json::from_str(session_json) {
        Ok(s) => s,
        Err(e) => return err_json(&format!("invalid session JSON: {}", e), None, None),
    };

    let state = match PROVER_STATE.lock() {
        Ok(s) => s,
        Err(e) => return err_json(&format!("lock poisoned: {}", e), None, None),
    };

    let prove_fn = match state.as_ref() {
        Some(f) => f,
        None => return err_json("jolt_init not called", None, None),
    };

    let captured_priv_keys: Vec<(String, Vec<u8>)> = session
        .params
        .captured_priv_keys
        .iter()
        .map(|(alg, h)| {
            (
                alg.clone(),
                hex::decode(h).unwrap_or_else(|_| panic!("invalid hex for key {}", alg)),
            )
        })
        .collect();

    let handshake_msgs: Vec<Vec<u8>> = session
        .params
        .handshake_msgs
        .iter()
        .map(|h| hex::decode(h).expect("invalid hex in handshake msgs"))
        .collect();

    let cipher = &session.params.negotiated_cipher_suite;
    let mut results: Vec<RecordResult> = Vec::new();

    for (i, rec) in session.records.iter().enumerate() {
        let ciphertext = match hex::decode(&rec.ciphertext) {
            Ok(c) => c,
            Err(e) => {
                return err_json(
                    &format!("invalid ciphertext hex at record {}: {}", i, e),
                    Some(&session.name),
                    Some(cipher),
                );
            }
        };

        let direction: u8 = match rec.direction.as_str() {
            "ServerToClient" => 0,
            "ClientToServer" => 1,
            other => {
                return err_json(
                    &format!("unknown direction '{}' at record {}", other, i),
                    Some(&session.name),
                    Some(cipher),
                );
            }
        };

        let expected_plaintext = match hex::decode(&rec.expected.plaintext_hex) {
            Ok(p) => p,
            Err(e) => {
                return err_json(
                    &format!("invalid expected plaintext hex at record {}: {}", i, e),
                    Some(&session.name),
                    Some(cipher),
                );
            }
        };

        let public = PublicInputs {
            cipher_suite: session.params.negotiated_cipher_suite.clone(),
            handshake_msgs: handshake_msgs.clone(),
            ciphertext,
            record_number: rec.record_number,
            direction,
            expected_plaintext,
        };

        let (output, _proof, io_device) =
            prove_fn(public, PrivateInput::new(captured_priv_keys.clone()));

        if io_device.panic {
            return err_json(
                &format!(
                    "record {}: guest panicked (decryption or assertion failed)",
                    i
                ),
                Some(&session.name),
                Some(cipher),
            );
        }

        results.push(RecordResult {
            index: i,
            direction: rec.direction.clone(),
            algorithm: rec.expected.algorithm.clone(),
            plaintext_hex: hex::encode(&output),
            plaintext_bytes: output.len(),
            proof_valid: true,
        });
    }

    serde_json::to_string(&ProveOutput {
        ok: true,
        error: None,
        name: Some(session.name),
        cipher_suite: Some(session.params.negotiated_cipher_suite),
        records: Some(results),
    })
    .unwrap()
}

// ─── C FFI ─────────────────────────────────────────────────────────

/// Initialize the Jolt prover. Must be called once before `jolt_prove`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `target_dir` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn jolt_init(target_dir: *const c_char) -> i32 {
    let dir = match CStr::from_ptr(target_dir).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match do_init(dir) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Prove TLS decryption for a session. Returns a JSON string.
/// Caller must free with `jolt_free_string`.
///
/// # Safety
/// `session_json` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn jolt_prove(session_json: *const c_char) -> *mut c_char {
    let json = match CStr::from_ptr(session_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            let err = r#"{"ok":false,"error":"invalid input string"}"#;
            return CString::new(err).unwrap().into_raw();
        }
    };

    let result = do_prove(json);
    CString::new(result).unwrap().into_raw()
}

/// Free a string returned by `jolt_prove`.
///
/// # Safety
/// `s` must have been returned by `jolt_prove`.
#[no_mangle]
pub unsafe extern "C" fn jolt_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
