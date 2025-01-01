/**
 * jolt_prove — standalone binary for Jolt zkTLS proving.
 *
 * Two modes:
 *
 * 1. Preprocess mode (run once at build time):
 *    jolt_prove --preprocess <output_dir>
 *    Compiles the guest program, preprocesses proving keys,
 *    and saves them to <output_dir>/jolt_prover_preprocessing.dat
 *
 * 2. Prove mode (run at runtime):
 *    jolt_prove <session.json> <output.json>
 *    Loads preprocessing data (embedded or cached), compiles the guest,
 *    and proves TLS decryption for each record.
 *
 * Stderr: status updates as JSON lines
 * Stdout: (unused, reserved)
 */

use guest::PublicInputs;
use jolt_sdk::PrivateInput;
use serde::Deserialize;
use std::io::Write;
use std::time::Instant;

static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

// ─── Embedded preprocessing data ──────────────────────────────────
// build.rs generates embedded_data.rs containing serialized bytes
// when JOLT_PREPROCESS_DAT / JOLT_GUEST_ELF / JOLT_GUEST_ELF_ADVICE env vars are set.
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_data.rs"));
}

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

// ─── Output ────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct RecordResult {
    index: usize,
    direction: String,
    algorithm: String,
    plaintext_hex: String,
    plaintext_bytes: usize,
    proof_valid: bool,
}

#[derive(serde::Serialize)]
struct Output {
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

fn status(step: &str) {
    let elapsed = START.get().map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
    let msg = serde_json::json!({ "status": "running", "step": step, "elapsed_s": (elapsed * 10.0).round() / 10.0 });
    eprintln!("{}", msg);
}

fn fail(error: &str, output_path: &str) -> ! {
    let out = Output {
        ok: false,
        error: Some(error.to_string()),
        name: None,
        cipher_suite: None,
        records: None,
    };
    if let Ok(json) = serde_json::to_string(&out) {
        let _ = std::fs::write(output_path, json);
    }
    std::process::exit(2);
}

// ─── Preprocess mode ───────────────────────────────────────────────

fn run_preprocess(output_dir: &str) {
    use jolt_sdk::Serializable;

    status("Compiling Jolt guest program...");
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_prove_decrypt(target_dir);
    status("Guest compiled.");

    status("Preprocessing proving keys...");
    let shared = guest::preprocess_shared_prove_decrypt(&mut program)
        .expect("shared preprocessing failed");
    let prover_pp = guest::preprocess_prover_prove_decrypt(shared);

    // Save to target dir (Jolt's native format)
    prover_pp.save_to_target_dir(target_dir)
        .expect("failed to save prover preprocessing to target dir");

    // Also save to the requested output directory as standalone file
    std::fs::create_dir_all(output_dir).expect("failed to create output dir");
    let out_path = format!("{}/jolt_prover_preprocessing.dat", output_dir);
    prover_pp.save_to_file(&out_path)
        .expect("failed to save prover preprocessing to output dir");

    let size = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    eprintln!("Preprocessing saved to {} ({} bytes)", out_path, size);
    status("Done.");
}

// ─── Prove mode ────────────────────────────────────────────────────

fn run_prove(session_path: &str, output_path: &str) {
    use jolt_sdk::Serializable;

    // ── Load session ──
    status("Loading session data...");
    let data = match std::fs::read_to_string(session_path) {
        Ok(d) => d,
        Err(e) => fail(&format!("Cannot read session file: {}", e), output_path),
    };

    let session: Session = match serde_json::from_str(&data) {
        Ok(s) => s,
        Err(e) => fail(&format!("Invalid session JSON: {}", e), output_path),
    };

    status(&format!(
        "Session '{}': {} records, cipher {}",
        session.name,
        session.records.len(),
        session.params.negotiated_cipher_suite
    ));

    // ── Prepare inputs ──
    let captured_priv_keys: Vec<(String, Vec<u8>)> = session
        .params
        .captured_priv_keys
        .iter()
        .map(|(alg, h)| {
            let bytes = hex::decode(h).unwrap_or_else(|_| panic!("invalid hex for key {}", alg));
            (alg.clone(), bytes)
        })
        .collect();

    let handshake_msgs: Vec<Vec<u8>> = session
        .params
        .handshake_msgs
        .iter()
        .map(|h| hex::decode(h).expect("invalid hex in handshake msgs"))
        .collect();

    // ── Load preprocessing ──
    let target_dir = "/tmp/jolt-guest-targets";
    let prover_pp = load_prover_preprocessing(target_dir);

    // ── Load or compile guest ──
    let program = load_or_compile_guest(target_dir);

    // ── Build prover ──
    status("Building prover...");
    let prove_fn = guest::build_prover_prove_decrypt(program, prover_pp);

    // ── Prove each record ──
    let mut results: Vec<RecordResult> = Vec::new();

    for (i, rec) in session.records.iter().enumerate() {
        status(&format!(
            "Proving record {}/{} ({})...",
            i + 1,
            session.records.len(),
            rec.direction
        ));

        let ciphertext = match hex::decode(&rec.ciphertext) {
            Ok(c) => c,
            Err(e) => fail(&format!("Invalid ciphertext hex at record {}: {}", i, e), output_path),
        };

        let direction: u8 = match rec.direction.as_str() {
            "ServerToClient" => 0,
            "ClientToServer" => 1,
            other => fail(&format!("Unknown direction '{}' at record {}", other, i), output_path),
        };

        let expected_plaintext = match hex::decode(&rec.expected.plaintext_hex) {
            Ok(p) => p,
            Err(e) => fail(&format!("Invalid expected plaintext hex at record {}: {}", i, e), output_path),
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
            prove_fn(public.clone(), PrivateInput::new(captured_priv_keys.clone()));

        if io_device.panic {
            fail(
                &format!("Record {}: guest panicked (decryption or assertion failed)", i),
                output_path,
            );
        }

        let proof_valid = !io_device.panic;

        status(&format!(
            "  Record {}: {} bytes plaintext, proof valid={}",
            i,
            output.len(),
            proof_valid
        ));

        results.push(RecordResult {
            index: i,
            direction: rec.direction.clone(),
            algorithm: rec.expected.algorithm.clone(),
            plaintext_hex: hex::encode(&output),
            plaintext_bytes: output.len(),
            proof_valid,
        });
    }

    // ── Write output ──
    let out = Output {
        ok: true,
        error: None,
        name: Some(session.name),
        cipher_suite: Some(session.params.negotiated_cipher_suite),
        records: Some(results),
    };

    let json = serde_json::to_string(&out).expect("failed to serialize output");
    let mut f = std::fs::File::create(output_path).expect("cannot create output file");
    f.write_all(json.as_bytes()).expect("failed to write output");

    status("Done.");
}

/// Load prover preprocessing from (in order of priority):
/// 1. Embedded data compiled into the binary (feature "embedded-preprocess")
/// 2. Cached file on disk (from previous run or --preprocess)
/// 3. Fresh generation (slow, first run only)
fn load_prover_preprocessing(
    target_dir: &str,
) -> jolt_sdk::JoltProverPreprocessing<jolt_sdk::F, jolt_sdk::Curve, jolt_sdk::PCS> {
    use jolt_sdk::Serializable;

    // 1. Try embedded data (compiled in by build.rs when JOLT_PREPROCESS_DAT is set)
    {
        status("Checking for embedded proving keys...");
        let bytes = embedded::JOLT_PROVER_PREPROCESSING_DATA;
        if !bytes.is_empty() {
            match jolt_sdk::JoltProverPreprocessing::deserialize_from_bytes(bytes) {
                Ok(pp) => {
                    status(&format!("Proving keys loaded from embedded data ({} bytes)", bytes.len()));
                    return pp;
                }
                Err(e) => {
                    status(&format!("Embedded data failed ({}), trying disk...", e));
                }
            }
        } else {
            status("No embedded data, trying disk cache...");
        }
    }

    // 2. Try disk cache
    let cache_path = format!("{}/jolt_prover_preprocessing.dat", target_dir);
    if std::path::Path::new(&cache_path).exists() {
        status("Loading cached proving keys from disk...");
        match jolt_sdk::JoltProverPreprocessing::from_file(&cache_path) {
            Ok(pp) => {
                status("Proving keys loaded from cache");
                return pp;
            }
            Err(e) => {
                status(&format!("Cache load failed ({}), regenerating...", e));
            }
        }
    }

    // 3. Generate fresh (slow)
    status("Preprocessing proving keys (first run, this takes a while)...");
    let mut program = guest::compile_prove_decrypt(target_dir);
    let shared = guest::preprocess_shared_prove_decrypt(&mut program)
        .expect("shared preprocessing failed");
    let pp = guest::preprocess_prover_prove_decrypt(shared);
    let _ = pp.save_to_target_dir(target_dir);
    status("Proving keys cached for next run");
    pp
}

/// Load guest program from embedded ELF data (skips cargo entirely).
/// Falls back to `compile_prove_decrypt` if no embedded data.
fn load_or_compile_guest(target_dir: &str) -> jolt_sdk::host::Program {
    use std::path::PathBuf;

    let elf_bytes = embedded::JOLT_GUEST_ELF_DATA;
    let elf_advice_bytes = embedded::JOLT_GUEST_ELF_COMPUTE_ADVICE_DATA;

    if !elf_bytes.is_empty() {
        status(&format!("Loading embedded guest ELF ({} bytes)...", elf_bytes.len()));

        // Extract to temp files (Jolt reads ELF from disk)
        let elf_path = PathBuf::from(target_dir).join("embedded-guest");
        let elf_advice_path = PathBuf::from(target_dir).join("embedded-guest-compute-advice");
        std::fs::create_dir_all(target_dir).ok();
        std::fs::write(&elf_path, elf_bytes).expect("failed to write embedded guest ELF");
        if !elf_advice_bytes.is_empty() {
            std::fs::write(&elf_advice_path, elf_advice_bytes)
                .expect("failed to write embedded guest ELF (compute_advice)");
        }

        // Create Program with pre-set ELFs (skips cargo build)
        let mc = guest::memory_config_prove_decrypt();
        let mut program = jolt_sdk::host::Program::new("guest");
        program.set_func("prove_decrypt");
        program.set_memory_config(mc);
        program.set_elf(elf_path);
        if !elf_advice_bytes.is_empty() {
            program.set_elf_compute_advice(elf_advice_path);
        }

        status("Guest loaded from embedded data (no cargo needed)");
        program
    } else {
        status("No embedded guest ELF, compiling with cargo...");
        guest::compile_prove_decrypt(target_dir)
    }
}

// ─── Entry point ───────────────────────────────────────────────────

fn main() {
    // Initialize rayon with a large stack to prevent overflow from nested pools
    // (arkworks scalar_mul creates rayon pools inside rayon workers).
    // RAYON_NUM_THREADS is read by rayon automatically; only configure stack here.
    rayon::ThreadPoolBuilder::new()
        .stack_size(64 * 1024 * 1024) // 64MB per thread
        .build_global()
        .unwrap_or(());

    let _ = START.set(Instant::now());
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 2 && args[1] == "--preprocess" {
        let output_dir = if args.len() >= 3 {
            &args[2]
        } else {
            "/tmp/jolt-preprocess"
        };
        run_preprocess(output_dir);
    } else if args.len() >= 3 {
        let session_path = &args[1];
        let output_path = &args[2];
        run_prove(session_path, output_path);
    } else {
        eprintln!("Usage:");
        eprintln!("  jolt_prove --preprocess <output_dir>     Generate and save proving keys");
        eprintln!("  jolt_prove <session.json> <output.json>  Prove TLS decryption");
        std::process::exit(1);
    }
}
