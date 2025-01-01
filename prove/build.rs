use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut embeds = Vec::new();

    // Embed preprocessing data
    embed_env("JOLT_PREPROCESS_DAT", "JOLT_PROVER_PREPROCESSING_DATA", &out_dir, &mut embeds);

    // Embed guest ELF (normal)
    embed_env("JOLT_GUEST_ELF", "JOLT_GUEST_ELF_DATA", &out_dir, &mut embeds);

    // Embed guest ELF (compute_advice)
    embed_env("JOLT_GUEST_ELF_ADVICE", "JOLT_GUEST_ELF_COMPUTE_ADVICE_DATA", &out_dir, &mut embeds);

    if embeds.is_empty() {
        write_placeholder(&out_dir);
    } else {
        for msg in &embeds {
            println!("cargo:warning={}", msg);
        }
    }
}

fn embed_env(env_var: &str, static_name: &str, out_dir: &PathBuf, messages: &mut Vec<String>) {
    if let Ok(path) = env::var(env_var) {
        let path = PathBuf::from(&path);
        if path.exists() {
            let data = std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
            let rs_code = format!("pub static {}: &[u8] = &{:?};\n", static_name, data);
            // Append to the shared file
            let file = out_dir.join("embedded_data.rs");
            let mut existing = std::fs::read_to_string(&file).unwrap_or_default();
            existing.push_str(&rs_code);
            std::fs::write(&file, existing).expect("failed to write embedded_data.rs");
            messages.push(format!("Embedded {} = {} bytes from {}", static_name, data.len(), path.display()));
        } else {
            println!("cargo:warning={}={} not found", env_var, path.display());
            append_empty(out_dir, static_name);
        }
    } else {
        append_empty(out_dir, static_name);
    }
}

fn append_empty(out_dir: &PathBuf, static_name: &str) {
    let file = out_dir.join("embedded_data.rs");
    let mut existing = std::fs::read_to_string(&file).unwrap_or_default();
    existing.push_str(&format!("pub static {}: &[u8] = &[];\n", static_name));
    std::fs::write(&file, existing).expect("failed to write embedded_data.rs");
}

fn write_placeholder(out_dir: &PathBuf) {
    let rs_code = concat!(
        "pub static JOLT_PROVER_PREPROCESSING_DATA: &[u8] = &[];\n",
        "pub static JOLT_GUEST_ELF_DATA: &[u8] = &[];\n",
        "pub static JOLT_GUEST_ELF_COMPUTE_ADVICE_DATA: &[u8] = &[];\n",
    );
    std::fs::write(out_dir.join("embedded_data.rs"), rs_code)
        .expect("failed to write embedded_data.rs");
}
