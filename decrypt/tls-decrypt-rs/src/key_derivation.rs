/// TLS 1.3 key derivation: ECDH → HKDF → traffic keys.
///
/// Implements the TLS 1.3 key schedule (RFC 8446 §7.1):
///   shared_secret = ECDH(client_priv, server_pub)
///   early_secret  = HKDF-Extract(0, PSK or 0)
///   handshake_secret = HKDF-Extract(early_secret, shared_secret)
///   client/server handshake traffic secrets = HKDF-Expand-Label(handshake_secret, ...)
///   master_secret = HKDF-Extract(handshake_secret, 0)
///   client/server application traffic secrets = HKDF-Expand-Label(master_secret, ...)
///   key, iv = HKDF-Expand-Label(traffic_secret, "key"/"iv", ...)

#[cfg(feature = "guest")]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::types::{DerivedKeys, KeyDerivationParams};

/// Hash algorithm used by the cipher suite.
enum HashAlgo {
    Sha256,
    Sha384,
}

impl HashAlgo {
    fn hash_len(&self) -> usize {
        match self {
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha384 => 48,
        }
    }
}

/// Derives TLS 1.3 traffic keys from scratch.
pub fn derive_keys_from_handshake(
    params: &KeyDerivationParams,
) -> Result<DerivedKeys, String> {
    if params.captured_priv_keys.is_empty()
        || params.negotiated_cipher_suite.is_empty()
        || params.handshake_msgs.len() < 2
    {
        return Err("Insufficient handshake data".into());
    }

    let hash_algo = match_cipher_suite(&params.negotiated_cipher_suite)?;
    let hash_len = hash_algo.hash_len();

    // Step 1: Parse ServerHello to extract server public key
    //   handshake_msgs[1] = [msg_type(1), length(3), body...] — strip 4-byte header
    let sh = &params.handshake_msgs[1];
    let server_hello_body = if sh.len() > 4 && sh[0] == 0x02 { &sh[4..] } else { sh };
    let (server_pub_key, key_type) = parse_server_hello_key_share(server_hello_body)?;

    // Step 2: Find the matching client private key
    let priv_key_bytes = params
        .captured_priv_keys
        .iter()
        .find(|(k, _)| k == &key_type)
        .map(|(_, v): &(String, Vec<u8>)| v.as_slice())
        .ok_or_else(|| format!("No captured private key for {}", key_type))?;

    // Step 3: ECDH shared secret
    let shared_secret = if key_type.as_str().eq("X25519") {
        let secret = StaticSecret::from(<[u8; 32]>::try_from(priv_key_bytes).map_err(|_| "Bad privkey len")?);
        let pub_key = X25519PublicKey::from(<[u8; 32]>::try_from(server_pub_key.as_slice()).map_err(|_| "Bad pubkey len")?);
        secret.diffie_hellman(&pub_key).to_bytes().to_vec()
    } else {
        return Err(format!("Unsupported key type: {}", key_type));
    };

    // Step 4: Hash the handshake messages up to ServerHello (for handshake keys)
    let hs_hash = hash_concat(&hash_algo, &params.handshake_msgs[..2]);

    // empty_hash = Hash("") — used as context for "derived" labels per RFC 8446
    let empty_hash = hash_concat(&hash_algo, &[] as &[Vec<u8>]);

    // Step 5: Derive handshake traffic keys
    //   early_secret = HKDF-Extract(0, PSK or 0)
    let early_secret = hkdf_extract_zero(&hash_algo, hash_len);

    //   derived1 = Derive-Secret(early_secret, "derived", Hash(""))
    let derived1 = hkdf_expand_label(&hash_algo, &early_secret, b"derived", &empty_hash, hash_len);

    //   handshake_secret = HKDF-Extract(derived1, shared_secret)
    let handshake_secret = hkdf_extract(&hash_algo, &derived1, &shared_secret);

    //   derived2 = Derive-Secret(handshake_secret, "derived", Hash(""))
    let derived_secret = hkdf_expand_label(&hash_algo, &handshake_secret, b"derived", &empty_hash, hash_len);

    //   master_secret = HKDF-Extract(derived2, 0)
    let _client_hs_traffic = hkdf_expand_label(
        &hash_algo,
        &handshake_secret,
        b"c hs traffic",
        &hs_hash,
        hash_len,
    );
    let _server_hs_traffic = hkdf_expand_label(
        &hash_algo,
        &handshake_secret,
        b"s hs traffic",
        &hs_hash,
        hash_len,
    );

    // Step 6: Derive application traffic keys
    //   master_secret = HKDF-Extract(derived_secret, 0)
    let master_secret = hkdf_extract_zero_salt(&hash_algo, &derived_secret, hash_len);

    //   Hash full handshake transcript
    let full_hash = hash_concat(&hash_algo, &params.handshake_msgs);

    let client_ap_traffic = hkdf_expand_label(
        &hash_algo,
        &master_secret,
        b"c ap traffic",
        &full_hash,
        hash_len,
    );
    let server_ap_traffic = hkdf_expand_label(
        &hash_algo,
        &master_secret,
        b"s ap traffic",
        &full_hash,
        hash_len,
    );

    // Step 7: Derive actual keys and IVs
    let server_enc_key = hkdf_expand_label(&hash_algo, &server_ap_traffic, b"key", b"", aead_key_len(&params.negotiated_cipher_suite));
    let server_iv = hkdf_expand_label(&hash_algo, &server_ap_traffic, b"iv", b"", 12);
    let client_enc_key = hkdf_expand_label(&hash_algo, &client_ap_traffic, b"key", b"", aead_key_len(&params.negotiated_cipher_suite));
    let client_iv = hkdf_expand_label(&hash_algo, &client_ap_traffic, b"iv", b"", 12);

    // The "master secret" we return is the application traffic secret (for verification)
    // Use server_ap_traffic as the representative master secret
    let master_secret_out = hkdf_expand_label(&hash_algo, &master_secret, b"res master", b"", hash_len);

    Ok(DerivedKeys {
        server_enc_key,
        server_iv,
        client_enc_key,
        client_iv,
        master_secret: master_secret_out,
        shared_secret,
        server_pub_key,
        key_type,
    })
}

fn match_cipher_suite(suite: &str) -> Result<HashAlgo, String> {
    if suite.eq("TLS_CHACHA20_POLY1305_SHA256") || suite.eq("TLS_AES_128_GCM_SHA256") {
        Ok(HashAlgo::Sha256)
    } else if suite.eq("TLS_AES_256_GCM_SHA384") {
        Ok(HashAlgo::Sha384)
    } else {
        Err(format!("Unsupported cipher suite: {}", suite))
    }
}

fn aead_key_len(suite: &str) -> usize {
    if suite.eq("TLS_AES_128_GCM_SHA256") {
        16
    } else {
        32
    }
}

// ─── HKDF helpers ─────────────────────────────────────────────────

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
fn hkdf_extract(algo: &HashAlgo, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match algo {
        HashAlgo::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC key");
            mac.update(ikm);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgo::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(salt).expect("HMAC key");
            mac.update(ikm);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// HKDF-Extract with salt=0 (empty) and IKM = 0x00 * hash_len
fn hkdf_extract_zero(algo: &HashAlgo, hash_len: usize) -> Vec<u8> {
    let zero_ikm = vec![0u8; hash_len];
    hkdf_extract(algo, &[], &zero_ikm)
}

/// HKDF-Extract with given salt and IKM = 0x00 * hash_len
fn hkdf_extract_zero_salt(algo: &HashAlgo, salt: &[u8], hash_len: usize) -> Vec<u8> {
    let zero_ikm = vec![0u8; hash_len];
    hkdf_extract(algo, salt, &zero_ikm)
}

/// HKDF-Expand-Label as defined in RFC 8446 §7.1.
///
/// HkdfLabel = struct {
///     uint16 length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255>;
/// };
fn hkdf_expand_label(
    algo: &HashAlgo,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    // Build the info = HkdfLabel
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut out = vec![0u8; length];
    match algo {
        HashAlgo::Sha256 => {
            let hk = Hkdf::<Sha256>::from_prk(secret).expect("bad PRK");
            hk.expand(&info, &mut out).expect("expand failed");
        }
        HashAlgo::Sha384 => {
            let hk = Hkdf::<Sha384>::from_prk(secret).expect("bad PRK");
            hk.expand(&info, &mut out).expect("expand failed");
        }
    }
    out
}

// ─── Hash helper ──────────────────────────────────────────────────

fn hash_concat(algo: &HashAlgo, msgs: &[Vec<u8>]) -> Vec<u8> {
    match algo {
        HashAlgo::Sha256 => {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            for msg in msgs {
                hasher.update(msg);
            }
            hasher.finalize().to_vec()
        }
        HashAlgo::Sha384 => {
            use sha2::Digest;
            let mut hasher = Sha384::new();
            for msg in msgs {
                hasher.update(msg);
            }
            hasher.finalize().to_vec()
        }
    }
}

// ─── ServerHello parsing ──────────────────────────────────────────

/// Parses a TLS ServerHello body to extract the key_share extension's public key.
///
/// ServerHello body format (after the 4-byte handshake header):
///   legacy_version (2) + random (32) + session_id_length (1) + session_id (var)
///   + cipher_suite (2) + compression_method (1) + extensions_length (2) + extensions
fn parse_server_hello_key_share(body: &[u8]) -> Result<(Vec<u8>, String), String> {
    let mut pos = 0;

    // legacy_version (2 bytes)
    pos += 2;
    // random (32 bytes)
    pos += 32;

    // session_id
    if pos >= body.len() {
        return Err("Truncated ServerHello".into());
    }
    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;

    // cipher_suite (2) + compression (1)
    pos += 3;

    // extensions_length
    if pos + 2 > body.len() {
        return Err("Truncated extensions length".into());
    }
    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    if pos + ext_len > body.len() {
        return Err("Truncated extensions".into());
    }
    let extensions = &body[pos..pos + ext_len];

    // Parse extensions looking for key_share (0x0033)
    let mut ep = 0;
    while ep + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[ep], extensions[ep + 1]]);
        let ext_len = u16::from_be_bytes([extensions[ep + 2], extensions[ep + 3]]) as usize;
        ep += 4;

        if ep + ext_len > extensions.len() {
            return Err("Truncated extension".into());
        }

        if ext_type == 0x0033 {
            // key_share
            let ks = &extensions[ep..ep + ext_len];
            if ks.len() < 4 {
                return Err("Truncated key_share".into());
            }
            let named_group = u16::from_be_bytes([ks[0], ks[1]]);
            let key_len = u16::from_be_bytes([ks[2], ks[3]]) as usize;
            if ks.len() < 4 + key_len {
                return Err("Truncated key_share key".into());
            }
            let key = &ks[4..4 + key_len];

            let key_type = match named_group {
                0x001d => "X25519",
                0x0017 => "P-256",
                0x0018 => "P-384",
                _ => return Err(format!("Unsupported named group: 0x{:04x}", named_group)),
            };

            return Ok((key.to_vec(), key_type.to_string()));
        }

        ep += ext_len;
    }

    Err("No key_share extension in ServerHello".into())
}
