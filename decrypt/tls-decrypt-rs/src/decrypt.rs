/// TLS 1.3 AEAD record decryption.
///
/// Mirrors the TypeScript `decryptRecord`:
///   1. Derive nonce = fixed_iv ⊕ seq_num  (big-endian, 12 bytes)
///   2. Construct AAD = TLS record header  (type=0x17, ver=0x0303, length)
///   3. Split ciphertext → encrypted_data + auth_tag (16 bytes)
///   4. AEAD-Decrypt (ChaCha20-Poly1305 or AES-GCM)
///   5. Strip TLS 1.3 inner content type byte

#[cfg(feature = "guest")]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::Aead};
use chacha20poly1305::ChaCha20Poly1305;

use crate::types::{DecryptResult, Direction, RawRecord};

/// Decrypt a TLS 1.3 record — derives keys from handshake, then AEAD-decrypts.
///
/// TypeScript signature: `decryptRecord(rec: RawRecord, params: KeyDerivationParams)`
pub fn decrypt_record(
    rec: &RawRecord,
    params: &crate::types::KeyDerivationParams,
) -> Result<DecryptResult, String> {
    let derived = crate::key_derivation::derive_keys_from_handshake(params)?;

    let (enc_key, fixed_iv) = match rec.direction {
        Direction::ServerToClient => (&derived.server_enc_key, &derived.server_iv),
        Direction::ClientToServer => (&derived.client_enc_key, &derived.client_iv),
    };

    decrypt_with_key(rec, enc_key, fixed_iv)
}

/// Low-level decrypt with explicit key/IV (no derivation).
pub fn decrypt_with_key(
    rec: &RawRecord,
    enc_key: &[u8],
    fixed_iv: &[u8],
) -> Result<DecryptResult, String> {
    // 1. Derive nonce = fixed_iv XOR record_sequence_number
    let nonce = derive_nonce(fixed_iv, rec.record_number);

    // 2. Construct AAD = TLS 1.3 record header
    let ct_len = rec.ciphertext.len();
    let aad: Vec<u8> = vec![
        0x17, // APPLICATION_DATA (outer type in TLS 1.3)
        0x03, 0x03, // version
        ((ct_len >> 8) & 0xFF) as u8,
        (ct_len & 0xFF) as u8,
    ];

    // 3. Split ciphertext → encrypted_data + auth_tag (last 16 bytes)
    if rec.ciphertext.len() < 16 {
        return Err("Ciphertext too short".into());
    }
    let auth_tag = &rec.ciphertext[rec.ciphertext.len() - 16..];
    let enc_data = &rec.ciphertext[..rec.ciphertext.len() - 16];

    // 4. Try decryption algorithms based on key length
    let candidates: &[(&str, usize)] = match enc_key.len() {
        32 => &[("chacha20-poly1305", 32), ("aes-256-gcm", 32)],
        16 => &[("aes-128-gcm", 16)],
        _ => return Err(format!("Unsupported key length: {}", enc_key.len())),
    };

    for &(algo, _) in candidates {
        if let Ok(plaintext_full) = try_decrypt(algo, enc_key, &nonce, &aad, enc_data, auth_tag) {
            if plaintext_full.is_empty() {
                return Err("Empty plaintext after decryption".into());
            }
            let plaintext = plaintext_full[..plaintext_full.len() - 1].to_vec();
            return Ok(DecryptResult {
                plaintext,
                algorithm: algo.to_string(),
                nonce,
                aad,
            });
        }
    }

    Err("Decryption failed with all candidate algorithms".into())
}

fn derive_nonce(fixed_iv: &[u8], record_number: u32) -> Vec<u8> {
    let mut nonce = fixed_iv.to_vec();
    // XOR the record number into the last 4 bytes (big-endian)
    let rn = record_number;
    let len = nonce.len();
    if len >= 4 {
        nonce[len - 4] ^= ((rn >> 24) & 0xFF) as u8;
        nonce[len - 3] ^= ((rn >> 16) & 0xFF) as u8;
        nonce[len - 2] ^= ((rn >> 8) & 0xFF) as u8;
        nonce[len - 1] ^= (rn & 0xFF) as u8;
    }
    nonce
}

fn try_decrypt(
    algo: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    enc_data: &[u8],
    auth_tag: &[u8],
) -> Result<Vec<u8>, String> {
    // Combine encrypted data + auth tag for the AEAD crates
    let mut ciphertext_with_tag = enc_data.to_vec();
    ciphertext_with_tag.extend_from_slice(auth_tag);

    if algo.eq("chacha20-poly1305") {
        use chacha20poly1305::Nonce;
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("ChaCha20 key error: {}", e))?;
        let nonce = Nonce::from_slice(nonce);
        use chacha20poly1305::aead::Payload;
        cipher
            .decrypt(nonce, Payload {
                msg: &ciphertext_with_tag,
                aad,
            })
            .map_err(|_| "ChaCha20-Poly1305 auth failed".to_string())
    } else if algo.eq("aes-256-gcm") {
        use aes_gcm::Nonce;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("AES-256 key error: {}", e))?;
        let nonce = Nonce::from_slice(nonce);
        use aes_gcm::aead::Payload;
        cipher
            .decrypt(nonce, Payload {
                msg: &ciphertext_with_tag,
                aad,
            })
            .map_err(|_| "AES-256-GCM auth failed".to_string())
    } else if algo.eq("aes-128-gcm") {
        use aes_gcm::Nonce;
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| format!("AES-128 key error: {}", e))?;
        let nonce = Nonce::from_slice(nonce);
        use aes_gcm::aead::Payload;
        cipher
            .decrypt(nonce, Payload {
                msg: &ciphertext_with_tag,
                aad,
            })
            .map_err(|_| "AES-128-GCM auth failed".to_string())
    } else {
        Err(format!("Unknown algorithm: {}", algo))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Direction;

    #[test]
    fn round_trip_chacha20() {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};

        let key = [0x42u8; 32];
        let fixed_iv = [0x01u8; 12];
        let plaintext = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        // TLS 1.3 encrypt: plaintext || content_type(0x17)
        let mut plaintext_with_ct = plaintext.to_vec();
        plaintext_with_ct.push(0x17);

        let nonce_bytes = fixed_iv; // XOR with 0 = unchanged
        let ct_len = plaintext_with_ct.len() + 16;
        let aad: Vec<u8> = vec![0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xFF) as u8];

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        use chacha20poly1305::aead::Payload;
        let ciphertext = cipher.encrypt(nonce, Payload {
            msg: &plaintext_with_ct,
            aad: &aad,
        }).unwrap();

        let rec = RawRecord {
            ciphertext,
            record_number: 0,
            direction: Direction::ServerToClient,
        };

        let result = decrypt_with_key(&rec, &key, &fixed_iv).unwrap();
        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.algorithm, "chacha20-poly1305");
    }

    #[test]
    fn round_trip_aes256gcm() {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

        let key = [0x37u8; 32];
        let fixed_iv = [0x09u8; 12];
        let plaintext = b"Hello from TLS 1.3!";

        let mut plaintext_with_ct = plaintext.to_vec();
        plaintext_with_ct.push(0x17);

        let nonce_bytes = fixed_iv;
        let ct_len = plaintext_with_ct.len() + 16;
        let aad: Vec<u8> = vec![0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xFF) as u8];

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        use aes_gcm::aead::Payload;
        let ciphertext = cipher.encrypt(nonce, Payload {
            msg: &plaintext_with_ct,
            aad: &aad,
        }).unwrap();

        let rec = RawRecord {
            ciphertext,
            record_number: 0,
            direction: Direction::ServerToClient,
        };

        let result = decrypt_with_key(&rec, &key, &fixed_iv).unwrap();
        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.algorithm, "aes-256-gcm");
    }

    #[test]
    fn nonce_derivation() {
        let fixed_iv = [0x00u8; 12];
        let nonce = derive_nonce(&fixed_iv, 1);
        assert_eq!(nonce[11], 1);

        let fixed_iv = [0xFFu8; 12];
        let nonce = derive_nonce(&fixed_iv, 0x01020304);
        assert_eq!(nonce[11], 0xFF ^ 0x04);
        assert_eq!(nonce[10], 0xFF ^ 0x03);
        assert_eq!(nonce[9],  0xFF ^ 0x02);
        assert_eq!(nonce[8],  0xFF ^ 0x01);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let fixed_iv = [0x01u8; 12];

        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};

        let mut pt = b"test".to_vec();
        pt.push(0x17);
        let nonce = Nonce::from_slice(&fixed_iv);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        use chacha20poly1305::aead::Payload;
        let ct = cipher.encrypt(nonce, Payload { msg: &pt, aad: &[0x17, 0x03, 0x03, 0x00, 0x14] }).unwrap();

        let rec = RawRecord {
            ciphertext: ct,
            record_number: 0,
            direction: Direction::ServerToClient,
        };

        assert!(decrypt_with_key(&rec, &wrong_key, &fixed_iv).is_err());
    }
}
