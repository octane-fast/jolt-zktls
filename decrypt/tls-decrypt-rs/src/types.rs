/// Shared types mirroring the TypeScript implementation.

#[cfg(feature = "guest")]
use alloc::{string::String, vec::Vec};

/// A captured TLS record (ciphertext only — keys derived separately).
pub struct RawRecord {
    pub ciphertext: Vec<u8>,
    pub record_number: u32,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    ServerToClient,
    ClientToServer,
}

impl Direction {
    pub fn label(&self) -> &'static str {
        match self {
            Direction::ServerToClient => "S→C",
            Direction::ClientToServer => "C→S",
        }
    }
}

/// Parameters needed to derive traffic keys from the handshake.
pub struct KeyDerivationParams {
    /// Client ephemeral private keys, keyed by curve name ("X25519", "P-256", "P-384").
    pub captured_priv_keys: Vec<(String, Vec<u8>)>,
    /// Negotiated cipher suite name (e.g. "TLS_CHACHA20_POLY1305_SHA256").
    pub negotiated_cipher_suite: String,
    /// Raw handshake messages in order: ClientHello, ServerHello, ...
    pub handshake_msgs: Vec<Vec<u8>>,
}

/// Derived TLS 1.3 traffic keys for one direction.
pub struct DerivedKeys {
    pub server_enc_key: Vec<u8>,
    pub server_iv: Vec<u8>,
    pub client_enc_key: Vec<u8>,
    pub client_iv: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub shared_secret: Vec<u8>,
    pub server_pub_key: Vec<u8>,
    pub key_type: String,
}

/// Result of a successful AEAD decryption.
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub algorithm: String,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
}
