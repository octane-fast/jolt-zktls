#![cfg_attr(feature = "guest", no_std)]

#[cfg(feature = "guest")]
extern crate alloc;

pub mod types;
pub mod key_derivation;
pub mod decrypt;

pub use types::*;
pub use key_derivation::derive_keys_from_handshake;
pub use decrypt::decrypt_record;
