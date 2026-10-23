//! The only crate that names an OpenMLS crypto provider (open question Q1). identity,
//! client and ds take their primitives from here, so swapping providers is a diff in
//! this file and nowhere else. `deny.toml` bans the provider crates everywhere else.
//!
//! Two providers, one picked at compile time: `rustcrypto` (default) and `libcrux`.
//! `libcrux` wins if both are on, which is how CI runs the suite twice.

#[cfg(not(any(feature = "rustcrypto", feature = "libcrux")))]
compile_error!("enable a crypto provider: feature `rustcrypto` or `libcrux`");

mod keys;
#[cfg(feature = "libcrux")]
mod libcrux;

pub use keys::SignatureKeyPair;

#[cfg(feature = "libcrux")]
pub use libcrux::{Crypto, Provider, SUITE};

/// Hashing, signatures, HPKE, AEAD and randomness.
#[cfg(all(feature = "rustcrypto", not(feature = "libcrux")))]
pub type Crypto = openmls_rust_crypto::RustCrypto;

/// Crypto, randomness and in-memory MLS storage in one `OpenMlsProvider`.
#[cfg(all(feature = "rustcrypto", not(feature = "libcrux")))]
pub type Provider = openmls_rust_crypto::OpenMlsRustCrypto;

/// Which provider this binary was built with.
pub const NAME: &str = if cfg!(feature = "libcrux") {
    "libcrux"
} else {
    "rustcrypto"
};

pub fn crypto() -> Crypto {
    Crypto::default()
}

pub fn provider() -> Provider {
    Provider::default()
}

#[cfg(test)]
mod tests;
