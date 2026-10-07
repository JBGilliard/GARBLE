//! ML-DSA-87 for `tlog` checkpoints. `tlog` names the traits; this is the only place
//! that knows the scheme.

use anyhow::{Result, anyhow};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer as _};

use crate::SCHEME;

/// The DS's checkpoint signing key under its origin name.
pub struct LogSigner {
    name: String,
    keys: SignatureKeyPair,
}

impl LogSigner {
    pub fn new(name: &str, keys: SignatureKeyPair) -> Self {
        Self {
            name: name.into(),
            keys,
        }
    }
}

impl tlog::Signer for LogSigner {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> &[u8] {
        self.keys.public()
    }

    fn sign(&self, msg: &[u8]) -> tlog::Result<Vec<u8>> {
        self.keys
            .sign(msg)
            .map_err(|e| tlog::Error::Sign(format!("{e:?}")))
    }
}

pub struct LogVerifier {
    name: String,
    key: Vec<u8>,
}

impl LogVerifier {
    pub fn new(name: &str, key: &[u8]) -> Self {
        Self {
            name: name.into(),
            key: key.to_vec(),
        }
    }
}

impl tlog::Verifier for LogVerifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> &[u8] {
        &self.key
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        RustCrypto::default()
            .verify_signature(SCHEME, msg, &self.key, sig)
            .is_ok()
    }
}

/// The origin doubles as the signed-note key name, which has rules.
pub fn checked_origin(origin: &str) -> Result<()> {
    if origin.is_empty() || origin.contains(char::is_whitespace) || origin.contains('+') {
        return Err(anyhow!(
            "log origin {origin:?} can't be a signed-note key name"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlog::{Checkpoint, open_checkpoint, sign_checkpoint};

    fn cp(size: u64) -> Checkpoint {
        Checkpoint {
            origin: "garble-ds".into(),
            size,
            root: [3; 32],
        }
    }

    #[test]
    fn ml_dsa_checkpoints_verify_and_reject_other_keys() {
        let signer = LogSigner::new("garble-ds", SignatureKeyPair::new(SCHEME).unwrap());
        let note = sign_checkpoint(&cp(9), &signer).unwrap();
        let good = LogVerifier::new("garble-ds", tlog::Signer::public_key(&signer));
        assert_eq!(open_checkpoint(&note, "garble-ds", &good).unwrap(), cp(9));

        let other = SignatureKeyPair::new(SCHEME).unwrap();
        let bad = LogVerifier::new("garble-ds", other.public());
        assert!(open_checkpoint(&note, "garble-ds", &bad).is_err());

        // Flip one bit of the signed size: the signature no longer covers it.
        let tampered = String::from_utf8(note)
            .unwrap()
            .replacen("\n9\n", "\n8\n", 1);
        assert!(open_checkpoint(tampered.as_bytes(), "garble-ds", &good).is_err());
    }

    #[test]
    fn origins_must_be_usable_as_key_names() {
        assert!(checked_origin("garble-ds").is_ok());
        for bad in ["", "a b", "a+b", "a\nb"] {
            assert!(checked_origin(bad).is_err(), "{bad:?}");
        }
    }
}
