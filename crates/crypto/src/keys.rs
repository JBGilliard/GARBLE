use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::{Signer, SignerError},
    types::{CryptoError, SignatureScheme},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A signing key that signs through the selected provider.
///
/// Replaces `openmls_basic_credential::SignatureKeyPair`, which hardwires RustCrypto's
/// ML-DSA and would have kept every signature off libcrux. The JSON is the same shape,
/// so existing dev key files still load.
#[derive(Serialize, Deserialize)]
pub struct SignatureKeyPair {
    private: Vec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

impl SignatureKeyPair {
    pub fn new(signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        let (private, public) = crate::crypto().signature_key_gen(signature_scheme)?;
        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn to_public_vec(&self) -> Vec<u8> {
        self.public.clone()
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        crate::crypto()
            .sign(self.signature_scheme, payload, &self.private)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

impl Drop for SignatureKeyPair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl std::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &"***")
            .field("public", &self.public)
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}
