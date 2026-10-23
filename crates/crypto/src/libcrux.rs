//! GARBLE's OpenMLS crypto provider over libcrux, for the one ciphersuite we run.
//!
//! `openmls_libcrux_crypto` 0.4.0 has no ML-DSA (Q1), so this wraps it: hashing, HMAC,
//! HKDF, AES-256-GCM, HPKE (ML-KEM-1024 via `libcrux-ml-kem` inside `hpke-rs-libcrux`)
//! and the DRBG are upstream's, all libcrux. ML-DSA-87 is ours, over `libcrux-ml-dsa`.
//! Nothing is delegated to RustCrypto. Not a validated module (docs/idea-v2.md §1).
//!
//! Everything outside [`SUITE`]'s primitives is refused rather than forwarded, so a
//! stray `HashType` or HPKE config fails loudly instead of running on code we never
//! exercised.

use libcrux_ml_dsa::ml_dsa_87::{
    self, MLDSA87Signature, MLDSA87SigningKey, MLDSA87VerificationKey,
};
use openmls_libcrux_crypto::{CryptoProvider, RandError};
use openmls_traits::{
    OpenMlsProvider,
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKeyPair, KemOutput, SignatureScheme,
    },
};
use tls_codec::SecretVLBytes;
use zeroize::Zeroize;

use openmls_memory_storage::MemoryStorage;

/// `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`, the 0x0907 of `proto::CIPHERSUITE`
/// (a test keeps the two in step).
pub const SUITE: Ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

const SEED_LEN: usize = 32;

pub struct Crypto(CryptoProvider);

impl Crypto {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(Self(CryptoProvider::new()?))
    }
}

impl Default for Crypto {
    fn default() -> Self {
        // No OS entropy means no key, nonce or KEM share we could trust.
        Self::new().expect("OS entropy source unavailable")
    }
}

impl std::fmt::Debug for Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Crypto(libcrux)")
    }
}

fn sha384_only(h: HashType) -> Result<(), CryptoError> {
    match h {
        HashType::Sha2_384 => Ok(()),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

fn suite_hpke(c: &HpkeConfig) -> Result<(), CryptoError> {
    let want = SUITE.hpke_config();
    if (c.0, c.1, c.2) == (want.0, want.1, want.2) {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedCiphersuite)
    }
}

impl OpenMlsCrypto for Crypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if ciphersuite == SUITE {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedCiphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![SUITE]
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        sha384_only(hash_type)?;
        self.0.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        sha384_only(hash_type)?;
        self.0.hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        sha384_only(hash_type)?;
        self.0.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        sha384_only(hash_type)?;
        self.0.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes256_only(alg)?;
        self.0.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes256_only(alg)?;
        self.0.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    /// The private half is the 32-byte FIPS 204 seed (ξ), not the expanded key: same
    /// format as `openmls_rust_crypto`, so a key file moves between providers.
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        mldsa87_only(alg)?;
        let mut seed = self
            .0
            .random_array::<SEED_LEN>()
            .map_err(|_| CryptoError::InsufficientRandomness)?;
        let kp = ml_dsa_87::generate_key_pair(seed);
        let public = kp.verification_key.as_ref().to_vec();
        let private = seed.to_vec();
        seed.zeroize();
        Ok((private, public))
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        mldsa87_only(alg)?;
        let pk =
            MLDSA87VerificationKey::new(pk.try_into().map_err(|_| CryptoError::InvalidLength)?);
        let sig = MLDSA87Signature::new(
            signature
                .try_into()
                .map_err(|_| CryptoError::InvalidLength)?,
        );
        // Empty context: the MLS draft signs the SignContent as-is, no ML-DSA context string.
        ml_dsa_87::verify(&pk, data, &[], &sig).map_err(|_| CryptoError::InvalidSignature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        mldsa87_only(alg)?;
        let mut seed: [u8; SEED_LEN] = key.try_into().map_err(|_| CryptoError::InvalidLength)?;
        let mut kp = ml_dsa_87::generate_key_pair(seed);
        seed.zeroize();
        let mut rnd = self
            .0
            .random_array::<32>()
            .map_err(|_| CryptoError::InsufficientRandomness)?;
        let sig = ml_dsa_87::sign(&kp.signing_key, data, &[], rnd);
        rnd.zeroize();
        scrub(&mut kp.signing_key);
        sig.map(|s| s.as_ref().to_vec())
            .map_err(|_| CryptoError::SigningError)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        suite_hpke(&config)?;
        self.0.hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        suite_hpke(&config)?;
        self.0.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        suite_hpke(&config)?;
        self.0
            .hpke_setup_sender_and_export(config, pk_r, info, exporter_context, exporter_length)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        suite_hpke(&config)?;
        self.0.hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        suite_hpke(&config)?;
        self.0.derive_hpke_keypair(config, ikm)
    }
}

impl OpenMlsRand for Crypto {
    type Error = RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.0.random_array()
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.0.random_vec(len)
    }
}

fn aes256_only(alg: AeadType) -> Result<(), CryptoError> {
    match alg {
        AeadType::Aes256Gcm => Ok(()),
        _ => Err(CryptoError::UnsupportedAeadAlgorithm),
    }
}

fn mldsa87_only(alg: SignatureScheme) -> Result<(), CryptoError> {
    match alg {
        SignatureScheme::MLDSA87 => Ok(()),
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

// libcrux's key types don't zeroize on drop; the expanded key is the thing worth wiping.
fn scrub(k: &mut MLDSA87SigningKey) {
    k.as_ref_mut().zeroize();
}

/// Crypto, randomness and in-memory MLS storage in one `OpenMlsProvider`.
#[derive(Default)]
pub struct Provider {
    crypto: Crypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = Crypto;
    type RandProvider = Crypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &Crypto {
        &self.crypto
    }

    fn rand(&self) -> &Crypto {
        &self.crypto
    }
}
