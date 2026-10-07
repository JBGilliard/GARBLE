//! Identity and attributes (architecture §3, §4.2, §4.3): turns signed bytes into a
//! verified `policy::Subject`.
//!
//! Seams a deployment swaps (idea-v1 §3): [`KeyStore`] (file for dev; PIV/HSM later)
//! and [`AttributeIssuer`] ([`MockIssuer`] for dev; DISS / Scattered Castles later).
//!
//! ponytail: no CAC enrollment and no EA-signed identity credential yet (the MLS
//! credential is the bare user ID); the trust bundle is an unsigned JSON file with
//! sample registers.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use markings::{Clearance, Country, Registers, parse};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer, types::SignatureScheme,
};
use policy::Subject;
use proto::{AttributeBody, AttributeCredential, Bytes, CustodianRef, WIRE_VERSION};
use serde::{Deserialize, Serialize};

pub mod archive;
pub mod log;
pub mod room;

pub const SCHEME: SignatureScheme = SignatureScheme::MLDSA87;

/// The delivery service's transparency-log identity: the origin line of its checkpoints
/// and the ML-DSA-87 key that signs them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRef {
    pub origin: String,
    pub key: Bytes,
}

/// What every party loads at start and refuses to run without (§4.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBundle {
    pub issuer_key: Bytes,
    /// Missing means rooms can't be created (policy fails closed), not that they're
    /// created unarchived.
    #[serde(default)]
    pub custodian: Option<CustodianRef>,
    #[serde(default)]
    pub records_officers: Vec<String>,
    /// Missing means the DS refuses to start and no client accepts a checkpoint.
    #[serde(default)]
    pub log: Option<LogRef>,
}

impl TrustBundle {
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read(path).with_context(|| format!("trust bundle {}", path.display()))?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub fn registers(&self) -> Registers {
        Registers::sample()
    }

    /// Checks checkpoints against the log key this bundle names.
    pub fn log_verifier(&self) -> Result<log::LogVerifier> {
        let log = self.log.as_ref().context("trust bundle names no log key")?;
        Ok(log::LogVerifier::new(&log.origin, &log.key.0))
    }

    /// Canonical bytes of the marking `cred`'s access string describes: what a log
    /// entry about its subject carries. The credential must already be verified.
    pub fn access_marking(&self, cred: &AttributeCredential) -> Result<Vec<u8>> {
        Ok(parse(&cred.body.access, &self.registers())?.canonical_bytes()?)
    }

    /// May `reader` see a log entry marked `marking` (canonical bytes)? An entry whose
    /// marking doesn't parse is an error, which callers treat as not visible.
    pub fn check_read_log(&self, reader: &Subject, marking: &[u8]) -> Result<policy::Decision> {
        let reg = self.registers();
        let marking = markings::Marking::from_canonical(marking, &reg)?;
        Ok(policy::decide(
            reader,
            &policy::Resource::Log { registers: &reg },
            &policy::Action::ReadLog { marking: &marking },
        ))
    }

    /// Verify a credential and return the subject it describes, as of `as_of`.
    /// Expiry is left to `policy::decide`, so an expired credential yields a Subject
    /// whose decisions are denials with a precise reason.
    pub fn verify(&self, cred: &AttributeCredential, as_of: u64) -> Result<Subject> {
        let b = &cred.body;
        ensure!(b.v == WIRE_VERSION, "attribute credential version {}", b.v);
        let reg = self.registers();
        ensure!(
            b.register_version == reg.version(),
            "register version {}",
            b.register_version
        );
        RustCrypto::default()
            .verify_signature(SCHEME, &b.signed_bytes(), &self.issuer_key.0, &cred.sig.0)
            .map_err(|_| {
                anyhow::anyhow!("attribute credential for {} has a bad signature", b.user)
            })?;
        let access = parse(&b.access, &reg)?;
        Ok(Subject {
            user: b.user.clone(),
            clearance: Clearance::covering(&access, Country::new(&b.citizenship)?),
            valid_until: b.not_after,
            as_of,
        })
    }
}

/// A fresh ML-KEM-1024 archive keypair `(private, public)`. The private half belongs
/// offline with the custodian; nothing else in GARBLE ever holds it.
pub fn generate_archive_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let crypto = RustCrypto::default();
    let ikm = crypto
        .random_vec(64)
        .map_err(|e| anyhow::anyhow!("rng: {e:?}"))?;
    let kp = crypto
        .derive_hpke_keypair(archive::ARCHIVE_HPKE, &ikm)
        .map_err(|e| anyhow::anyhow!("archive keypair: {e:?}"))?;
    Ok((kp.private.as_ref().to_vec(), kp.public))
}

/// The bytes a client signs to open a session: domain-separated so a session
/// signature can never be replayed as an MLS or credential signature.
pub fn session_bytes(user: &str, nonce: &[u8]) -> Vec<u8> {
    let mut b = b"GARBLE-SESSION-v1\0".to_vec();
    b.extend_from_slice(user.as_bytes());
    b.push(0);
    b.extend_from_slice(nonce);
    b
}

pub fn verify_session(key: &[u8], user: &str, nonce: &[u8], sig: &[u8]) -> Result<()> {
    RustCrypto::default()
        .verify_signature(SCHEME, &session_bytes(user, nonce), key, sig)
        .map_err(|_| anyhow::anyhow!("bad session signature for {user}"))
}

/// Where a device's ML-DSA-87 signing key lives. The signer signs in place, so a
/// PIV card or HSM implementation never exports the private key.
pub trait KeyStore {
    type Signer: Signer;
    /// The signing key, created on first use.
    fn signer(&self) -> Result<Self::Signer>;
    fn public_key(&self) -> Result<Vec<u8>>;
}

/// Development key store: the key pair in a JSON file.
/// ponytail: plaintext on disk; OS keychain wrapping or an HSM before any pilot.
pub struct FileKeyStore {
    path: std::path::PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl KeyStore for FileKeyStore {
    type Signer = SignatureKeyPair;

    fn signer(&self) -> Result<SignatureKeyPair> {
        if self.path.exists() {
            return Ok(serde_json::from_slice(&std::fs::read(&self.path)?)?);
        }
        let k = SignatureKeyPair::new(SCHEME)?;
        std::fs::write(&self.path, serde_json::to_vec(&k)?)?;
        Ok(k)
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.signer()?.to_public_vec())
    }
}

/// The site attribute authority (§4.2): issues short-lived, signed attributes bound
/// to a user's key. Fails closed: an unknown user is an error, never empty attributes.
pub trait AttributeIssuer {
    fn issue(
        &self,
        user: &str,
        key: &[u8],
        access: &str,
        citizenship: &str,
        not_after: u64,
    ) -> Result<AttributeCredential>;
    /// The trust bundle naming this issuer's key.
    fn trust_bundle(&self) -> TrustBundle;
}

/// Development issuer: signs whatever access it's told to. Holds an ML-DSA-87 key.
#[derive(Serialize, Deserialize)]
pub struct MockIssuer {
    keys: SignatureKeyPair,
}

impl MockIssuer {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            keys: SignatureKeyPair::new(SCHEME)?,
        })
    }
}

impl AttributeIssuer for MockIssuer {
    fn trust_bundle(&self) -> TrustBundle {
        TrustBundle {
            issuer_key: Bytes(self.keys.to_public_vec()),
            custodian: None,
            records_officers: vec![],
            log: None,
        }
    }

    /// Issue a credential. `access` is in marking syntax and must parse.
    fn issue(
        &self,
        user: &str,
        key: &[u8],
        access: &str,
        citizenship: &str,
        not_after: u64,
    ) -> Result<AttributeCredential> {
        let reg = Registers::sample();
        if let Err(e) = parse(access, &reg) {
            bail!("access '{access}': {e}");
        }
        Country::new(citizenship)?;
        let body = AttributeBody {
            v: WIRE_VERSION,
            user: user.into(),
            key: Bytes(key.to_vec()),
            access: access.into(),
            citizenship: citizenship.into(),
            register_version: reg.version(),
            not_after,
        };
        let sig = self
            .keys
            .sign(&body.signed_bytes())
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(AttributeCredential {
            body,
            sig: Bytes(sig),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_keypairs_are_ml_kem_1024() {
        let (private, public) = generate_archive_keypair().unwrap();
        assert_eq!(public.len(), 1568); // ML-KEM-1024 encapsulation key
        assert!(!private.is_empty());
        assert_ne!(public, generate_archive_keypair().unwrap().1);
    }

    #[test]
    fn session_signatures_bind_user_and_nonce() {
        let k = SignatureKeyPair::new(SCHEME).unwrap();
        let sig = k.sign(&session_bytes("alice", b"n1")).unwrap();
        assert!(verify_session(k.public(), "alice", b"n1", &sig).is_ok());
        assert!(verify_session(k.public(), "mallory", b"n1", &sig).is_err());
        assert!(verify_session(k.public(), "alice", b"n2", &sig).is_err());
    }

    #[test]
    fn issued_credentials_verify_and_tampering_fails() {
        let issuer = MockIssuer::generate().unwrap();
        let trust = issuer.trust_bundle();
        let cred = issuer
            .issue("bob", b"bob-key", "TS//SI//NF", "USA", 1_000)
            .unwrap();
        let subject = trust.verify(&cred, 10).unwrap();
        assert_eq!(subject.user, "bob");
        assert_eq!(subject.valid_until, 1_000);

        let mut forged = cred.clone();
        forged.body.access = "TS//SI/TK//NF".into(); // bob grants himself TK
        assert!(trust.verify(&forged, 10).is_err());

        let mut rebound = cred.clone();
        rebound.body.key = Bytes(b"mallory-key".to_vec()); // steal bob's credential
        assert!(trust.verify(&rebound, 10).is_err());

        let other = MockIssuer::generate().unwrap().trust_bundle();
        assert!(other.verify(&cred, 10).is_err());
    }

    #[test]
    fn log_entries_follow_the_subjects_clearance() {
        let issuer = MockIssuer::generate().unwrap();
        let trust = issuer.trust_bundle();
        let issue = |user, access| issuer.issue(user, b"k", access, "USA", 1_000).unwrap();
        let (bob, carol) = (issue("bob", "TS//SI//NF"), issue("carol", "TS//SI/TK//NF"));
        let tk_entry = trust.access_marking(&carol).unwrap();
        let si_entry = trust.access_marking(&bob).unwrap();
        let read = |who: &AttributeCredential, entry: &[u8]| {
            trust
                .check_read_log(&trust.verify(who, 10).unwrap(), entry)
                .unwrap()
        };
        assert_eq!(read(&carol, &tk_entry), policy::Decision::Permit);
        assert_eq!(read(&carol, &si_entry), policy::Decision::Permit);
        assert_eq!(read(&bob, &si_entry), policy::Decision::Permit);
        assert!(matches!(read(&bob, &tk_entry), policy::Decision::Deny(_)));
        // Garbage markings don't parse into "visible".
        let subject = trust.verify(&carol, 10).unwrap();
        assert!(trust.check_read_log(&subject, b"junk").is_err());
        assert!(trust.check_read_log(&subject, b"").is_err());
    }
}
