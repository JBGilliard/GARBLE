//! ML-DSA-87 for `tlog` checkpoints. `tlog` names the traits; this is the only place
//! that knows the scheme.

use anyhow::{Context, Result, anyhow, ensure};
use crypto::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer as _};
use proto::WIRE_VERSION;
use tlog::{Checkpoint, Log, TileStore};

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
        crypto::crypto()
            .verify_signature(SCHEME, msg, &self.key, sig)
            .is_ok()
    }
}

/// Where a store keeps its latest signed checkpoint.
pub const CHECKPOINT_KEY: &str = "checkpoint";

/// A tree can't change its leaf encoding mid-way, so a new wire version is a new log, and
/// the origin says which one.
pub fn origin_suffix() -> String {
    format!("/v{WIRE_VERSION}")
}

pub fn default_origin() -> String {
    format!("garble-ds{}", origin_suffix())
}

/// Does `origin` name a log of this wire version?
pub fn is_current_origin(origin: &str) -> bool {
    origin
        .strip_suffix(&origin_suffix())
        .is_some_and(|name| !name.is_empty())
}

/// The origin doubles as the signed-note key name, which has rules.
pub fn checked_origin(origin: &str) -> Result<()> {
    if origin.is_empty() || origin.contains(char::is_whitespace) || origin.contains('+') {
        return Err(anyhow!(
            "log origin {origin:?} can't be a signed-note key name"
        ));
    }
    ensure!(
        is_current_origin(origin),
        "log origin {origin:?} must end in {} (e.g. {}): its leaves aren't this wire version's",
        origin_suffix(),
        default_origin()
    );
    Ok(())
}

/// Sign `store`'s log closed: a final checkpoint over everything in it, with the
/// `closed` line. The log stays readable and verifiable; a DS won't append to it again.
/// Refuses unless the store matches the last checkpoint `signer` signed, so sealing can't
/// launder a log that lost or rewrote entries.
pub fn seal<S: TileStore + Clone>(store: &mut S, signer: &LogSigner) -> Result<Checkpoint> {
    let verifier = LogVerifier::new(&signer.name, signer.keys.public());
    let log = Log::open(store.clone())?;
    let note = store
        .read(CHECKPOINT_KEY)?
        .context("no signed checkpoint in this log directory; nothing to seal")?;
    let last = tlog::open_checkpoint(&note, &signer.name, &verifier)
        .context("last checkpoint isn't this origin's, signed by this key")?;
    ensure!(!last.closed, "log is already sealed (size {})", last.size);
    ensure!(
        last.size <= log.size() && log.root_at(last.size)? == last.root,
        "log store does not match its last signed checkpoint (size {})",
        last.size
    );
    // Entries past the last signed checkpoint were appended but never attested to a
    // client (the checkpoint goes out before the reply), so sealing them in is safe.
    let sealed = Checkpoint {
        closed: true,
        ..log.checkpoint(&signer.name)
    };
    let note = tlog::sign_checkpoint(&sealed, signer)?;
    store.write(CHECKPOINT_KEY, &note)?;
    Ok(sealed)
}

/// Check a sealed log from nothing but its files and `verifier`: the final checkpoint is
/// signed, for `origin`, closed, and its root is what the entries on disk hash to.
/// Makes no assumption about the leaf encoding, so it works on logs of older wire versions.
pub fn verify_sealed<S: TileStore>(
    store: S,
    origin: &str,
    verifier: &LogVerifier,
) -> Result<Checkpoint> {
    let note = store
        .read(CHECKPOINT_KEY)?
        .context("no checkpoint here; not a log directory")?;
    let cp = tlog::open_checkpoint(&note, origin, verifier)?;
    ensure!(
        cp.closed,
        "checkpoint at size {} isn't closed: a live or unsealed log (`garble-ds log seal`)",
        cp.size
    );
    let log = Log::open(store)?;
    ensure!(
        log.size() == cp.size,
        "log holds {} entries, the sealed checkpoint covers {}",
        log.size(),
        cp.size
    );
    ensure!(
        log.recompute_root()? == cp.root,
        "entries on disk don't hash to the sealed root"
    );
    Ok(cp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlog::{MemStore, open_checkpoint, sign_checkpoint};

    fn cp(size: u64) -> Checkpoint {
        Checkpoint {
            origin: "garble-ds".into(),
            size,
            root: [3; 32],
            closed: false,
        }
    }

    const ORIGIN: &str = "garble-ds/v2";

    /// A log of `n` entries with the checkpoint a running DS would have last signed.
    fn live(n: u8) -> (MemStore, LogSigner, LogVerifier) {
        let signer = LogSigner::new(ORIGIN, SignatureKeyPair::new(SCHEME).unwrap());
        let verifier = LogVerifier::new(ORIGIN, tlog::Signer::public_key(&signer));
        let mut log = Log::open(MemStore::default()).unwrap();
        for i in 0..n {
            log.append(&[i; 5]).unwrap();
        }
        let note = sign_checkpoint(&log.checkpoint(ORIGIN), &signer).unwrap();
        log.store_mut().write(CHECKPOINT_KEY, &note).unwrap();
        (log.store().clone(), signer, verifier)
    }

    #[test]
    fn a_sealed_log_verifies_from_its_files_alone() {
        let (mut store, signer, verifier) = live(5);
        assert!(verify_sealed(store.clone(), ORIGIN, &verifier).is_err());

        let sealed = seal(&mut store, &signer).unwrap();
        assert!(sealed.closed && sealed.size == 5);
        let cp = verify_sealed(store.clone(), ORIGIN, &verifier).unwrap();
        assert_eq!((cp.size, cp.closed), (5, true));

        // Not this log's key, not this log's origin.
        let other = LogVerifier::new(ORIGIN, SignatureKeyPair::new(SCHEME).unwrap().public());
        assert!(verify_sealed(store.clone(), ORIGIN, &other).is_err());
        assert!(verify_sealed(store.clone(), "garble-ds", &verifier).is_err());

        // Entries added after the seal.
        let mut grown = Log::open(store.clone()).unwrap();
        grown.append(b"late").unwrap();
        assert!(verify_sealed(grown.store().clone(), ORIGIN, &verifier).is_err());

        // An entry edited in place, same length.
        let mut edited = store.clone();
        let bundle = edited.0.get_mut("tile/entries/000.p/5").unwrap();
        let last = bundle.len() - 1;
        bundle[last] ^= 1;
        let err = verify_sealed(edited, ORIGIN, &verifier).unwrap_err();
        assert!(err.to_string().contains("sealed root"), "{err:#}");

        // The directory has to be one.
        assert!(verify_sealed(MemStore::default(), ORIGIN, &verifier).is_err());
    }

    #[test]
    fn sealing_refuses_what_it_shouldnt_attest() {
        let (store, signer, _) = live(5);
        assert!(
            seal(&mut MemStore::default(), &signer).is_err(),
            "nothing here"
        );

        let stranger = LogSigner::new(ORIGIN, SignatureKeyPair::new(SCHEME).unwrap());
        assert!(seal(&mut store.clone(), &stranger).is_err(), "not this key");

        // Rolled back past the last signed checkpoint.
        let mut shorter = store.clone();
        shorter.0.remove("tile/entries/000.p/5");
        assert!(seal(&mut shorter, &signer).is_err());

        let mut done = store;
        seal(&mut done, &signer).unwrap();
        let err = seal(&mut done, &signer).unwrap_err();
        assert!(err.to_string().contains("already sealed"), "{err:#}");
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
        assert!(checked_origin("garble-ds/v2").is_ok());
        assert!(checked_origin(&default_origin()).is_ok());
        for bad in ["", "a b/v2", "a+b/v2", "a\nb/v2"] {
            assert!(checked_origin(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn origins_carry_the_wire_version() {
        for old in ["garble-ds", "garble-ds/v1", "/v2", "garble-ds/v22", "v2"] {
            assert!(!is_current_origin(old), "{old:?}");
            assert!(checked_origin(old).is_err(), "{old:?}");
        }
        assert!(is_current_origin("site-7/v2"));
    }
}
