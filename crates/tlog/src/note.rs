//! Checkpoints as C2SP signed notes (tlog-checkpoint over signed-note).
//!
//! A note is the checkpoint text, a blank line, then one `— <name> <base64>` line per
//! signature, where the base64 holds a 4-byte key ID followed by the signature.
//! Signing is behind [`Signer`] / [`Verifier`]: this crate has no idea what ML-DSA is.

use sha2::{Digest, Sha256};

use crate::b64;
use crate::error::{Error, Result};
use crate::hash::Hash;

/// Signature-type byte in the key ID.
///
/// ponytail: signed-note assigns no byte to ML-DSA-87 (docs/open-questions.md); this is
/// a placeholder in the unassigned range. Change it here, and only here, when one is
/// registered; every existing checkpoint's key ID changes with it.
pub const SIG_TYPE_ML_DSA_87: u8 = 0xA7;

/// The em dash and space that open every signature line.
const SIG_PREFIX: &str = "\u{2014} ";

pub trait Signer {
    /// The key name on signature lines: non-empty, no spaces, no `+`.
    fn name(&self) -> &str;
    fn public_key(&self) -> &[u8];
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

pub trait Verifier {
    fn name(&self) -> &str;
    fn public_key(&self) -> &[u8];
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

/// `SHA-256(name || 0x0A || type || public key)[..4]`.
pub fn key_id(name: &str, public_key: &[u8]) -> [u8; 4] {
    let h = Sha256::new_with_prefix(name)
        .chain_update([b'\n', SIG_TYPE_ML_DSA_87])
        .chain_update(public_key)
        .finalize();
    [h[0], h[1], h[2], h[3]]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

impl Checkpoint {
    /// The signed text: origin, size, root, one per line.
    pub fn text(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            b64::encode(&self.root)
        )
    }

    fn parse(text: &str) -> Result<Self> {
        let bad = |why: &str| Error::BadNote(format!("checkpoint: {why}"));
        let body = text
            .strip_suffix('\n')
            .ok_or_else(|| bad("no final newline"))?;
        let mut lines = body.split('\n');
        let (Some(origin), Some(size), Some(root), None) =
            (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return Err(bad("expected origin, size and root"));
        };
        let size_n: u64 = size.parse().map_err(|_| bad("size is not a number"))?;
        if size_n.to_string() != size {
            return Err(bad("size is not canonical"));
        }
        let root: Hash = b64::decode(root)
            .and_then(|r| r.try_into().ok())
            .ok_or_else(|| bad("root is not 32 bytes of base64"))?;
        check_origin(origin)?;
        Ok(Self {
            origin: origin.into(),
            size: size_n,
            root,
        })
    }
}

fn check_origin(origin: &str) -> Result<()> {
    if origin.is_empty() || origin.contains('\n') {
        return Err(Error::BadNote("origin is empty or has a newline".into()));
    }
    Ok(())
}

/// A signed note over `cp`.
pub fn sign_checkpoint(cp: &Checkpoint, signer: &dyn Signer) -> Result<Vec<u8>> {
    check_origin(&cp.origin)?;
    let name = signer.name();
    if name.is_empty() || name.contains(char::is_whitespace) || name.contains('+') {
        return Err(Error::Sign(format!("bad key name {name:?}")));
    }
    let text = cp.text();
    let sig = signer.sign(text.as_bytes())?;
    let mut blob = key_id(name, signer.public_key()).to_vec();
    blob.extend_from_slice(&sig);
    Ok(format!("{text}\n{SIG_PREFIX}{name} {}\n", b64::encode(&blob)).into_bytes())
}

/// The checkpoint in `note`, if `verifier` signed it and it is for `origin`. Signatures
/// by other keys are ignored (cosignatures); with none from `verifier`, it fails.
pub fn open_checkpoint(note: &[u8], origin: &str, verifier: &dyn Verifier) -> Result<Checkpoint> {
    let note = std::str::from_utf8(note).map_err(|_| Error::BadNote("not UTF-8".into()))?;
    let split = note
        .rfind("\n\n")
        .ok_or_else(|| Error::BadNote("no signature block".into()))?;
    let (text, sigs) = (&note[..=split], &note[split + 2..]);
    let sigs = sigs
        .strip_suffix('\n')
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::BadNote("no signatures".into()))?;

    let id = key_id(verifier.name(), verifier.public_key());
    let mut verified = false;
    for line in sigs.split('\n') {
        let rest = line
            .strip_prefix(SIG_PREFIX)
            .ok_or_else(|| Error::BadNote("malformed signature line".into()))?;
        let (name, b64) = rest
            .split_once(' ')
            .ok_or_else(|| Error::BadNote("malformed signature line".into()))?;
        let blob = b64::decode(b64).filter(|b| b.len() > 4);
        let Some(blob) = blob else {
            return Err(Error::BadNote("malformed signature".into()));
        };
        if name == verifier.name()
            && blob[..4] == id
            && verifier.verify(text.as_bytes(), &blob[4..])
        {
            verified = true;
        }
    }
    if !verified {
        return Err(Error::BadNote(format!(
            "no valid signature by {}",
            verifier.name()
        )));
    }
    let cp = Checkpoint::parse(text)?;
    if cp.origin != origin {
        return Err(Error::BadNote(format!(
            "checkpoint is for {}, not {origin}",
            cp.origin
        )));
    }
    Ok(cp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a signature scheme: a keyed hash, enough to exercise the format.
    struct Fake {
        name: &'static str,
        key: Vec<u8>,
    }

    impl Fake {
        fn new(name: &'static str, key: &[u8]) -> Self {
            Self {
                name,
                key: key.to_vec(),
            }
        }
    }

    impl Signer for Fake {
        fn name(&self) -> &str {
            self.name
        }
        fn public_key(&self) -> &[u8] {
            &self.key
        }
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
            Ok(Sha256::new_with_prefix(&self.key)
                .chain_update(msg)
                .finalize()
                .to_vec())
        }
    }

    impl Verifier for Fake {
        fn name(&self) -> &str {
            self.name
        }
        fn public_key(&self) -> &[u8] {
            &self.key
        }
        fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
            self.sign(msg).is_ok_and(|s| s == sig)
        }
    }

    fn cp() -> Checkpoint {
        Checkpoint {
            origin: "garble-ds".into(),
            size: 42,
            root: [7; 32],
        }
    }

    #[test]
    fn note_layout_is_signed_note() {
        let key = Fake::new("garble-ds", b"k");
        let note = String::from_utf8(sign_checkpoint(&cp(), &key).unwrap()).unwrap();
        let (text, sigs) = note.split_once("\n\n").unwrap();
        assert_eq!(text, format!("garble-ds\n42\n{}", b64::encode(&[7; 32])));
        let line = sigs.strip_suffix('\n').unwrap();
        let (name, blob) = line
            .strip_prefix("\u{2014} ")
            .unwrap()
            .split_once(' ')
            .unwrap();
        assert_eq!(name, "garble-ds");
        let blob = b64::decode(blob).unwrap();
        assert_eq!(blob[..4], key_id("garble-ds", b"k"));
        assert_eq!(blob.len(), 4 + 32);
    }

    #[test]
    fn round_trips_and_ignores_other_signers() {
        let ds = Fake::new("garble-ds", b"k");
        let witness = Fake::new("witness", b"w");
        let mut note = sign_checkpoint(&cp(), &ds).unwrap();
        assert_eq!(open_checkpoint(&note, "garble-ds", &ds).unwrap(), cp());
        // Someone cosigns: the extra line is ignored, not an error.
        let cosigned = sign_checkpoint(&cp(), &witness).unwrap();
        let line = String::from_utf8(cosigned).unwrap();
        note.extend_from_slice(line.split_once("\n\n").unwrap().1.as_bytes());
        assert_eq!(open_checkpoint(&note, "garble-ds", &ds).unwrap(), cp());
        assert_eq!(open_checkpoint(&note, "garble-ds", &witness).unwrap(), cp());
        let stranger = Fake::new("stranger", b"s");
        assert!(open_checkpoint(&note, "garble-ds", &stranger).is_err());
    }

    #[test]
    fn tampering_and_wrong_keys_fail() {
        let ds = Fake::new("garble-ds", b"k");
        let note = String::from_utf8(sign_checkpoint(&cp(), &ds).unwrap()).unwrap();
        let open = |n: &str| open_checkpoint(n.as_bytes(), "garble-ds", &ds);
        assert!(open(&note).is_ok());
        assert!(open(&note.replacen("\n42\n", "\n43\n", 1)).is_err());
        assert!(open(&note.replacen("garble-ds\n", "garble-dx\n", 1)).is_err());
        assert!(open(&note.replacen("\n\n", "\n", 1)).is_err());
        assert!(open(note.trim_end()).is_err());
        assert!(open(&format!("{note}\n")).is_err());
        assert!(open("").is_err());
        // Right name, someone else's key.
        let other = Fake::new("garble-ds", b"other");
        assert!(open_checkpoint(note.as_bytes(), "garble-ds", &other).is_err());
        // Signed correctly, but for another log.
        assert!(open_checkpoint(note.as_bytes(), "elsewhere", &ds).is_err());
    }

    #[test]
    fn refuses_to_sign_garbage() {
        let ds = Fake::new("garble-ds", b"k");
        for origin in ["", "a\nb"] {
            let bad = Checkpoint {
                origin: origin.into(),
                ..cp()
            };
            assert!(sign_checkpoint(&bad, &ds).is_err());
        }
        for name in ["", "has space", "plus+"] {
            assert!(
                sign_checkpoint(&cp(), &Fake::new(name, b"k")).is_err(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn checkpoint_text_is_strict() {
        let root = b64::encode(&[1; 32]);
        for bad in [
            format!("o\n01\n{root}\n"),
            format!("o\n+1\n{root}\n"),
            format!("o\n1\n{root}"),
            format!("o\n1\n{root}\nextra\n"),
            "o\n1\nAAAA\n".to_string(),
            format!("\n1\n{root}\n"),
            format!("o\n-1\n{root}\n"),
        ] {
            assert!(Checkpoint::parse(&bad).is_err(), "{bad:?}");
        }
        assert!(Checkpoint::parse(&format!("o\n1\n{root}\n")).is_ok());
    }
}
