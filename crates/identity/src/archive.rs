//! Crypto for the two things that leave a room's MLS group on purpose: the sealed copy
//! the custodian archives, and file blobs the DS stores (architecture §5.9, idea-v1 §1).
//!
//! Both sit on the same provider as the MLS suite, so they inherit its caveats (Q1).

use anyhow::{Result, bail, ensure};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, HashType, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType,
    },
};
use proto::{ArchiveCopy, ArchiveRecord, Bytes, Envelope, WIRE_VERSION};

/// The suite's own KEM, so the archive key is as post-quantum as the rooms are.
pub(crate) const ARCHIVE_HPKE: HpkeConfig = HpkeConfig(
    HpkeKemType::MlKem1024,
    HpkeKdfType::HkdfSha384,
    HpkeAeadType::AesGcm256,
);

/// Domain separation for the HPKE `aad`; the room id is the HPKE `info`.
const ARCHIVE_AAD: &[u8] = b"GARBLE-ARCHIVE-v1";
/// AAD for file blobs. No room or name in it: a forwarded file must still open.
const FILE_AAD: &[u8] = b"GARBLE-FILE-v1";

pub const FILE_KEY_LEN: usize = 32;
pub const FILE_NONCE_LEN: usize = 12;

pub fn sha384(data: &[u8]) -> Result<Vec<u8>> {
    crypto::crypto()
        .hash(HashType::Sha2_384, data)
        .map_err(|e| anyhow::anyhow!("sha384: {e:?}"))
}

/// What `AppAad::envelope` must carry for `envelope`.
pub fn envelope_hash(envelope: &Envelope) -> Result<Vec<u8>> {
    sha384(&proto::encode(envelope)?)
}

/// Seal `record` to the custodian. Returns the [`ArchiveCopy`] bytes: what the DS
/// stores and what `AppAad::archive` hashes.
pub fn seal_archive(archive_key: &[u8], room: &str, record: &ArchiveRecord) -> Result<Vec<u8>> {
    ensure!(
        record.room == room,
        "record is for {}, not {room}",
        record.room
    );
    let sealed = crypto::crypto()
        .hpke_seal(
            ARCHIVE_HPKE,
            archive_key,
            room.as_bytes(),
            ARCHIVE_AAD,
            &proto::encode(record)?,
        )
        .map_err(|e| anyhow::anyhow!("seal archive copy: {e:?}"))?;
    Ok(proto::encode(&ArchiveCopy {
        v: WIRE_VERSION,
        kem_output: Bytes(sealed.kem_output.as_slice().to_vec()),
        ciphertext: Bytes(sealed.ciphertext.as_slice().to_vec()),
    })?)
}

/// Only the custodian's offline key gets here. `room` is the room the copy was filed
/// under: a copy sealed for another room fails to open.
pub fn open_archive(private_key: &[u8], room: &str, copy: &[u8]) -> Result<ArchiveRecord> {
    let c: ArchiveCopy = proto::decode(copy)?;
    ensure!(c.v == WIRE_VERSION, "archive copy version {}", c.v);
    let plain = crypto::crypto()
        .hpke_open(
            ARCHIVE_HPKE,
            &HpkeCiphertext {
                kem_output: c.kem_output.0.into(),
                ciphertext: c.ciphertext.0.into(),
            },
            private_key,
            room.as_bytes(),
            ARCHIVE_AAD,
        )
        .map_err(|e| anyhow::anyhow!("open archive copy: {e:?}"))?;
    let r: ArchiveRecord = proto::decode(&plain)?;
    ensure!(r.v == WIRE_VERSION, "archive record version {}", r.v);
    ensure!(
        r.room == room,
        "record claims {}, filed under {room}",
        r.room
    );
    Ok(r)
}

/// Does `copy` parse as an [`ArchiveCopy`] this version can hold? All the DS can say
/// about something it can't open.
pub fn check_archive_shape(copy: &[u8]) -> Result<()> {
    let c: ArchiveCopy = proto::decode(copy)?;
    ensure!(c.v == WIRE_VERSION, "archive copy version {}", c.v);
    ensure!(
        !c.kem_output.0.is_empty() && !c.ciphertext.0.is_empty(),
        "archive copy is empty"
    );
    Ok(())
}

/// A fresh random key and nonce for one file.
pub struct FileKey {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// AES-256-GCM under a fresh key. The tag is the last 16 bytes of the result.
pub fn encrypt_file(plain: &[u8]) -> Result<(Vec<u8>, FileKey)> {
    let crypto = crypto::crypto();
    let fk = FileKey {
        key: crypto
            .random_vec(FILE_KEY_LEN)
            .map_err(|e| anyhow::anyhow!("rng: {e:?}"))?,
        nonce: crypto
            .random_vec(FILE_NONCE_LEN)
            .map_err(|e| anyhow::anyhow!("rng: {e:?}"))?,
    };
    let ct = crypto
        .aead_encrypt(AeadType::Aes256Gcm, &fk.key, plain, &fk.nonce, FILE_AAD)
        .map_err(|e| anyhow::anyhow!("encrypt file: {e:?}"))?;
    Ok((ct, fk))
}

pub fn decrypt_file(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != FILE_KEY_LEN || nonce.len() != FILE_NONCE_LEN {
        bail!("file key or nonce has the wrong length");
    }
    crypto::crypto()
        .aead_decrypt(AeadType::Aes256Gcm, key, ciphertext, nonce, FILE_AAD)
        .map_err(|_| anyhow::anyhow!("file doesn't decrypt: wrong key or altered blob"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{Envelope, Precedence, TEXT_PLAIN};

    fn record(room: &str) -> ArchiveRecord {
        ArchiveRecord {
            v: WIRE_VERSION,
            room: room.into(),
            sender: "alice".into(),
            marking: Bytes(vec![1, 2]),
            sent_at: 42,
            envelope: Envelope {
                v: WIRE_VERSION,
                msg_id: Bytes(vec![7; 16]),
                content_type: TEXT_PLAIN.into(),
                precedence: Precedence::Routine,
                body: Bytes(b"the codeword is swordfish".to_vec()),
                reply_to: None,
                audience: vec![],
                cosignatures: vec![],
                forwarded_from: None,
            },
        }
    }

    #[test]
    fn only_the_private_key_opens_a_copy_and_only_for_its_room() {
        let (private, public) = crate::generate_archive_keypair().unwrap();
        let copy = seal_archive(&public, "ops", &record("ops")).unwrap();
        let text = String::from_utf8_lossy(&copy);
        assert!(!text.contains("swordfish"));
        assert_eq!(open_archive(&private, "ops", &copy).unwrap(), record("ops"));

        // HPKE info is the room: the same bytes filed under another room don't open.
        assert!(open_archive(&private, "other", &copy).is_err());
        let (other_private, _) = crate::generate_archive_keypair().unwrap();
        assert!(open_archive(&other_private, "ops", &copy).is_err());

        // Sealing is randomized: two copies of one message aren't the same bytes.
        assert_ne!(copy, seal_archive(&public, "ops", &record("ops")).unwrap());
        // A record can't be sealed under a room it isn't for.
        assert!(seal_archive(&public, "other", &record("ops")).is_err());
    }

    #[test]
    fn a_tampered_copy_is_refused() {
        let (private, public) = crate::generate_archive_keypair().unwrap();
        let copy = seal_archive(&public, "ops", &record("ops")).unwrap();
        let mut c: ArchiveCopy = proto::decode(&copy).unwrap();
        c.ciphertext.0[0] ^= 1;
        assert!(open_archive(&private, "ops", &proto::encode(&c).unwrap()).is_err());
        assert!(check_archive_shape(&copy).is_ok());
        assert!(check_archive_shape(b"{}").is_err());
        assert!(check_archive_shape(b"junk").is_err());
    }

    #[test]
    fn files_round_trip_and_fail_on_any_change() {
        let (ct, fk) = encrypt_file(b"attachment bytes").unwrap();
        assert_eq!(
            (fk.key.len(), fk.nonce.len()),
            (FILE_KEY_LEN, FILE_NONCE_LEN)
        );
        assert_eq!(ct.len(), 16 + 16);
        assert_eq!(
            decrypt_file(&ct, &fk.key, &fk.nonce).unwrap(),
            b"attachment bytes"
        );

        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(decrypt_file(&bad, &fk.key, &fk.nonce).is_err());
        assert!(decrypt_file(&ct[..ct.len() - 1], &fk.key, &fk.nonce).is_err());
        let (_, other) = encrypt_file(b"x").unwrap();
        assert!(decrypt_file(&ct, &other.key, &fk.nonce).is_err());
        assert!(decrypt_file(&ct, &fk.key[..16], &fk.nonce).is_err());
        // Fresh key per file.
        assert_ne!(fk.key, encrypt_file(b"attachment bytes").unwrap().1.key);
        // Empty files are files.
        let (ct, fk) = encrypt_file(b"").unwrap();
        assert!(decrypt_file(&ct, &fk.key, &fk.nonce).unwrap().is_empty());
    }

    #[test]
    fn sha384_is_48_bytes() {
        assert_eq!(sha384(b"").unwrap().len(), 48);
        assert_ne!(sha384(b"a").unwrap(), sha384(b"b").unwrap());
    }
}
