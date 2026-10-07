//! File attachments (idea-v1 §1): the client encrypts, the DS stores ciphertext by its
//! SHA-384, and the key rides inside the MLS message.
//!
//! ponytail: whole files in memory, capped at `MAX_BLOB`. Chunking comes with big
//! attachments.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use identity::KeyStore;
use identity::archive::{FILE_KEY_LEN, FILE_NONCE_LEN, decrypt_file, encrypt_file, sha384};
use markings::parse;
use proto::{Bytes, FILE, FileRef, MAX_BLOB, api};

use crate::{Client, Outgoing, hex};

/// AES-GCM tag, appended to the ciphertext.
const TAG_LEN: usize = 16;
const NAME_MAX: usize = 255;

/// What a receiver insists on before it shows a file message: a well-formed `FileRef`
/// that names exactly the blob the sender's signed AAD declared.
pub(crate) fn check_received(body: &[u8], aad_blobs: &[Bytes]) -> Result<FileRef> {
    let f: FileRef = serde_json::from_slice(body)?;
    check_ref(&f)?;
    ensure!(
        aad_blobs == [f.hash.clone()],
        "the signed message header names different blobs than the file does"
    );
    Ok(f)
}

fn check_ref(f: &FileRef) -> Result<()> {
    ensure!(
        !f.name.is_empty() && f.name.len() <= NAME_MAX,
        "file name is empty or too long"
    );
    ensure!(
        f.key.0.len() == FILE_KEY_LEN && f.nonce.0.len() == FILE_NONCE_LEN,
        "file key or nonce has the wrong length"
    );
    ensure!(f.hash.0.len() == 48, "blob address isn't a SHA-384");
    ensure!(
        f.size as usize + TAG_LEN <= MAX_BLOB,
        "file is larger than the blob limit"
    );
    Ok(())
}

/// The last path component, never a path: a sender picks the name, the receiver's disk
/// is the receiver's business.
fn safe_name(name: &str) -> Result<&std::ffi::OsStr> {
    match Path::new(name).file_name() {
        Some(n) if n != ".." => Ok(n),
        _ => bail!("{name:?} isn't a usable file name"),
    }
}

impl<K: KeyStore> Client<K> {
    /// Send the file at `path` to `room` under `marking`. The DS holds the encrypted
    /// bytes; the message holds the key.
    pub fn send_file(&mut self, room: &str, marking: &str, path: &Path) -> Result<u64> {
        let marking = parse(marking, &self.trust.registers())?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .with_context(|| format!("{} has no file name", path.display()))?;
        let len = std::fs::metadata(path)
            .with_context(|| format!("read {}", path.display()))?
            .len();
        ensure!(
            len as usize + TAG_LEN <= MAX_BLOB,
            "{} is {len} bytes; the limit is {} MiB",
            path.display(),
            MAX_BLOB >> 20
        );
        let (ciphertext, fk) = encrypt_file(&std::fs::read(path)?)?;
        let file = FileRef {
            name,
            size: len,
            hash: Bytes(sha384(&ciphertext)?),
            key: Bytes(fk.key),
            nonce: Bytes(fk.nonce),
        };
        check_ref(&file)?;
        let out = Outgoing {
            blob: Some(ciphertext),
            ..Outgoing::new(FILE, serde_json::to_vec(&file)?)
        };
        Ok(self.post(room, "send-file", &marking, out)?.0)
    }

    /// Download and decrypt the file in message `seq` of `room` into `dir`. Refuses to
    /// overwrite: two files with one name is the user's call to make.
    pub fn fetch(&self, room: &str, seq: u64, dir: &Path) -> Result<PathBuf> {
        let m = self.stored(room, seq)?;
        ensure!(m.content_type == FILE, "#{seq} in {room} isn't a file");
        let f: FileRef = serde_json::from_slice(&m.body.0)?;
        check_ref(&f)?;
        let name = safe_name(&f.name)?;
        let ciphertext = self.blob(&f.hash.0)?;
        ensure!(
            sha384(&ciphertext)? == f.hash.0,
            "DS served bytes that don't match the blob's address"
        );
        let plain = decrypt_file(&ciphertext, &f.key.0, &f.nonce.0)?;
        ensure!(
            plain.len() as u64 == f.size,
            "file is {} bytes, the message says {}",
            plain.len(),
            f.size
        );
        let path = dir.join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?
            .write_all(&plain)?;
        Ok(path)
    }

    /// A blob by its SHA-384, if the DS lets this user have it: members of the room it
    /// was uploaded to, and the custodian.
    pub fn blob(&self, hash: &[u8]) -> Result<Vec<u8>> {
        self.raw(&format!("/v1/blobs/{}", hex(hash)))
    }

    pub(crate) fn upload_blob(&self, room: &str, marking: &Bytes, ciphertext: &[u8]) -> Result<()> {
        self.upload::<api::Accepted>(
            &format!("/v1/rooms/{room}/blobs?marking={}", hex(&marking.0)),
            ciphertext,
        )
        .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> FileRef {
        FileRef {
            name: "plan.pdf".into(),
            size: 10,
            hash: Bytes(vec![1; 48]),
            key: Bytes(vec![2; FILE_KEY_LEN]),
            nonce: Bytes(vec![3; FILE_NONCE_LEN]),
        }
    }

    #[test]
    fn a_file_message_must_agree_with_its_signed_header() {
        let body = serde_json::to_vec(&file()).unwrap();
        assert!(check_received(&body, &[Bytes(vec![1; 48])]).is_ok());
        for wrong in [
            vec![],
            vec![Bytes(vec![9; 48])],
            vec![Bytes(vec![1; 48]); 2],
        ] {
            assert!(check_received(&body, &wrong).is_err());
        }
    }

    #[test]
    fn malformed_file_refs_are_refused() {
        let bad = |f: FileRef| check_ref(&f).is_err();
        assert!(!bad(file()));
        assert!(bad(FileRef {
            name: "".into(),
            ..file()
        }));
        assert!(bad(FileRef {
            name: "x".repeat(256),
            ..file()
        }));
        assert!(bad(FileRef {
            key: Bytes(vec![0; 16]),
            ..file()
        }));
        assert!(bad(FileRef {
            nonce: Bytes(vec![0; 8]),
            ..file()
        }));
        assert!(bad(FileRef {
            hash: Bytes(vec![0; 32]),
            ..file()
        }));
        assert!(bad(FileRef {
            size: MAX_BLOB as u64,
            ..file()
        }));
    }

    #[test]
    fn names_never_escape_the_target_directory() {
        assert_eq!(safe_name("a.txt").unwrap(), "a.txt");
        assert_eq!(safe_name("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(safe_name("/abs/path.bin").unwrap(), "path.bin");
        assert!(safe_name("..").is_err());
        assert!(safe_name("a/..").is_err());
        assert!(safe_name("/").is_err());
    }
}
