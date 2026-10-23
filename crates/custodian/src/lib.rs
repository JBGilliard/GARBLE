//! Records custodian (architecture §5.9, idea-v1 §1).
//!
//! It keeps what senders sealed to the archive key, and holds no key that opens any of
//! it. Opening takes two things together: the offline private key, supplied per
//! invocation, and a permit, which is a DS log entry proving a records officer's
//! `ReadArchive` was decided and permitted.
//!
//! The permit check is procedure, not cryptography: whoever holds the private key can
//! decrypt without one (open-questions Q16).
//!
//! ponytail: the store is a JSON-lines file plus a blob directory in the custodian's
//! home; nothing here rewrites either. Real retention (schedules, legal holds, WORM
//! media) is a deployment concern.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use client::Client;
use identity::TrustBundle;
use identity::archive::{decrypt_file, envelope_hash, open_archive, sha384};
use proto::api::{ArchiveEntry, ArchivePermit, LogEntry};
use proto::{ArchiveRecord, FILE, FileRef};

/// How long a permit stays good. Short: it is a bearer artifact (Q16).
pub const PERMIT_TTL_SECS: u64 = 15 * 60;
/// Clock slack between the DS that wrote the entry and this machine.
const SKEW_SECS: u64 = 60;

const ARCHIVE: &str = "archive.jsonl";
const READS: &str = "reads.jsonl";
const BLOBS: &str = "blobs";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Everything pulled so far, oldest first. A damaged line is an error, not a skip: a
/// custodian that quietly drops records isn't one.
pub fn held(home: &Path) -> Result<Vec<ArchiveEntry>> {
    let path = home.join(ARCHIVE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(&path)?;
    text.lines()
        .enumerate()
        .map(|(i, l)| {
            serde_json::from_str(l).with_context(|| format!("{} line {}", path.display(), i + 1))
        })
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pulled {
    pub entries: u64,
    pub blobs: u64,
}

/// Pull everything the DS has sequenced since the last pull, blobs included, into
/// `home`. Blobs go first: an entry on disk always has its attachments beside it.
pub fn pull(client: &Client, home: &Path) -> Result<Pulled> {
    fs::create_dir_all(home.join(BLOBS))?;
    let mut after = held(home)?.len() as u64;
    let mut got = Pulled::default();
    loop {
        let page = client.archive_pull(after)?;
        if page.is_empty() {
            return Ok(got);
        }
        for e in page {
            for b in &e.blobs {
                got.blobs += u64::from(store_blob(client, home, &b.0)?);
            }
            append(home, ARCHIVE, &e)?;
            got.entries += 1;
            after += 1;
        }
    }
}

/// Fetch a blob unless we already hold it. True if it was new.
fn store_blob(client: &Client, home: &Path, hash: &[u8]) -> Result<bool> {
    let path = home.join(BLOBS).join(hex(hash));
    if path.exists() {
        return Ok(false);
    }
    let bytes = client.blob(hash)?;
    ensure!(
        sha384(&bytes)? == hash,
        "DS served bytes that don't match blob {}",
        hex(hash)
    );
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(&bytes)?;
    Ok(true)
}

fn append(home: &Path, file: &str, line: &impl serde::Serialize) -> Result<()> {
    let mut out = serde_json::to_vec(line)?;
    out.push(b'\n');
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join(file))?;
    f.write_all(&out)?;
    f.sync_all()?;
    Ok(())
}

/// What a permit proved.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Permit {
    /// The log entry id; a permit opens once.
    pub id: u64,
    pub actor: String,
    pub room: String,
    pub at: u64,
}

/// Is `permit` a permitted `ReadArchive` for `room`, in a log the trust bundle's key
/// signed, by a listed records officer, recent enough to act on?
pub fn verify_permit(
    trust: &TrustBundle,
    permit: &ArchivePermit,
    room: &str,
    now: u64,
) -> Result<Permit> {
    let log = trust
        .log
        .as_ref()
        .context("trust bundle names no log key")?;
    let head = tlog::open_checkpoint(&permit.checkpoint.0, &log.origin, &trust.log_verifier()?)
        .context("permit checkpoint")?;
    let proof = permit
        .proof
        .iter()
        .map(|h| {
            tlog::Hash::try_from(h.0.as_slice()).map_err(|_| anyhow::anyhow!("proof hash length"))
        })
        .collect::<Result<Vec<_>>>()?;
    let leaf = &permit.record.leaf.0;
    tlog::verify_inclusion(
        &tlog::leaf_hash(leaf),
        permit.record.index,
        head.size,
        &proof,
        &head.root,
    )
    .context("permit isn't in the log")?;

    let e = LogEntry::from_leaf(leaf)?;
    ensure!(
        e.id == permit.record.index + 1,
        "entry {} at index {}",
        e.id,
        permit.record.index
    );
    ensure!(
        e.event == "archive-read" && e.decision == "permit" && e.code.is_none(),
        "log entry L-{} is a {} {}, not a permitted archive read",
        e.id,
        e.decision,
        e.event
    );
    ensure!(e.room == room, "permit is for {:?}, not {room}", e.room);
    ensure!(
        trust.records_officers.contains(&e.actor),
        "{} is not a records officer",
        e.actor
    );
    ensure!(
        e.at <= now.saturating_add(SKEW_SECS) && now.saturating_sub(e.at) <= PERMIT_TTL_SECS,
        "permit L-{} is from {}, now is {now}; ask again",
        e.id,
        e.at
    );
    Ok(Permit {
        id: e.id,
        actor: e.actor,
        room: e.room,
        at: e.at,
    })
}

/// One archived message, opened.
#[derive(Debug)]
pub struct Opened {
    pub n: u64,
    pub seq: u64,
    /// `Err` when the copy didn't open, lied about its room, or holds a different
    /// envelope than the message carried: a sender sealed something else, or to someone
    /// else's key. Reported, never skipped.
    pub record: Result<ArchiveRecord, String>,
    /// For file messages, when `files` was given: where the decrypted file went.
    pub file: Option<Result<PathBuf, String>>,
}

/// Open `room`'s archive. Consumes the permit first, so a crash can't turn one permit
/// into two reads. Every read is appended to `reads.jsonl`.
pub fn read(
    home: &Path,
    trust: &TrustBundle,
    private_key: &[u8],
    room: &str,
    permit: &ArchivePermit,
    now: u64,
    files: Option<&Path>,
) -> Result<Vec<Opened>> {
    let p = verify_permit(trust, permit, room, now)?;
    let used = home.join(READS);
    if used.exists() {
        for l in fs::read_to_string(&used)?.lines() {
            let prior: Permit = serde_json::from_str(l).context("reads.jsonl")?;
            if prior.id == p.id {
                bail!("permit L-{} was already used", p.id);
            }
        }
    }
    append(home, READS, &p)?;

    let mut out = Vec::new();
    for e in held(home)?.into_iter().filter(|e| e.room == room) {
        let record = open_record(private_key, &e);
        let file = match (&record, files) {
            (Ok(r), Some(dir)) if r.envelope.content_type == FILE => {
                Some(export_file(home, dir, e.n, r).map_err(|e| format!("{e:#}")))
            }
            _ => None,
        };
        out.push(Opened {
            n: e.n,
            seq: e.seq,
            record,
            file,
        });
    }
    Ok(out)
}

/// Opens the copy and holds its envelope to the hash members signed (Q17). The hash
/// comes from the DS, but the DS took it from the sender's MLS-signed AAD.
fn open_record(private_key: &[u8], e: &ArchiveEntry) -> Result<ArchiveRecord, String> {
    let r = open_archive(private_key, &e.room, &e.copy.0).map_err(|e| format!("{e:#}"))?;
    match envelope_hash(&r.envelope) {
        Ok(h) if h == e.envelope.0 => Ok(r),
        Ok(_) => Err("archived message differs from the one members received".into()),
        Err(e) => Err(format!("{e:#}")),
    }
}

fn export_file(home: &Path, dir: &Path, n: u64, r: &ArchiveRecord) -> Result<PathBuf> {
    let f: FileRef = proto::decode(&r.envelope.body.0)?;
    let ciphertext = fs::read(home.join(BLOBS).join(hex(&f.hash.0)))
        .context("the blob isn't in this custodian's store")?;
    ensure!(
        sha384(&ciphertext)? == f.hash.0,
        "stored blob doesn't match its address"
    );
    let plain = decrypt_file(&ciphertext, &f.key.0, &f.nonce.0)?;
    let name = Path::new(&f.name)
        .file_name()
        .context("file has no usable name")?;
    fs::create_dir_all(dir)?;
    // n keeps two files with one name apart.
    let path = dir.join(format!("{n}-{}", name.to_string_lossy()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(&plain)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::log::LogSigner;
    use identity::{AttributeIssuer, FileKeyStore, KeyStore, LogRef, MockIssuer};
    use proto::api::LogRecord;
    use proto::{Bytes, LOG_ENTRY_VERSION};
    use tlog::{Log, MemStore};

    const ORIGIN: &str = "garble-test";
    const NOW: u64 = 1_000_000;

    fn entry(id: u64, actor: &str, room: &str, event: &str, code: Option<&str>) -> LogEntry {
        LogEntry {
            v: LOG_ENTRY_VERSION,
            id,
            at: NOW - 10,
            actor: actor.into(),
            room: room.into(),
            event: event.into(),
            decision: if code.is_some() { "deny" } else { "permit" }.into(),
            code: code.map(str::to_owned),
            detail: "reason: audit".into(),
            marking: Bytes(vec![1]),
            message: None,
        }
    }

    /// A signed log holding `entries`, a trust bundle naming its key, and a permit for
    /// the entry at `index`.
    fn rig(tag: &str, entries: &[LogEntry], index: usize) -> (TrustBundle, ArchivePermit) {
        let key =
            std::env::temp_dir().join(format!("garble-cust-{tag}-{}.key", std::process::id()));
        let _ = fs::remove_file(&key);
        let keys = FileKeyStore::new(&key);
        let mut trust = MockIssuer::generate().unwrap().trust_bundle();
        trust.records_officers = vec!["olga".into()];
        trust.log = Some(LogRef {
            origin: ORIGIN.into(),
            key: Bytes(keys.public_key().unwrap()),
        });
        let signer = LogSigner::new(ORIGIN, keys.signer().unwrap());
        let mut log = Log::open(MemStore::default()).unwrap();
        for e in entries {
            log.append(&e.to_leaf()).unwrap();
        }
        let head = log.checkpoint(ORIGIN);
        let proof = log.inclusion_proof(index as u64, head.size).unwrap();
        let permit = ArchivePermit {
            checkpoint: Bytes(tlog::sign_checkpoint(&head, &signer).unwrap()),
            record: LogRecord {
                index: index as u64,
                leaf: Bytes(entries[index].to_leaf()),
            },
            proof: proof.into_iter().map(|h| Bytes(h.to_vec())).collect(),
        };
        let _ = fs::remove_file(key);
        (trust, permit)
    }

    fn log() -> Vec<LogEntry> {
        vec![
            entry(1, "olga", "ops", "message", None),
            entry(2, "olga", "ops", "archive-read", None),
            entry(3, "mallory", "ops", "archive-read", Some("P-007")),
            entry(4, "mallory", "ops", "archive-read", None),
            entry(5, "olga", "other", "archive-read", None),
        ]
    }

    #[test]
    fn a_permitted_read_by_a_records_officer_is_a_permit() {
        let (trust, permit) = rig("good", &log(), 1);
        let p = verify_permit(&trust, &permit, "ops", NOW).unwrap();
        assert_eq!(
            (p.id, p.actor.as_str(), p.room.as_str()),
            (2, "olga", "ops")
        );
    }

    #[test]
    fn nothing_else_in_the_log_is_a_permit() {
        let say = |index, room, now| {
            let (trust, permit) = rig(&format!("bad{index}"), &log(), index);
            verify_permit(&trust, &permit, room, now)
                .unwrap_err()
                .to_string()
        };
        // Another event by the same officer.
        assert!(say(0, "ops", NOW).contains("not a permitted archive read"));
        // The refusal the DS logged for someone who asked and was turned down.
        assert!(say(2, "ops", NOW).contains("not a permitted archive read"));
        // Permitted, but the actor isn't a listed officer (a bundle/room mismatch).
        assert!(say(3, "ops", NOW).contains("not a records officer"));
        // A real permit, for another room.
        assert!(say(1, "other", NOW).contains("is for"));
        assert!(say(4, "ops", NOW).contains("is for"));
    }

    #[test]
    fn permits_expire_and_do_not_come_from_the_future() {
        let (trust, permit) = rig("time", &log(), 1);
        let at = NOW - 10;
        assert!(verify_permit(&trust, &permit, "ops", at + PERMIT_TTL_SECS).is_ok());
        assert!(verify_permit(&trust, &permit, "ops", at + PERMIT_TTL_SECS + 1).is_err());
        assert!(verify_permit(&trust, &permit, "ops", at - SKEW_SECS).is_ok());
        assert!(verify_permit(&trust, &permit, "ops", at - SKEW_SECS - 1).is_err());
    }

    #[test]
    fn a_permit_has_to_be_in_a_log_the_bundle_trusts() {
        let (trust, permit) = rig("forge", &log(), 1);

        // Edited entry: the proof no longer fits.
        let mut edited = permit.clone();
        let mut e = LogEntry::from_leaf(&edited.record.leaf.0).unwrap();
        e.actor = "mallory".into();
        edited.record.leaf = Bytes(e.to_leaf());
        assert!(verify_permit(&trust, &edited, "ops", NOW).is_err());

        // Wrong position.
        let mut moved = permit.clone();
        moved.record.index = 3;
        assert!(verify_permit(&trust, &moved, "ops", NOW).is_err());

        // Missing proof.
        let mut bare = permit.clone();
        bare.proof.clear();
        assert!(verify_permit(&trust, &bare, "ops", NOW).is_err());

        // A log some other key signed.
        let (_, foreign) = rig("foreign", &log(), 1);
        assert!(verify_permit(&trust, &foreign, "ops", NOW).is_err());

        // A forged checkpoint note.
        let mut note = permit.clone();
        note.checkpoint.0.reverse();
        assert!(verify_permit(&trust, &note, "ops", NOW).is_err());
    }

    #[test]
    fn a_copy_has_to_hold_the_envelope_members_received() {
        use proto::{Envelope, Precedence, TEXT_PLAIN, WIRE_VERSION};

        let envelope = |text: &str| Envelope {
            v: WIRE_VERSION,
            msg_id: Bytes(vec![3; 16]),
            content_type: TEXT_PLAIN.into(),
            precedence: Precedence::Routine,
            body: Bytes(text.into()),
            reply_to: None,
            audience: vec![],
            cosignatures: vec![],
            forwarded_from: None,
        };
        let (private, public) = identity::generate_archive_keypair().unwrap();
        let seal = |e: Envelope| {
            let record = ArchiveRecord {
                v: WIRE_VERSION,
                room: "ops".into(),
                sender: "alice".into(),
                marking: Bytes(vec![1]),
                sent_at: 5,
                envelope: e,
            };
            Bytes(identity::archive::seal_archive(&public, "ops", &record).unwrap())
        };
        let entry = |copy: Bytes, signed: &Envelope| ArchiveEntry {
            n: 0,
            room: "ops".into(),
            seq: 1,
            copy,
            blobs: vec![],
            envelope: Bytes(envelope_hash(signed).unwrap()),
        };

        let sent = envelope("meet at noon");
        let honest = entry(seal(sent.clone()), &sent);
        assert_eq!(open_record(&private, &honest).unwrap().envelope, sent);

        // Well-formed, opens fine, and says something else: the Q17 case.
        let lie = entry(seal(envelope("nothing to report")), &sent);
        let why = open_record(&private, &lie).unwrap_err();
        assert!(why.contains("differs"), "{why}");

        // A DS that lost or never had the hash can't vouch for any copy.
        let unbound = ArchiveEntry {
            envelope: Bytes(vec![]),
            ..honest
        };
        assert!(open_record(&private, &unbound).is_err());
    }

    #[test]
    fn a_permit_opens_once() {
        let home = std::env::temp_dir().join(format!("garble-cust-once-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let (trust, permit) = rig("once", &log(), 1);
        let key = identity::generate_archive_keypair().unwrap().0;
        let first = read(&home, &trust, &key, "ops", &permit, NOW, None).unwrap();
        assert!(first.is_empty()); // nothing pulled yet; the permit is spent anyway
        let again = read(&home, &trust, &key, "ops", &permit, NOW, None).unwrap_err();
        assert!(again.to_string().contains("already used"), "{again:#}");
        let _ = fs::remove_dir_all(&home);
    }
}
