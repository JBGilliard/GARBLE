//! The client's side of the records archive (architecture §5.9, idea-v1 §1): seal a copy
//! of every message to the custodian, ask for a logged permit to read, and, for the
//! custodian itself, pull what the DS holds.
//!
//! The client never holds a key that opens an archive copy.

use anyhow::{Context, Result, ensure};
use identity::KeyStore;
use identity::archive::{seal_archive, sha384};
use identity::room::RoomRules;
use proto::{AppAad, ArchiveRecord, Bytes, Envelope, WIRE_VERSION, api};

use crate::audit::Advance;
use crate::{Client, IntegrityAlert};

impl<K: KeyStore> Client<K> {
    /// Seal `envelope` to the room's custodian and file it with the DS. Returns the
    /// hash the message's AAD will carry.
    pub(crate) fn file_archive_copy(
        &self,
        room: &str,
        rules: &RoomRules,
        aad: &AppAad,
        envelope: &Envelope,
    ) -> Result<Bytes> {
        let custodian = rules
            .custodian
            .as_ref()
            .context("room names no custodian; refusing to send unarchived")?;
        let record = ArchiveRecord {
            v: WIRE_VERSION,
            room: room.into(),
            sender: aad.sender.clone(),
            marking: aad.marking.clone(),
            sent_at: aad.sent_at,
            envelope: envelope.clone(),
        };
        let copy = seal_archive(&custodian.archive_key.0, room, &record)?;
        self.upload::<api::Accepted>(&format!("/v1/rooms/{room}/archive"), &copy)?;
        Ok(Bytes(sha384(&copy)?))
    }

    /// Ask the DS to decide `ReadArchive` for this user in `room`, and bring back the
    /// logged permit: the log entry, its inclusion proof and the checkpoint it's
    /// proven against. Refused, the refusal is logged too and comes back as `Denied`.
    ///
    /// The permit is a bearer artifact: whoever carries it to the custodian can use it
    /// once, within its window (Q16).
    pub fn archive_permit(&mut self, room: &str, reason: &str) -> Result<api::ArchivePermit> {
        if let Some(why) = self.state.alert.clone() {
            return Err(IntegrityAlert(why).into());
        }
        let a: api::Accepted = self.call(
            &format!("/v1/rooms/{room}/archive-read"),
            Some(&api::ArchiveRead {
                reason: reason.into(),
            }),
        )?;
        let id: u64 = a
            .audit
            .strip_prefix("L-")
            .and_then(|n| n.parse().ok())
            .filter(|n| *n > 0)
            .with_context(|| format!("DS returned audit reference {:?}", a.audit))?;
        // Entries first, then the checkpoint: the checkpoint can only be as new or newer.
        let records: Vec<api::LogRecord> = self.call("/v1/log/entries", None::<&()>)?;
        let head = match self.advance_checkpoint()? {
            Advance::Fine { head, .. } => head,
            Advance::Fault(why) => return Err(self.raise(why)),
        };
        let record = records
            .into_iter()
            .find(|r| r.index + 1 == id)
            .with_context(|| {
                format!(
                    "the permit's log entry {} isn't readable by its holder",
                    a.audit
                )
            })?;
        let proof = match self.prove_record(&record, &head) {
            Ok(p) => p,
            Err(why) => return Err(self.raise(format!("log entry {id}: {why:#}"))),
        };
        let checkpoint = self
            .state
            .checkpoint
            .clone()
            .context("no pinned checkpoint after advancing")?;
        Ok(api::ArchivePermit {
            checkpoint,
            record,
            proof,
        })
    }

    /// The custodian's pull: sealed copies sequenced after the first `after` it holds.
    /// The DS answers only to the user the trust bundle names as custodian.
    pub fn archive_pull(&self, after: u64) -> Result<Vec<api::ArchiveEntry>> {
        let entries: Vec<api::ArchiveEntry> =
            self.call(&format!("/v1/archive?after={after}"), None::<&()>)?;
        for (n, e) in (after..).zip(&entries) {
            ensure!(e.n == n, "archive entry {} served at position {n}", e.n);
        }
        Ok(entries)
    }
}
