//! Checkpoint pinning and log verification (architecture §5.10, §8).
//!
//! The client remembers the last checkpoint it accepted and only moves forward from it:
//! a new one must be signed by the log key in the trust bundle and consistent with the
//! pinned one. Failing that is an integrity alert: sending stops, reading doesn't.
//!
//! ponytail: first checkpoint is trusted on first use; witnesses would fix that.

use std::fmt;

use anyhow::{Context, Result, ensure};
use identity::KeyStore;
use proto::{Bytes, api};
use tlog::{Checkpoint, Hash};

use crate::Client;

/// The log can't be trusted: the DS served something that doesn't fit what it signed.
#[derive(Debug, Clone)]
pub struct IntegrityAlert(pub String);

impl fmt::Display for IntegrityAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "INTEGRITY ALERT: {}", self.0)
    }
}

impl std::error::Error for IntegrityAlert {}

/// What `garble log verify` checked.
#[derive(Debug, Clone)]
pub struct LogReport {
    /// Size of the checkpoint pinned before this run, if there was one.
    pub from: Option<u64>,
    pub size: u64,
    pub root: String,
    /// Entries this reader may see, each proven to be in the tree.
    pub verified: u64,
}

pub(crate) enum Advance {
    Fine { from: Option<u64>, head: Checkpoint },
    Fault(String),
}

/// `new` must extend `old`. `proof` is the consistency proof from the DS, only
/// needed once both trees are non-empty and differ in size.
pub(crate) fn check_advance(
    old: Option<&Checkpoint>,
    new: &Checkpoint,
    proof: &[Hash],
) -> Result<(), String> {
    // A DS that's serving doesn't hand out a sealed head; one that does is lying about
    // being finished, and a later "extension" of it would otherwise pass silently.
    if new.closed {
        return Err(format!(
            "log was sealed at {} entries but is still being served",
            new.size
        ));
    }
    let Some(old) = old else { return Ok(()) };
    if new.size < old.size {
        return Err(format!(
            "log shrank from {} to {} entries",
            old.size, new.size
        ));
    }
    tlog::verify_consistency(old.size, new.size, &old.root, &new.root, proof).map_err(|e| {
        format!(
            "checkpoint {} doesn't extend checkpoint {}: {e}",
            new.size, old.size
        )
    })
}

fn hash(b: &Bytes) -> Result<Hash> {
    Hash::try_from(b.0.as_slice()).map_err(|_| anyhow::anyhow!("proof hash is {} bytes", b.0.len()))
}

impl<K: KeyStore> Client<K> {
    /// Set when the DS's log failed a check. Stays set: someone has to look.
    pub fn integrity_alert(&self) -> Option<&str> {
        self.state.alert.as_deref()
    }

    pub(crate) fn raise(&mut self, why: String) -> anyhow::Error {
        self.state.alert.get_or_insert_with(|| why.clone());
        IntegrityAlert(why).into()
    }

    fn pinned(&self) -> Result<Option<Checkpoint>> {
        let Some(note) = &self.state.checkpoint else {
            return Ok(None);
        };
        // Local state, so a failure here is a damaged home dir, not a lying DS.
        let log = self
            .trust
            .log
            .as_ref()
            .context("trust bundle names no log")?;
        let v = self.trust.log_verifier()?;
        Ok(Some(
            tlog::open_checkpoint(&note.0, &log.origin, &v).context("pinned checkpoint")?,
        ))
    }

    /// Fetch the DS's checkpoint and move the pin to it if it checks out. Transport
    /// errors are `Err`; a checkpoint that fails verification is `Advance::Fault`.
    pub(crate) fn advance_checkpoint(&mut self) -> Result<Advance> {
        let note = self.raw("/v1/log/checkpoint")?;
        let log = self
            .trust
            .log
            .as_ref()
            .context("trust bundle names no log")?;
        let verifier = self.trust.log_verifier()?;
        let head = match tlog::open_checkpoint(&note, &log.origin, &verifier) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Advance::Fault(format!(
                    "checkpoint not from the log key: {e}"
                )));
            }
        };
        let old = self.pinned()?;
        let proof = match &old {
            Some(o) if o.size > 0 && head.size > o.size => {
                let p: api::ConsistencyProof = self.call(
                    &format!("/v1/log/proof/consistency?old={}&new={}", o.size, head.size),
                    None::<&()>,
                )?;
                match p.proof.iter().map(hash).collect::<Result<Vec<_>>>() {
                    Ok(p) => p,
                    Err(e) => return Ok(Advance::Fault(format!("consistency proof: {e:#}"))),
                }
            }
            _ => vec![],
        };
        if let Err(why) = check_advance(old.as_ref(), &head, &proof) {
            return Ok(Advance::Fault(why));
        }
        self.state.checkpoint = Some(Bytes(note));
        Ok(Advance::Fine {
            from: old.map(|o| o.size),
            head,
        })
    }

    /// Check every log entry this user may read against the pinned checkpoint, after
    /// moving the pin forward.
    /// ponytail: one proof request per entry; tiles (§5.10) once logs are big.
    pub fn verify_log(&mut self) -> Result<LogReport> {
        if let Some(why) = self.state.alert.clone() {
            return Err(IntegrityAlert(why).into());
        }
        // Entries first: the checkpoint fetched after them can only be as new or newer.
        let records: Vec<api::LogRecord> = self.call("/v1/log/entries", None::<&()>)?;
        let (from, head) = match self.advance_checkpoint()? {
            Advance::Fine { from, head } => (from, head),
            Advance::Fault(why) => return Err(self.raise(why)),
        };
        for r in &records {
            if let Err(why) = self.check_record(r, &head) {
                return Err(self.raise(format!("log entry {}: {why:#}", r.index + 1)));
            }
        }
        Ok(LogReport {
            from,
            size: head.size,
            root: head.root.iter().map(|b| format!("{b:02x}")).collect(),
            verified: records.len() as u64,
        })
    }

    pub(crate) fn check_record(&self, r: &api::LogRecord, head: &Checkpoint) -> Result<()> {
        self.prove_record(r, head).map(drop)
    }

    /// Check `r` against `head` and return the inclusion proof that passed.
    pub(crate) fn prove_record(&self, r: &api::LogRecord, head: &Checkpoint) -> Result<Vec<Bytes>> {
        let e = api::LogEntry::from_leaf(&r.leaf.0)?;
        ensure!(e.id == r.index + 1, "id {} at index {}", e.id, r.index);
        ensure!(r.index < head.size, "beyond the checkpoint ({})", head.size);
        let p: api::InclusionProof = self.call(
            &format!(
                "/v1/log/proof/inclusion?index={}&size={}",
                r.index, head.size
            ),
            None::<&()>,
        )?;
        let proof = p.proof.iter().map(hash).collect::<Result<Vec<_>>>()?;
        tlog::verify_inclusion(
            &tlog::leaf_hash(&r.leaf.0),
            r.index,
            head.size,
            &proof,
            &head.root,
        )?;
        Ok(p.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlog::{Log, MemStore};

    fn log(n: u8) -> Log<MemStore> {
        let mut l = Log::open(MemStore::default()).unwrap();
        for i in 0..n {
            l.append(&[i]).unwrap();
        }
        l
    }

    fn head(l: &Log<MemStore>) -> Checkpoint {
        l.checkpoint("garble-ds")
    }

    #[test]
    fn honest_growth_is_accepted() {
        let (a, mut b) = (log(3), log(3));
        b.append(b"more").unwrap();
        b.append(b"more").unwrap();
        let proof = b.consistency_proof(3, 5).unwrap();
        assert!(check_advance(Some(&head(&a)), &head(&b), &proof).is_ok());
        assert!(check_advance(None, &head(&b), &[]).is_ok());
        assert!(check_advance(Some(&head(&b)), &head(&b), &[]).is_ok());
    }

    #[test]
    fn rewritten_history_is_refused() {
        let a = log(3);
        // Same size, one entry different: a split view.
        let mut fork = Log::open(MemStore::default()).unwrap();
        for e in [&[0u8][..], &[1], &[9]] {
            fork.append(e).unwrap();
        }
        assert!(check_advance(Some(&head(&a)), &head(&fork), &[]).is_err());

        // Bigger, but built on a different past. The proof is as good as a liar can make.
        fork.append(b"more").unwrap();
        let proof = fork.consistency_proof(3, 4).unwrap();
        assert!(check_advance(Some(&head(&a)), &head(&fork), &proof).is_err());
    }

    #[test]
    fn a_sealed_head_is_never_accepted_from_a_live_ds() {
        let a = log(3);
        let sealed = Checkpoint {
            closed: true,
            ..head(&a)
        };
        assert!(check_advance(None, &sealed, &[]).is_err());
        assert!(check_advance(Some(&head(&a)), &sealed, &[]).is_err());
    }

    #[test]
    fn a_shorter_log_is_refused() {
        assert!(check_advance(Some(&head(&log(5))), &head(&log(4)), &[]).is_err());
    }

    #[test]
    fn missing_or_bogus_proofs_are_refused() {
        let (a, mut b) = (log(3), log(3));
        b.append(b"more").unwrap();
        assert!(check_advance(Some(&head(&a)), &head(&b), &[]).is_err());
        assert!(check_advance(Some(&head(&a)), &head(&b), &[[7; 32]]).is_err());
    }
}
