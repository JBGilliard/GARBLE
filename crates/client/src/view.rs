//! Read-only questions a UI asks of the client: what rooms, what history, would this
//! marking be accepted, what does the log say about that refusal. Nothing here sends.

use anyhow::{Context, Result, ensure};
use identity::KeyStore;
use identity::room::{RoomRules, user_of};
use markings::{Marking, MarkingError, parse};
use policy::Decision;
use proto::{AppAad, Bytes, WIRE_VERSION, api};

use crate::audit::Advance;
use crate::{Client, IntegrityAlert, now};

#[derive(Debug, Clone)]
pub struct RoomInfo {
    pub room: String,
    pub ceiling: Marking,
    pub members: Vec<String>,
    pub stewards: Vec<String>,
    /// Frozen after a fork: reads stop, nothing can be sent.
    pub held: bool,
    pub last_seq: u64,
}

/// A text message this client has seen, from the local copy.
#[derive(Debug, Clone)]
pub struct Remembered {
    pub seq: u64,
    pub sender: String,
    pub marking: String,
    pub text: String,
}

/// Why a send would be refused. Same codes the real refusal carries.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum Inclusion {
    /// The entry is in the tree of this checkpoint, proof checked here.
    Proven { size: u64, root: String },
    /// Not among the entries this reader may see. Not the same as absent.
    Withheld,
}

#[derive(Debug, Clone)]
pub struct AuditLine {
    pub id: u64,
    pub at: u64,
    pub actor: String,
    pub room: String,
    pub event: String,
    pub decision: String,
    pub code: Option<String>,
    pub detail: String,
    pub marking: String,
}

#[derive(Debug, Clone)]
pub struct AuditDetail {
    pub entry: Option<AuditLine>,
    pub inclusion: Inclusion,
}

impl<K: KeyStore> Client<K> {
    pub fn rooms(&self) -> Result<Vec<RoomInfo>> {
        self.state
            .rooms
            .iter()
            .map(|(room, rs)| {
                let group = self.group(room)?;
                let rules = RoomRules::read(group.extensions(), &self.trust)?;
                let mut members: Vec<String> = group
                    .members()
                    .filter_map(|m| user_of(&m.credential).ok())
                    .collect();
                members.sort();
                members.dedup();
                Ok(RoomInfo {
                    room: room.clone(),
                    ceiling: rules.ceiling,
                    members,
                    stewards: rules.stewards,
                    held: rs.held,
                    last_seq: rs.cursor,
                })
            })
            .collect()
    }

    /// Text messages kept locally, oldest first. Acks and quarantined messages aren't
    /// kept, so a UI that wants them has to hold on to the events.
    pub fn history(&self, room: &str) -> Vec<Remembered> {
        let Some(rs) = self.state.rooms.get(room) else {
            return vec![];
        };
        rs.inbox
            .iter()
            .map(|(seq, m)| Remembered {
                seq: *seq,
                sender: m.sender.clone(),
                marking: self
                    .marking_of(m)
                    .map_or_else(|e| format!("unreadable: {e}"), |m| m.portion()),
                text: m.text(),
            })
            .collect()
    }

    pub fn parse_marking(&self, text: &str) -> Result<Marking, MarkingError> {
        parse(text, &self.trust.registers())
    }

    /// Would `send` accept `marking` in `room` right now? Runs the same checks and
    /// reports nothing to the DS: it's for a composer that checks as you type.
    pub fn check_send(&self, room: &str, marking: &Marking) -> Result<Option<Refusal>> {
        if let Some(why) = &self.state.alert {
            return Ok(Some(Refusal {
                code: "L-001".into(),
                reason: format!("log integrity: {why}"),
            }));
        }
        if self.state.rooms.get(room).is_some_and(|r| r.held) {
            return Ok(Some(Refusal {
                code: "F-001".into(),
                reason: "room frozen after a fork".into(),
            }));
        }
        let group = self.group(room)?;
        let rules = RoomRules::read(group.extensions(), &self.trust)?;
        let aad = AppAad {
            v: WIRE_VERSION,
            sender: self.state.user.clone(),
            marking: Bytes(marking.canonical_bytes()?),
            sent_at: now(),
            blobs: vec![],
            archive: None,
            envelope: Bytes(vec![]),
        };
        let (_, d) = rules.check_message(
            &self.trust,
            &aad,
            self.own_credential()?,
            &self.state.signer_public.0,
        )?;
        Ok(match d {
            Decision::Permit => None,
            Decision::Deny(r) => Some(Refusal {
                code: r.code().into(),
                reason: r.to_string(),
            }),
        })
    }

    /// When our attribute credential lapses, seconds since the epoch. `None`: not enrolled.
    pub fn credential_expiry(&self) -> Option<u64> {
        self.state.credential.as_ref().map(|c| c.body.not_after)
    }

    /// What the log says about `audit_ref` (`L-<id>`), with its inclusion proof checked
    /// against the checkpoint. A bad proof is an integrity alert, as in `verify_log`.
    /// ponytail: fetches every entry we may read to find one; the DS has no by-id route.
    pub fn audit_detail(&mut self, audit_ref: &str) -> Result<AuditDetail> {
        let id: u64 = audit_ref
            .strip_prefix("L-")
            .and_then(|n| n.parse().ok())
            .filter(|n| *n > 0)
            .with_context(|| format!("{audit_ref:?} isn't an audit reference"))?;
        if let Some(why) = self.state.alert.clone() {
            return Err(IntegrityAlert(why).into());
        }
        let records: Vec<api::LogRecord> = self.call("/v1/log/entries", None::<&()>)?;
        let head = match self.advance_checkpoint()? {
            Advance::Fine { head, .. } => head,
            Advance::Fault(why) => return Err(self.raise(why)),
        };
        let Some(r) = records.iter().find(|r| r.index + 1 == id) else {
            return Ok(AuditDetail {
                entry: None,
                inclusion: Inclusion::Withheld,
            });
        };
        if let Err(why) = self.check_record(r, &head) {
            return Err(self.raise(format!("log entry {id}: {why:#}")));
        }
        let e = api::LogEntry::from_leaf(&r.leaf.0)?;
        let marking = Marking::from_canonical(&e.marking.0, &self.trust.registers())
            .map_or_else(|err| format!("unreadable: {err}"), |m| m.portion());
        ensure!(e.id == id, "log entry {} served as {id}", e.id);
        Ok(AuditDetail {
            entry: Some(AuditLine {
                id: e.id,
                at: e.at,
                actor: e.actor,
                room: e.room,
                event: e.event,
                decision: e.decision,
                code: e.code,
                detail: e.detail,
                marking,
            }),
            inclusion: Inclusion::Proven {
                size: head.size,
                root: head.root.iter().map(|b| format!("{b:02x}")).collect(),
            },
        })
    }
}
