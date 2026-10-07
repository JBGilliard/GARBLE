//! Every byte on the wire or in the log (architecture §3, §4). Every structure carries
//! a version (`v`); receivers reject versions they don't know.
//!
//! ponytail: JSON with hex-encoded bytes for the walking skeleton. §4 specifies
//! `tls_codec`; switch when a second implementation or MIMI mapping needs it. MLS
//! messages inside are already TLS-encoded by OpenMLS.

use serde::{Deserialize, Serialize};

pub const WIRE_VERSION: u16 = 1;
/// `LogEntry` version. v2 added `marking` and `message`; v1 was never signed into a log.
pub const LOG_ENTRY_VERSION: u16 = 2;
/// `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`, OpenMLS's provisional code point.
/// The single place the suite is named (§12.3).
pub const CIPHERSUITE: u16 = 0x0907;
/// Private-use GroupContext extension carrying [`RoomPolicy`].
pub const ROOM_POLICY_EXT: u16 = 0xF0A0;
/// Private-use LeafNode extension carrying the member's issuer-signed
/// [`AttributeCredential`], so every member can verify a joiner from the tree itself.
pub const ATTRIBUTES_EXT: u16 = 0xF0A2;
/// Private-use MLS credential type; the payload is the user ID.
/// ponytail: should be an EA-signed `IdentityCredential` (§4.2).
pub const GARBLE_CREDENTIAL: u16 = 0xF0A1;

/// Bytes as lower-case hex in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bytes(#[serde(with = "hex")] pub Vec<u8>);

/// The records custodian every room archives to (idea-v1 §1). It holds only the
/// public half of `archive_key`; the private half stays offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodianRef {
    pub id: String,
    /// HPKE public key for the suite's own KEM, ML-KEM-1024.
    pub archive_key: Bytes,
}

/// Room policy, carried in the MLS GroupContext so every member and the DS see the
/// same rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomPolicy {
    pub v: u16,
    /// `markings` canonical bytes.
    pub ceiling: Bytes,
    pub stewards: Vec<String>,
    /// `None` parses fine and fails `Create`: a room with nowhere to archive is refused,
    /// not silently unarchived.
    #[serde(default)]
    pub custodian: Option<CustodianRef>,
    /// Who may ask the custodian to open the archive (`Action::ReadArchive`).
    #[serde(default)]
    pub records_officers: Vec<String>,
}

/// What the issuer signs. `access` is in marking syntax: the clearance covers
/// everything that marking covers (`markings::Clearance::covering`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeBody {
    pub v: u16,
    pub user: String,
    /// The subject's ML-DSA-87 public key. Binds the credential to one key, so a copy
    /// of someone else's credential is useless without their private key.
    pub key: Bytes,
    pub access: String,
    pub citizenship: String,
    pub register_version: u32,
    /// Seconds since the Unix epoch.
    pub not_after: u64,
}

impl AttributeBody {
    /// The exact bytes the issuer signs.
    pub fn signed_bytes(&self) -> Vec<u8> {
        // ponytail: serde_json struct output is deterministic (field order); a real
        // canonical encoding comes with the tls_codec switch.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeCredential {
    pub body: AttributeBody,
    pub sig: Bytes,
}

/// MLS authenticated_data on every handshake: the evidence the policy decision used,
/// so the DS and every member evaluate identical inputs (§4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeAad {
    pub v: u16,
    pub decided_at: u64,
    pub evidence: Vec<AttributeCredential>,
}

/// MLS authenticated_data on every application message. Readable by the DS, signed
/// by the sender (§4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppAad {
    pub v: u16,
    pub sender: String,
    /// `markings` canonical bytes.
    pub marking: Bytes,
    pub sent_at: u64,
    /// Blobs this message points at, so the DS can bind them to its log entry. The
    /// receiver checks them against the envelope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<Bytes>,
    /// SHA-384 of the sealed archive copy ([`ArchiveCopy`] bytes as uploaded). The DS
    /// refuses a message without one: a room with a custodian is always archived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<Bytes>,
}

/// Message priority (idea-v1 §2). v1 sends `Routine` only; the field exists so FLASH
/// handling can arrive without a wire change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Precedence {
    Routine,
    Priority,
    Immediate,
    Flash,
}

pub const TEXT_PLAIN: &str = "text/plain";
/// Signed acknowledgment: the body is the 16-byte `msg_id` being acknowledged, and the
/// message carries that message's marking.
pub const ACK: &str = "application/garble-ack";
/// File attachment: the body is a JSON [`FileRef`]; the bytes live in a DS blob.
pub const FILE: &str = "application/garble-file";
/// Largest ciphertext the DS stores as a blob (and the largest body it reads at all).
pub const MAX_BLOB: usize = 32 * 1024 * 1024;

/// Body of a [`FILE`] envelope. The key travels only inside the MLS message, so the DS
/// stores ciphertext it can't open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    pub name: String,
    /// Plaintext length.
    pub size: u64,
    /// SHA-384 of the blob as stored: its address on the DS.
    pub hash: Bytes,
    /// AES-256 key, 32 bytes.
    pub key: Bytes,
    /// AES-GCM nonce, 12 bytes. One key per file, so a fixed nonce is never reused.
    pub nonce: Bytes,
}

/// What the sender seals to the custodian's archive key: the envelope plus the facts a
/// records officer needs that the envelope doesn't carry.
/// The sender writes this, so it is the sender's word until the custodian is a member
/// that sees the same message (open-questions Q17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRecord {
    pub v: u16,
    pub room: String,
    pub sender: String,
    /// `markings` canonical bytes.
    pub marking: Bytes,
    pub sent_at: u64,
    pub envelope: Envelope,
}

/// An [`ArchiveRecord`] under HPKE (ML-KEM-1024), with the room id as HPKE `info`. The
/// serialized form is what the DS stores and what `AppAad::archive` hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveCopy {
    pub v: u16,
    pub kem_output: Bytes,
    pub ciphertext: Bytes,
}

/// Payload encrypted to a subset of members via HPKE (tearlines, per-message audience).
/// Reserved: v1 senders leave it empty and v1 receivers refuse a message that uses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudienceSlot {
    pub recipients: Vec<String>,
    pub ciphertext: Bytes,
}

/// An additional signer over the envelope (two-person integrity). Reserved: v1 has a
/// single signer, the MLS sender, and refuses messages that carry cosignatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    pub signer: String,
    pub sig: Bytes,
}

/// Where a forwarded message came from. Only the forwarder vouches for it: nothing in
/// the envelope is signed by the original sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forwarded {
    pub room: String,
    pub msg_id: Bytes,
    pub sender: String,
}

/// MLS application plaintext. The marking travels in [`AppAad`] so the DS can check
/// it; everything else is end-to-end encrypted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u16,
    pub msg_id: Bytes,
    pub content_type: String,
    pub precedence: Precedence,
    pub body: Bytes,
    pub reply_to: Option<Bytes>,
    pub audience: Vec<AudienceSlot>,
    pub cosignatures: Vec<Cosignature>,
    /// Set by `garble forward`. The message keeps its original marking.
    #[serde(default)]
    pub forwarded_from: Option<Forwarded>,
}

/// Delivery-service HTTP API bodies.
pub mod api {
    use super::*;

    /// `POST /v1/session/challenge`: a single-use nonce for `user`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ChallengeRequest {
        pub user: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Challenge {
        pub nonce: Bytes,
    }

    /// `POST /v1/session`: the nonce signed with the user's enrolled key.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionRequest {
        pub user: String,
        pub nonce: Bytes,
        pub sig: Bytes,
    }

    /// Bearer token for `authorization: Bearer <token>`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Session {
        pub token: String,
        pub expires_at: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Enroll {
        pub key_package: Bytes,
        pub credential: AttributeCredential,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CreateRoom {
        pub room: String,
        pub group_info: Bytes,
        pub ratchet_tree: Bytes,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Commit {
        pub commit: Bytes,
        pub welcome: Option<Bytes>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Send {
        pub message: Bytes,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Accepted {
        pub seq: u64,
        pub audit: String,
    }

    /// A refusal the UI can inspect: reason, stable code, and the log entry it made.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Refused {
        pub code: String,
        pub reason: String,
        pub audit: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StreamEntry {
        pub seq: u64,
        pub message: Bytes,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Welcome {
        pub room: String,
        pub welcome: Bytes,
        pub ratchet_tree: Bytes,
        /// Stream position of the commit that added this user; read from after it.
        pub after_seq: u64,
    }

    /// The DS asks members to remove `user`; `evidence` is what authorizes it (§5.7).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RemovalRequest {
        pub user: String,
        pub reason: String,
        pub evidence: AttributeCredential,
    }

    /// A removed client reports that it purged its local copy of the room. Proves
    /// compliance only for honest clients (§5.6).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PurgeReceipt {
        pub room: String,
    }

    /// A member's client refused a commit the DS sequenced: the group has forked
    /// (idea-v1 §1a). The DS freezes the room and logs this with the commit's hash.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ForkReport {
        pub seq: u64,
        pub reason: String,
    }

    /// A steward closes a frozen room after investigating; it is never reopened.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClearFork {
        pub note: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClientDenial {
        pub room: String,
        pub action: String,
        pub code: String,
        pub reason: String,
    }

    /// What the log records about a message, never its content: the hash ties the entry
    /// to the exact MLS ciphertext the DS sequenced.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MessageFacts {
        /// SHA-384 of the MLS message as sequenced.
        pub ciphertext_hash: Bytes,
        pub epoch: u64,
        pub sent_at: u64,
        /// Blobs the message references, as in its AAD.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub blobs: Vec<Bytes>,
        /// SHA-384 of the sealed archive copy bound to this message.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub archive: Option<Bytes>,
    }

    /// One sequenced message's sealed archive copy, as the custodian pulls it. `n` is
    /// the position in the DS's archive, so a puller resumes with `after=<count held>`.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ArchiveEntry {
        pub n: u64,
        pub room: String,
        /// Stream position of the message in its room.
        pub seq: u64,
        /// The [`ArchiveCopy`] bytes exactly as uploaded.
        pub copy: Bytes,
        pub blobs: Vec<Bytes>,
    }

    /// `POST /v1/rooms/{r}/archive-read`: ask for a logged `ReadArchive` decision.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ArchiveRead {
        pub reason: String,
    }

    /// Proof that the DS logged a permitted `ReadArchive`: the log entry, its inclusion
    /// proof, and the signed checkpoint the proof is against. What the custodian
    /// checks before it opens anything.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ArchivePermit {
        /// Signed-note checkpoint, as the DS served it.
        pub checkpoint: Bytes,
        pub record: LogRecord,
        pub proof: Vec<Bytes>,
    }

    /// One transparency-log leaf. The leaf bytes are `to_leaf()`; readers hash the bytes
    /// the DS served, not a re-encoding of them.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LogEntry {
        pub v: u16,
        pub id: u64,
        pub at: u64,
        pub actor: String,
        pub room: String,
        pub event: String,
        /// "permit" or "deny".
        pub decision: String,
        pub code: Option<String>,
        pub detail: String,
        /// `markings` canonical bytes; who may read this entry. Room events carry the
        /// room ceiling, user events the subject's access marking.
        pub marking: Bytes,
        /// Set on message events (permitted or denied).
        pub message: Option<MessageFacts>,
    }

    impl LogEntry {
        pub fn to_leaf(&self) -> Vec<u8> {
            // ponytail: same caveat as `AttributeBody::signed_bytes`.
            serde_json::to_vec(self).unwrap_or_default()
        }

        pub fn from_leaf(leaf: &[u8]) -> Result<Self, serde_json::Error> {
            let e: Self = serde_json::from_slice(leaf)?;
            if e.v != LOG_ENTRY_VERSION {
                return Err(serde::de::Error::custom(format!(
                    "log entry version {}",
                    e.v
                )));
            }
            Ok(e)
        }
    }

    /// A log entry the reader may see, as the exact leaf bytes the tree hashes.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LogRecord {
        /// Zero-based leaf index; the entry's `id` minus one.
        pub index: u64,
        pub leaf: Bytes,
    }

    /// `GET /v1/log/proof/inclusion?index=I&size=S`
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InclusionProof {
        pub index: u64,
        pub size: u64,
        pub proof: Vec<Bytes>,
    }

    /// `GET /v1/log/proof/consistency?old=A&new=B`
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConsistencyProof {
        pub old: u64,
        pub new: u64,
        pub proof: Vec<Bytes>,
    }
}

#[cfg(test)]
mod tests {
    use super::api::{LogEntry, MessageFacts};
    use super::*;

    fn entry() -> LogEntry {
        LogEntry {
            v: LOG_ENTRY_VERSION,
            id: 7,
            at: 1_000,
            actor: "alice".into(),
            room: "ops".into(),
            event: "message".into(),
            decision: "permit".into(),
            code: None,
            detail: "marking TS//SI//NF".into(),
            marking: Bytes(vec![1, 2, 3]),
            message: Some(MessageFacts {
                ciphertext_hash: Bytes(vec![9; 48]),
                epoch: 3,
                sent_at: 999,
                blobs: vec![],
                archive: None,
            }),
        }
    }

    #[test]
    fn envelopes_without_forwarded_from_still_parse() {
        let old = br#"{"v":1,"msg_id":"00","content_type":"text/plain","precedence":"Routine","body":"","reply_to":null,"audience":[],"cosignatures":[]}"#;
        assert_eq!(
            serde_json::from_slice::<Envelope>(old)
                .unwrap()
                .forwarded_from,
            None
        );
    }

    #[test]
    fn aad_without_blobs_or_archive_serializes_as_before() {
        let aad = AppAad {
            v: 1,
            sender: "a".into(),
            marking: Bytes(vec![1]),
            sent_at: 5,
            blobs: vec![],
            archive: None,
        };
        let json = serde_json::to_string(&aad).unwrap();
        assert_eq!(json, r#"{"v":1,"sender":"a","marking":"01","sent_at":5}"#);
        assert_eq!(serde_json::from_str::<AppAad>(&json).unwrap(), aad);
    }

    #[test]
    fn leaf_round_trips_and_is_stable() {
        let e = entry();
        assert_eq!(LogEntry::from_leaf(&e.to_leaf()).unwrap(), e);
        assert_eq!(e.to_leaf(), e.clone().to_leaf());
    }

    #[test]
    fn unknown_entry_versions_are_refused() {
        for v in [0, 1, LOG_ENTRY_VERSION + 1] {
            let leaf = LogEntry { v, ..entry() }.to_leaf();
            assert!(LogEntry::from_leaf(&leaf).is_err(), "v{v}");
        }
        // v1 had no marking at all; it must not parse as a v2 entry with a blank one.
        let v1 = br#"{"v":1,"id":1,"at":1,"actor":"a","room":"","event":"e","decision":"permit","code":null,"detail":""}"#;
        assert!(LogEntry::from_leaf(v1).is_err());
    }
}
