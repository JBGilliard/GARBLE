//! Every byte on the wire or in the log (architecture §3, §4). Every structure carries
//! a version (`v`); receivers reject versions they don't know.
//!
//! Anything signed, hashed or carried inside MLS is TLS-encoded (`tls_codec`), one
//! canonical form per value: use [`encode`] and [`decode`]. JSON survives only for the
//! HTTP bodies and local files around those bytes, which is why the serde derives stay.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsDeserialize,
    TlsSerialize, TlsSize, VLByteSlice, VLBytes,
};

pub use tls_codec::Error as TlsError;

pub const WIRE_VERSION: u16 = 2;
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

/// Bytes as lower-case hex in JSON, a variable-length vector in TLS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bytes(#[serde(with = "hex")] pub Vec<u8>);

impl Size for Bytes {
    fn tls_serialized_len(&self) -> usize {
        VLByteSlice(&self.0).tls_serialized_len()
    }
}

impl TlsSerializeTrait for Bytes {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        VLByteSlice(&self.0).tls_serialize(writer)
    }
}

impl TlsDeserializeTrait for Bytes {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, TlsError> {
        Ok(Self(VLBytes::tls_deserialize(reader)?.into()))
    }
}

pub fn encode<T: TlsSerializeTrait>(value: &T) -> Result<Vec<u8>, TlsError> {
    value.tls_serialize_detached()
}

/// Rejects trailing bytes and anything that doesn't re-encode to the same bytes (a
/// non-minimal length prefix, say), so a hash of the input is a hash of the value.
pub fn decode<T: TlsDeserializeTrait + TlsSerializeTrait>(bytes: &[u8]) -> Result<T, TlsError> {
    let value = T::tls_deserialize_exact(bytes)?;
    if value.tls_serialize_detached()? != bytes {
        return Err(TlsError::DecodingError("non-canonical encoding".into()));
    }
    Ok(value)
}

// Only reachable above the 2^30-byte vector limit; bodies are capped far below that.
fn canonical<T: TlsSerializeTrait>(value: &T) -> Vec<u8> {
    encode(value).expect("encoded size is capped well below the TLS vector limit")
}

/// The records custodian every room archives to (idea-v1 §1). It holds only the
/// public half of `archive_key`; the private half stays offline.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CustodianRef {
    pub id: String,
    /// HPKE public key for the suite's own KEM, ML-KEM-1024.
    pub archive_key: Bytes,
}

/// Room policy, carried in the MLS GroupContext so every member and the DS see the
/// same rules.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct RoomPolicy {
    pub v: u16,
    /// `markings` canonical bytes.
    pub ceiling: Bytes,
    pub stewards: Vec<String>,
    /// `None` parses fine and fails `Create`: a room with nowhere to archive is refused,
    /// not silently unarchived.
    pub custodian: Option<CustodianRef>,
    /// Who may ask the custodian to open the archive (`Action::ReadArchive`).
    pub records_officers: Vec<String>,
}

/// What the issuer signs. `access` is in marking syntax: the clearance covers
/// everything that marking covers (`markings::Clearance::covering`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
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
        canonical(self)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AttributeCredential {
    pub body: AttributeBody,
    pub sig: Bytes,
}

/// MLS authenticated_data on every handshake: the evidence the policy decision used,
/// so the DS and every member evaluate identical inputs (§4.5).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct HandshakeAad {
    pub v: u16,
    pub decided_at: u64,
    pub evidence: Vec<AttributeCredential>,
}

/// MLS authenticated_data on every application message. Readable by the DS, signed
/// by the sender (§4.5).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AppAad {
    pub v: u16,
    pub sender: String,
    /// `markings` canonical bytes.
    pub marking: Bytes,
    pub sent_at: u64,
    /// Blobs this message points at, so the DS can bind them to its log entry. The
    /// receiver checks them against the envelope.
    pub blobs: Vec<Bytes>,
    /// SHA-384 of the sealed archive copy ([`ArchiveCopy`] bytes as uploaded). The DS
    /// refuses a message without one: a room with a custodian is always archived.
    pub archive: Option<Bytes>,
    /// SHA-384 of the canonical [`Envelope`]. Receivers and the custodian check it, so
    /// the archived message is the one members got (Q17). Safe to expose: the random
    /// `msg_id` inside keeps it from confirming a guess at the content. Empty only where
    /// no message exists yet (composer previews, blob uploads).
    pub envelope: Bytes,
}

/// Message priority (idea-v1 §2). v1 sends `Routine` only; the field exists so FLASH
/// handling can arrive without a wire change.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
#[repr(u8)]
pub enum Precedence {
    Routine = 0,
    Priority = 1,
    Immediate = 2,
    Flash = 3,
}

pub const TEXT_PLAIN: &str = "text/plain";
/// Signed acknowledgment: the body is the 16-byte `msg_id` being acknowledged, and the
/// message carries that message's marking.
pub const ACK: &str = "application/garble-ack";
/// File attachment: the body is a TLS-encoded [`FileRef`]; the bytes live in a DS blob.
pub const FILE: &str = "application/garble-file";
/// Largest ciphertext the DS stores as a blob (and the largest body it reads at all).
pub const MAX_BLOB: usize = 32 * 1024 * 1024;

/// Body of a [`FILE`] envelope. The key travels only inside the MLS message, so the DS
/// stores ciphertext it can't open.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
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
/// The sender writes this, so the custodian checks the envelope against the hash in the
/// message's [`AppAad`] before believing it (open-questions Q17). `marking` and
/// `sent_at` are still the sender's word.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
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
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ArchiveCopy {
    pub v: u16,
    pub kem_output: Bytes,
    pub ciphertext: Bytes,
}

/// Payload encrypted to a subset of members via HPKE (tearlines, per-message audience).
/// Reserved: v1 senders leave it empty and v1 receivers refuse a message that uses it.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct AudienceSlot {
    pub recipients: Vec<String>,
    pub ciphertext: Bytes,
}

/// An additional signer over the envelope (two-person integrity). Reserved: v1 has a
/// single signer, the MLS sender, and refuses messages that carry cosignatures.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct Cosignature {
    pub signer: String,
    pub sig: Bytes,
}

/// Where a forwarded message came from. Only the forwarder vouches for it: nothing in
/// the envelope is signed by the original sender.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct Forwarded {
    pub room: String,
    pub msg_id: Bytes,
    pub sender: String,
}

/// MLS application plaintext. The marking travels in [`AppAad`] so the DS can check
/// it; everything else is end-to-end encrypted here.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
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
    #[derive(
        Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
    )]
    pub struct MessageFacts {
        /// SHA-384 of the MLS message as sequenced.
        pub ciphertext_hash: Bytes,
        pub epoch: u64,
        pub sent_at: u64,
        /// Blobs the message references, as in its AAD.
        pub blobs: Vec<Bytes>,
        /// SHA-384 of the sealed archive copy bound to this message.
        pub archive: Option<Bytes>,
        /// SHA-384 of the envelope, as in its AAD.
        pub envelope: Bytes,
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
        /// `AppAad::envelope` of the message the copy was filed for.
        pub envelope: Bytes,
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
    #[derive(
        Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
    )]
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
            canonical(self)
        }

        pub fn from_leaf(leaf: &[u8]) -> Result<Self, TlsError> {
            let e: Self = decode(leaf)?;
            if e.v != LOG_ENTRY_VERSION {
                return Err(TlsError::DecodingError(format!(
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

    fn b(n: u8) -> Bytes {
        Bytes(vec![n; 3])
    }

    fn entry() -> LogEntry {
        LogEntry {
            v: LOG_ENTRY_VERSION,
            id: 7,
            at: 1_000,
            actor: "alice".into(),
            room: "ops".into(),
            event: "message".into(),
            decision: "permit".into(),
            code: Some("P-001".into()),
            detail: "marking TS//SI//NF".into(),
            marking: Bytes(vec![1, 2, 3]),
            message: Some(MessageFacts {
                ciphertext_hash: Bytes(vec![9; 48]),
                epoch: 3,
                sent_at: 999,
                blobs: vec![b(1), b(2)],
                archive: Some(b(3)),
                envelope: Bytes(vec![8; 48]),
            }),
        }
    }

    fn body() -> AttributeBody {
        AttributeBody {
            v: WIRE_VERSION,
            user: "alice".into(),
            key: Bytes(vec![7; 2592]),
            access: "TS//SI".into(),
            citizenship: "USA".into(),
            register_version: 4,
            not_after: 2_000_000_000,
        }
    }

    fn credential() -> AttributeCredential {
        AttributeCredential {
            body: body(),
            sig: b(5),
        }
    }

    fn policy() -> RoomPolicy {
        RoomPolicy {
            v: WIRE_VERSION,
            ceiling: b(1),
            stewards: vec!["alice".into(), "bob".into()],
            custodian: Some(CustodianRef {
                id: "records".into(),
                archive_key: b(2),
            }),
            records_officers: vec!["carol".into()],
        }
    }

    fn app_aad() -> AppAad {
        AppAad {
            v: WIRE_VERSION,
            sender: "alice".into(),
            marking: b(1),
            sent_at: 5,
            blobs: vec![b(2)],
            archive: Some(b(3)),
            envelope: Bytes(vec![4; 48]),
        }
    }

    fn envelope() -> Envelope {
        Envelope {
            v: WIRE_VERSION,
            msg_id: Bytes(vec![4; 16]),
            content_type: TEXT_PLAIN.into(),
            precedence: Precedence::Flash,
            body: Bytes("héllo".into()),
            reply_to: Some(Bytes(vec![5; 16])),
            audience: vec![AudienceSlot {
                recipients: vec!["bob".into()],
                ciphertext: b(6),
            }],
            cosignatures: vec![Cosignature {
                signer: "carol".into(),
                sig: b(7),
            }],
            forwarded_from: Some(Forwarded {
                room: "ops".into(),
                msg_id: b(8),
                sender: "dave".into(),
            }),
        }
    }

    fn file_ref() -> FileRef {
        FileRef {
            name: "plan.pdf".into(),
            size: 1 << 33,
            hash: Bytes(vec![1; 48]),
            key: Bytes(vec![2; 32]),
            nonce: Bytes(vec![3; 12]),
        }
    }

    fn handshake_aad() -> HandshakeAad {
        HandshakeAad {
            v: WIRE_VERSION,
            decided_at: 42,
            evidence: vec![credential(), credential()],
        }
    }

    fn archive_record() -> ArchiveRecord {
        ArchiveRecord {
            v: WIRE_VERSION,
            room: "ops".into(),
            sender: "alice".into(),
            marking: b(1),
            sent_at: 5,
            envelope: envelope(),
        }
    }

    fn archive_copy() -> ArchiveCopy {
        ArchiveCopy {
            v: WIRE_VERSION,
            kem_output: Bytes(vec![1; 1568]),
            ciphertext: b(2),
        }
    }

    fn round_trips<T>(value: T)
    where
        T: TlsSerializeTrait + TlsDeserializeTrait + PartialEq + std::fmt::Debug,
    {
        let bytes = encode(&value).unwrap();
        assert_eq!(decode::<T>(&bytes).unwrap(), value);
        assert_eq!(encode(&value).unwrap(), bytes, "encoding must be stable");
        // Every proper prefix is a truncation, and none may parse.
        for n in 0..bytes.len() {
            assert!(decode::<T>(&bytes[..n]).is_err(), "prefix of {n} bytes");
        }
        let mut long = bytes;
        long.push(0);
        assert!(decode::<T>(&long).is_err(), "trailing byte");
    }

    #[test]
    fn every_type_round_trips() {
        round_trips(body());
        round_trips(credential());
        round_trips(policy());
        round_trips(RoomPolicy {
            custodian: None,
            records_officers: vec![],
            ..policy()
        });
        round_trips(handshake_aad());
        round_trips(app_aad());
        round_trips(AppAad {
            blobs: vec![],
            archive: None,
            ..app_aad()
        });
        round_trips(envelope());
        round_trips(Envelope {
            reply_to: None,
            audience: vec![],
            cosignatures: vec![],
            forwarded_from: None,
            ..envelope()
        });
        round_trips(file_ref());
        round_trips(archive_record());
        round_trips(archive_copy());
        round_trips(entry());
        round_trips(LogEntry {
            code: None,
            message: None,
            ..entry()
        });
    }

    #[test]
    fn precedence_codes_are_fixed() {
        for (p, code) in [
            (Precedence::Routine, 0u8),
            (Precedence::Priority, 1),
            (Precedence::Immediate, 2),
            (Precedence::Flash, 3),
        ] {
            assert_eq!(encode(&p).unwrap(), [code]);
            assert_eq!(decode::<Precedence>(&[code]).unwrap(), p);
        }
        assert!(decode::<Precedence>(&[4]).is_err());
    }

    #[test]
    fn encoding_layout_is_fixed() {
        // v=2, user "al", key 01, access "", citizenship "", register 3, not_after 4.
        let body = AttributeBody {
            v: 2,
            user: "al".into(),
            key: Bytes(vec![1]),
            access: String::new(),
            citizenship: String::new(),
            register_version: 3,
            not_after: 4,
        };
        let want = [
            &[0, 2][..],
            &[2, b'a', b'l'],
            &[1, 1],
            &[0],
            &[0],
            &[0, 0, 0, 3],
            &[0, 0, 0, 0, 0, 0, 0, 4],
        ]
        .concat();
        assert_eq!(body.signed_bytes(), want);
    }

    #[test]
    fn signed_bytes_are_the_tls_encoding() {
        let b = body();
        assert_eq!(b.signed_bytes(), encode(&b).unwrap());
        assert_eq!(entry().to_leaf(), encode(&entry()).unwrap());
    }

    #[test]
    fn a_non_minimal_length_prefix_is_refused() {
        // 0x40 0x01 is the two-byte spelling of length 1. It parses, but it isn't the
        // bytes `encode` would produce, so hashing it would hash a second spelling.
        assert_eq!(decode::<Bytes>(&[1, 9]).unwrap(), Bytes(vec![9]));
        assert!(decode::<Bytes>(&[0x40, 1, 9]).is_err());
    }

    #[test]
    fn invalid_utf8_is_refused() {
        let mut bytes = encode(&Forwarded {
            room: "r".into(),
            msg_id: b(1),
            sender: "s".into(),
        })
        .unwrap();
        bytes[1] = 0xff;
        assert!(decode::<Forwarded>(&bytes).is_err());
    }

    #[test]
    fn v1_json_is_refused() {
        let envelope = br#"{"v":1,"msg_id":"00","content_type":"text/plain","precedence":"Routine","body":"","reply_to":null,"audience":[],"cosignatures":[]}"#;
        let aad = br#"{"v":1,"sender":"a","marking":"01","sent_at":5}"#;
        let handshake = br#"{"v":1,"decided_at":5,"evidence":[]}"#;
        let attrs = br#"{"v":1,"user":"a","key":"00","access":"S","citizenship":"USA","register_version":1,"not_after":9}"#;
        let cred = br#"{"body":{"v":1,"user":"a","key":"00","access":"S","citizenship":"USA","register_version":1,"not_after":9},"sig":"00"}"#;
        let policy =
            br#"{"v":1,"ceiling":"01","stewards":[],"custodian":null,"records_officers":[]}"#;
        let record = br#"{"v":1,"room":"r","sender":"a","marking":"01","sent_at":1,"envelope":{}}"#;
        let copy = br#"{"v":1,"kem_output":"00","ciphertext":"00"}"#;
        let file = br#"{"name":"f","size":1,"hash":"00","key":"00","nonce":"00"}"#;
        assert!(decode::<Envelope>(envelope).is_err());
        assert!(decode::<AppAad>(aad).is_err());
        assert!(decode::<HandshakeAad>(handshake).is_err());
        assert!(decode::<AttributeBody>(attrs).is_err());
        assert!(decode::<AttributeCredential>(cred).is_err());
        assert!(decode::<RoomPolicy>(policy).is_err());
        assert!(decode::<ArchiveRecord>(record).is_err());
        assert!(decode::<ArchiveCopy>(copy).is_err());
        assert!(decode::<FileRef>(file).is_err());
        // A JSON leaf reads as version 0x7b22.
        let v1 = br#"{"v":2,"id":1,"at":1,"actor":"a","room":"","event":"e","decision":"permit","code":null,"detail":"","marking":"01","message":null}"#;
        assert!(LogEntry::from_leaf(v1).is_err());
    }

    #[test]
    fn fuzz_seeds_are_valid_v2_values() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/wire_decode/");
        let read = |f: &str| std::fs::read(format!("{dir}{f}")).unwrap();
        assert!(decode::<Envelope>(&read("envelope")).is_ok());
        assert!(decode::<AppAad>(&read("app_aad")).is_ok());
        assert!(decode::<HandshakeAad>(&read("handshake_aad")).is_ok());
    }

    #[test]
    fn unknown_entry_versions_are_refused() {
        for v in [0, 1, LOG_ENTRY_VERSION + 1] {
            let leaf = LogEntry { v, ..entry() }.to_leaf();
            assert!(LogEntry::from_leaf(&leaf).is_err(), "v{v}");
        }
        assert_eq!(LogEntry::from_leaf(&entry().to_leaf()).unwrap(), entry());
    }

    #[test]
    fn wire_version_is_two() {
        assert_eq!(WIRE_VERSION, 2);
        // The first field of every versioned structure is `v`, big-endian.
        assert_eq!(app_aad().tls_serialize_detached().unwrap()[..2], [0, 2]);
    }

    #[test]
    fn json_bodies_still_carry_bytes_as_hex() {
        let c = credential();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(
            serde_json::from_str::<AttributeCredential>(&json).unwrap(),
            c
        );
        assert_eq!(
            serde_json::to_string(&Bytes(vec![0xab, 1])).unwrap(),
            r#""ab01""#
        );
    }
}
