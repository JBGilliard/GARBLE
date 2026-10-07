//! Client core shared by the CLI, the desktop app and the custodian (architecture §3, §7).
//!
//! Every action is checked by `policy` here *before* it is sent; every refusal is
//! reported to the DS so it is logged. Everything received is checked again, so a
//! malicious DS can't slip a policy-violating commit or message past this client.
//!
//! ponytail: walking skeleton.
//! - One process per command: state is loaded from and saved to `home` each time.
//!   MLS state is a plaintext JSON dump; SQLCipher (§7.2) replaces it.
//! - Provider is `openmls_rust_crypto` (open question Q1); keys live in that storage
//!   file, no `KeyStore` trait yet.
//! - Message plaintext is bare UTF-8 text; the §4.5 `Envelope` (msg ids, files) later.

mod archive;
mod audit;
mod files;
mod view;

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use identity::room::{
    CommitView, LeafIdentity, RoomRules, attributes_extension, ciphersuite, leaf_identity, user_of,
};
use identity::{FileKeyStore, KeyStore, TrustBundle};
use markings::{Marking, parse};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::Signer as _;
use policy::Decision;
use proto::{
    ACK, ATTRIBUTES_EXT, AppAad, AttributeCredential, Bytes, CustodianRef, Envelope, FILE, FileRef,
    Forwarded, GARBLE_CREDENTIAL, HandshakeAad, MAX_BLOB, Precedence, ROOM_POLICY_EXT, RoomPolicy,
    TEXT_PLAIN, WIRE_VERSION, api,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use audit::{IntegrityAlert, LogReport};
pub use view::{AuditDetail, AuditLine, Inclusion, Refusal, Remembered, RoomInfo};

/// A refusal, from this client's own policy check or from the DS. Inspectable: it
/// carries the stable reason code and the audit log entry it produced.
#[derive(Debug, Clone)]
pub struct Denied {
    pub by: &'static str,
    pub code: String,
    pub reason: String,
    pub audit: String,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DENIED by {} [{}] {} (audit {})",
            self.by, self.code, self.reason, self.audit
        )
    }
}

impl std::error::Error for Denied {}

/// One thing that happened in a room, as the reader sees it.
#[derive(Debug, Clone)]
pub enum Event {
    Message {
        seq: u64,
        sender: String,
        marking: String,
        text: String,
        forwarded_from: Option<Forwarded>,
    },
    /// A signed acknowledgment. `of` is the stream position of the message it
    /// acknowledges, when this client has that message.
    Ack {
        seq: u64,
        sender: String,
        of: Option<u64>,
        marking: String,
    },
    /// Received but refused by this client's policy check; the body is not shown.
    Quarantined {
        seq: u64,
        sender: String,
        reason: String,
    },
    Joined {
        room: String,
    },
    CeilingChanged {
        seq: u64,
        by: String,
        ceiling: String,
    },
    /// We were added to a room our own clearance doesn't cover; we refused to join.
    JoinRefused {
        reason: String,
    },
    MembershipChanged {
        seq: u64,
        by: String,
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// We were removed. The local copy of the room has been purged and the purge
    /// reported (§5.6). Best effort: a modified client could keep what it had.
    Purged {
        seq: u64,
        by: String,
    },
    /// The DS sequenced a commit this client's policy refuses (§5.3 case C).
    IntegrityHold {
        seq: u64,
        reason: String,
    },
    /// The DS's log failed verification (§8). Sending is off until someone looks; reads
    /// carry on. Reported on every sync while it stands, under an empty room name.
    LogAlert {
        reason: String,
    },
}

#[derive(Default, Serialize, Deserialize)]
struct RoomState {
    cursor: u64,
    /// Sequence numbers of our own commits and messages, which we never re-process.
    own: BTreeSet<u64>,
    held: bool,
    /// Text messages sent or received, by stream position.
    #[serde(default)]
    inbox: BTreeMap<u64, Stored>,
}

/// Kept so a message can be acked, forwarded or fetched later: MLS can't decrypt it
/// twice.
/// ponytail: plaintext in state.json like the MLS dump; SQLCipher (§7.2) replaces it,
/// and purge already drops it with the room.
#[derive(Serialize, Deserialize)]
struct Stored {
    sender: String,
    msg_id: Bytes,
    /// `markings` canonical bytes.
    marking: Bytes,
    body: Bytes,
    /// `TEXT_PLAIN` or `FILE` (whose body is a `FileRef`).
    #[serde(default = "text_plain")]
    content_type: String,
}

fn text_plain() -> String {
    TEXT_PLAIN.into()
}

/// What a file looks like in a message list. The bytes come with `fetch`.
fn file_text(f: &FileRef) -> String {
    format!("[file] {} ({} bytes)", f.name, f.size)
}

impl Stored {
    /// What to show for it: the text, or a line about the file.
    fn text(&self) -> String {
        match serde_json::from_slice::<FileRef>(&self.body.0) {
            Ok(f) if self.content_type == FILE => file_text(&f),
            _ => String::from_utf8_lossy(&self.body.0).into_owned(),
        }
    }
}

/// An application message on its way out.
struct Outgoing {
    content_type: &'static str,
    body: Vec<u8>,
    forwarded_from: Option<Forwarded>,
    /// Ciphertext for the DS blob store, when the body is a `FileRef` to it.
    blob: Option<Vec<u8>>,
}

impl Outgoing {
    fn new(content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            content_type,
            body,
            forwarded_from: None,
            blob: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct State {
    user: String,
    ds: String,
    signer_public: Bytes,
    credential: Option<AttributeCredential>,
    rooms: BTreeMap<String, RoomState>,
    /// Last log checkpoint accepted, as the signed note the DS served.
    #[serde(default)]
    checkpoint: Option<Bytes>,
    /// Why the log is distrusted, once it is.
    #[serde(default)]
    alert: Option<String>,
}

#[derive(Default)]
struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

/// A client over any [`KeyStore`]; the default is the development file store.
pub struct Client<K: KeyStore = FileKeyStore> {
    home: PathBuf,
    state: State,
    provider: Provider,
    signer: K::Signer,
    trust: TrustBundle,
    http: ureq::Agent,
    session: OnceCell<String>,
}

/// A 200 passes; a 403 becomes a `Denied` the caller can inspect.
fn ok(mut resp: ureq::http::Response<ureq::Body>) -> Result<ureq::http::Response<ureq::Body>> {
    match resp.status().as_u16() {
        200 => Ok(resp),
        401 => bail!("DS refused the session (401)"),
        403 => {
            let r: api::Refused = resp.body_mut().read_json()?;
            Err(Denied {
                by: "DS",
                code: r.code,
                reason: r.reason,
                audit: r.audit,
            }
            .into())
        }
        n => bail!("DS returned {n}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Client<FileKeyStore> {
    /// Development identity: key in `home/key.json`.
    pub fn create(home: &Path, user: &str, ds: &str, trust: &Path) -> Result<Self> {
        std::fs::create_dir_all(home)?;
        Self::create_with(
            home,
            FileKeyStore::new(home.join("key.json")),
            user,
            ds,
            trust,
        )
    }

    pub fn open(home: &Path) -> Result<Self> {
        Self::open_with(home, FileKeyStore::new(home.join("key.json")))
    }
}

impl<K: KeyStore> Client<K> {
    /// Create a new identity in `home` (a fresh ML-DSA-87 key).
    /// Create a new identity in `home`, with its key in `keys`.
    pub fn create_with(home: &Path, keys: K, user: &str, ds: &str, trust: &Path) -> Result<Self> {
        ensure!(
            !home.join("state.json").exists(),
            "{} already holds an identity",
            home.display()
        );
        std::fs::create_dir_all(home)?;
        std::fs::copy(trust, home.join("trust.json"))?;
        let state = State {
            user: user.into(),
            ds: ds.trim_end_matches('/').into(),
            signer_public: Bytes(keys.public_key()?),
            credential: None,
            rooms: BTreeMap::new(),
            checkpoint: None,
            alert: None,
        };
        let c = Self::assemble(home, state, Provider::default(), keys.signer()?)?;
        c.save()?;
        Ok(c)
    }

    pub fn open_with(home: &Path, keys: K) -> Result<Self> {
        let state: State = serde_json::from_slice(
            &std::fs::read(home.join("state.json"))
                .with_context(|| format!("no identity in {}", home.display()))?,
        )?;
        ensure!(
            keys.public_key()? == state.signer_public.0,
            "key store holds a different key than this identity"
        );
        let dump: Vec<(Bytes, Bytes)> =
            serde_json::from_slice(&std::fs::read(home.join("mls.json"))?)?;
        let values: HashMap<Vec<u8>, Vec<u8>> = dump.into_iter().map(|(k, v)| (k.0, v.0)).collect();
        let provider = Provider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(values),
            },
        };
        Self::assemble(home, state, provider, keys.signer()?)
    }

    fn assemble(home: &Path, state: State, provider: Provider, signer: K::Signer) -> Result<Self> {
        let trust = TrustBundle::load(&home.join("trust.json"))?;
        let http = ureq::Agent::config_builder()
            .http_status_as_error(false)
            // A UI holds a lock across sync; a DS that never answers mustn't freeze it.
            .timeout_global(Some(std::time::Duration::from_secs(20)))
            .build()
            .into();
        Ok(Self {
            home: home.into(),
            state,
            provider,
            signer,
            trust,
            http,
            session: OnceCell::new(),
        })
    }

    pub fn save(&self) -> Result<()> {
        let values = self
            .provider
            .storage
            .values
            .read()
            .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
        let dump: Vec<(Bytes, Bytes)> = values
            .iter()
            .map(|(k, v)| (Bytes(k.clone()), Bytes(v.clone())))
            .collect();
        std::fs::write(self.home.join("mls.json"), serde_json::to_vec(&dump)?)?;
        std::fs::write(
            self.home.join("state.json"),
            serde_json::to_vec_pretty(&self.state)?,
        )?;
        Ok(())
    }

    pub fn user(&self) -> &str {
        &self.state.user
    }

    /// This identity's ML-DSA-87 public key, hex. The issuer binds credentials to it.
    pub fn public_key_hex(&self) -> String {
        self.state
            .signer_public
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The log entries this user is cleared to read.
    /// ponytail: trusts the DS for inclusion; `garble log verify` checks the proofs.
    pub fn audit_log(&self) -> Result<Vec<api::LogEntry>> {
        let records: Vec<api::LogRecord> = self.call("/v1/log/entries", None::<&()>)?;
        records
            .iter()
            .map(|r| Ok(api::LogEntry::from_leaf(&r.leaf.0)?))
            .collect()
    }

    // ───────────────────────────── HTTP ─────────────────────────────

    /// POST or GET to the DS. A 403 becomes a `Denied` error.
    fn call<T: DeserializeOwned>(&self, path: &str, body: Option<&impl Serialize>) -> Result<T> {
        let auth = format!("Bearer {}", self.token()?);
        self.request(path, body, Some(&auth))
    }

    /// The session token, opened on first use by signing a DS challenge (§5).
    fn token(&self) -> Result<&str> {
        if let Some(t) = self.session.get() {
            return Ok(t);
        }
        let user = self.state.user.clone();
        let c: api::Challenge = self.request(
            "/v1/session/challenge",
            Some(&api::ChallengeRequest { user: user.clone() }),
            None,
        )?;
        let sig = self
            .signer
            .sign(&identity::session_bytes(&user, &c.nonce.0))
            .map_err(|e| anyhow::anyhow!("sign session: {e:?}"))?;
        let s: api::Session = self.request(
            "/v1/session",
            Some(&api::SessionRequest {
                user,
                nonce: c.nonce,
                sig: Bytes(sig),
            }),
            None,
        )?;
        Ok(self.session.get_or_init(|| s.token))
    }

    fn request<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<&impl Serialize>,
        auth: Option<&str>,
    ) -> Result<T> {
        let url = format!("{}{path}", self.state.ds);
        let resp = match (body, auth) {
            (Some(b), Some(a)) => self
                .http
                .post(&url)
                .header("authorization", a)
                .send_json(b)?,
            (Some(b), None) => self.http.post(&url).send_json(b)?,
            (None, Some(a)) => self.http.get(&url).header("authorization", a).call()?,
            (None, None) => self.http.get(&url).call()?,
        };
        Ok(ok(resp)?.body_mut().read_json()?)
    }

    /// GET a non-JSON body (checkpoints are signed notes, blobs are ciphertext).
    fn raw(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}{path}", self.state.ds))
            .header("authorization", format!("Bearer {}", self.token()?))
            .call()?;
        Ok(ok(resp)?
            .body_mut()
            .with_config()
            .limit(MAX_BLOB as u64 + 1024)
            .read_to_vec()?)
    }

    /// POST a non-JSON body: a blob, or a sealed archive copy.
    fn upload<T: DeserializeOwned>(&self, path: &str, bytes: &[u8]) -> Result<T> {
        let resp = self
            .http
            .post(format!("{}{path}", self.state.ds))
            .header("authorization", format!("Bearer {}", self.token()?))
            .content_type("application/octet-stream")
            .send(bytes)?;
        Ok(ok(resp)?.body_mut().read_json()?)
    }

    /// Report a refusal made by this client, so it is logged too (§5.3 case A).
    fn refuse(&self, room: &str, action: &str, code: &str, reason: &str) -> anyhow::Error {
        let report = api::ClientDenial {
            room: room.into(),
            action: action.into(),
            code: code.into(),
            reason: reason.into(),
        };
        let audit = self
            .call::<api::Accepted>("/v1/denials", Some(&report))
            .map(|a| a.audit)
            .unwrap_or_else(|e| format!("not logged: {e}")); // ponytail: queue and retry (§5.3)
        Denied {
            by: "client",
            code: code.into(),
            reason: reason.into(),
            audit,
        }
        .into()
    }

    // ──────────────────────────── actions ────────────────────────────

    /// Register with the DS: the issuer-signed attribute credential plus one KeyPackage.
    pub fn enroll(&mut self, credential: AttributeCredential) -> Result<()> {
        let subject = self.trust.verify(&credential, now())?;
        ensure!(
            subject.user == self.state.user,
            "credential is for {}",
            subject.user
        );
        let kp = KeyPackage::builder()
            .leaf_node_capabilities(capabilities()?)
            .leaf_node_extensions(attributes_extension(&credential)?)
            .build(
                ciphersuite()?,
                &self.provider,
                &self.signer,
                self.credential_with_key(),
            )?;
        let body = api::Enroll {
            key_package: Bytes(kp.key_package().tls_serialize_detached()?),
            credential: credential.clone(),
        };
        // No session yet: enrollment is what registers the key sessions are signed with.
        self.request::<api::Accepted>(
            &format!("/v1/users/{}/enroll", self.state.user),
            Some(&body),
            None,
        )?;
        self.state.credential = Some(credential);
        Ok(())
    }

    pub fn create_room(&mut self, room: &str, ceiling: &str) -> Result<()> {
        self.log_ok(room, "create-room")?;
        let reg = self.trust.registers();
        let ceiling: Marking = parse(ceiling, &reg)?;
        let ext = room_extensions(
            &ceiling,
            std::slice::from_ref(&self.state.user),
            self.trust.custodian.as_ref(),
            &self.trust.records_officers,
        )?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite()?)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .capabilities(capabilities()?)
            .with_leaf_node_extensions(attributes_extension(self.own_credential()?)?)?
            .with_group_context_extensions(ext)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(room.as_bytes()),
            self.credential_with_key(),
        )?;
        // Client-side check first; the DS runs the same one.
        let rules = RoomRules::read(group.extensions(), &self.trust)?;
        let me = self.trust.verify(self.own_credential()?, now())?;
        if let Decision::Deny(r) = rules.check_create(&me) {
            group.delete(self.provider.storage()).ok();
            return Err(self.refuse(room, "create-room", r.code(), &r.to_string()));
        }
        let gi = group.export_group_info(self.provider.crypto(), &self.signer, false)?;
        let body = api::CreateRoom {
            room: room.into(),
            group_info: Bytes(gi.tls_serialize_detached()?),
            ratchet_tree: Bytes(group.export_ratchet_tree().tls_serialize_detached()?),
        };
        self.call::<api::Accepted>("/v1/rooms", Some(&body))?;
        self.state.rooms.insert(room.into(), RoomState::default());
        Ok(())
    }

    /// Add `joiner` to `room`. `client_check: false` skips this client's own policy
    /// check, to demonstrate that the DS refuses on its own (§5.3 case B).
    pub fn add(&mut self, room: &str, joiner: &str, client_check: bool) -> Result<u64> {
        let mut group = self.writable(room, "add")?;
        let kp: Bytes = self.call(&format!("/v1/users/{joiner}/key-package"), None::<&()>)?;
        let kp = KeyPackageIn::tls_deserialize_exact(&kp.0)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)?;
        // The joiner is judged on the attributes signed into its own leaf.
        let joiner_id = leaf_identity(kp.leaf_node())?;
        ensure!(joiner_id.user == joiner, "key package is not {joiner}'s");
        let aad = HandshakeAad {
            v: WIRE_VERSION,
            decided_at: now(),
            evidence: vec![self.own_credential()?.clone()],
        };
        let aad = serde_json::to_vec(&aad)?;
        if client_check {
            let rules = RoomRules::read(group.extensions(), &self.trust)?;
            let view = self.own_view(vec![joiner_id], vec![], None, vec![]);
            let d = rules.check_commit(&self.trust, &view, &aad, now())?;
            if let Decision::Deny(r) = d {
                return Err(self.refuse(room, "add", r.code(), &r.to_string()));
            }
        }
        group.set_aad(aad);
        let (commit, welcome, _) = group.add_members(&self.provider, &self.signer, &[kp])?;
        let body = api::Commit {
            commit: Bytes(commit.tls_serialize_detached()?),
            welcome: Some(Bytes(welcome.tls_serialize_detached()?)),
        };
        match self.call::<api::Accepted>(&format!("/v1/rooms/{room}/commit"), Some(&body)) {
            Ok(a) => {
                group.merge_pending_commit(&self.provider)?;
                self.room_state(room).own.insert(a.seq);
                Ok(a.seq)
            }
            Err(e) => {
                group.clear_pending_commit(self.provider.storage())?;
                Err(e)
            }
        }
    }

    /// Remove `user` from `room`, as a steward: every device of theirs, new epoch.
    pub fn remove(&mut self, room: &str, target: &str) -> Result<u64> {
        let mut group = self.writable(room, "remove")?;
        let leaves: Vec<LeafNodeIndex> = group
            .members()
            .filter(|m| user_of(&m.credential).is_ok_and(|u| u == target))
            .map(|m| m.index)
            .collect();
        ensure!(!leaves.is_empty(), "{target} is not in {room}");
        let aad = HandshakeAad {
            v: WIRE_VERSION,
            decided_at: now(),
            evidence: vec![self.own_credential()?.clone()],
        };
        let aad = serde_json::to_vec(&aad)?;
        let rules = RoomRules::read(group.extensions(), &self.trust)?;
        let view = self.own_view(vec![], vec![target.to_owned()], None, vec![]);
        let d = rules.check_commit(&self.trust, &view, &aad, now())?;
        if let Decision::Deny(r) = d {
            return Err(self.refuse(room, "remove", r.code(), &r.to_string()));
        }
        group.set_aad(aad);
        let (commit, _, _) = group.remove_members(&self.provider, &self.signer, &leaves)?;
        let body = api::Commit {
            commit: Bytes(commit.tls_serialize_detached()?),
            welcome: None,
        };
        match self.call::<api::Accepted>(&format!("/v1/rooms/{room}/commit"), Some(&body)) {
            Ok(a) => {
                group.merge_pending_commit(&self.provider)?;
                self.room_state(room).own.insert(a.seq);
                Ok(a.seq)
            }
            Err(e) => {
                group.clear_pending_commit(self.provider.storage())?;
                Err(e)
            }
        }
    }

    /// A view of a commit we're about to make, for our own pre-commit check.
    fn own_view(
        &self,
        added: Vec<LeafIdentity>,
        removed: Vec<String>,
        new_rules: Option<RoomRules>,
        members_after: Vec<LeafIdentity>,
    ) -> CommitView {
        CommitView {
            committer: self.state.user.clone(),
            committer_key: self.state.signer_public.0.clone(),
            added,
            removed,
            new_rules,
            members_after,
        }
    }

    /// Change the room ceiling (steward). Raising it requires every member to be
    /// cleared for the new ceiling; the DS and every member check that again.
    pub fn set_ceiling(&mut self, room: &str, ceiling: &str) -> Result<u64> {
        let mut group = self.writable(room, "set-ceiling")?;
        let rules = RoomRules::read(group.extensions(), &self.trust)?;
        let ceiling = parse(ceiling, &self.trust.registers())?;
        let ext = room_extensions(
            &ceiling,
            &rules.stewards,
            rules.custodian.as_ref(),
            &rules.records_officers,
        )?;
        let members = group
            .public_group()
            .members()
            .map(|m| leaf_identity(group.public_group().leaf(m.index).context("member leaf")?))
            .collect::<Result<_>>()?;
        let new_rules = RoomRules::read(&ext, &self.trust)?;
        let aad = serde_json::to_vec(&HandshakeAad {
            v: WIRE_VERSION,
            decided_at: now(),
            evidence: vec![self.own_credential()?.clone()],
        })?;
        let view = self.own_view(vec![], vec![], Some(new_rules), members);
        if let Decision::Deny(r) = rules.check_commit(&self.trust, &view, &aad, now())? {
            return Err(self.refuse(room, "set-ceiling", r.code(), &r.to_string()));
        }
        group.set_aad(aad);
        let (commit, _, _) =
            group.update_group_context_extensions(&self.provider, ext, &self.signer)?;
        let body = api::Commit {
            commit: Bytes(commit.tls_serialize_detached()?),
            welcome: None,
        };
        match self.call::<api::Accepted>(&format!("/v1/rooms/{room}/commit"), Some(&body)) {
            Ok(a) => {
                group.merge_pending_commit(&self.provider)?;
                self.room_state(room).own.insert(a.seq);
                Ok(a.seq)
            }
            Err(e) => {
                group.clear_pending_commit(self.provider.storage())?;
                Err(e)
            }
        }
    }

    /// A direct message is a two-person room (idea-v1 §1): one primitive, not two.
    /// Returns the room name, which is the same from either side.
    pub fn dm(&mut self, peer: &str, ceiling: &str) -> Result<String> {
        let mut pair = [self.state.user.as_str(), peer];
        pair.sort();
        let room = format!("dm-{}-{}", pair[0], pair[1]);
        self.create_room(&room, ceiling)?;
        self.add(&room, peer, true)?;
        Ok(room)
    }

    /// Close a room frozen after a fork, recording what the investigation found. The
    /// room is never reopened: its MLS state can't be trusted, so recreate it with
    /// its honest members (open question Q12).
    pub fn clear_fork(&mut self, room: &str, note: &str) -> Result<()> {
        self.log_ok(room, "clear-fork")?;
        let body = api::ClearFork { note: note.into() };
        self.call::<api::Accepted>(&format!("/v1/rooms/{room}/clear-fork"), Some(&body))?;
        Ok(())
    }

    /// Steward cleanup (idea-v1 §1): remove members whose credential expired more than
    /// `expired_for` seconds ago. Expiry itself only suspends; this is the deliberate
    /// act, meant to run on a timer from an admin client.
    pub fn cleanup(&mut self, room: &str, expired_for: u64) -> Result<Vec<String>> {
        let members: Vec<String> = self
            .group(room)?
            .members()
            .filter_map(|m| user_of(&m.credential).ok())
            .filter(|u| *u != self.state.user)
            .collect();
        let mut removed = Vec::new();
        for u in members {
            let cred: AttributeCredential =
                self.call(&format!("/v1/users/{u}/credential"), None::<&()>)?;
            if cred.body.not_after.saturating_add(expired_for) <= now() {
                self.remove(room, &u)?;
                removed.push(u);
            }
        }
        Ok(removed)
    }

    pub fn send(&mut self, room: &str, marking: &str, text: &str) -> Result<u64> {
        let marking = parse(marking, &self.trust.registers())?;
        let out = Outgoing::new(TEXT_PLAIN, text.as_bytes().to_vec());
        let (seq, _) = self.post(room, "send", &marking, out)?;
        Ok(seq)
    }

    /// Acknowledge message `seq` of `room`. The ack is an MLS message signed by us, so
    /// it proves receipt, and it carries the message's own marking so the ordinary
    /// send check covers it.
    pub fn ack(&mut self, room: &str, seq: u64) -> Result<u64> {
        let (marking, msg_id) = {
            let m = self.stored(room, seq)?;
            (self.marking_of(m)?, m.msg_id.0.clone())
        };
        Ok(self
            .post(room, "ack", &marking, Outgoing::new(ACK, msg_id))?
            .0)
    }

    /// Re-send message `seq` of `from` into `to`, keeping its marking. A destination
    /// whose ceiling is below that marking refuses it, and the refusal is logged.
    pub fn forward(&mut self, from: &str, seq: u64, to: &str) -> Result<u64> {
        let (marking, body, origin) = {
            let m = self.stored(from, seq)?;
            // The blob lives in the source room; moving it is its own feature (Q18).
            ensure!(
                m.content_type == TEXT_PLAIN,
                "only text can be forwarded so far"
            );
            let origin = Forwarded {
                room: from.into(),
                msg_id: m.msg_id.clone(),
                sender: m.sender.clone(),
            };
            (self.marking_of(m)?, m.body.0.clone(), origin)
        };
        let out = Outgoing {
            forwarded_from: Some(origin),
            ..Outgoing::new(TEXT_PLAIN, body)
        };
        Ok(self.post(to, "forward", &marking, out)?.0)
    }

    fn stored(&self, room: &str, seq: u64) -> Result<&Stored> {
        self.state
            .rooms
            .get(room)
            .and_then(|r| r.inbox.get(&seq))
            .with_context(|| format!("no message #{seq} in {room} (run `read` first?)"))
    }

    fn marking_of(&self, m: &Stored) -> Result<Marking> {
        Ok(Marking::from_canonical(
            &m.marking.0,
            &self.trust.registers(),
        )?)
    }

    /// One path for everything that goes into a room as an application message, so
    /// acks and forwards face the same check as a plain send.
    fn post(
        &mut self,
        room: &str,
        action: &str,
        marking: &Marking,
        out: Outgoing,
    ) -> Result<(u64, Bytes)> {
        let mut group = self.writable(room, action)?;
        let mut aad = AppAad {
            v: WIRE_VERSION,
            sender: self.state.user.clone(),
            marking: Bytes(marking.canonical_bytes()?),
            sent_at: now(),
            blobs: out
                .blob
                .iter()
                .map(|ct| Ok(Bytes(identity::archive::sha384(ct)?)))
                .collect::<Result<_>>()?,
            archive: None,
        };
        let rules = RoomRules::read(group.extensions(), &self.trust)?;
        let (_, d) = rules.check_message(
            &self.trust,
            &aad,
            self.own_credential()?,
            &self.state.signer_public.0,
        )?;
        if let Decision::Deny(r) = d {
            return Err(self.refuse(room, action, r.code(), &r.to_string()));
        }
        if let Some(ct) = &out.blob {
            self.upload_blob(room, &aad.marking, ct)?;
        }
        let msg_id = Bytes(self.provider.rand().random_vec(16)?);
        let envelope = Envelope {
            v: WIRE_VERSION,
            msg_id: msg_id.clone(),
            content_type: out.content_type.into(),
            precedence: Precedence::Routine,
            body: Bytes(out.body.clone()),
            reply_to: None,
            audience: vec![],
            cosignatures: vec![],
            forwarded_from: out.forwarded_from,
        };
        // Sealed and filed before the message exists: no archive copy, no send.
        aad.archive = Some(self.file_archive_copy(room, &rules, &aad, &envelope)?);
        group.set_aad(serde_json::to_vec(&aad)?);
        let msg = group.create_message(
            &self.provider,
            &self.signer,
            &serde_json::to_vec(&envelope)?,
        )?;
        let a: api::Accepted = self.call(
            &format!("/v1/rooms/{room}/messages"),
            Some(&api::Send {
                message: Bytes(msg.tls_serialize_detached()?),
            }),
        )?;
        let rs = self.room_state(room);
        rs.own.insert(a.seq);
        if out.content_type != ACK {
            let sender = self.state.user.clone();
            self.room_state(room).inbox.insert(
                a.seq,
                Stored {
                    sender,
                    msg_id: msg_id.clone(),
                    marking: aad.marking,
                    body: Bytes(out.body),
                    content_type: out.content_type.into(),
                },
            );
        }
        Ok((a.seq, msg_id))
    }

    /// Join rooms we've been welcomed to, then read everything new in every room.
    pub fn sync(&mut self) -> Result<Vec<(String, Event)>> {
        let mut events = Vec::new();
        if self.state.alert.is_none()
            && let audit::Advance::Fault(why) = self.advance_checkpoint()?
        {
            self.raise(why);
        }
        if let Some(reason) = &self.state.alert {
            events.push((
                String::new(),
                Event::LogAlert {
                    reason: reason.clone(),
                },
            ));
        }
        let welcomes: Vec<api::Welcome> = self.call(
            &format!("/v1/users/{}/welcomes", self.state.user),
            None::<&()>,
        )?;
        for w in welcomes {
            let MlsMessageBodyIn::Welcome(welcome) =
                MlsMessageIn::tls_deserialize_exact(&w.welcome.0)?.extract()
            else {
                bail!("expected a Welcome");
            };
            let tree = RatchetTreeIn::tls_deserialize_exact(&w.ratchet_tree.0)?;
            let join = MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            let group =
                StagedWelcome::new_from_welcome(&self.provider, &join, welcome, Some(tree))?
                    .into_group(&self.provider)?;
            // Check 4 (idea-v1 §1a): judge the room ourselves before joining it.
            let mut group = group;
            let rules = RoomRules::read(group.extensions(), &self.trust)?;
            let me = self.trust.verify(self.own_credential()?, now())?;
            if let Decision::Deny(r) = rules.check_join(&me) {
                group.delete(self.provider.storage())?;
                let reason = r.to_string();
                let denied = self.refuse(&w.room, "join", r.code(), &reason);
                events.push((
                    w.room.clone(),
                    Event::JoinRefused {
                        reason: denied.to_string(),
                    },
                ));
                continue;
            }
            self.state.rooms.insert(
                w.room.clone(),
                RoomState {
                    cursor: w.after_seq,
                    ..Default::default()
                },
            );
            events.push((w.room.clone(), Event::Joined { room: w.room }));
        }
        let rooms: Vec<String> = self.state.rooms.keys().cloned().collect();
        for room in rooms {
            for e in self.read_room(&room)? {
                events.push((room.clone(), e));
            }
            // As the room's steward, act on the DS's removal requests (debriefs).
            // Removal is a deliberate steward act; other members ignore requests.
            if self.state.alert.is_some() || self.state.rooms.get(&room).is_none_or(|r| r.held) {
                continue;
            }
            let rules = RoomRules::read(self.group(&room)?.extensions(), &self.trust)?;
            if !rules.stewards.contains(&self.state.user) {
                continue;
            }
            let requests: Vec<api::RemovalRequest> =
                self.call(&format!("/v1/rooms/{room}/removals"), None::<&()>)?;
            let me = self.state.user.clone();
            for req in requests.into_iter().filter(|r| r.user != me) {
                let user = req.user.clone();
                // ponytail: another member may have committed it first (stale epoch);
                // the request stays pending and the next sync retries.
                if let Ok(seq) = self.remove(&room, &user) {
                    let by = format!("{} (DS request: {})", self.state.user, req.reason);
                    events.push((
                        room.clone(),
                        Event::MembershipChanged {
                            seq,
                            by,
                            added: vec![],
                            removed: vec![user],
                        },
                    ));
                }
            }
        }
        Ok(events)
    }

    fn read_room(&mut self, room: &str) -> Result<Vec<Event>> {
        let rs = self.room_state(room);
        if rs.held {
            return Ok(vec![]);
        }
        let cursor = rs.cursor;
        let entries: Vec<api::StreamEntry> = self.call(
            &format!("/v1/rooms/{room}/messages?after={cursor}"),
            None::<&()>,
        )?;
        let mut group = self.group(room)?;
        let mut out = Vec::new();
        for entry in entries {
            self.room_state(room).cursor = entry.seq;
            if self.room_state(room).own.contains(&entry.seq) {
                continue;
            }
            let msg = MlsMessageIn::tls_deserialize_exact(&entry.message.0)?
                .try_into_protocol_message()?;
            let processed = group.process_message(&self.provider, msg)?;
            let sender = user_of(processed.credential())?;
            let Sender::Member(idx) = processed.sender() else {
                bail!("message not from a member");
            };
            let sender_idx = *idx;
            let sender_key = group
                .member_at(*idx)
                .context("sender not in group")?
                .signature_key;
            let aad = processed.aad().to_vec();
            let rules = RoomRules::read(group.extensions(), &self.trust)?;
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(m) => {
                    let (event, stored) = self.check_received(
                        &rules,
                        room,
                        entry.seq,
                        (&sender, &sender_key),
                        &aad,
                        m.into_bytes(),
                    );
                    if let Some(s) = stored {
                        self.room_state(room).inbox.insert(entry.seq, s);
                    }
                    out.push(event);
                }
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    let view =
                        CommitView::of(group.public_group(), &staged, sender_idx, &self.trust)?;
                    let added: Vec<String> = view.added.iter().map(|j| j.user.clone()).collect();
                    let removed = view.removed.clone();
                    if removed.contains(&self.state.user) {
                        return self.purge(room, group, entry.seq, sender, out);
                    }
                    // ponytail: skew is checked by the DS; clients judge at the signed time
                    // until stream entries carry the DS sequence time (§4.4.1).
                    let decided_at = serde_json::from_slice::<HandshakeAad>(&aad)
                        .map(|a| a.decided_at)
                        .unwrap_or(0);
                    match rules.check_commit(&self.trust, &view, &aad, decided_at) {
                        Ok(Decision::Permit) => {
                            group.merge_staged_commit(&self.provider, *staged)?;
                            if let Some(new) = &view.new_rules {
                                out.push(Event::CeilingChanged {
                                    seq: entry.seq,
                                    by: sender.clone(),
                                    ceiling: new.ceiling.portion(),
                                });
                            }
                            out.push(Event::MembershipChanged {
                                seq: entry.seq,
                                by: sender,
                                added,
                                removed,
                            });
                        }
                        refusal => {
                            let reason = match refusal {
                                Ok(Decision::Deny(r)) => r.to_string(),
                                Err(e) => format!("{e:#}"),
                                Ok(Decision::Permit) => unreachable!(),
                            };
                            // Fork (idea-v1 §1a): freeze locally, whatever the DS does, and
                            // report the conflicting commit so the DS freezes and logs it.
                            self.room_state(room).held = true;
                            let report = api::ForkReport {
                                seq: entry.seq,
                                reason: reason.clone(),
                            };
                            if let Err(e) = self.call::<api::Accepted>(
                                &format!("/v1/rooms/{room}/fork"),
                                Some(&report),
                            ) {
                                eprintln!("fork report not delivered: {e:#}"); // ponytail: queue and retry
                            }
                            out.push(Event::IntegrityHold {
                                seq: entry.seq,
                                reason,
                            });
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// We were removed: delete the room's MLS state and history, then report it.
    /// ponytail: history and search live only in MLS state for now; when the message
    /// store and FTS index exist (§7.2–7.3) they are purged here too.
    fn purge(
        &mut self,
        room: &str,
        mut group: MlsGroup,
        seq: u64,
        by: String,
        mut out: Vec<Event>,
    ) -> Result<Vec<Event>> {
        group.delete(self.provider.storage())?;
        self.state.rooms.remove(room);
        let receipt = api::PurgeReceipt { room: room.into() };
        if let Err(e) =
            self.call::<api::Accepted>(&format!("/v1/rooms/{room}/purged"), Some(&receipt))
        {
            eprintln!("purge receipt not delivered: {e:#}"); // ponytail: queue and retry
        }
        out.push(Event::Purged { seq, by });
        Ok(out)
    }

    /// Re-check a received message against the room and the sender's credential. The
    /// second half is what to keep for later acks and forwards.
    fn check_received(
        &self,
        rules: &RoomRules,
        room: &str,
        seq: u64,
        (sender, sender_key): (&str, &[u8]),
        aad: &[u8],
        body: Vec<u8>,
    ) -> (Event, Option<Stored>) {
        let quarantine = |reason: String| {
            let event = Event::Quarantined {
                seq,
                sender: sender.into(),
                reason,
            };
            (event, None)
        };
        let Ok(aad) = serde_json::from_slice::<AppAad>(aad) else {
            return quarantine("unreadable AAD".into());
        };
        if aad.sender != sender {
            return quarantine(format!("AAD claims {}, signed by {sender}", aad.sender));
        }
        let cred: AttributeCredential =
            match self.call(&format!("/v1/users/{sender}/credential"), None::<&()>) {
                Ok(c) => c,
                Err(e) => return quarantine(format!("no sender credential: {e:#}")),
            };
        let envelope = match serde_json::from_slice::<Envelope>(&body) {
            Ok(e) if e.v == WIRE_VERSION => e,
            Ok(e) => return quarantine(format!("unsupported envelope version {}", e.v)),
            Err(e) => return quarantine(format!("unreadable envelope: {e}")),
        };
        // Reserved slots (idea-v1 §2): a v1 client can't honor them, so it refuses
        // rather than show a tearline or a 2PI message as if it were ordinary.
        if !envelope.audience.is_empty() || !envelope.cosignatures.is_empty() {
            return quarantine("uses a reserved envelope feature (audience/cosignatures)".into());
        }
        if ![TEXT_PLAIN, ACK, FILE].contains(&envelope.content_type.as_str()) {
            return quarantine(format!(
                "unsupported content type {}",
                envelope.content_type
            ));
        }
        let marking = match rules.check_message(&self.trust, &aad, &cred, sender_key) {
            Ok((m, Decision::Permit)) => m,
            Ok((_, Decision::Deny(r))) => return quarantine(r.to_string()),
            Err(e) => return quarantine(format!("{e:#}")),
        };
        if envelope.content_type == ACK {
            if envelope.body.0.len() != 16 {
                return quarantine("ack body isn't a message id".into());
            }
            let of = self
                .state
                .rooms
                .get(room)
                .and_then(|r| r.inbox.iter().find(|(_, m)| m.msg_id == envelope.body))
                .map(|(seq, _)| *seq);
            let event = Event::Ack {
                seq,
                sender: sender.into(),
                of,
                marking: marking.portion(),
            };
            return (event, None);
        }
        let text = if envelope.content_type == FILE {
            match files::check_received(&envelope.body.0, &aad.blobs) {
                Ok(f) => file_text(&f),
                Err(why) => return quarantine(format!("bad file message: {why:#}")),
            }
        } else {
            String::from_utf8_lossy(&envelope.body.0).into_owned()
        };
        let event = Event::Message {
            seq,
            sender: sender.into(),
            marking: marking.portion(),
            text,
            forwarded_from: envelope.forwarded_from,
        };
        let stored = Stored {
            sender: sender.into(),
            msg_id: envelope.msg_id,
            marking: aad.marking,
            body: envelope.body,
            content_type: envelope.content_type,
        };
        (event, Some(stored))
    }

    // ──────────────────────────── helpers ────────────────────────────

    /// The group, for an action that changes the room. Refused while the room is
    /// frozen after a fork: no sends, adds or removes from anyone (idea-v1 §1a).
    fn writable(&self, room: &str, action: &str) -> Result<MlsGroup> {
        self.log_ok(room, action)?;
        if self.state.rooms.get(room).is_some_and(|r| r.held) {
            return Err(self.refuse(room, action, "F-001", "room frozen after a fork"));
        }
        self.group(room)
    }

    /// Nothing goes out while the DS's log is distrusted: what we send would be recorded
    /// in a log we can't vouch for.
    fn log_ok(&self, room: &str, action: &str) -> Result<()> {
        match &self.state.alert {
            Some(why) => Err(self.refuse(room, action, "L-001", &format!("log integrity: {why}"))),
            None => Ok(()),
        }
    }

    fn group(&self, room: &str) -> Result<MlsGroup> {
        MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(room.as_bytes()),
        )?
        .with_context(|| format!("not a member of {room}"))
    }

    fn room_state(&mut self, room: &str) -> &mut RoomState {
        self.state.rooms.entry(room.into()).or_default()
    }

    fn own_credential(&self) -> Result<&AttributeCredential> {
        self.state.credential.as_ref().context("not enrolled")
    }

    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: Credential::new(
                CredentialType::Other(GARBLE_CREDENTIAL),
                self.state.user.as_bytes().to_vec(),
            ),
            signature_key: self.state.signer_public.0.clone().into(),
        }
    }
}

/// The GroupContext extensions that carry a room's policy.
fn room_extensions(
    ceiling: &Marking,
    stewards: &[String],
    custodian: Option<&CustodianRef>,
    records_officers: &[String],
) -> Result<Extensions<GroupContext>> {
    let policy = RoomPolicy {
        v: WIRE_VERSION,
        ceiling: Bytes(ceiling.canonical_bytes()?),
        stewards: stewards.to_vec(),
        custodian: custodian.cloned(),
        records_officers: records_officers.to_vec(),
    };
    Ok(Extensions::from_vec(vec![
        Extension::Unknown(
            ROOM_POLICY_EXT,
            UnknownExtension(serde_json::to_vec(&policy)?),
        ),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(ROOM_POLICY_EXT)],
            &[],
            &[CredentialType::Other(GARBLE_CREDENTIAL)],
        )),
    ])?)
}

fn capabilities() -> Result<Capabilities> {
    Ok(Capabilities::new(
        None,
        Some(&[ciphersuite()?]),
        Some(&[
            ExtensionType::Unknown(ROOM_POLICY_EXT),
            ExtensionType::Unknown(ATTRIBUTES_EXT),
        ]),
        None,
        Some(&[CredentialType::Other(GARBLE_CREDENTIAL)]),
    ))
}
