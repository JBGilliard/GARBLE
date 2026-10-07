//! GARBLE delivery service (architecture §3, §6).
//!
//! Tracks every room's public MLS state, runs `policy::decide` on every Add and every
//! message, sequences commits, holds Welcomes until their commit is accepted, and logs
//! every decision, permits and denials alike.
//!
//! ponytail: walking skeleton.
//! - One thread, requests handled serially: the global lock. Per-room sequencers (§6.2)
//!   when throughput matters.
//! - State in memory, lost on restart. `GroupStore` / `BlobStore` traits come with SQLite;
//!   until then blobs and archive copies live in RAM too, capped per item by `MAX_BLOB`.
//! - Plain HTTP (TLS terminates in front, or comes later). Sessions are signed-nonce
//!   bearer tokens (§5) held in memory.
//! - Enrollment trusts the issuer's key binding: the attribute credential names the
//!   user's public key. ponytail: the EA-signed identity credential and CAC attestation
//!   (§5.1) replace the mock issuer here.
//! - The audit log is a `tlog` Merkle log in `--log-dir`, with a signed checkpoint after
//!   every request. Reading entries scans the whole log and filters by marking on each
//!   call; an index by marking when logs get long.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use identity::log::LogSigner;
use identity::room::{CommitView, RoomRules, leaf_identity, user_of};
use identity::{FileKeyStore, KeyStore, TrustBundle, verify_session};
use openmls::prelude::{tls_codec::*, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::random::OpenMlsRand;
use policy::Decision;
use proto::api::{self, LogEntry, MessageFacts};
use proto::{AppAad, AttributeCredential, Bytes, LOG_ENTRY_VERSION, MAX_BLOB, WIRE_VERSION};
use tiny_http::{Header, Method, Request, Response, Server};
use tlog::{FileStore, Log, TileStore};

const DEFAULT_LOG_KEY: &str = "garble-ds-log.key";
const CHECKPOINT_KEY: &str = "checkpoint";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(String::as_str) == Some("keygen") {
        args.next();
        return keygen(args);
    }
    let (mut listen, mut trust, mut log_dir, mut log_key, mut malicious) = (
        "127.0.0.1:7777".to_string(),
        None,
        PathBuf::from("garble-log"),
        PathBuf::from(DEFAULT_LOG_KEY),
        false,
    );
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().context("--listen ADDR")?,
            "--trust" => trust = Some(PathBuf::from(args.next().context("--trust FILE")?)),
            "--log-dir" => log_dir = PathBuf::from(args.next().context("--log-dir DIR")?),
            "--log-key" => log_key = PathBuf::from(args.next().context("--log-key FILE")?),
            "--simulate-malicious" => malicious = true,
            _ => bail!(
                "usage: garble-ds --trust FILE [--listen ADDR] [--log-dir DIR] [--log-key FILE] [--simulate-malicious]\n       garble-ds keygen [--key FILE]"
            ),
        }
    }
    let trust =
        TrustBundle::load(&trust.context("--trust FILE is required: the DS fails closed")?)?;
    let log_ref = trust.log.clone().context(
        "trust bundle names no log key (garble issuer init --log-key); the DS fails closed",
    )?;
    identity::log::checked_origin(&log_ref.origin)?;
    ensure!(
        log_key.exists(),
        "no log key at {}; run `garble-ds keygen --key {0}`",
        log_key.display()
    );
    let signer = LogSigner::new(&log_ref.origin, FileKeyStore::new(&log_key).signer()?);
    ensure!(
        tlog::Signer::public_key(&signer) == log_ref.key.0,
        "{} is not the log key the trust bundle names",
        log_key.display()
    );
    let log = Log::open(FileStore::new(&log_dir))?;
    let server = Server::http(&listen).map_err(|e| anyhow::anyhow!("listen {listen}: {e}"))?;
    eprintln!(
        "garble-ds listening on http://{listen}, audit log {} ({} entries)",
        log_dir.display(),
        log.size()
    );
    if malicious {
        eprintln!("WARNING: --simulate-malicious: this DS sequences commits WITHOUT policy checks");
    }
    let mut ds = Ds::new(trust, log, signer, malicious)?;
    for req in server.incoming_requests() {
        ds.handle(req);
    }
    Ok(())
}

/// `garble-ds keygen [--key FILE]`: make the checkpoint signing key and print its public
/// half (hex) for `garble issuer init --log-key`.
/// ponytail: plaintext on disk, like every dev key here; HSM before any pilot.
fn keygen(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut key = PathBuf::from(DEFAULT_LOG_KEY);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => key = PathBuf::from(args.next().context("--key FILE")?),
            _ => bail!("usage: garble-ds keygen [--key FILE]"),
        }
    }
    ensure!(
        !key.exists(),
        "{} exists; refusing to replace a log key",
        key.display()
    );
    println!("{}", hex(&FileKeyStore::new(&key).public_key()?));
    eprintln!("log key written to {}", key.display());
    Ok(())
}

struct Entry {
    commit: bool,
    bytes: Vec<u8>,
}

struct Room {
    group: PublicGroup,
    /// Sequenced messages and commits; `seq` is index + 1.
    stream: Vec<Entry>,
    /// Removed users → seq of their removal; they may read up to it, to purge.
    removed: BTreeMap<String, u64>,
    /// Removals requested by the DS, waiting for a member to commit them.
    pending: BTreeMap<String, api::RemovalRequest>,
    /// Set when a member reports a fork; nothing is sequenced afterwards (idea-v1 §1a).
    frozen: Option<Frozen>,
}

enum Frozen {
    /// Under investigation.
    Held,
    /// A steward closed it after investigating. Permanent: recreate the room.
    Closed,
}

const MAX_BLOBS_PER_MESSAGE: usize = 16;
/// Archive entries per pull; the custodian asks again from where it stopped.
const ARCHIVE_PAGE: usize = 100;
const CHALLENGE_SECS: u64 = 60;
const SESSION_SECS: u64 = 3600;

struct User {
    /// The ML-DSA-87 key the issuer bound this user to; sessions are signed with it.
    key: Vec<u8>,
    credential: AttributeCredential,
    key_packages: Vec<Vec<u8>>,
}

struct Blob {
    room: String,
    uploader: String,
    /// Canonical marking bytes the upload was decided under.
    marking: Vec<u8>,
    bytes: Vec<u8>,
}

struct Copy {
    room: String,
    uploader: String,
    bytes: Vec<u8>,
}

/// What an audit entry needs beyond who, where and what.
#[derive(Default)]
struct Ctx {
    /// Canonical marking bytes. Unset: the room's ceiling, else the actor's own access.
    marking: Option<Vec<u8>>,
    message: Option<MessageFacts>,
}

struct Ds<S: TileStore> {
    trust: TrustBundle,
    provider: OpenMlsRustCrypto,
    users: BTreeMap<String, User>,
    rooms: BTreeMap<String, Room>,
    welcomes: BTreeMap<String, Vec<api::Welcome>>,
    /// nonce → (user, expiry). Single use.
    challenges: BTreeMap<Vec<u8>, (String, u64)>,
    /// token → (user, expiry).
    sessions: BTreeMap<String, (String, u64)>,
    /// Users whose credential has expired: suspended until they refresh.
    suspended: BTreeSet<String>,
    /// Skip policy on commits, to demonstrate that members' clients catch what a
    /// compromised or colluding DS lets through. Never in a real deployment.
    malicious: bool,
    /// Encrypted file bytes by SHA-384. The DS can't open them.
    blobs: BTreeMap<Vec<u8>, Blob>,
    /// Sealed archive copies uploaded and not yet tied to a sequenced message.
    copies: BTreeMap<Vec<u8>, Copy>,
    /// Hashes of copies already tied to a message: a copy archives exactly one.
    filed: BTreeSet<Vec<u8>>,
    /// What the custodian pulls: one entry per sequenced message, in sequence order.
    archive: Vec<api::ArchiveEntry>,
    log: Log<S>,
    signer: LogSigner,
    /// The latest signed checkpoint, as served.
    checkpoint: Vec<u8>,
    /// Entries appended since `checkpoint` was signed.
    unsigned: bool,
}

/// A request outcome: a JSON body, or a refusal the client can inspect.
enum Reply {
    Ok(serde_json::Value),
    /// Bytes as stored: checkpoints and hash tiles keep their tlog-tiles encoding.
    Raw(Vec<u8>, &'static str),
    Refused(api::Refused),
    Unauthenticated,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<S: TileStore> Ds<S> {
    /// Fails if the log's own store disagrees with the last checkpoint it signed: a DS
    /// that lost or rewrote entries refuses to come back up quietly.
    fn new(trust: TrustBundle, log: Log<S>, signer: LogSigner, malicious: bool) -> Result<Self> {
        let verifier = trust.log_verifier()?;
        if let Some(note) = log.store().read(CHECKPOINT_KEY)? {
            let last = tlog::open_checkpoint(&note, &log_origin(&trust)?, &verifier)?;
            ensure!(
                last.size <= log.size() && log.root_at(last.size)? == last.root,
                "log store does not match its last signed checkpoint (size {})",
                last.size
            );
        }
        let mut ds = Self {
            trust,
            provider: OpenMlsRustCrypto::default(),
            users: BTreeMap::new(),
            rooms: BTreeMap::new(),
            welcomes: BTreeMap::new(),
            challenges: BTreeMap::new(),
            sessions: BTreeMap::new(),
            suspended: BTreeSet::new(),
            malicious,
            blobs: BTreeMap::new(),
            copies: BTreeMap::new(),
            filed: BTreeSet::new(),
            archive: Vec::new(),
            log,
            signer,
            checkpoint: Vec::new(),
            unsigned: true,
        };
        ds.publish_checkpoint()?;
        Ok(ds)
    }

    /// Sign the log's current head, if it moved. Called after every request.
    fn publish_checkpoint(&mut self) -> Result<()> {
        if !self.unsigned {
            return Ok(());
        }
        let origin = log_origin(&self.trust)?;
        let note = tlog::sign_checkpoint(&self.log.checkpoint(&origin), &self.signer)?;
        self.log.store_mut().write(CHECKPOINT_KEY, &note)?;
        self.checkpoint = note;
        self.unsigned = false;
        Ok(())
    }

    fn handle(&mut self, mut req: Request) {
        let token = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("authorization"))
            .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
            .map(str::to_owned);
        let user = token
            .and_then(|t| self.sessions.get(&t).cloned())
            .filter(|(_, expires)| *expires > now())
            .map(|(user, _)| user);
        let mut body = Vec::new();
        // One more byte than allowed, so an oversized body is seen rather than truncated.
        let read = req
            .as_reader()
            .take(MAX_BLOB as u64 + 1)
            .read_to_end(&mut body)
            .and_then(|n| {
                if n > MAX_BLOB {
                    Err(std::io::Error::other("request body too large"))
                } else {
                    Ok(n)
                }
            });
        let method = req.method().clone();
        let url = req.url().to_owned();
        let reply = match read {
            Ok(_) => self
                .route(&method, &url, user.as_deref(), &body)
                .unwrap_or_else(|e| {
                    Reply::Refused(api::Refused {
                        code: "E-REQUEST".into(),
                        reason: format!("{e:#}"),
                        audit: String::new(),
                    })
                }),
            Err(e) => Reply::Refused(api::Refused {
                code: "E-REQUEST".into(),
                reason: e.to_string(),
                audit: String::new(),
            }),
        };
        // Before the reply goes out, so nothing a client was told is unsigned.
        if let Err(e) = self.publish_checkpoint() {
            eprintln!("checkpoint: {e:#}");
        }
        let json =
            |status, v: serde_json::Value| (status, v.to_string().into_bytes(), "application/json");
        let (status, body, ctype) = match reply {
            Reply::Ok(v) => json(200, v),
            Reply::Raw(b, ctype) => (200, b, ctype),
            Reply::Refused(r) => json(403, serde_json::to_value(r).unwrap_or_default()),
            Reply::Unauthenticated => json(401, serde_json::json!({"reason": "no valid session"})),
        };
        let mut resp = Response::from_data(body).with_status_code(status);
        if let Ok(h) = Header::from_bytes("Content-Type", ctype) {
            resp.add_header(h);
        }
        if let Err(e) = req.respond(resp) {
            eprintln!("respond: {e}");
        }
    }

    fn route(
        &mut self,
        method: &Method,
        url: &str,
        user: Option<&str>,
        body: &[u8],
    ) -> Result<Reply> {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let ok = |v: serde_json::Value| Ok(Reply::Ok(v));
        // The only routes open without a session.
        match (method, parts.as_slice()) {
            (Method::Post, ["v1", "session", "challenge"]) => {
                return self.challenge(serde_json::from_slice(body)?);
            }
            (Method::Post, ["v1", "session"]) => {
                return self.open_session(serde_json::from_slice(body)?);
            }
            // Proof of possession: the key package is signed by the key the issuer bound.
            (Method::Post, ["v1", "users", u, "enroll"]) => {
                return self.enroll(u, serde_json::from_slice(body)?);
            }
            _ => {}
        }
        let Some(user) = user else {
            return Ok(Reply::Unauthenticated);
        };
        self.sweep()?;
        match (method, parts.as_slice()) {
            (Method::Get, ["v1", "users", u, "credential"]) => ok(serde_json::to_value(
                &self.users.get(*u).context("unknown user")?.credential,
            )?),
            (Method::Get, ["v1", "users", u, "key-package"]) => {
                // Consumed only when an Add using it is accepted.
                let kp = self
                    .users
                    .get(*u)
                    .context("unknown user")?
                    .key_packages
                    .last();
                ok(serde_json::to_value(Bytes(
                    kp.context("no key package left; the user must re-enroll")?
                        .clone(),
                ))?)
            }
            (Method::Get, ["v1", "users", u, "welcomes"]) => {
                ensure!(*u == user, "welcomes are only for their recipient");
                ok(serde_json::to_value(
                    self.welcomes.remove(*u).unwrap_or_default(),
                )?)
            }
            (Method::Post, ["v1", "rooms"]) => {
                self.create_room(user, serde_json::from_slice(body)?)
            }
            (Method::Post, ["v1", "rooms", r, "commit"]) => {
                self.commit(user, r, serde_json::from_slice(body)?)
            }
            (Method::Post, ["v1", "rooms", r, "messages"]) => {
                self.send(user, r, serde_json::from_slice(body)?)
            }
            (Method::Post, ["v1", "rooms", r, "blobs"]) => {
                self.upload_blob(user, r, query_str(query, "marking"), body)
            }
            (Method::Post, ["v1", "rooms", r, "archive"]) => self.file_copy(user, r, body),
            (Method::Post, ["v1", "rooms", r, "archive-read"]) => {
                self.archive_read(user, r, serde_json::from_slice(body)?)
            }
            (Method::Get, ["v1", "blobs", id]) => self.get_blob(user, id),
            (Method::Get, ["v1", "archive"]) => {
                self.pull_archive(user, query_u64(query, "after")?.unwrap_or(0))
            }
            (Method::Get, ["v1", "rooms", r, "messages"]) => {
                let after: u64 = query.strip_prefix("after=").unwrap_or("0").parse()?;
                let room = self.rooms.get(*r).context("unknown room")?;
                let member = is_member(&room.group, user);
                let expired = self
                    .users
                    .get(user)
                    .is_none_or(|u| u.credential.body.not_after <= now());
                // Expired or awaiting removal (e.g. debriefed): nothing new until removed.
                let lapsed = expired || room.pending.contains_key(user);
                let (upto, commits_only) = match room.removed.get(user) {
                    // A removed user may fetch the commits up to its own removal, to
                    // process it and purge; never messages, which may postdate a debrief.
                    Some(seq) if !member => (*seq, true),
                    _ if member && lapsed => (0, true), // withheld until removed (§5.7)
                    _ if member => (u64::MAX, false),
                    _ => bail!("{user} is not a member of {r}"),
                };
                let entries: Vec<api::StreamEntry> = room
                    .stream
                    .iter()
                    .zip(1u64..)
                    .filter(|(e, seq)| *seq > after && *seq <= upto && (e.commit || !commits_only))
                    .map(|(e, seq)| api::StreamEntry {
                        seq,
                        message: Bytes(e.bytes.clone()),
                    })
                    .collect();
                ok(serde_json::to_value(entries)?)
            }
            (Method::Get, ["v1", "rooms", r, "removals"]) => {
                let room = self.rooms.get(*r).context("unknown room")?;
                ensure!(
                    is_member(&room.group, user),
                    "{user} is not a member of {r}"
                );
                ok(serde_json::to_value(
                    room.pending.values().collect::<Vec<_>>(),
                )?)
            }
            (Method::Post, ["v1", "rooms", r, "purged"]) => {
                let room = self.rooms.get(*r).context("unknown room")?;
                ensure!(
                    room.removed.contains_key(user),
                    "{user} was not removed from {r}"
                );
                let audit = self.append(user, r, "purge-receipt", None, "local copy purged")?;
                ok(serde_json::to_value(api::Accepted { seq: 0, audit })?)
            }
            (Method::Post, ["v1", "rooms", r, "fork"]) => {
                self.fork(user, r, serde_json::from_slice(body)?)
            }
            (Method::Post, ["v1", "rooms", r, "clear-fork"]) => {
                let c: api::ClearFork = serde_json::from_slice(body)?;
                let room = self.rooms.get_mut(*r).context("unknown room")?;
                ensure!(room.frozen.is_some(), "{r} is not frozen");
                let rules = RoomRules::read(room.group.group_context().extensions(), &self.trust)?;
                ensure!(
                    rules.stewards.iter().any(|s| s == user),
                    "only a steward clears a fork"
                );
                room.frozen = Some(Frozen::Closed);
                let audit = self.append(
                    user,
                    r,
                    "fork-cleared",
                    None,
                    &format!("closed: {}", c.note),
                )?;
                ok(serde_json::to_value(api::Accepted { seq: 0, audit })?)
            }
            (Method::Post, ["v1", "denials"]) => {
                let d: api::ClientDenial = serde_json::from_slice(body)?;
                let audit = self.append(
                    user,
                    &d.room,
                    &format!("client-denial:{}", d.action),
                    Some(&d.code),
                    &d.reason,
                )?;
                ok(serde_json::to_value(api::Accepted { seq: 0, audit })?)
            }
            (Method::Get, ["v1", "log", "checkpoint"]) => {
                self.publish_checkpoint()?;
                Ok(Reply::Raw(
                    self.checkpoint.clone(),
                    "text/plain; charset=utf-8",
                ))
            }
            // Hash tiles only, to any session: hashes carry no entry content. Entry
            // bundles never leave through here; `entries` applies the policy check.
            (Method::Get, ["v1", "log", "tile", rest @ ..]) => {
                let key = format!("tile/{}", rest.join("/"));
                let (level, n, width) =
                    tlog::parse_hash_tile_key(&key).context("not a hash tile")?;
                let tile = self.log.hash_tile(level, n, width)?;
                Ok(Reply::Raw(
                    tile.context("log has no such tile")?,
                    "application/octet-stream",
                ))
            }
            (Method::Get, ["v1", "log", "proof", "inclusion"]) => {
                let size = query_u64(query, "size")?.unwrap_or(self.log.size());
                let index = query_u64(query, "index")?.context("index=N is required")?;
                ok(serde_json::to_value(api::InclusionProof {
                    index,
                    size,
                    proof: hashes(self.log.inclusion_proof(index, size)?),
                })?)
            }
            (Method::Get, ["v1", "log", "proof", "consistency"]) => {
                let new = query_u64(query, "new")?.unwrap_or(self.log.size());
                let old = query_u64(query, "old")?.context("old=N is required")?;
                ok(serde_json::to_value(api::ConsistencyProof {
                    old,
                    new,
                    proof: hashes(self.log.consistency_proof(old, new)?),
                })?)
            }
            (Method::Get, ["v1", "log", "entries"]) => {
                self.read_entries(user, query_u64(query, "after")?.unwrap_or(0))
            }
            _ => bail!("no route {method} {path}"),
        }
    }

    fn enroll(&mut self, u: &str, e: api::Enroll) -> Result<Reply> {
        let subject = self.trust.verify(&e.credential, now())?;
        ensure!(
            subject.user == u,
            "credential is for {}, not {u}",
            subject.user
        );
        let kp = KeyPackageIn::tls_deserialize_exact(&e.key_package.0)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)?;
        ensure!(
            user_of(kp.leaf_node().credential())? == u,
            "key package credential is not {u}"
        );
        let key = kp.leaf_node().signature_key().as_slice().to_vec();
        let about = Ctx {
            marking: Some(self.trust.access_marking(&e.credential)?),
            ..Ctx::default()
        };
        // Logged, not just refused: an enrollment with someone else's credential is
        // an identity-takeover attempt.
        let mismatch = if e.credential.body.key.0 != key {
            Some("credential is bound to a different key than the key package")
        } else if self.users.get(u).is_some_and(|x| x.key != key) {
            // ponytail: key rotation needs an EA-signed re-enrollment (§5.1).
            Some("already enrolled with another key")
        } else {
            None
        };
        if let Some(why) = mismatch {
            let audit = self.append_with(u, "", "enroll", Some("A-002"), why, about)?;
            return Ok(refused("A-002", why, audit));
        }
        // The key package's leaf must carry exactly this credential (attribute binding).
        ensure!(
            leaf_identity(kp.leaf_node())?.attributes == e.credential,
            "key package leaf carries different attributes"
        );
        let detail = format!("access {}", e.credential.body.access);
        let user = self.users.entry(u.to_owned()).or_insert(User {
            key,
            credential: e.credential.clone(),
            key_packages: vec![],
        });
        user.credential = e.credential;
        user.key_packages.push(e.key_package.0);
        let audit = self.append_with(u, "", "enroll", None, &detail, about)?;
        Ok(Reply::Ok(serde_json::to_value(api::Accepted {
            seq: 0,
            audit,
        })?))
    }

    fn challenge(&mut self, c: api::ChallengeRequest) -> Result<Reply> {
        ensure!(self.users.contains_key(&c.user), "unknown user {}", c.user);
        let nonce = self.provider.rand().random_vec(32)?;
        let now = now();
        self.challenges.retain(|_, (_, exp)| *exp > now);
        self.challenges
            .insert(nonce.clone(), (c.user, now + CHALLENGE_SECS));
        Ok(Reply::Ok(serde_json::to_value(api::Challenge {
            nonce: Bytes(nonce),
        })?))
    }

    fn open_session(&mut self, s: api::SessionRequest) -> Result<Reply> {
        let (user, expires) = self
            .challenges
            .remove(&s.nonce.0)
            .context("unknown or used challenge")?;
        ensure!(
            user == s.user && expires > now(),
            "challenge expired or not for {}",
            s.user
        );
        let key = &self.users.get(&user).context("unknown user")?.key;
        if let Err(e) = verify_session(key, &user, &s.nonce.0, &s.sig.0) {
            let audit = self.append(&user, "", "session", Some("A-001"), &e.to_string())?;
            return Ok(refused("A-001", &e.to_string(), audit));
        }
        let token = hex(&self.provider.rand().random_vec(32)?);
        let expires_at = now() + SESSION_SECS;
        self.sessions.retain(|_, (_, exp)| *exp > now());
        self.sessions
            .insert(token.clone(), (user.clone(), expires_at));
        self.append(&user, "", "session", None, "opened")?;
        Ok(Reply::Ok(serde_json::to_value(api::Session {
            token,
            expires_at,
        })?))
    }

    fn create_room(&mut self, user: &str, c: api::CreateRoom) -> Result<Reply> {
        ensure!(!self.rooms.contains_key(&c.room), "room {} exists", c.room);
        let MlsMessageBodyIn::GroupInfo(gi) =
            MlsMessageIn::tls_deserialize_exact(&c.group_info.0)?.extract()
        else {
            bail!("expected GroupInfo");
        };
        ensure!(
            gi.group_id().as_slice() == c.room.as_bytes(),
            "group id does not match room name"
        );
        let tree = RatchetTreeIn::tls_deserialize_exact(&c.ratchet_tree.0)?;
        let (group, _) = PublicGroup::from_external(
            self.provider.crypto(),
            self.provider.storage(),
            tree,
            gi,
            ProposalStore::new(),
        )?;
        ensure!(
            group.ciphersuite() == identity::room::ciphersuite()?,
            "wrong ciphersuite"
        );
        ensure!(
            is_member(&group, user),
            "{user} is not in the room they are creating"
        );
        let rules = RoomRules::read(group.group_context().extensions(), &self.trust)?;
        let creator = self.trust.verify(
            &self.users.get(user).context("unknown user")?.credential,
            now(),
        )?;
        let decision = rules.check_create(&creator);
        let detail = format!("ceiling {}", rules.ceiling.portion());
        // The room doesn't exist yet to ask for its ceiling.
        let about = Ctx {
            marking: Some(rules.ceiling.canonical_bytes()?),
            ..Ctx::default()
        };
        self.decided(
            user,
            &c.room,
            "create-room",
            decision,
            &detail,
            about,
            |ds| {
                ds.rooms.insert(
                    c.room.clone(),
                    Room {
                        group,
                        stream: vec![],
                        removed: BTreeMap::new(),
                        pending: BTreeMap::new(),
                        frozen: None,
                    },
                );
                0
            },
        )
    }

    fn commit(&mut self, user: &str, room_id: &str, c: api::Commit) -> Result<Reply> {
        if let Some(reply) = self.refuse_if_frozen(user, room_id, "commit")? {
            return Ok(reply);
        }
        let room = self.rooms.get_mut(room_id).context("unknown room")?;
        let ProtocolMessage::PublicMessage(pm) =
            MlsMessageIn::tls_deserialize_exact(&c.commit.0)?.try_into_protocol_message()?
        else {
            // §4.4: handshakes must be PublicMessage so the DS can evaluate them.
            let audit = self.append(
                user,
                room_id,
                "commit",
                Some("P-PRIVATE-HANDSHAKE"),
                "handshake sent as PrivateMessage",
            )?;
            return Ok(refused(
                "P-PRIVATE-HANDSHAKE",
                "handshakes must be PublicMessage",
                audit,
            ));
        };
        let processed = room.group.process_message(self.provider.crypto(), *pm)?;
        let Sender::Member(idx) = processed.sender() else {
            bail!("commit not from a member")
        };
        let idx = *idx;
        let aad = processed.aad().to_vec();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            bail!("expected a commit");
        };
        let view = CommitView::of(&room.group, &staged, idx, &self.trust)?;
        ensure!(
            view.committer == user,
            "commit signed by {}, sent by {user}",
            view.committer
        );
        let joiners: Vec<String> = view.added.iter().map(|j| j.user.clone()).collect();
        let removed = view.removed.clone();
        let used_kps: Vec<Vec<u8>> = staged
            .add_proposals()
            .map(|p| p.add_proposal().key_package().tls_serialize_detached())
            .collect::<Result<_, _>>()?;
        let rules = RoomRules::read(room.group.group_context().extensions(), &self.trust)?;
        let decision = if self.malicious {
            Decision::Permit // simulated compromise: sequence anything
        } else {
            rules.check_commit(&self.trust, &view, &aad, now())?
        };
        let mut detail = format!(
            "add [{}] remove [{}]",
            joiners.join(", "),
            removed.join(", ")
        );
        if let Some(new) = &view.new_rules {
            detail.push_str(&format!(
                " ceiling {} -> {}",
                rules.ceiling.portion(),
                new.ceiling.portion()
            ));
        }
        self.decided(
            user,
            room_id,
            "commit",
            decision,
            &detail,
            Ctx::default(),
            |ds| {
                let Some(room) = ds.rooms.get_mut(room_id) else {
                    return 0;
                };
                if let Err(e) = room.group.merge_commit(ds.provider.storage(), *staged) {
                    eprintln!("merge: {e}");
                }
                room.stream.push(Entry {
                    commit: true,
                    bytes: c.commit.0.clone(),
                });
                let seq = room.stream.len() as u64;
                for u in &removed {
                    room.removed.insert(u.clone(), seq);
                    room.pending.remove(u);
                }
                for (j, kp) in joiners.iter().zip(&used_kps) {
                    if let Some(user) = ds.users.get_mut(j) {
                        user.key_packages.retain(|k| k != kp);
                    }
                }
                // Welcomes are released only now that the commit is sequenced (§4.4).
                if let (Some(w), Ok(tree)) = (
                    &c.welcome,
                    room.group.export_ratchet_tree().tls_serialize_detached(),
                ) {
                    for j in &joiners {
                        ds.welcomes
                            .entry(j.clone())
                            .or_default()
                            .push(api::Welcome {
                                room: room_id.to_owned(),
                                welcome: w.clone(),
                                ratchet_tree: Bytes(tree.clone()),
                                after_seq: seq,
                            });
                    }
                }
                seq
            },
        )
    }

    fn send(&mut self, user: &str, room_id: &str, s: api::Send) -> Result<Reply> {
        if let Some(reply) = self.refuse_if_frozen(user, room_id, "message")? {
            return Ok(reply);
        }
        let room = self.rooms.get(room_id).context("unknown room")?;
        let ProtocolMessage::PrivateMessage(pm) =
            MlsMessageIn::tls_deserialize_exact(&s.message.0)?.try_into_protocol_message()?
        else {
            bail!("application messages must be PrivateMessage");
        };
        ensure!(
            pm.content_type() == ContentType::Application,
            "not an application message"
        );
        ensure!(
            pm.epoch() == room.group.group_context().epoch(),
            "stale epoch"
        );
        let aad: AppAad = serde_json::from_slice(pm.aad()).context("message AAD")?;
        // The DS can't decrypt the sender; it binds the AAD claim to the session (§4.4.2).
        ensure!(
            aad.sender == user,
            "message claims sender {}, session is {user}",
            aad.sender
        );
        ensure!(
            aad.sent_at.abs_diff(now()) <= identity::room::MAX_SKEW_SECS,
            "sent_at outside skew window"
        );
        let rules = RoomRules::read(room.group.group_context().extensions(), &self.trust)?;
        let sender = self.users.get(user).context("unknown user")?;
        let (marking, decision) =
            rules.check_message(&self.trust, &aad, &sender.credential, &sender.key)?;
        let detail = format!("marking {}", marking.portion());
        let marking_bytes = marking.canonical_bytes()?;
        let about = Ctx {
            marking: None,
            message: Some(MessageFacts {
                ciphertext_hash: Bytes(
                    self.provider
                        .crypto()
                        .hash(openmls_traits::types::HashType::Sha2_384, &s.message.0)?,
                ),
                epoch: pm.epoch().as_u64(),
                sent_at: aad.sent_at,
                blobs: aad.blobs.clone(),
                archive: aad.archive.clone(),
            }),
        };
        // Archive and blob bindings are structure, not policy: checked only for a
        // message policy already permits, and refused the same way, on the record.
        if matches!(decision, Decision::Permit)
            && let Err((code, why)) = self.check_bindings(user, room_id, &aad, &marking_bytes)
        {
            let audit = self.append_with(
                user,
                room_id,
                "message",
                Some(code),
                &format!("{detail}: {why}"),
                about,
            )?;
            return Ok(refused(code, &why, audit));
        }
        let archive = aad.archive.map(|h| h.0);
        let blobs = aad.blobs;
        self.decided(user, room_id, "message", decision, &detail, about, |ds| {
            let Some(room) = ds.rooms.get_mut(room_id) else {
                return 0;
            };
            room.stream.push(Entry {
                commit: false,
                bytes: s.message.0.clone(),
            });
            let seq = room.stream.len() as u64;
            if let Some(copy) = archive.and_then(|h| ds.copies.remove(&h).map(|c| (h, c))) {
                ds.filed.insert(copy.0);
                ds.archive.push(api::ArchiveEntry {
                    n: ds.archive.len() as u64,
                    room: room_id.to_owned(),
                    seq,
                    copy: Bytes(copy.1.bytes),
                    blobs,
                });
            }
            seq
        })
    }

    /// A message must carry the sealed copy its sender filed for this room, and may only
    /// point at blobs that sender uploaded here under the same marking. Anything else
    /// would put an unarchived or someone else's attachment into the room.
    fn check_bindings(
        &self,
        user: &str,
        room_id: &str,
        aad: &AppAad,
        marking: &[u8],
    ) -> Result<(), (&'static str, String)> {
        let filed = aad
            .archive
            .as_ref()
            .and_then(|h| self.copies.get(&h.0))
            .is_some_and(|c| c.room == room_id && c.uploader == user);
        if !filed {
            return Err((
                "R-001",
                "no sealed archive copy from this sender for this room matches the message".into(),
            ));
        }
        if aad.blobs.len() > MAX_BLOBS_PER_MESSAGE {
            return Err(("B-001", "too many blobs in one message".into()));
        }
        for b in &aad.blobs {
            let ours = self
                .blobs
                .get(&b.0)
                .is_some_and(|x| x.room == room_id && x.uploader == user && x.marking == marking);
            if !ours {
                return Err((
                    "B-001",
                    "blob wasn't uploaded to this room by this sender under this marking".into(),
                ));
            }
        }
        Ok(())
    }

    /// `POST /v1/rooms/{r}/blobs?marking=HEX`: ciphertext for a message about to be
    /// sent under that marking. Decided like the send it precedes, so a member who
    /// couldn't send the message can't park the file either.
    fn upload_blob(
        &mut self,
        user: &str,
        room_id: &str,
        marking: Option<&str>,
        body: &[u8],
    ) -> Result<Reply> {
        if let Some(reply) = self.refuse_if_frozen(user, room_id, "blob-upload")? {
            return Ok(reply);
        }
        ensure!(
            !body.is_empty() && body.len() <= MAX_BLOB,
            "blob is empty or over {} MiB",
            MAX_BLOB >> 20
        );
        let room = self.rooms.get(room_id).context("unknown room")?;
        ensure!(
            is_member(&room.group, user),
            "{user} is not a member of {room_id}"
        );
        let rules = RoomRules::read(room.group.group_context().extensions(), &self.trust)?;
        let sender = self.users.get(user).context("unknown user")?;
        let aad = AppAad {
            v: WIRE_VERSION,
            sender: user.into(),
            marking: Bytes(unhex(marking.context("marking=HEX is required")?)?),
            sent_at: now(),
            blobs: vec![],
            archive: None,
        };
        let (marking, decision) =
            rules.check_message(&self.trust, &aad, &sender.credential, &sender.key)?;
        let marking = marking.canonical_bytes()?;
        let hash = identity::archive::sha384(body)?;
        let detail = format!("sha384:{} {} bytes", hex(&hash), body.len());
        // Same bytes under another room, sender or marking: not ours to merge.
        if self
            .blobs
            .get(&hash)
            .is_some_and(|b| b.room != room_id || b.uploader != user || b.marking != marking)
        {
            let why = "this blob is already stored for another room, sender or marking";
            let audit = self.append(
                user,
                room_id,
                "blob-upload",
                Some("B-002"),
                &format!("{detail}: {why}"),
            )?;
            return Ok(refused("B-002", why, audit));
        }
        let stored = Blob {
            room: room_id.to_owned(),
            uploader: user.to_owned(),
            marking,
            bytes: body.to_vec(),
        };
        self.decided(
            user,
            room_id,
            "blob-upload",
            decision,
            &detail,
            Ctx::default(),
            move |ds| {
                ds.blobs.insert(hash, stored);
                0
            },
        )
    }

    /// `POST /v1/rooms/{r}/archive`: a sealed copy for a message about to be sent. Held
    /// until a message that names its hash is sequenced. It is a member's act, so
    /// lapsed credentials and pending removals are turned away, as for reads.
    fn file_copy(&mut self, user: &str, room_id: &str, body: &[u8]) -> Result<Reply> {
        if let Some(reply) = self.refuse_if_frozen(user, room_id, "archive-copy")? {
            return Ok(reply);
        }
        ensure!(
            self.reads_now(room_id, user)?,
            "{user} may not post to {room_id} now"
        );
        ensure!(
            body.len() <= MAX_BLOB,
            "archive copy is over the size limit"
        );
        identity::archive::check_archive_shape(body)?;
        let hash = identity::archive::sha384(body)?;
        ensure!(
            !self.filed.contains(&hash),
            "that copy already archives a message"
        );
        match self.copies.get(&hash) {
            Some(c) => ensure!(
                c.room == room_id && c.uploader == user,
                "that copy was filed by someone else"
            ),
            None => {
                self.copies.insert(
                    hash,
                    Copy {
                        room: room_id.into(),
                        uploader: user.into(),
                        bytes: body.to_vec(),
                    },
                );
            }
        }
        Ok(Reply::Ok(serde_json::to_value(api::Accepted {
            seq: 0,
            audit: String::new(),
        })?))
    }

    /// `POST /v1/rooms/{r}/archive-read`: the logged `ReadArchive` decision. The custodian
    /// opens nothing without the entry this writes (and its own offline key).
    fn archive_read(&mut self, user: &str, room_id: &str, req: api::ArchiveRead) -> Result<Reply> {
        let room = self.rooms.get(room_id).context("unknown room")?;
        let rules = RoomRules::read(room.group.group_context().extensions(), &self.trust)?;
        let cred = &self.users.get(user).context("unknown user")?.credential;
        let decision = rules.check_read_archive(&self.trust.verify(cred, now())?);
        self.decided(
            user,
            room_id,
            "archive-read",
            decision,
            &format!("reason: {}", req.reason),
            Ctx::default(),
            |_| 0,
        )
    }

    /// Is `user` a member of `room_id` whose credential is current and who isn't
    /// awaiting removal? The same test that withholds messages.
    fn reads_now(&self, room_id: &str, user: &str) -> Result<bool> {
        let room = self.rooms.get(room_id).context("unknown room")?;
        let expired = self
            .users
            .get(user)
            .is_none_or(|u| u.credential.body.not_after <= now());
        Ok(is_member(&room.group, user) && !expired && !room.pending.contains_key(user))
    }

    fn is_custodian(&self, user: &str) -> bool {
        self.trust.custodian.as_ref().is_some_and(|c| c.id == user)
    }

    /// `GET /v1/blobs/{sha384}`: members of the room it was uploaded to, and the
    /// custodian. Every other case answers the same, so a hash isn't an existence test.
    fn get_blob(&self, user: &str, id: &str) -> Result<Reply> {
        let blob = self
            .blobs
            .get(&unhex(id)?)
            .filter(|b| self.is_custodian(user) || self.reads_now(&b.room, user).unwrap_or(false))
            .context("no such blob")?;
        Ok(Reply::Raw(blob.bytes.clone(), "application/octet-stream"))
    }

    /// `GET /v1/archive?after=N`: sealed copies for the custodian, oldest first.
    fn pull_archive(&self, user: &str, after: u64) -> Result<Reply> {
        ensure!(
            self.is_custodian(user),
            "only the custodian pulls the archive"
        );
        let from = usize::try_from(after)
            .unwrap_or(usize::MAX)
            .min(self.archive.len());
        let to = self.archive.len().min(from + ARCHIVE_PAGE);
        Ok(Reply::Ok(serde_json::to_value(&self.archive[from..to])?))
    }

    fn refuse_if_frozen(&mut self, user: &str, room: &str, event: &str) -> Result<Option<Reply>> {
        let why = match self.rooms.get(room).and_then(|r| r.frozen.as_ref()) {
            None => return Ok(None),
            Some(Frozen::Held) => "room frozen: a member reported a fork; awaiting investigation",
            Some(Frozen::Closed) => "room closed after a fork; recreate it",
        };
        let audit = self.append(user, room, event, Some("F-001"), why)?;
        Ok(Some(refused("F-001", why, audit)))
    }

    /// A member refused a sequenced commit. Freeze the room and log the commit's hash
    /// so the conflicting branch is on record (idea-v1 §1a).
    fn fork(&mut self, user: &str, room_id: &str, f: api::ForkReport) -> Result<Reply> {
        let room = self.rooms.get_mut(room_id).context("unknown room")?;
        ensure!(
            is_member(&room.group, user) || room.removed.contains_key(user),
            "{user} is not in {room_id}"
        );
        let entry = room
            .stream
            .get((f.seq as usize).wrapping_sub(1))
            .context("no such seq")?;
        ensure!(entry.commit, "seq {} is not a commit", f.seq);
        let hash = hex(&self
            .provider
            .crypto()
            .hash(openmls_traits::types::HashType::Sha2_384, &entry.bytes)?);
        if room.frozen.is_none() {
            room.frozen = Some(Frozen::Held);
        }
        let detail = format!(
            "commit #{} sha384:{hash} refused by {user}: {}",
            f.seq, f.reason
        );
        let audit = self.append(user, room_id, "fork", Some("F-002"), &detail)?;
        Ok(Reply::Ok(serde_json::to_value(api::Accepted {
            seq: f.seq,
            audit,
        })?))
    }

    /// Keep membership state in line with attributes (idea-v1 §1):
    /// - expired credential → **suspended**: sends rejected (by `policy`), nothing
    ///   delivered; a fresh credential resumes them, backlog included;
    /// - attributes that no longer cover a room (debrief, clearance loss) → a removal
    ///   request to that room's steward, who commits the `Remove`.
    ///
    /// ponytail: runs on every authenticated request, O(users + rooms × members). A
    /// timer when scale arrives.
    fn sweep(&mut self) -> Result<()> {
        let now = now();
        let mut transitions = Vec::new();
        for (u, user) in &self.users {
            let expired = user.credential.body.not_after <= now;
            if expired != self.suspended.contains(u) {
                transitions.push((u.clone(), expired));
            }
        }
        for (u, expired) in transitions {
            let event = if expired { "suspended" } else { "resumed" };
            let about = Ctx {
                marking: Some(self.user_marking(&u)?),
                ..Ctx::default()
            };
            self.append_with(
                "ds",
                "",
                event,
                None,
                &format!(
                    "{u}: credential {}",
                    if expired { "expired" } else { "refreshed" }
                ),
                about,
            )?;
            if expired {
                self.suspended.insert(u);
            } else {
                self.suspended.remove(&u);
            }
        }

        let mut requests = Vec::new();
        let mut withdrawn = Vec::new();
        for (id, room) in &self.rooms {
            let rules = RoomRules::read(room.group.group_context().extensions(), &self.trust)?;
            for m in room.group.members() {
                let u = user_of(&m.credential)?;
                let Some(user) = self.users.get(&u) else {
                    continue;
                };
                let cleared = rules.still_cleared(&self.trust.verify(&user.credential, now)?);
                match (room.pending.contains_key(&u), cleared) {
                    (true, true) => withdrawn.push((id.clone(), u)),
                    (false, false) => requests.push((
                        id.clone(),
                        api::RemovalRequest {
                            user: u,
                            reason: "no longer cleared".into(),
                            evidence: user.credential.clone(),
                        },
                    )),
                    _ => {}
                }
            }
        }
        for (room, u) in withdrawn {
            self.append(
                "ds",
                &room,
                "removal-withdrawn",
                None,
                &format!("{u} cleared again"),
            )?;
            if let Some(r) = self.rooms.get_mut(&room) {
                r.pending.remove(&u);
            }
        }
        for (room, req) in requests {
            let detail = format!("{} {}", req.user, req.reason);
            self.append("ds", &room, "removal-requested", None, &detail)?;
            if let Some(r) = self.rooms.get_mut(&room) {
                r.pending.insert(req.user.clone(), req);
            }
        }
        Ok(())
    }

    /// Log a decision; on Permit, apply it and return its sequence number.
    #[allow(clippy::too_many_arguments)] // all of it is the entry; a struct would only rename the list
    fn decided(
        &mut self,
        user: &str,
        room: &str,
        event: &str,
        decision: Decision,
        detail: &str,
        about: Ctx,
        apply: impl FnOnce(&mut Self) -> u64,
    ) -> Result<Reply> {
        match decision {
            Decision::Permit => {
                let audit = self.append_with(user, room, event, None, detail, about)?;
                let seq = apply(self);
                Ok(Reply::Ok(serde_json::to_value(api::Accepted {
                    seq,
                    audit,
                })?))
            }
            Decision::Deny(reason) => {
                let audit = self.append_with(
                    user,
                    room,
                    event,
                    Some(reason.code()),
                    &format!("{detail}: {reason}"),
                    about,
                )?;
                Ok(refused(reason.code(), &reason.to_string(), audit))
            }
        }
    }

    /// Append to the transparency log. Returns the entry's audit reference.
    fn append(
        &mut self,
        actor: &str,
        room: &str,
        event: &str,
        code: Option<&str>,
        detail: &str,
    ) -> Result<String> {
        self.append_with(actor, room, event, code, detail, Ctx::default())
    }

    fn append_with(
        &mut self,
        actor: &str,
        room: &str,
        event: &str,
        code: Option<&str>,
        detail: &str,
        about: Ctx,
    ) -> Result<String> {
        let marking = match about.marking {
            Some(m) => m,
            None => self.default_marking(actor, room)?,
        };
        let entry = LogEntry {
            v: LOG_ENTRY_VERSION,
            id: self.log.size() + 1,
            at: now(),
            actor: actor.into(),
            room: room.into(),
            event: event.into(),
            decision: if code.is_some() { "deny" } else { "permit" }.into(),
            code: code.map(str::to_owned),
            detail: detail.into(),
            marking: Bytes(marking),
            message: about.message,
        };
        self.log.append(&entry.to_leaf())?;
        self.unsigned = true;
        Ok(format!("L-{}", entry.id))
    }

    /// Room events carry the room's ceiling; everything else is about its actor.
    /// No marking, no entry: an unmarked entry would be readable by nobody or by all.
    fn default_marking(&self, actor: &str, room: &str) -> Result<Vec<u8>> {
        if let Some(r) = self.rooms.get(room) {
            let rules = RoomRules::read(r.group.group_context().extensions(), &self.trust)?;
            return Ok(rules.ceiling.canonical_bytes()?);
        }
        self.user_marking(actor)
            .with_context(|| format!("no marking for a log entry by {actor} in room {room:?}"))
    }

    fn user_marking(&self, user: &str) -> Result<Vec<u8>> {
        let u = self.users.get(user).context("unknown user")?;
        self.trust.access_marking(&u.credential)
    }

    /// The entries `user` may read, with their leaf bytes as hashed. Expired or
    /// otherwise invalid attributes read nothing, like every other act.
    fn read_entries(&mut self, user: &str, after: u64) -> Result<Reply> {
        let cred = &self.users.get(user).context("unknown user")?.credential;
        let reader = self.trust.verify(cred, now())?;
        let end = self.log.size();
        let start = after.min(end);
        let mut out = Vec::new();
        for (index, leaf) in (start..).zip(self.log.entries(start, end)?) {
            // An entry we can't read or place is one we don't show.
            let permitted = LogEntry::from_leaf(&leaf).is_ok_and(|e| {
                matches!(
                    self.trust.check_read_log(&reader, &e.marking.0),
                    Ok(Decision::Permit)
                )
            });
            if permitted {
                out.push(api::LogRecord {
                    index,
                    leaf: Bytes(leaf),
                });
            }
        }
        Ok(Reply::Ok(serde_json::to_value(out)?))
    }
}

/// `key=VALUE` out of a query string, undecoded: callers pass hex.
fn query_str<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected hex"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

fn hashes(h: Vec<tlog::Hash>) -> Vec<Bytes> {
    h.into_iter().map(|h| Bytes(h.to_vec())).collect()
}

/// `key=N` out of a query string.
fn query_u64(query: &str, key: &str) -> Result<Option<u64>> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.parse().with_context(|| format!("{key} is not a number")))
        .transpose()
}

fn log_origin(trust: &TrustBundle) -> Result<String> {
    Ok(trust
        .log
        .as_ref()
        .context("trust bundle names no log key")?
        .origin
        .clone())
}

fn refused(code: &str, reason: &str, audit: String) -> Reply {
    Reply::Refused(api::Refused {
        code: code.into(),
        reason: reason.into(),
        audit,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn is_member(group: &PublicGroup, user: &str) -> bool {
    group
        .members()
        .any(|m| user_of(&m.credential).is_ok_and(|u| u == user))
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::log::LogVerifier;
    use identity::{AttributeIssuer, MockIssuer};
    use proto::api::{ConsistencyProof, InclusionProof, LogRecord};
    use tlog::MemStore;

    const ORIGIN: &str = "garble-test";

    struct Rig {
        ds: Ds<MemStore>,
        issuer: MockIssuer,
        key: PathBuf,
    }

    fn make(tag: &str) -> (Ds<MemStore>, MockIssuer, PathBuf) {
        let (ds, issuer, key, _) = make_with_archive(tag);
        (ds, issuer, key)
    }

    /// Also hands back the archive private key: the custodian's, which no DS holds.
    fn make_with_archive(tag: &str) -> (Ds<MemStore>, MockIssuer, PathBuf, Vec<u8>) {
        let key = std::env::temp_dir().join(format!("garble-ds-{tag}-{}.key", std::process::id()));
        let _ = std::fs::remove_file(&key);
        let keys = FileKeyStore::new(&key);
        let issuer = MockIssuer::generate().unwrap();
        let mut trust = issuer.trust_bundle();
        let (archive_private, archive_public) = identity::generate_archive_keypair().unwrap();
        trust.custodian = Some(proto::CustodianRef {
            id: "records".into(),
            archive_key: Bytes(archive_public),
        });
        trust.records_officers = vec!["olga".into()];
        trust.log = Some(identity::LogRef {
            origin: ORIGIN.into(),
            key: Bytes(keys.public_key().unwrap()),
        });
        let ds = Ds::new(
            trust,
            Log::open(MemStore::default()).unwrap(),
            LogSigner::new(ORIGIN, keys.signer().unwrap()),
            false,
        )
        .unwrap();
        (ds, issuer, key, archive_private)
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            let (ds, issuer, key) = make(tag);
            Self { ds, issuer, key }
        }

        /// A user the DS knows, as if enrolled; `secs` of validity from now.
        fn user(&mut self, name: &str, access: &str, secs: i64) -> &mut Self {
            let not_after = now().saturating_add_signed(secs);
            let credential = self
                .issuer
                .issue(name, b"k", access, "USA", not_after)
                .unwrap();
            self.ds.users.insert(
                name.into(),
                User {
                    key: b"k".to_vec(),
                    credential,
                    key_packages: vec![],
                },
            );
            self
        }

        fn get<T: serde::de::DeserializeOwned>(&mut self, user: &str, url: &str) -> T {
            match self.ds.route(&Method::Get, url, Some(user), b"").unwrap() {
                Reply::Ok(v) => serde_json::from_value(v).unwrap(),
                _ => panic!("{url} was not a JSON reply"),
            }
        }

        fn raw(&mut self, user: &str, url: &str) -> Result<Vec<u8>> {
            match self.ds.route(&Method::Get, url, Some(user), b"")? {
                Reply::Raw(b, _) => Ok(b),
                _ => bail!("not a raw reply"),
            }
        }

        fn checkpoint(&mut self) -> tlog::Checkpoint {
            self.ds.publish_checkpoint().unwrap();
            let verifier = self.ds.trust.log_verifier().unwrap();
            tlog::open_checkpoint(
                &self.raw("bob", "/v1/log/checkpoint").unwrap(),
                ORIGIN,
                &verifier,
            )
            .unwrap()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.key);
        }
    }

    // Append-only is a promise the route table has to keep: nothing but GET and POST.
    #[test]
    fn no_route_deletes_or_rewrites_anything() {
        let mut rig = Rig::new("routes");
        rig.user("alice", "TS", 3600);
        let paths = [
            "/v1/log/entries",
            "/v1/log/entries/1",
            "/v1/log/checkpoint",
            "/v1/log/tile/0/000",
            "/v1/log/proof/inclusion",
            "/v1/rooms",
            "/v1/rooms/ops",
            "/v1/rooms/ops/messages",
            "/v1/rooms/ops/messages/1",
            "/v1/rooms/ops/commit",
            "/v1/rooms/ops/archive",
            "/v1/rooms/ops/archive-read",
            "/v1/rooms/ops/blobs",
            "/v1/blobs/00",
            "/v1/archive",
            "/v1/users/alice/credential",
            "/v1/users/alice/enroll",
            "/v1/denials",
        ];
        for method in [Method::Delete, Method::Put, Method::Patch] {
            for path in paths {
                let err = rig
                    .ds
                    .route(&method, path, Some("alice"), b"{}")
                    .err()
                    .unwrap_or_else(|| panic!("{method} {path} was routed"));
                assert!(
                    err.to_string().contains("no route"),
                    "{method} {path}: {err:#}"
                );
            }
        }
        // Sanity: the harness does reach the real routes, and the old world-readable
        // dump is gone.
        assert!(matches!(
            rig.ds
                .route(&Method::Get, "/v1/log/entries", Some("alice"), b"")
                .unwrap(),
            Reply::Ok(_)
        ));
        assert!(
            rig.ds
                .route(&Method::Get, "/v1/log", Some("alice"), b"")
                .is_err()
        );
    }

    #[test]
    fn entries_are_readable_only_by_the_cleared() {
        let mut rig = Rig::new("gate");
        rig.user("carol", "TS//SI/TK//NF", 3600)
            .user("bob", "TS//SI//NF", 3600)
            .user("dave", "TS//SI/TK//NF", -10);
        // Entries about carol (TK), then about bob (SI).
        rig.ds.append("carol", "", "enroll", None, "tk").unwrap();
        rig.ds.append("bob", "", "enroll", None, "si").unwrap();
        rig.ds
            .append("bob", "", "session", Some("A-001"), "si again")
            .unwrap();

        let indexes = |r: Vec<LogRecord>| r.iter().map(|r| r.index).collect::<Vec<_>>();
        // The first request also logs dave's suspension (index 3), marked at his TK access.
        assert_eq!(indexes(rig.get("carol", "/v1/log/entries")), [0, 1, 2, 3]);
        assert_eq!(indexes(rig.get("bob", "/v1/log/entries")), [1, 2]);
        assert_eq!(
            indexes(rig.get("carol", "/v1/log/entries?after=1")),
            [1, 2, 3]
        );
        assert_eq!(
            indexes(rig.get("carol", "/v1/log/entries?after=99")),
            Vec::<u64>::new()
        );
        // Suspended: cleared, but reads nothing.
        assert!(
            rig.get::<Vec<LogRecord>>("dave", "/v1/log/entries")
                .is_empty()
        );
        // Not a user at all.
        assert!(
            rig.ds
                .route(&Method::Get, "/v1/log/entries", Some("mallory"), b"")
                .is_err()
        );

        let records: Vec<LogRecord> = rig.get("bob", "/v1/log/entries");
        let e = LogEntry::from_leaf(&records[0].leaf.0).unwrap();
        assert_eq!((e.id, e.v, e.actor.as_str()), (2, LOG_ENTRY_VERSION, "bob"));
        let bob = rig.ds.users["bob"].credential.clone();
        assert_eq!(e.marking.0, rig.ds.trust.access_marking(&bob).unwrap());
    }

    #[test]
    fn proofs_and_tiles_match_the_signed_checkpoints() {
        let mut rig = Rig::new("proofs");
        rig.user("bob", "TS//SI//NF", 3600);
        for i in 0..3 {
            rig.ds
                .append("bob", "", "session", None, &format!("opened {i}"))
                .unwrap();
        }
        let first = rig.checkpoint();
        assert_eq!((first.origin.as_str(), first.size), (ORIGIN, 3));
        for i in 3..9 {
            rig.ds
                .append("bob", "", "session", None, &format!("opened {i}"))
                .unwrap();
        }
        let head = rig.checkpoint();
        assert_eq!(head.size, 9);

        let records: Vec<LogRecord> = rig.get("bob", "/v1/log/entries");
        assert_eq!(records.len(), 9);
        for r in &records {
            let url = format!("/v1/log/proof/inclusion?index={}&size=9", r.index);
            let p: InclusionProof = rig.get("bob", &url);
            let proof: Vec<tlog::Hash> = p
                .proof
                .iter()
                .map(|h| h.0.clone().try_into().unwrap())
                .collect();
            tlog::verify_inclusion(&tlog::leaf_hash(&r.leaf.0), r.index, 9, &proof, &head.root)
                .unwrap();
        }
        // The size defaults to the current head.
        let p: InclusionProof = rig.get("bob", "/v1/log/proof/inclusion?index=0");
        assert_eq!(p.size, 9);

        let c: ConsistencyProof = rig.get("bob", "/v1/log/proof/consistency?old=3&new=9");
        let proof: Vec<tlog::Hash> = c
            .proof
            .iter()
            .map(|h| h.0.clone().try_into().unwrap())
            .collect();
        tlog::verify_consistency(3, 9, &first.root, &head.root, &proof).unwrap();

        for bad in [
            "/v1/log/proof/inclusion?index=9&size=9",
            "/v1/log/proof/inclusion?size=9",
            "/v1/log/proof/inclusion?index=0&size=10",
            "/v1/log/proof/consistency?old=10&new=9",
            "/v1/log/proof/consistency?new=9",
            "/v1/log/proof/consistency?old=x",
        ] {
            assert!(
                rig.ds.route(&Method::Get, bad, Some("bob"), b"").is_err(),
                "{bad}"
            );
        }

        // Hash tiles go out; nothing else under tile/ does.
        let tile = rig.raw("bob", "/v1/log/tile/0/000.p/9").unwrap();
        let want: Vec<u8> = records
            .iter()
            .flat_map(|r| tlog::leaf_hash(&r.leaf.0))
            .collect();
        assert_eq!(tile, want);
        for bad in [
            "/v1/log/tile/entries/000.p/9",
            "/v1/log/tile/0/000",
            "/v1/log/tile/0/000.p/10",
            "/v1/log/tile/0/../000.p/9",
            "/v1/log/tile/9/000.p/1",
            "/v1/log/tile",
        ] {
            assert!(rig.raw("bob", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_restarted_ds_keeps_the_log_and_notices_a_rollback() {
        let mut rig = Rig::new("restart");
        rig.user("bob", "TS//SI//NF", 3600);
        for _ in 0..4 {
            rig.ds.append("bob", "", "session", None, "opened").unwrap();
        }
        rig.ds.publish_checkpoint().unwrap();
        let store = rig.ds.log.store().clone();
        let trust = rig.ds.trust.clone();
        let signer = || LogSigner::new(ORIGIN, FileKeyStore::new(&rig.key).signer().unwrap());

        let mut again = Ds::new(
            trust.clone(),
            Log::open(store.clone()).unwrap(),
            signer(),
            false,
        )
        .unwrap();
        assert_eq!(again.log.size(), 4);
        again.users.insert(
            "bob".into(),
            User {
                key: vec![],
                credential: rig.ds.users["bob"].credential.clone(),
                key_packages: vec![],
            },
        );
        again
            .append("bob", "", "session", None, "after restart")
            .unwrap();
        assert_eq!(again.log.size(), 5);
        assert_eq!(again.log.entries(4, 5).unwrap().len(), 1);

        let mut rolled_back = store.clone();
        rolled_back.0.remove("tile/entries/000.p/4");
        let err = Ds::new(
            trust.clone(),
            Log::open(rolled_back).unwrap(),
            signer(),
            false,
        )
        .err()
        .expect("a rolled-back log must not start");
        assert!(
            err.to_string().contains("last signed checkpoint"),
            "{err:#}"
        );

        // A checkpoint signed by some other key isn't ours to trust either.
        let other = Rig::new("restart-other");
        let mut foreign = store;
        foreign.0.insert(
            CHECKPOINT_KEY.into(),
            other.ds.log.store().0[CHECKPOINT_KEY].clone(),
        );
        assert!(Ds::new(trust, Log::open(foreign).unwrap(), signer(), false).is_err());
    }

    #[test]
    fn the_ds_needs_a_log_key_in_the_trust_bundle() {
        let issuer = MockIssuer::generate().unwrap();
        let key = std::env::temp_dir().join(format!("garble-ds-nokey-{}.key", std::process::id()));
        let signer = LogSigner::new(ORIGIN, FileKeyStore::new(&key).signer().unwrap());
        let err = Ds::new(
            issuer.trust_bundle(),
            Log::open(MemStore::default()).unwrap(),
            signer,
            false,
        )
        .err()
        .expect("no log key, no DS");
        assert!(err.to_string().contains("log key"), "{err:#}");
        let _ = std::fs::remove_file(key);
    }

    #[test]
    fn verifier_in_the_bundle_matches_the_signer() {
        let rig = Rig::new("verifier");
        let v: LogVerifier = rig.ds.trust.log_verifier().unwrap();
        let note = rig.ds.checkpoint.clone();
        assert_eq!(tlog::open_checkpoint(&note, ORIGIN, &v).unwrap().size, 0);
    }

    // The whole path over real HTTP: what a message leaves in the log, who can read it.
    #[test]
    fn messages_are_logged_by_hash_and_rooms_stay_in_their_clearance() {
        let (ds, issuer, key) = make("e2e");
        let dir = std::env::temp_dir().join(format!("garble-ds-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let trust_file = dir.join("trust.json");
        std::fs::write(&trust_file, serde_json::to_vec(&ds.trust).unwrap()).unwrap();

        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        let mut ds = ds;
        let sent_before = now();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                ds.handle(req);
            }
        });

        let join = |user: &str, access: &str| {
            let mut c = client::Client::create(&dir.join(user), user, &url, &trust_file).unwrap();
            let key: Vec<u8> = (0..c.public_key_hex().len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&c.public_key_hex()[i..i + 2], 16).unwrap())
                .collect();
            let cred = issuer
                .issue(user, &key, access, "USA", now() + 3600)
                .unwrap();
            c.enroll(cred).unwrap();
            c
        };
        let (mut alice, mut bob, carol) = (
            join("alice", "TS//SI/TK//NF"),
            join("bob", "TS//SI//NF"),
            join("carol", "S//NF"),
        );
        alice.create_room("ops", "TS//SI//NF").unwrap();
        alice.add("ops", "bob", true).unwrap();
        bob.sync().unwrap();
        alice.send("ops", "TS//SI//NF", "hello").unwrap();

        let ours = alice.audit_log().unwrap();
        let message = ours
            .iter()
            .find(|e| e.event == "message")
            .expect("a message entry");
        assert_eq!(
            (message.room.as_str(), message.decision.as_str()),
            ("ops", "permit")
        );
        let facts = message.message.as_ref().expect("message facts");
        assert_eq!(facts.ciphertext_hash.0.len(), 48);
        assert!(facts.epoch >= 1);
        assert!(facts.sent_at >= sent_before && facts.sent_at <= now());
        // Only message events carry facts, and room events carry the room's ceiling.
        assert!(
            ours.iter()
                .filter(|e| e.event != "message")
                .all(|e| e.message.is_none())
        );
        let ops_marking = &ours
            .iter()
            .find(|e| e.event == "create-room")
            .unwrap()
            .marking;
        assert!(
            ours.iter()
                .filter(|e| e.room == "ops")
                .all(|e| &e.marking == ops_marking)
        );

        // Bob's TS//SI covers the ceiling; carol's S doesn't. Carol still sees her own.
        assert!(
            bob.audit_log()
                .unwrap()
                .iter()
                .any(|e| e.event == "message")
        );
        let hers = carol.audit_log().unwrap();
        assert!(
            hers.iter().all(|e| e.room.is_empty() && e.actor == "carol"),
            "{hers:?}"
        );
        assert!(!hers.is_empty());

        // The old world-readable dump and unauthenticated reads are both gone.
        for path in ["/v1/log", "/v1/log/entries", "/v1/log/checkpoint"] {
            let status = http_status(&format!("{url}{path}"));
            assert_eq!(status, 401, "{path}");
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(key);
    }

    fn alice_aad(archive: Option<u8>, blobs: &[u8], marking: u8) -> AppAad {
        AppAad {
            v: WIRE_VERSION,
            sender: "alice".into(),
            marking: Bytes(vec![marking]),
            sent_at: 0,
            blobs: blobs.iter().map(|b| Bytes(vec![*b])).collect(),
            archive: archive.map(|a| Bytes(vec![a])),
        }
    }

    #[test]
    fn a_message_needs_its_own_archive_copy_and_its_own_blobs() {
        let mut rig = Rig::new("bindings");
        let ds = &mut rig.ds;
        let check = |ds: &Ds<MemStore>, user, room, aad: &AppAad, marking: u8| {
            ds.check_bindings(user, room, aad, &[marking])
                .map_err(|(code, _)| code)
        };
        assert_eq!(
            check(ds, "alice", "ops", &alice_aad(None, &[], 7), 7),
            Err("R-001")
        );
        assert_eq!(
            check(ds, "alice", "ops", &alice_aad(Some(1), &[], 7), 7),
            Err("R-001")
        );

        ds.copies.insert(
            vec![1],
            Copy {
                room: "ops".into(),
                uploader: "alice".into(),
                bytes: vec![],
            },
        );
        assert_eq!(
            check(ds, "alice", "ops", &alice_aad(Some(1), &[], 7), 7),
            Ok(())
        );
        // Someone else's copy, or one filed for another room, archives nothing here.
        assert_eq!(
            check(ds, "bob", "ops", &alice_aad(Some(1), &[], 7), 7),
            Err("R-001")
        );
        assert_eq!(
            check(ds, "alice", "other", &alice_aad(Some(1), &[], 7), 7),
            Err("R-001")
        );

        ds.blobs.insert(
            vec![2],
            Blob {
                room: "ops".into(),
                uploader: "alice".into(),
                marking: vec![7],
                bytes: vec![],
            },
        );
        assert_eq!(
            check(ds, "alice", "ops", &alice_aad(Some(1), &[2], 7), 7),
            Ok(())
        );
        for (user, room, blob, marking) in [
            ("bob", "ops", 2, 7),     // someone else's upload
            ("alice", "other", 2, 7), // another room's
            ("alice", "ops", 3, 7),   // never uploaded
            ("alice", "ops", 2, 8),   // uploaded under a different marking
        ] {
            let aad = AppAad {
                sender: user.into(),
                ..alice_aad(Some(1), &[blob], marking)
            };
            ds.copies.insert(
                vec![1],
                Copy {
                    room: room.into(),
                    uploader: user.into(),
                    bytes: vec![],
                },
            );
            assert_eq!(
                check(ds, user, room, &aad, marking),
                Err("B-001"),
                "{user} {room} {blob}"
            );
        }
        let many = vec![2; MAX_BLOBS_PER_MESSAGE + 1];
        assert_eq!(
            check(ds, "alice", "ops", &alice_aad(Some(1), &many, 7), 7),
            Err("B-001")
        );
    }

    #[test]
    fn blob_and_archive_routes_fail_closed() {
        let mut rig = Rig::new("blob-routes");
        rig.user("alice", "TS//SI//NF", 3600)
            .user("records", "U", 3600);
        let route = |rig: &mut Rig, m: Method, url: &str, user: &str, body: &[u8]| {
            rig.ds.route(&m, url, Some(user), body)
        };
        // No such room, no marking, no such blob, bad hex: all refused.
        for (m, url) in [
            (Method::Post, "/v1/rooms/nope/blobs?marking=00"),
            (Method::Post, "/v1/rooms/nope/archive"),
            (Method::Post, "/v1/rooms/nope/archive-read"),
            (Method::Get, "/v1/blobs/00"),
            (Method::Get, "/v1/blobs/zz"),
            (Method::Get, "/v1/blobs/0"),
        ] {
            assert!(
                route(&mut rig, m.clone(), url, "alice", br#"{"reason":"x"}"#).is_err(),
                "{m} {url}"
            );
        }
        // Only the custodian pulls, and an empty archive is an empty page.
        assert!(route(&mut rig, Method::Get, "/v1/archive", "alice", b"").is_err());
        assert!(matches!(
            route(&mut rig, Method::Get, "/v1/archive?after=5", "records", b"").unwrap(),
            Reply::Ok(v) if v == serde_json::json!([])
        ));
        // The custodian isn't a general reader: an unknown blob is still unknown.
        assert!(route(&mut rig, Method::Get, "/v1/blobs/00", "records", b"").is_err());
    }

    /// A DS on a real socket, and a way to make users it knows.
    struct Site {
        url: String,
        dir: PathBuf,
        issuer: MockIssuer,
        key: PathBuf,
        trust_file: PathBuf,
        archive_private: Vec<u8>,
    }

    impl Site {
        fn start(tag: &str) -> Self {
            let (ds, issuer, key, archive_private) = make_with_archive(tag);
            let dir = std::env::temp_dir().join(format!("garble-ds-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let trust_file = dir.join("trust.json");
            std::fs::write(&trust_file, serde_json::to_vec(&ds.trust).unwrap()).unwrap();
            let server = Server::http("127.0.0.1:0").unwrap();
            let url = format!("http://{}", server.server_addr().to_ip().unwrap());
            let mut ds = ds;
            std::thread::spawn(move || {
                for req in server.incoming_requests() {
                    ds.handle(req);
                }
            });
            Self {
                url,
                dir,
                issuer,
                key,
                trust_file,
                archive_private,
            }
        }

        fn join(&self, user: &str, access: &str) -> client::Client {
            let mut c =
                client::Client::create(&self.dir.join(user), user, &self.url, &self.trust_file)
                    .unwrap();
            let key = unhex(&c.public_key_hex()).unwrap();
            let cred = self
                .issuer
                .issue(user, &key, access, "USA", now() + 3600)
                .unwrap();
            c.enroll(cred).unwrap();
            c
        }
    }

    impl Drop for Site {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
            let _ = std::fs::remove_file(&self.key);
        }
    }

    fn denied(e: anyhow::Error) -> client::Denied {
        e.downcast::<client::Denied>().expect("a Denied error")
    }

    #[test]
    fn files_and_the_archive_go_through_the_ds_and_open_only_with_a_logged_permit() {
        use client::Event;
        let site = Site::start("files");
        let mut alice = site.join("alice", "TS//SI//NF");
        let mut bob = site.join("bob", "TS//SI//NF");
        let mut carol = site.join("carol", "S//NF");
        let mut olga = site.join("olga", "TS//SI//NF");
        let records = site.join("records", "U");

        alice.create_room("ops", "TS//SI//NF").unwrap();
        alice.add("ops", "bob", true).unwrap();
        bob.sync().unwrap();

        // An attachment: encrypted by the sender, opened by a member.
        let src = site.dir.join("plan.txt");
        std::fs::write(&src, b"launch at dawn").unwrap();
        let file_seq = alice.send_file("ops", "TS//SI//NF", &src).unwrap();
        let text_seq = alice.send("ops", "TS//SI//NF", "see attached").unwrap();
        let events = bob.sync().unwrap();
        assert!(events.iter().any(|(room, e)| room == "ops"
            && matches!(e, Event::Message { seq, text, .. }
                if *seq == file_seq && text == "[file] plan.txt (14 bytes)")));
        let out = site.dir.join("bob-downloads");
        std::fs::create_dir_all(&out).unwrap();
        let got = bob.fetch("ops", file_seq, &out).unwrap();
        assert_eq!(std::fs::read(&got).unwrap(), b"launch at dawn");
        assert!(
            bob.fetch("ops", file_seq, &out).is_err(),
            "never overwrites"
        );
        assert!(bob.fetch("ops", text_seq, &out).is_err(), "not a file");
        // Files can be acked like any message; forwarding them isn't built.
        bob.ack("ops", file_seq).unwrap();
        assert!(bob.forward("ops", file_seq, "ops").is_err());
        let mine = site.dir.join("alice-downloads");
        std::fs::create_dir_all(&mine).unwrap();
        assert!(
            alice.fetch("ops", file_seq, &mine).is_ok(),
            "senders keep access"
        );

        // The log names the upload, the blob and the sealed copy, never the content.
        let log = alice.audit_log().unwrap();
        assert!(
            log.iter()
                .any(|e| e.event == "blob-upload" && e.decision == "permit")
        );
        let facts = log
            .iter()
            .filter_map(|e| e.message.as_ref())
            .find(|m| !m.blobs.is_empty())
            .expect("the file message's entry names its blob");
        assert_eq!(facts.blobs.len(), 1);
        assert_eq!(facts.archive.as_ref().map(|a| a.0.len()), Some(48));
        assert!(
            log.iter()
                .filter_map(|e| e.message.as_ref())
                .all(|m| m.archive.is_some()),
            "every message entry binds an archive copy"
        );
        assert!(!log.iter().any(|e| e.detail.contains("launch at dawn")));

        // Who can pull the blob: members and the custodian. It is ciphertext.
        let blob_id = facts.blobs[0].0.clone();
        let ct = bob.blob(&blob_id).unwrap();
        assert_eq!(ct.len(), 14 + 16);
        assert!(!ct.windows(14).any(|w| w == b"launch at dawn"));
        assert_eq!(records.blob(&blob_id).unwrap(), ct);
        assert!(carol.blob(&blob_id).is_err(), "not a member");
        assert!(olga.blob(&blob_id).is_err(), "cleared, but not in the room");

        // The custodian pulls sealed copies and files. It holds no key to open them.
        let home = site.dir.join("records");
        let pulled = custodian::pull(&records, &home).unwrap();
        assert_eq!((pulled.entries, pulled.blobs), (3, 1)); // file, text, ack
        assert_eq!(
            custodian::pull(&records, &home).unwrap(),
            Default::default()
        );
        assert!(alice.archive_pull(0).is_err(), "only the custodian pulls");
        let stored = std::fs::read_to_string(home.join("archive.jsonl")).unwrap();
        assert!(!stored.contains("launch at dawn") && !stored.contains("see attached"));

        // Reading needs a logged permit: officers get one, everyone else a logged refusal.
        let steward = denied(alice.archive_permit("ops", "curious").unwrap_err());
        assert_eq!((steward.by, steward.code.as_str()), ("DS", "P-007"));
        assert!(steward.audit.starts_with("L-"));
        denied(carol.archive_permit("ops", "me too").unwrap_err());
        let permit = olga.archive_permit("ops", "records request 42").unwrap();

        let trust = identity::TrustBundle::load(&home.join("trust.json")).unwrap();
        let files = site.dir.join("exported");
        // The wrong key opens nothing, and the permit is spent by the attempt.
        let wrong = identity::generate_archive_keypair().unwrap().0;
        let spent = custodian::read(&home, &trust, &wrong, "ops", &permit, now(), None).unwrap();
        assert!(spent.iter().all(|o| o.record.is_err()));
        let again = custodian::read(
            &home,
            &trust,
            &site.archive_private,
            "ops",
            &permit,
            now(),
            Some(&files),
        );
        assert!(again.unwrap_err().to_string().contains("already used"));

        let permit = olga.archive_permit("ops", "records request 43").unwrap();
        assert!(
            custodian::read(
                &home,
                &trust,
                &site.archive_private,
                "other",
                &permit,
                now(),
                None
            )
            .is_err(),
            "a permit is for one room"
        );
        let opened = custodian::read(
            &home,
            &trust,
            &site.archive_private,
            "ops",
            &permit,
            now(),
            Some(&files),
        )
        .unwrap();
        let records_in: Vec<_> = opened.iter().map(|o| o.record.as_ref().unwrap()).collect();
        assert_eq!(records_in.len(), 3);
        assert!(records_in.iter().all(|r| r.room == "ops"));
        let sent: Vec<&str> = records_in.iter().map(|r| r.sender.as_str()).collect();
        assert_eq!(sent, ["alice", "alice", "bob"]);
        let body =
            |r: &proto::ArchiveRecord| String::from_utf8_lossy(&r.envelope.body.0).into_owned();
        assert_eq!(body(records_in[1]), "see attached");
        let exported = opened[0].file.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(std::fs::read(exported).unwrap(), b"launch at dawn");

        // Every one of those reads is on the record, with its reason.
        let after = olga.audit_log().unwrap();
        let reads: Vec<_> = after.iter().filter(|e| e.event == "archive-read").collect();
        let who: Vec<_> = reads
            .iter()
            .map(|e| (e.actor.as_str(), e.decision.as_str()))
            .collect();
        assert_eq!(
            who,
            [
                ("alice", "deny"),
                ("carol", "deny"),
                ("olga", "permit"),
                ("olga", "permit")
            ]
        );
        assert!(
            reads
                .iter()
                .any(|e| e.detail.contains("records request 43"))
        );

        // A removed member loses the blob with the room.
        alice.remove("ops", "bob").unwrap();
        bob.sync().unwrap();
        assert!(bob.blob(&blob_id).is_err());
    }

    /// Status of an unauthenticated GET, over a bare socket: no HTTP client in the DS's
    /// own dependencies.
    fn http_status(url: &str) -> u16 {
        use std::io::{Read, Write};
        let (host, path) = url.trim_start_matches("http://").split_once('/').unwrap();
        let mut s = std::net::TcpStream::connect(host).unwrap();
        write!(
            s,
            "GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out.split_whitespace().nth(1).unwrap().parse().unwrap()
    }
}
