//! The device's one SQLCipher file (idea-v2 §7.2): OpenMLS storage, identity,
//! cursors, history. One file means one at-rest story and one purge.
//!
//! Everything between `open` and `commit` is a single open transaction, so MLS
//! state and cursors reach disk together or not at all. Dropping a `Store` without
//! committing rolls back, the same load-mutate-save-or-lose shape the JSON files had.
//! Safe because `lock_home` allows one process per home.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use proto::{AttributeCredential, Bytes};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::{RoomState, State, Stored};

/// OpenMLS's own tables come from its migrations; this is ours.
const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = "
CREATE TABLE identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    user TEXT NOT NULL,
    ds TEXT NOT NULL,
    signer_public BLOB NOT NULL,
    credential TEXT,
    checkpoint BLOB,
    alert TEXT
);
CREATE TABLE rooms (
    room TEXT PRIMARY KEY,
    cursor INTEGER NOT NULL,
    held INTEGER NOT NULL
);
CREATE TABLE own (
    room TEXT NOT NULL,
    seq INTEGER NOT NULL,
    PRIMARY KEY (room, seq)
);
CREATE TABLE messages (
    room TEXT NOT NULL,
    seq INTEGER NOT NULL,
    sender TEXT NOT NULL,
    msg_id BLOB NOT NULL,
    marking BLOB NOT NULL,
    body BLOB NOT NULL,
    content_type TEXT NOT NULL,
    PRIMARY KEY (room, seq)
);
";

/// How OpenMLS values are serialized into the DB. JSON, same as the crate's own tests.
#[derive(Default)]
pub struct Json;

impl Codec for Json {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// OpenMLS's view of the store. Borrows the connection, so it's rebuilt per call
/// rather than held: a held one would pin the connection and `Client` couldn't move.
pub type MlsStorage<'a> = SqliteStorageProvider<Json, &'a Connection>;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn create(path: &Path, key: &[u8]) -> Result<Self> {
        ensure!(!path.exists(), "{} already exists", path.display());
        let mut conn = connect(path, key)?;
        migrate_mls(&mut conn)?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Self::begin(conn)
    }

    pub fn open(path: &Path, key: &[u8]) -> Result<Self> {
        let mut conn = connect(path, key)?;
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        ensure!(
            v == SCHEMA_VERSION,
            "{} has store schema {v}, this build reads {SCHEMA_VERSION}",
            path.display()
        );
        migrate_mls(&mut conn)?;
        Self::begin(conn)
    }

    fn begin(conn: Connection) -> Result<Self> {
        conn.execute_batch("BEGIN")?;
        Ok(Self { conn })
    }

    pub fn mls(&self) -> MlsStorage<'_> {
        SqliteStorageProvider::new(&self.conn)
    }

    /// Make everything since the last commit durable, and start the next batch.
    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT; BEGIN")?;
        Ok(())
    }

    pub fn load(&self) -> Result<State> {
        let mut state = self
            .conn
            .query_row(
                "SELECT user, ds, signer_public, credential, checkpoint, alert FROM identity",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<Vec<u8>>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?
            .map(|(user, ds, signer_public, credential, checkpoint, alert)| {
                Ok::<_, anyhow::Error>(State {
                    user,
                    ds,
                    signer_public: Bytes(signer_public),
                    credential: credential
                        .map(|c| serde_json::from_str::<AttributeCredential>(&c))
                        .transpose()?,
                    rooms: BTreeMap::new(),
                    checkpoint: checkpoint.map(Bytes),
                    alert,
                })
            })
            .transpose()?
            .context("store has no identity")?;

        let mut rooms = self.conn.prepare("SELECT room, cursor, held FROM rooms")?;
        for r in rooms.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?, r.get::<_, bool>(2)?))
        })? {
            let (room, cursor, held) = r?;
            state.rooms.insert(
                room,
                RoomState {
                    cursor,
                    held,
                    own: BTreeSet::new(),
                    inbox: BTreeMap::new(),
                },
            );
        }
        let mut own = self.conn.prepare("SELECT room, seq FROM own")?;
        for r in own.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?)))? {
            let (room, seq) = r?;
            if let Some(rs) = state.rooms.get_mut(&room) {
                rs.own.insert(seq);
            }
        }
        let mut msgs = self.conn.prepare(
            "SELECT room, seq, sender, msg_id, marking, body, content_type FROM messages",
        )?;
        for r in msgs.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u64>(1)?,
                Stored {
                    sender: r.get(2)?,
                    msg_id: Bytes(r.get(3)?),
                    marking: Bytes(r.get(4)?),
                    body: Bytes(r.get(5)?),
                    content_type: r.get(6)?,
                },
            ))
        })? {
            let (room, seq, stored) = r?;
            if let Some(rs) = state.rooms.get_mut(&room) {
                rs.inbox.insert(seq, stored);
            }
        }
        Ok(state)
    }

    /// The fields that change in place. Own seqs and messages are append-only and go
    /// through `mark_own` / `remember` as they happen.
    pub fn flush(&self, s: &State) -> Result<()> {
        let credential = s
            .credential
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        self.conn.execute(
            "INSERT INTO identity (id, user, ds, signer_public, credential, checkpoint, alert)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (id) DO UPDATE SET
                 credential = excluded.credential,
                 checkpoint = excluded.checkpoint,
                 alert = excluded.alert",
            params![
                s.user,
                s.ds,
                s.signer_public.0,
                credential,
                s.checkpoint.as_ref().map(|c| &c.0),
                s.alert
            ],
        )?;
        let mut up = self.conn.prepare_cached(
            "INSERT INTO rooms (room, cursor, held) VALUES (?1, ?2, ?3)
             ON CONFLICT (room) DO UPDATE SET cursor = excluded.cursor, held = excluded.held",
        )?;
        for (room, rs) in &s.rooms {
            up.execute(params![room, rs.cursor, rs.held])?;
        }
        Ok(())
    }

    pub fn mark_own(&self, room: &str, seq: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO own (room, seq) VALUES (?1, ?2)",
            params![room, seq],
        )?;
        Ok(())
    }

    pub fn remember(&self, room: &str, seq: u64, m: &Stored) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO messages
                 (room, seq, sender, msg_id, marking, body, content_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                room,
                seq,
                m.sender,
                m.msg_id.0,
                m.marking.0,
                m.body.0,
                m.content_type
            ],
        )?;
        Ok(())
    }

    /// Delete everything we hold for `room` except the MLS group, which the caller
    /// drops through OpenMLS first. Nothing here commits: group and rows go out in one
    /// transaction (`Client::purge` commits after both).
    pub fn forget(&self, room: &str) -> Result<()> {
        for table in ["rooms", "own", "messages"] {
            self.conn
                .execute(&format!("DELETE FROM {table} WHERE room = ?1"), [room])?;
        }
        Ok(())
    }
}

/// Opens the file under `key` and proves it's really SQLCipher and really that key.
fn connect(path: &Path, key: &[u8]) -> Result<Connection> {
    ensure!(key.len() == 32, "DB key must be 32 bytes");
    let conn = Connection::open(path)?;
    // A raw key skips SQLCipher's PBKDF2; it's already 256 random bits.
    let pragma = Zeroizing::new(format!(
        "x'{}'",
        key.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    conn.pragma_update(None, "key", pragma.as_str())?;
    // A build that lost the sqlcipher feature would happily write plaintext.
    let cipher: Option<String> = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .optional()?;
    if cipher.is_none_or(|v| v.is_empty()) {
        bail!("SQLite was built without SQLCipher; refusing to store state unencrypted");
    }
    // First read: a wrong key or a plaintext file fails here, not three calls later.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .with_context(|| {
        format!(
            "can't read {}: wrong key or not a GARBLE store",
            path.display()
        )
    })?;
    // Purge has to overwrite pages, not just unlink them.
    conn.pragma_update(None, "secure_delete", true)?;
    Ok(conn)
}

fn migrate_mls(conn: &mut Connection) -> Result<()> {
    SqliteStorageProvider::<Json, &mut Connection>::new(conn).run_migrations()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("garble-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        d
    }

    fn state() -> State {
        State {
            user: "alice".into(),
            ds: "http://ds".into(),
            signer_public: Bytes(vec![1, 2, 3]),
            credential: None,
            rooms: BTreeMap::new(),
            checkpoint: Some(Bytes(vec![9])),
            alert: None,
        }
    }

    fn stored(text: &str) -> Stored {
        Stored {
            sender: "bob".into(),
            msg_id: Bytes(vec![0; 16]),
            marking: Bytes(vec![1]),
            body: Bytes(text.as_bytes().to_vec()),
            content_type: proto::TEXT_PLAIN.into(),
        }
    }

    #[test]
    fn file_is_ciphertext_and_needs_the_key() {
        let d = dir("cipher");
        let path = d.join("store.db");
        let s = Store::create(&path, &KEY).expect("create");
        s.remember("r", 1, &stored("needle-in-the-store"))
            .expect("remember");
        s.flush(&state()).expect("flush");
        s.commit().expect("commit");
        drop(s);

        let raw = std::fs::read(&path).expect("read");
        assert!(!raw.starts_with(b"SQLite format 3"), "plaintext header");
        assert!(!raw.windows(8).any(|w| w == b"needle-i"), "plaintext body");
        assert!(Store::open(&path, &[8; 32]).is_err(), "wrong key opened it");
        Store::open(&path, &KEY).expect("right key");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn commit_persists_and_drop_rolls_back() {
        let d = dir("tx");
        let path = d.join("store.db");
        let s = Store::create(&path, &KEY).expect("create");
        let mut st = state();
        st.rooms.insert("r".into(), RoomState::default());
        s.flush(&st).expect("flush");
        s.mark_own("r", 4).expect("own");
        s.commit().expect("commit");
        s.remember("r", 5, &stored("lost")).expect("remember");
        drop(s);

        let st = Store::open(&path, &KEY)
            .expect("open")
            .load()
            .expect("load");
        assert_eq!(st.user, "alice");
        assert_eq!(st.checkpoint, Some(Bytes(vec![9])));
        let r = &st.rooms["r"];
        assert!(r.own.contains(&4));
        assert!(r.inbox.is_empty(), "uncommitted message survived");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn forget_drops_the_room_and_only_the_room() {
        let d = dir("forget");
        let path = d.join("store.db");
        let s = Store::create(&path, &KEY).expect("create");
        let mut st = state();
        for r in ["gone", "kept"] {
            st.rooms.insert(r.into(), RoomState::default());
            s.mark_own(r, 1).expect("own");
            s.remember(r, 2, &stored("hi")).expect("remember");
        }
        s.flush(&st).expect("flush");
        s.forget("gone").expect("forget");
        s.commit().expect("commit");
        drop(s);

        let st = Store::open(&path, &KEY)
            .expect("open")
            .load()
            .expect("load");
        assert_eq!(st.rooms.keys().collect::<Vec<_>>(), ["kept"]);
        assert_eq!(st.rooms["kept"].inbox.len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
