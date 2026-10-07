//! Transparency log library (architecture §3, §5.10).
//!
//! Knows nothing about GARBLE messages: hashes opaque leaves (RFC 6962), lays them out
//! as C2SP tlog-tiles, proves inclusion and consistency, and signs checkpoints as
//! signed notes through a [`Signer`].
//!
//! Not yet built: cosignature verification and witnesses (the note format already
//! tolerates their lines).

mod b64;
mod error;
mod hash;
mod log;
mod note;
mod proof;
mod tile;

pub use error::{Error, Result};
pub use hash::{Hash, empty_root, leaf_hash, node_hash};
pub use log::Log;
pub use note::{
    Checkpoint, SIG_TYPE_ML_DSA_87, Signer, Verifier, key_id, open_checkpoint, sign_checkpoint,
};
pub use proof::{verify_consistency, verify_inclusion};
pub use tile::{
    FileStore, MemStore, TILE_WIDTH, TileStore, entries_key, hash_tile_key, parse_hash_tile_key,
};

#[cfg(test)]
mod tests;
