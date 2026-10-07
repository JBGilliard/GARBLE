//! C2SP tlog-tiles layout: storage keys, and the stores that hold them.
//!
//! Hash tiles are `tile/<L>/<N>[.p/<W>]` (256 hashes of tree level 8·L); entry bundles are
//! `tile/entries/<N>[.p/<W>]`. `<N>` is split into three-digit groups, every group but
//! the last prefixed with `x`: tile 1234067 is `x001/x234/067`.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Hashes per tile (height 8).
pub const TILE_WIDTH: u64 = 256;

/// Where tiles and the checkpoint live. Keys are the tlog-tiles paths, `/`-separated.
pub trait TileStore {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn write(&mut self, key: &str, data: &[u8]) -> Result<()>;
    /// Removing what isn't there is not an error.
    fn remove(&mut self, key: &str) -> Result<()>;
}

fn index_path(n: u64) -> String {
    let mut groups = Vec::new();
    let mut n = n;
    loop {
        groups.push(n % 1000);
        n /= 1000;
        if n == 0 {
            break;
        }
    }
    let last = groups.len() - 1;
    groups
        .iter()
        .rev()
        .enumerate()
        .map(|(i, g)| {
            if i < last {
                format!("x{g:03}")
            } else {
                format!("{g:03}")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn suffix(width: u64) -> String {
    if width < TILE_WIDTH {
        format!(".p/{width}")
    } else {
        String::new()
    }
}

/// Key of hash tile `n` at tile level `level`, holding `width` hashes (1..=256).
pub fn hash_tile_key(level: u32, n: u64, width: u64) -> String {
    format!("tile/{level}/{}{}", index_path(n), suffix(width))
}

/// Key of entry bundle `n`, holding `width` entries (1..=256).
pub fn entries_key(n: u64, width: u64) -> String {
    format!("tile/entries/{}{}", index_path(n), suffix(width))
}

/// Parse a hash-tile key into `(level, n, width)`. Entry bundles don't parse: they hold
/// entries, which the DS only releases through a policy check. Anything that isn't the
/// canonical spelling of a key is refused, so a request can't name a file the log
/// didn't write.
pub fn parse_hash_tile_key(key: &str) -> Option<(u32, u64, u64)> {
    let rest = key.strip_prefix("tile/")?;
    let (rest, width) = match rest.split_once(".p/") {
        Some((r, w)) => (
            r,
            w.parse::<u64>()
                .ok()
                .filter(|w| (1..TILE_WIDTH).contains(w))?,
        ),
        None => (rest, TILE_WIDTH),
    };
    let (level, idx) = rest.split_once('/')?;
    let level: u32 = level.parse().ok().filter(|l| *l < 8)?;
    let groups: Vec<&str> = idx.split('/').collect();
    let mut n = 0u64;
    for (i, g) in groups.iter().enumerate() {
        let digits = if i + 1 < groups.len() {
            g.strip_prefix('x')?
        } else {
            g
        };
        if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        n = n.checked_mul(1000)?.checked_add(digits.parse().ok()?)?;
    }
    (hash_tile_key(level, n, width) == key).then_some((level, n, width))
}

/// In memory; tests and anything that doesn't need to outlive the process.
#[derive(Default, Debug, Clone)]
pub struct MemStore(pub BTreeMap<String, Vec<u8>>);

impl TileStore for MemStore {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key).cloned())
    }
    fn write(&mut self, key: &str, data: &[u8]) -> Result<()> {
        self.0.insert(key.to_owned(), data.to_vec());
        Ok(())
    }
    fn remove(&mut self, key: &str) -> Result<()> {
        self.0.remove(key);
        Ok(())
    }
}

/// One file per key under a root directory. Writes go to a temp file and rename, so a
/// reader never sees half a tile.
#[derive(Debug, Clone)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        // Keys are generated, never taken from a request unparsed; this is the backstop.
        if key.is_empty()
            || key
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err(Error::Store(format!("bad key {key:?}")));
        }
        Ok(self.root.join(key))
    }
}

fn io(e: std::io::Error) -> Error {
    Error::Store(e.to_string())
}

impl TileStore for FileStore {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(key)?) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(e)),
        }
    }

    fn write(&mut self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.path(key)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data).map_err(io)?;
        std::fs::rename(&tmp, &path).map_err(io)
    }

    fn remove(&mut self, key: &str) -> Result<()> {
        match std::fs::remove_file(self.path(key)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_follow_the_tlog_tiles_layout() {
        assert_eq!(hash_tile_key(0, 0, 256), "tile/0/000");
        assert_eq!(hash_tile_key(1, 7, 5), "tile/1/007.p/5");
        assert_eq!(hash_tile_key(0, 1_234_067, 256), "tile/0/x001/x234/067");
        assert_eq!(hash_tile_key(2, 999, 256), "tile/2/999");
        assert_eq!(hash_tile_key(2, 1000, 1), "tile/2/x001/000.p/1");
        assert_eq!(entries_key(12, 256), "tile/entries/012");
        assert_eq!(entries_key(0, 255), "tile/entries/000.p/255");
    }

    #[test]
    fn only_canonical_hash_tile_keys_parse() {
        for (l, n, w) in [
            (0, 0, 256),
            (7, 1_234_067, 1),
            (3, 999, 255),
            (0, 1000, 256),
        ] {
            assert_eq!(
                parse_hash_tile_key(&hash_tile_key(l, n, w)),
                Some((l, n, w))
            );
        }
        for bad in [
            "tile/entries/000",
            "tile/entries/000.p/3",
            "tile/0/0",
            "tile/0/0000",
            "tile/0/001/234",
            "tile/0/x001",
            "tile/0/000.p/0",
            "tile/0/000.p/256",
            "tile/0/000.p/03",
            "tile/8/000",
            "tile/00/000",
            "tile/0/../000",
            "tile/0/000/",
            "/tile/0/000",
            "tile/0/-01",
            "checkpoint",
            "",
        ] {
            assert_eq!(parse_hash_tile_key(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn file_store_round_trips_and_refuses_escapes() {
        let dir = std::env::temp_dir().join(format!("tlog-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = FileStore::new(&dir);
        assert_eq!(s.read("tile/0/000").unwrap(), None);
        s.write("tile/0/x001/234", b"abc").unwrap();
        assert_eq!(s.read("tile/0/x001/234").unwrap().unwrap(), b"abc");
        s.remove("tile/0/x001/234").unwrap();
        s.remove("tile/0/x001/234").unwrap();
        assert_eq!(s.read("tile/0/x001/234").unwrap(), None);
        for bad in ["../x", "tile/../../x", "/etc/passwd", "a//b", ""] {
            assert!(s.read(bad).is_err(), "{bad:?}");
            assert!(s.write(bad, b"").is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
