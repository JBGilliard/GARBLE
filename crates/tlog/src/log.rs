//! The append-only log: an RFC 6962 tree over opaque entries, kept in tlog-tiles layout.
//!
//! Only tree levels that are multiples of 8 are stored (as tiles); the levels between
//! are recomputed from the tile row below, at most 128 hashes. Reads at any earlier
//! size work because a partial tile of every width is kept until its tile is full.
//!
//! ponytail: one writer, no locking; the DS serializes appends already. A crash between
//! the tile writes and the entry bundle leaves the log at its old size (the bundle is
//! the commit point) and the next append overwrites the strays.

use crate::error::{Error, Result};
use crate::hash::{Hash, empty_root, leaf_hash, node_hash, split};
use crate::note::Checkpoint;
use crate::tile::{TILE_WIDTH, TileStore, entries_key, hash_tile_key};

/// Tile levels: tree levels 0, 8, ..., 56 (a u64 size has no more).
const TILE_LEVELS: usize = 8;

pub struct Log<S: TileStore> {
    store: S,
    size: u64,
    /// Roots of the perfect subtrees that make up the tree, largest first.
    frontier: Vec<(u32, Hash)>,
    /// The unfinished tile at each tile level.
    rows: [Vec<Hash>; TILE_LEVELS],
    /// The unfinished entry bundle.
    bundle: Vec<u8>,
    broken: bool,
}

impl<S: TileStore> Log<S> {
    /// Open the log in `store`, which may be empty. The size is whatever the entry
    /// bundles hold; hash tiles that don't agree with them are an error, never repaired.
    pub fn open(store: S) -> Result<Self> {
        let mut log = Self {
            store,
            size: 0,
            frontier: Vec::new(),
            rows: Default::default(),
            bundle: Vec::new(),
            broken: false,
        };
        let mut n = 0;
        while log.store.read(&entries_key(n, TILE_WIDTH))?.is_some() {
            n += 1;
        }
        log.size = n * TILE_WIDTH;
        for w in (1..TILE_WIDTH).rev() {
            if let Some(b) = log.store.read(&entries_key(n, w))? {
                if parse_bundle(&b)?.len() as u64 != w {
                    return Err(Error::Corrupt(entries_key(n, w)));
                }
                log.size += w;
                log.bundle = b;
                break;
            }
        }
        let mut start = 0;
        for k in (0..64u32).rev() {
            if log.size >> k & 1 == 1 {
                let h = log.node(k, start >> k)?;
                log.frontier.push((k, h));
                start += 1 << k;
            }
        }
        for l in 0..TILE_LEVELS {
            let count = log.size >> (8 * l);
            let w = count % TILE_WIDTH;
            if w > 0 {
                log.rows[l] = log.tile_hashes(l as u32, count / TILE_WIDTH, w)?;
            }
        }
        Ok(log)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn root(&self) -> Hash {
        let mut it = self.frontier.iter().rev();
        let Some((_, last)) = it.next() else {
            return empty_root();
        };
        it.fold(*last, |acc, (_, h)| node_hash(h, &acc))
    }

    pub fn checkpoint(&self, origin: &str) -> Checkpoint {
        Checkpoint {
            origin: origin.into(),
            size: self.size,
            root: self.root(),
            closed: false,
        }
    }

    /// The root rebuilt from the entries themselves, for a log being audited rather than
    /// served: `open` trusts the hash tiles to agree with the entry bundles.
    pub fn recompute_root(&self) -> Result<Hash> {
        let mut stack: Vec<(u32, Hash)> = Vec::new();
        for start in (0..self.size).step_by(TILE_WIDTH as usize) {
            for entry in self.entries(start, (start + TILE_WIDTH).min(self.size))? {
                let mut node = (0u32, leaf_hash(&entry));
                while let Some(&(level, left)) = stack.last() {
                    if level != node.0 {
                        break;
                    }
                    stack.pop();
                    node = (level + 1, node_hash(&left, &node.1));
                }
                stack.push(node);
            }
        }
        let mut it = stack.iter().rev();
        let Some((_, last)) = it.next() else {
            return Ok(empty_root());
        };
        Ok(it.fold(*last, |acc, (_, h)| node_hash(h, &acc)))
    }

    /// Append `entry`; returns its index and leaf hash.
    pub fn append(&mut self, entry: &[u8]) -> Result<(u64, Hash)> {
        if self.broken {
            return Err(Error::Broken);
        }
        // Before anything is written: a refused entry leaves the log as it was.
        let len = u16::try_from(entry.len()).map_err(|_| Error::EntryTooLarge(entry.len()))?;
        self.try_append(entry, len)
            .inspect_err(|_| self.broken = true)
    }

    fn try_append(&mut self, entry: &[u8], len: u16) -> Result<(u64, Hash)> {
        let index = self.size;
        let new_size = index + 1;
        let leaf = leaf_hash(entry);

        self.record(0, leaf, new_size)?;
        let mut node = (0u32, leaf);
        while let Some(&(level, left)) = self.frontier.last() {
            if level != node.0 {
                break;
            }
            self.frontier.pop();
            node = (level + 1, node_hash(&left, &node.1));
            if node.0.is_multiple_of(8) {
                self.record(node.0, node.1, new_size)?;
            }
        }
        self.frontier.push(node);

        // Last, because it's what `open` counts.
        self.bundle.extend_from_slice(&len.to_be_bytes());
        self.bundle.extend_from_slice(entry);
        let n = index / TILE_WIDTH;
        let w = new_size - n * TILE_WIDTH;
        self.store.write(&entries_key(n, w), &self.bundle)?;
        if w == TILE_WIDTH {
            self.bundle.clear();
            for p in 1..TILE_WIDTH {
                self.store.remove(&entries_key(n, p))?;
            }
        }
        self.size = new_size;
        Ok((index, leaf))
    }

    /// A subtree at tree level `level` (a multiple of 8) just completed on the way to
    /// `new_size`: add it to its tile.
    fn record(&mut self, level: u32, h: Hash, new_size: u64) -> Result<()> {
        let l = (level / 8) as usize;
        let i = (new_size >> level) - 1;
        let (n, w) = (i / TILE_WIDTH, i % TILE_WIDTH + 1);
        self.rows[l].push(h);
        self.store
            .write(&hash_tile_key(l as u32, n, w), &self.rows[l].concat())?;
        if w == TILE_WIDTH {
            self.rows[l].clear();
            for p in 1..TILE_WIDTH {
                self.store.remove(&hash_tile_key(l as u32, n, p))?;
            }
        }
        Ok(())
    }

    /// The first `width` hashes of tile `n` at tile level `level`.
    fn tile_hashes(&self, level: u32, n: u64, width: u64) -> Result<Vec<Hash>> {
        let exact = hash_tile_key(level, n, width);
        let data = match self.store.read(&exact)? {
            Some(d) => d,
            // Complete since: the prefix is what an older reader asked for.
            None => self
                .store
                .read(&hash_tile_key(level, n, TILE_WIDTH))?
                .ok_or_else(|| Error::Corrupt(format!("missing {exact}")))?,
        };
        if data.len() % 32 != 0 || (data.len() as u64) < width * 32 {
            return Err(Error::Corrupt(exact));
        }
        Ok(data
            .chunks_exact(32)
            .take(width as usize)
            .map(|c| c.try_into().unwrap_or([0; 32]))
            .collect())
    }

    /// Hash of the perfect subtree at `level`, index `i` (leaves `i·2^level ..`).
    fn node(&self, level: u32, i: u64) -> Result<Hash> {
        let j = level % 8;
        let tile_level = level / 8;
        let first = i << j; // index at the tile's own level
        let (n, offset) = (first / TILE_WIDTH, first % TILE_WIDTH);
        let row = self.tile_hashes(tile_level, n, offset + (1 << j))?;
        let mut span = row[offset as usize..].to_vec();
        while span.len() > 1 {
            span = span.chunks(2).map(|p| node_hash(&p[0], &p[1])).collect();
        }
        Ok(span[0])
    }

    /// RFC 6962 `MTH` over leaves `start..end` (non-empty, within the log).
    fn subtree(&self, start: u64, end: u64) -> Result<Hash> {
        let n = end - start;
        if n.is_power_of_two() && start.is_multiple_of(n) {
            return self.node(n.trailing_zeros(), start / n);
        }
        let k = split(n);
        Ok(node_hash(
            &self.subtree(start, start + k)?,
            &self.subtree(start + k, end)?,
        ))
    }

    pub fn root_at(&self, size: u64) -> Result<Hash> {
        self.check_size(size)?;
        if size == 0 {
            return Ok(empty_root());
        }
        self.subtree(0, size)
    }

    fn check_size(&self, size: u64) -> Result<()> {
        if size > self.size {
            return Err(Error::OutOfRange(format!(
                "size {size}, log has {}",
                self.size
            )));
        }
        Ok(())
    }

    /// RFC 6962 `PATH(index, D[size])`.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Hash>> {
        self.check_size(size)?;
        if index >= size {
            return Err(Error::OutOfRange(format!("index {index}, size {size}")));
        }
        let mut proof = Vec::new();
        let (mut lo, mut hi) = (0, size);
        // Collected top-down, but RFC 6962 lists the path bottom-up.
        while hi - lo > 1 {
            let k = split(hi - lo);
            if index < lo + k {
                proof.push(self.subtree(lo + k, hi)?);
                hi = lo + k;
            } else {
                proof.push(self.subtree(lo, lo + k)?);
                lo += k;
            }
        }
        proof.reverse();
        Ok(proof)
    }

    /// RFC 6962 `PROOF(old, D[new])`. Empty when `old` is 0 or equals `new`.
    pub fn consistency_proof(&self, old: u64, new: u64) -> Result<Vec<Hash>> {
        self.check_size(new)?;
        if old > new {
            return Err(Error::OutOfRange(format!("old {old} > new {new}")));
        }
        let mut proof = Vec::new();
        if old > 0 && old < new {
            // SUBPROOF(m, D[lo..lo+n], b), unrolled; `b` stays true while the old tree
            // is a prefix on the left edge.
            let (mut m, mut lo, mut n, mut b) = (old, 0, new, true);
            while m != n {
                let k = split(n);
                if m <= k {
                    proof.push(self.subtree(lo + k, lo + n)?);
                    n = k;
                } else {
                    proof.push(self.subtree(lo, lo + k)?);
                    m -= k;
                    lo += k;
                    n -= k;
                    b = false;
                }
            }
            if !b {
                proof.push(self.subtree(lo, lo + n)?);
            }
            proof.reverse();
        }
        Ok(proof)
    }

    /// Entries `start..end`, as appended.
    pub fn entries(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>> {
        self.check_size(end)?;
        let mut out = Vec::new();
        if start >= end {
            return Ok(out);
        }
        for n in start / TILE_WIDTH..=(end - 1) / TILE_WIDTH {
            let width = (self.size - n * TILE_WIDTH).min(TILE_WIDTH);
            let key = entries_key(n, width);
            let data = self
                .store
                .read(&key)?
                .ok_or_else(|| Error::Corrupt(format!("missing {key}")))?;
            let all = parse_bundle(&data)?;
            if all.len() as u64 != width {
                return Err(Error::Corrupt(key));
            }
            let base = n * TILE_WIDTH;
            out.extend(
                all.into_iter()
                    .zip(base..)
                    .filter(|(_, i)| (start..end).contains(i))
                    .map(|(e, _)| e.to_vec()),
            );
        }
        Ok(out)
    }

    /// A hash tile as a client would fetch it, if the log has that many hashes there.
    pub fn hash_tile(&self, level: u32, n: u64, width: u64) -> Result<Option<Vec<u8>>> {
        if level as usize >= TILE_LEVELS
            || !(1..=TILE_WIDTH).contains(&width)
            || (self.size >> (8 * level)) < n.saturating_mul(TILE_WIDTH).saturating_add(width)
        {
            return Ok(None);
        }
        Ok(Some(self.tile_hashes(level, n, width)?.concat()))
    }
}

fn parse_bundle(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (len, tail) = rest
            .split_first_chunk::<2>()
            .ok_or_else(|| Error::Corrupt("entry bundle: short length".into()))?;
        let len = u16::from_be_bytes(*len) as usize;
        if tail.len() < len {
            return Err(Error::Corrupt("entry bundle: short entry".into()));
        }
        let (entry, tail) = tail.split_at(len);
        out.push(entry);
        rest = tail;
    }
    Ok(out)
}
