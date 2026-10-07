//! Vectors, an independent oracle, and properties over real logs.

use proptest::prelude::*;

use crate::hash::split;
use crate::*;

fn h(s: &str) -> Hash {
    let b: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    b.try_into().unwrap()
}

/// RFC 6962 §2.1 `MTH`, straight from the definition, over entry bytes.
fn mth(entries: &[Vec<u8>]) -> Hash {
    match entries.len() {
        0 => empty_root(),
        1 => leaf_hash(&entries[0]),
        n => {
            let k = split(n as u64) as usize;
            node_hash(&mth(&entries[..k]), &mth(&entries[k..]))
        }
    }
}

fn entry(i: u64) -> Vec<u8> {
    format!("entry {i}").into_bytes()
}

fn build(n: u64) -> (Log<MemStore>, Vec<Vec<u8>>) {
    let mut log = Log::open(MemStore::default()).unwrap();
    let entries: Vec<_> = (0..n).map(entry).collect();
    for (i, e) in entries.iter().enumerate() {
        let (idx, leaf) = log.append(e).unwrap();
        assert_eq!((idx, leaf), (i as u64, leaf_hash(e)));
    }
    (log, entries)
}

// The eight leaves and roots from certificate-transparency's merkle tree tests, which
// every RFC 6962 implementation is held to.
const CT_LEAVES: [&str; 8] = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];
const CT_ROOTS: [&str; 8] = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

fn ct_leaf(i: usize) -> Vec<u8> {
    (0..CT_LEAVES[i].len())
        .step_by(2)
        .map(|j| u8::from_str_radix(&CT_LEAVES[i][j..j + 2], 16).unwrap())
        .collect()
}

#[test]
fn matches_the_certificate_transparency_vectors() {
    assert_eq!(
        empty_root(),
        h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    let mut log = Log::open(MemStore::default()).unwrap();
    assert_eq!(log.root(), empty_root());
    for (i, root) in CT_ROOTS.iter().enumerate() {
        log.append(&ct_leaf(i)).unwrap();
        assert_eq!(log.root(), h(root), "size {}", i + 1);
    }
    // Earlier sizes stay answerable after the log has grown.
    for (i, root) in CT_ROOTS.iter().enumerate() {
        assert_eq!(log.root_at(i as u64 + 1).unwrap(), h(root));
    }
}

// RFC 6962 §2.1.1 and §2.1.2 worked examples, seven leaves d0..d6.
#[test]
fn proofs_have_the_rfc_6962_shape() {
    let (log, _) = build(7);
    let a = |i: u64| leaf_hash(&entry(i));
    let (b, c, d, e, f, g) = (a(1), a(2), a(3), a(4), a(5), a(6));
    let h01 = node_hash(&a(0), &b);
    let i = node_hash(&c, &d);
    let j = node_hash(&e, &f);
    let l = node_hash(&j, &g);
    assert_eq!(log.inclusion_proof(0, 7).unwrap(), vec![b, i, l]);
    assert_eq!(log.consistency_proof(4, 7).unwrap(), vec![l]);
    assert_eq!(log.consistency_proof(3, 7).unwrap(), vec![c, d, h01, l]);
    assert!(log.consistency_proof(7, 7).unwrap().is_empty());
    assert!(log.consistency_proof(0, 7).unwrap().is_empty());
    assert!(log.inclusion_proof(0, 1).unwrap().is_empty());
}

#[test]
fn every_proof_in_small_trees_verifies() {
    let (log, entries) = build(40);
    for size in 1..=40u64 {
        let root = log.root_at(size).unwrap();
        assert_eq!(root, mth(&entries[..size as usize]));
        for index in 0..size {
            let proof = log.inclusion_proof(index, size).unwrap();
            let leaf = leaf_hash(&entries[index as usize]);
            verify_inclusion(&leaf, index, size, &proof, &root).unwrap();
        }
        for old in 0..=size {
            let proof = log.consistency_proof(old, size).unwrap();
            verify_consistency(old, size, &log.root_at(old).unwrap(), &root, &proof).unwrap();
        }
    }
}

#[test]
fn wrong_claims_fail_to_verify() {
    let (log, entries) = build(13);
    let root = log.root();
    let leaf = leaf_hash(&entries[5]);
    let proof = log.inclusion_proof(5, 13).unwrap();
    verify_inclusion(&leaf, 5, 13, &proof, &root).unwrap();
    // Wrong index, size, leaf, root; truncated and extended proofs.
    assert!(verify_inclusion(&leaf, 4, 13, &proof, &root).is_err());
    assert!(verify_inclusion(&leaf, 13, 13, &proof, &root).is_err());
    assert!(verify_inclusion(&leaf_hash(b"x"), 5, 13, &proof, &root).is_err());
    assert!(verify_inclusion(&leaf, 5, 13, &proof, &[0; 32]).is_err());
    assert!(verify_inclusion(&leaf, 5, 13, &proof[1..], &root).is_err());
    let mut longer = proof.clone();
    longer.push([0; 32]);
    assert!(verify_inclusion(&leaf, 5, 13, &longer, &root).is_err());
    assert!(verify_inclusion(&leaf, 0, 0, &[], &empty_root()).is_err());

    let (old_root, proof) = (
        log.root_at(6).unwrap(),
        log.consistency_proof(6, 13).unwrap(),
    );
    verify_consistency(6, 13, &old_root, &root, &proof).unwrap();
    assert!(verify_consistency(7, 13, &old_root, &root, &proof).is_err());
    assert!(verify_consistency(6, 13, &root, &old_root, &proof).is_err());
    assert!(verify_consistency(6, 13, &old_root, &root, &proof[1..]).is_err());
    assert!(verify_consistency(6, 13, &old_root, &root, &[]).is_err());
    assert!(verify_consistency(13, 6, &root, &old_root, &[]).is_err());
    assert!(verify_consistency(13, 13, &root, &old_root, &[]).is_err());
    assert!(verify_consistency(0, 13, &[1; 32], &root, &[]).is_err());
    // A forked history: same size as the old checkpoint, different content.
    let mut other = Log::open(MemStore::default()).unwrap();
    for i in 0..5 {
        other.append(&entry(i)).unwrap();
    }
    other.append(b"rewritten").unwrap();
    let fork_root = other.root();
    assert!(verify_consistency(6, 13, &fork_root, &root, &proof).is_err());
}

#[test]
fn out_of_range_requests_are_errors() {
    let (log, _) = build(5);
    assert!(log.inclusion_proof(5, 5).is_err());
    assert!(log.inclusion_proof(0, 6).is_err());
    assert!(log.consistency_proof(3, 6).is_err());
    assert!(log.consistency_proof(4, 3).is_err());
    assert!(log.root_at(6).is_err());
    assert!(log.entries(0, 6).is_err());
}

#[test]
fn tiles_land_in_the_tlog_tiles_layout() {
    let (log, entries) = build(600);
    let keys: Vec<&str> = log.store().0.keys().map(String::as_str).collect();
    for want in [
        "tile/0/000",
        "tile/0/001",
        "tile/0/002.p/88",
        "tile/1/000.p/2",
        "tile/entries/000",
        "tile/entries/001",
        "tile/entries/002.p/88",
    ] {
        assert!(keys.contains(&want), "{want} missing from {keys:?}");
    }
    // Partials are dropped once their tile is full, and not before.
    assert!(!keys.contains(&"tile/0/000.p/255"));
    assert!(!keys.contains(&"tile/entries/000.p/17"));
    assert!(keys.contains(&"tile/0/002.p/1"));

    let tile = log.hash_tile(0, 1, 256).unwrap().unwrap();
    assert_eq!(tile.len(), 256 * 32);
    assert_eq!(tile[..32], leaf_hash(&entries[256]));
    let top = log.hash_tile(1, 0, 2).unwrap().unwrap();
    assert_eq!(top[..32], mth(&entries[..256]));
    assert_eq!(top[32..], mth(&entries[256..512]));
    // Only what the log has, and only hash tiles.
    assert!(log.hash_tile(0, 2, 89).unwrap().is_none());
    assert!(log.hash_tile(1, 0, 3).unwrap().is_none());
    assert!(log.hash_tile(8, 0, 1).unwrap().is_none());
    assert!(log.hash_tile(0, 0, 0).unwrap().is_none());
}

#[test]
fn entries_come_back_as_appended() {
    let (log, entries) = build(700);
    assert_eq!(log.entries(0, 700).unwrap(), entries);
    assert_eq!(log.entries(255, 258).unwrap(), entries[255..258]);
    assert_eq!(log.entries(699, 700).unwrap(), entries[699..]);
    assert!(log.entries(10, 10).unwrap().is_empty());
}

#[test]
fn a_reopened_log_carries_on() {
    let (log, mut entries) = build(300);
    let before = log.root();
    let mut log = Log::open(log.store().clone()).unwrap();
    assert_eq!((log.size(), log.root()), (300, before));
    for i in 300..520 {
        entries.push(entry(i));
        log.append(&entry(i)).unwrap();
        if i % 97 == 0 {
            log = Log::open(log.store().clone()).unwrap();
        }
    }
    assert_eq!(log.root(), mth(&entries));
    assert_eq!(log.entries(0, 520).unwrap(), entries);
    for size in [1, 255, 256, 257, 300, 512, 520] {
        assert_eq!(
            log.root_at(size).unwrap(),
            mth(&entries[..size as usize]),
            "size {size}"
        );
    }
}

#[test]
fn missing_tiles_fail_closed() {
    let (log, _) = build(300);
    for gone in ["tile/0/001.p/44", "tile/1/000.p/1", "tile/0/001.p/32"] {
        let mut store = log.store().clone();
        store.0.remove(gone);
        assert!(Log::open(store).is_err(), "{gone}");
    }
    // A rolled-back entry store opens as a shorter log. That's not caught here: a client
    // holding the longer checkpoint fails its consistency check against the shorter one.
    let mut store = log.store().clone();
    store.0.remove("tile/entries/001.p/44");
    assert_eq!(Log::open(store).unwrap().size(), 299);
}

#[test]
fn oversized_entries_are_refused_without_breaking_the_log() {
    let mut log = Log::open(MemStore::default()).unwrap();
    assert!(matches!(
        log.append(&vec![0; 65536]),
        Err(Error::EntryTooLarge(_))
    ));
    log.append(&vec![0; 65535]).unwrap();
    log.append(b"after").unwrap();
    assert_eq!(log.size(), 2);
}

#[test]
fn a_failed_write_stops_the_log() {
    struct Flaky(MemStore, bool);
    impl TileStore for Flaky {
        fn read(&self, k: &str) -> Result<Option<Vec<u8>>> {
            self.0.read(k)
        }
        fn write(&mut self, k: &str, d: &[u8]) -> Result<()> {
            if self.1 {
                return Err(Error::Store("disk full".into()));
            }
            self.0.write(k, d)
        }
        fn remove(&mut self, k: &str) -> Result<()> {
            self.0.remove(k)
        }
    }
    let mut log = Log::open(Flaky(MemStore::default(), false)).unwrap();
    log.append(b"one").unwrap();
    log.store_mut().1 = true;
    assert!(log.append(b"two").is_err());
    log.store_mut().1 = false;
    assert!(matches!(log.append(b"three"), Err(Error::Broken)));
    // Reopening recovers the last committed state.
    let store = Flaky(log.store().0.clone(), false);
    let mut log = Log::open(store).unwrap();
    assert_eq!(log.size(), 1);
    log.append(b"two").unwrap();
    assert_eq!(log.root(), mth(&[b"one".to_vec(), b"two".to_vec()]));
}

#[test]
fn file_store_logs_survive_reopening() {
    let dir = std::env::temp_dir().join(format!("tlog-log-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let entries: Vec<_> = (0..260).map(entry).collect();
    {
        let mut log = Log::open(FileStore::new(&dir)).unwrap();
        for e in &entries[..259] {
            log.append(e).unwrap();
        }
    }
    let mut log = Log::open(FileStore::new(&dir)).unwrap();
    assert_eq!(log.size(), 259);
    log.append(&entries[259]).unwrap();
    assert_eq!(log.root(), mth(&entries));
    assert!(dir.join("tile/0/000").is_file());
    assert!(
        !dir.join("tile/0/000.p").exists()
            || std::fs::read_dir(dir.join("tile/0/000.p"))
                .unwrap()
                .next()
                .is_none()
    );
    assert!(dir.join("tile/entries/000").is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    // Across tile boundaries (256, 512) and a second tile level, every proof the log
    // makes verifies against the oracle's root, and any single-byte change to it fails.
    #[test]
    fn proofs_verify_and_tampering_fails(
        n in 1u64..=620,
        picks in proptest::collection::vec((any::<u64>(), any::<u64>(), any::<u64>()), 8),
    ) {
        let (log, entries) = build(n);
        let root = mth(&entries);
        prop_assert_eq!(log.root(), root);
        for (a, b, c) in picks {
            let size = 1 + a % n;
            let index = b % size;
            let sized_root = mth(&entries[..size as usize]);
            let leaf = leaf_hash(&entries[index as usize]);
            let proof = log.inclusion_proof(index, size).unwrap();
            prop_assert!(verify_inclusion(&leaf, index, size, &proof, &sized_root).is_ok());
            for k in 0..proof.len() {
                let mut bad = proof.clone();
                bad[k][(c % 32) as usize] ^= 1 << (c % 8);
                prop_assert!(verify_inclusion(&leaf, index, size, &bad, &sized_root).is_err());
            }

            let old = c % (size + 1);
            let proof = log.consistency_proof(old, size).unwrap();
            let old_root = mth(&entries[..old as usize]);
            prop_assert!(verify_consistency(old, size, &old_root, &sized_root, &proof).is_ok());
            for k in 0..proof.len() {
                let mut bad = proof.clone();
                bad[k][(a % 32) as usize] ^= 1 << (a % 8);
                prop_assert!(verify_consistency(old, size, &old_root, &sized_root, &bad).is_err());
            }
            // A different old root never verifies against this proof.
            if old > 0 && old < size {
                let mut bad_root = old_root;
                bad_root[0] ^= 1;
                prop_assert!(verify_consistency(old, size, &bad_root, &sized_root, &proof).is_err());
            }
        }
    }
}
