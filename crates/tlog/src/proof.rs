//! Proof verification, RFC 9162 §2.1.3.2 and §2.1.4.2 (the same trees as RFC 6962).
//! Takes only hashes: a verifier needs no log, no store and no GARBLE types.

use crate::error::{Error, Result};
use crate::hash::{Hash, empty_root, node_hash};

/// `leaf` is the leaf hash of entry number `index` in the tree of `size` leaves whose
/// root is `root`.
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Hash],
    root: &Hash,
) -> Result<()> {
    if index >= size {
        return Err(Error::BadProof("index outside the tree"));
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return Err(Error::BadProof("proof is too long"));
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(Error::BadProof("proof is too short"));
    }
    if r != *root {
        return Err(Error::BadProof("root mismatch"));
    }
    Ok(())
}

/// The tree of `old` leaves (root `old_root`) is a prefix of the tree of `new` leaves
/// (root `new_root`).
pub fn verify_consistency(
    old: u64,
    new: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<()> {
    if old > new {
        return Err(Error::BadProof("old tree is larger than the new one"));
    }
    if old == new {
        if !proof.is_empty() {
            return Err(Error::BadProof("proof for equal sizes must be empty"));
        }
        return (old_root == new_root)
            .then_some(())
            .ok_or(Error::BadProof("same size, different roots"));
    }
    if old == 0 {
        if !proof.is_empty() {
            return Err(Error::BadProof("proof from the empty tree must be empty"));
        }
        return (*old_root == empty_root())
            .then_some(())
            .ok_or(Error::BadProof("not the empty root"));
    }
    // A power-of-two old tree is a complete subtree: its root is the proof's start.
    let mut path = Vec::with_capacity(proof.len() + 1);
    if old.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let Some((first, rest)) = path.split_first() else {
        return Err(Error::BadProof("empty proof"));
    };
    let (mut f, mut s) = (old - 1, new - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (*first, *first);
    for c in rest {
        if s == 0 {
            return Err(Error::BadProof("proof is too long"));
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    if s != 0 {
        return Err(Error::BadProof("proof is too short"));
    }
    if fr != *old_root {
        return Err(Error::BadProof("old root mismatch"));
    }
    if sr != *new_root {
        return Err(Error::BadProof("new root mismatch"));
    }
    Ok(())
}
