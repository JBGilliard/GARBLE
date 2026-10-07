//! RFC 6962 §2.1 hashing: SHA-256 with a 0x00 / 0x01 domain-separation byte.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn leaf_hash(data: &[u8]) -> Hash {
    Sha256::new_with_prefix([0u8])
        .chain_update(data)
        .finalize()
        .into()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new_with_prefix([1u8])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The root of a tree with no leaves.
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// Largest power of two strictly below `n` (`n >= 2`): where RFC 6962 splits a tree.
pub(crate) fn split(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1 << (63 - (n - 1).leading_zeros())
}
