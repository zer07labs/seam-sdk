//! S-3 — the Merkle batch link (`seam-event.v1.md` §Merkle batch link), transcribed from the spec alone.
//!
//! Since S-3 the chain links **batches**: one commit chains ONE entry per chain over the digests of every
//! chained event it appends to that chain, and a commit that appends one event is a batch of one. Every
//! chained event at or above its chain's history boundary carries its place in its batch: `leaf_index`
//! (tag 31), `leaf_count` (tag 32) and `inclusion_path` (tag 33).
//!
//! ```text
//! leaf          = SHA256(0x00 ‖ "seam.audit.leaf.v1" ‖ digest)
//! node(l, r)    = SHA256(0x01 ‖ l ‖ r)
//! root          = RFC 9162 MTH over the batch's leaves (the largest power of two < n on the left)
//! entry_digest  = SHA256("seam.audit.batch.v1" ‖ root ‖ u64be(leaf_count))
//! checksum      = SHA256(prev_checksum ‖ entry_digest)
//! ```
//!
//! A verifier folds `digest` through `inclusion_path` (RFC 9162 §2.1.3.2) to the root. A path of the wrong
//! length, a hash that is not 32 bytes, `leaf_index >= leaf_count` or `leaf_count == 0` does not fold.

use sha2::{Digest, Sha256};

/// Domain tag of a leaf.
pub const LEAF_DOMAIN: &[u8] = b"seam.audit.leaf.v1";
/// Domain tag of a batch entry digest.
pub const BATCH_DOMAIN: &[u8] = b"seam.audit.batch.v1";

/// One tree hash.
pub type Hash = [u8; 32];

/// `SHA256(0x00 ‖ LEAF_DOMAIN ‖ digest)`.
pub fn leaf_hash(digest: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(LEAF_DOMAIN);
    h.update(digest);
    h.finalize().into()
}

/// `SHA256(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// `SHA256(BATCH_DOMAIN ‖ root ‖ u64be(leaf_count))`: the digest the chain links.
pub fn batch_digest(root: &Hash, leaf_count: u32) -> Hash {
    let mut h = Sha256::new();
    h.update(BATCH_DOMAIN);
    h.update(root);
    h.update(u64::from(leaf_count).to_be_bytes());
    h.finalize().into()
}

/// RFC 9162 §2.1.3.2: fold `path` from `leaf` at `leaf_index` of `leaf_count` to the root. `None` when the
/// index is out of range, a path hash is not 32 bytes, or the path is too short or too long for the size.
pub fn root_from_path<P: AsRef<[u8]>>(
    leaf: &Hash,
    leaf_index: u32,
    leaf_count: u32,
    path: &[P],
) -> Option<Hash> {
    if leaf_index >= leaf_count {
        return None;
    }
    let (mut fnode, mut snode) = (leaf_index, leaf_count - 1);
    let mut r = *leaf;
    for p in path {
        let p: &Hash = p.as_ref().try_into().ok()?;
        if snode == 0 {
            return None;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    (snode == 0).then_some(r)
}

/// The batch entry digest a member with `digest` and its proof folds to. `None` when the proof does not
/// fold ([`root_from_path`]).
pub fn entry_digest<P: AsRef<[u8]>>(
    digest: &[u8],
    leaf_index: u32,
    leaf_count: u32,
    inclusion_path: &[P],
) -> Option<Hash> {
    let root = root_from_path(&leaf_hash(digest), leaf_index, leaf_count, inclusion_path)?;
    Some(batch_digest(&root, leaf_count))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The largest power of two strictly below `n` (`n >= 2`).
    fn split(n: usize) -> usize {
        let mut k = 1;
        while k << 1 < n {
            k <<= 1;
        }
        k
    }

    /// RFC 9162 MTH — the writer's side, for the tests only.
    pub(crate) fn root(leaves: &[Hash]) -> Hash {
        match leaves.len() {
            1 => leaves[0],
            n => {
                let k = split(n);
                node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
            }
        }
    }

    /// RFC 9162 `PATH(m, D[n])`, leaf to root — the writer's side, for the tests only.
    pub(crate) fn path(leaves: &[Hash], m: usize) -> Vec<Hash> {
        let n = leaves.len();
        if n <= 1 {
            return Vec::new();
        }
        let k = split(n);
        let mut p = if m < k {
            path(&leaves[..k], m)
        } else {
            path(&leaves[k..], m - k)
        };
        p.push(if m < k {
            root(&leaves[k..])
        } else {
            root(&leaves[..k])
        });
        p
    }

    fn digests(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i as u8; 32]).collect()
    }

    fn sealed(ds: &[[u8; 32]]) -> (Hash, Vec<Vec<Hash>>) {
        let leaves: Vec<Hash> = ds.iter().map(|d| leaf_hash(d)).collect();
        let entry = batch_digest(&root(&leaves), ds.len() as u32);
        (entry, (0..ds.len()).map(|m| path(&leaves, m)).collect())
    }

    /// Every member of every batch size up to 33, and 255/256, proves its entry.
    #[test]
    fn every_member_of_every_batch_size_proves_its_entry() {
        for n in (1..=33).chain([255, 256]) {
            let ds = digests(n);
            let (entry, paths) = sealed(&ds);
            for (i, (d, p)) in ds.iter().zip(&paths).enumerate() {
                assert_eq!(
                    entry_digest(d, i as u32, n as u32, p),
                    Some(entry),
                    "n={n} i={i}"
                );
            }
        }
    }

    /// A tampered leaf, index, count, path hash or path length never proves the entry.
    #[test]
    fn a_tampered_member_never_proves_the_entry() {
        let ds = digests(5);
        let (entry, paths) = sealed(&ds);
        let p = &paths[2];
        let ok =
            |d: &[u8], i: u32, n: u32, path: &[Hash]| entry_digest(d, i, n, path) == Some(entry);
        assert!(ok(&ds[2], 2, 5, p));
        assert!(!ok(&[9u8; 32], 2, 5, p), "leaf");
        for i in [0, 1, 3, 4, 5, 9] {
            assert!(!ok(&ds[2], i, 5, p), "index {i}");
        }
        for n in [3, 4, 6, 8] {
            assert!(!ok(&ds[2], 2, n, p), "count {n}");
        }
        for k in 0..p.len() {
            let mut bad = p.clone();
            bad[k][0] ^= 1;
            assert!(!ok(&ds[2], 2, 5, &bad), "path[{k}]");
        }
        let mut short = p.clone();
        short.pop();
        assert!(!ok(&ds[2], 2, 5, &short), "short path");
        let mut long = p.clone();
        long.push([0; 32]);
        assert_eq!(entry_digest(&ds[2], 2, 5, &long), None, "long path");
        assert_eq!(
            entry_digest(&ds[2], 2, 5, &[vec![0u8; 31]]),
            None,
            "31-byte hash"
        );
        assert_eq!(entry_digest(&ds[0], 0, 0, &[] as &[Hash]), None, "count 0");
    }

    /// The runtime's frozen vectors (`seam_store::merkle`), rebuilt from sha2 alone: a batch of 3 over
    /// `[0x00;32]`, `[0x01;32]`, `[0x02;32]`, and a batch of one over `[0x00;32]`.
    #[test]
    fn frozen_vectors_match_the_runtime() {
        let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let (entry, paths) = sealed(&digests(3));
        assert_eq!(
            hx(&entry),
            "9ef7f536c0959bd166729af59ad73e63eca773af0f40df6c6ca6406456ce54de"
        );
        for (i, p) in paths.iter().enumerate() {
            assert_eq!(entry_digest(&[i as u8; 32], i as u32, 3, p), Some(entry));
        }
        assert_eq!(
            hx(&batch_digest(&leaf_hash(&[0u8; 32]), 1)),
            "f40003121d7aeaf4144e7d0dba3401c6e63597c878a8a49f018337140710ab5f"
        );
    }
}
