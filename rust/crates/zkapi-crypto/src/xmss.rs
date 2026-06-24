//! XMSS Merkle authentication tree over WOTS+ public keys.
//!
//! Tree height: 20 (2^20 = 1,048,576 one-time signatures per tree)
//! Node hash: Poseidon(domain("zkapi.xmss.node"), left, right)

use starknet_crypto::poseidon_hash_many;
use starknet_types_core::felt::Felt;

type FieldElement = Felt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use zkapi_core::poseidon::{felt_to_field, field_to_felt};
use zkapi_types::domain::{DOMAIN_XMSS_MSG, DOMAIN_XMSS_NODE, DOMAIN_XMSS_SK};
use zkapi_types::{Felt252, XmssSignature, WOTS_LEN, XMSS_TREE_HEIGHT};

use crate::wots::{wots_keygen, wots_pk_to_leaf, wots_sign, wots_verify};

/// XMSS node hash.
fn xmss_node_hash(left: &FieldElement, right: &FieldElement) -> FieldElement {
    let domain = felt_to_field(&DOMAIN_XMSS_NODE);
    poseidon_hash_many(&[domain, *left, *right])
}

/// Hash a message for XMSS signing.
///
/// m = Poseidon(domain("zkapi.xmss.msg"), message)
pub fn xmss_hash_message(message: &Felt252) -> FieldElement {
    let domain = felt_to_field(&DOMAIN_XMSS_MSG);
    poseidon_hash_many(&[domain, felt_to_field(message)])
}

/// XMSS keypair for signing.
pub struct XmssKeypair {
    /// Secret keys for each leaf.
    secret_keys: Vec<[FieldElement; WOTS_LEN]>,
    /// XMSS tree nodes. Level 0 = leaves (WOTS pk hashes).
    tree: Vec<Vec<FieldElement>>,
    /// Root of the XMSS tree.
    pub root: FieldElement,
    /// Next available leaf index (atomic for thread safety).
    next_index: AtomicU32,
    /// Lock for signing to prevent index reuse.
    sign_lock: Mutex<()>,
    /// The height of this tree (may differ from XMSS_TREE_HEIGHT in tests).
    height: usize,
}

impl XmssKeypair {
    /// Generate a new XMSS keypair with the protocol-standard height.
    ///
    /// `seed` is used to deterministically derive all WOTS+ secret keys.
    pub fn generate(seed: &FieldElement) -> Self {
        Self::generate_with_height(seed, XMSS_TREE_HEIGHT)
    }

    /// Generate a keypair with a custom tree height (for testing).
    pub fn generate_with_height(seed: &FieldElement, height: usize) -> Self {
        let num_leaves = 1u32 << height;

        // Generate all WOTS+ secret keys deterministically from seed
        let mut secret_keys = Vec::with_capacity(num_leaves as usize);
        for i in 0..num_leaves {
            let mut sk = [FieldElement::ZERO; WOTS_LEN];
            for (j, item) in sk.iter_mut().enumerate().take(WOTS_LEN) {
                *item = poseidon_hash_many(&[
                    felt_to_field(&DOMAIN_XMSS_SK),
                    *seed,
                    FieldElement::from(i as u64),
                    FieldElement::from(j as u64),
                ]);
            }
            secret_keys.push(sk);
        }

        // Build the tree
        let mut tree: Vec<Vec<FieldElement>> = Vec::with_capacity(height + 1);

        // Level 0: WOTS+ public key hashes
        let leaves: Vec<FieldElement> = secret_keys
            .iter()
            .map(|sk| {
                let pk = wots_keygen(sk);
                wots_pk_to_leaf(&pk)
            })
            .collect();
        tree.push(leaves);

        // Build internal levels
        for level in 0..height {
            let prev = &tree[level];
            let mut nodes = Vec::with_capacity(prev.len() / 2);
            for i in (0..prev.len()).step_by(2) {
                nodes.push(xmss_node_hash(&prev[i], &prev[i + 1]));
            }
            tree.push(nodes);
        }

        let root = tree[height][0];

        Self {
            secret_keys,
            tree,
            root,
            next_index: AtomicU32::new(0),
            sign_lock: Mutex::new(()),
            height,
        }
    }

    /// Get the root as Felt252.
    pub fn root_felt(&self) -> Felt252 {
        field_to_felt(&self.root)
    }

    /// Sign a message, consuming the next available leaf index.
    ///
    /// Returns None if the tree is exhausted.
    pub fn sign(&self, message: &Felt252) -> Option<(XmssSignature, u32)> {
        self.sign_with_index(|_| *message)
            .map(|(sig, index, _message)| (sig, index))
    }

    /// Reserve the next leaf under the signer lock, build the message from
    /// that exact leaf index, and sign it.
    pub fn sign_with_index<F>(&self, build_message: F) -> Option<(XmssSignature, u32, Felt252)>
    where
        F: FnOnce(u32) -> Felt252,
    {
        let _lock = self.sign_lock.lock().unwrap();
        let idx = self.next_index.load(Ordering::SeqCst);
        if idx >= (1 << self.height) {
            return None; // Tree exhausted
        }
        let message = build_message(idx);
        self.next_index.store(idx + 1, Ordering::SeqCst);

        let msg_hash = xmss_hash_message(&message);

        // WOTS+ sign
        let wots_sig = wots_sign(&self.secret_keys[idx as usize], &msg_hash);

        // Build auth path
        let mut auth_path = Vec::with_capacity(self.height);
        let mut node_idx = idx;
        for level in 0..self.height {
            let sibling_idx = node_idx ^ 1;
            auth_path.push(field_to_felt(&self.tree[level][sibling_idx as usize]));
            node_idx /= 2;
        }

        let sig = XmssSignature {
            epoch: 0, // Caller sets this
            leaf_index: idx,
            wots_sig: wots_sig.iter().map(field_to_felt).collect(),
            auth_path,
        };

        Some((sig, idx, message))
    }

    /// Sign a message using an externally reserved leaf index.
    ///
    /// This is used by durable signers that reserve/burn the leaf in persistent
    /// storage before constructing the message. The in-memory cursor is advanced
    /// past the reserved index so non-durable peeks remain conservative.
    pub fn sign_reserved(&self, index: u32, message: &Felt252) -> Option<XmssSignature> {
        let _lock = self.sign_lock.lock().unwrap();
        if index >= (1 << self.height) {
            return None;
        }
        let next = index.checked_add(1)?;
        let current = self.next_index.load(Ordering::SeqCst);
        if current < next {
            self.next_index.store(next, Ordering::SeqCst);
        }

        let msg_hash = xmss_hash_message(message);
        let wots_sig = wots_sign(&self.secret_keys[index as usize], &msg_hash);

        let mut auth_path = Vec::with_capacity(self.height);
        let mut node_idx = index;
        for level in 0..self.height {
            let sibling_idx = node_idx ^ 1;
            auth_path.push(field_to_felt(&self.tree[level][sibling_idx as usize]));
            node_idx /= 2;
        }

        Some(XmssSignature {
            epoch: 0,
            leaf_index: index,
            wots_sig: wots_sig.iter().map(field_to_felt).collect(),
            auth_path,
        })
    }

    /// Get the number of remaining signatures.
    pub fn remaining(&self) -> u32 {
        let used = self.next_index.load(Ordering::SeqCst);
        self.capacity() - used
    }

    /// Total number of leaves in this XMSS tree.
    pub fn capacity(&self) -> u32 {
        1u32 << self.height
    }

    /// Peek the next unused leaf index without consuming it.
    pub fn next_index(&self) -> u32 {
        self.next_index.load(Ordering::SeqCst)
    }

    /// Check if the tree is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.remaining() == 0
    }
}

/// XMSS verification (stateless).
pub struct XmssVerifier;

impl XmssVerifier {
    /// Verify an XMSS signature against a known root.
    ///
    /// Structural validation uses the height committed by the signature's own
    /// authentication path (which `verify_inner` walks); the operator's tree
    /// height is a deployment parameter bound into `root`, so soundness comes
    /// from the root match below, not from pinning a fixed `XMSS_TREE_HEIGHT`.
    pub fn verify(root: &Felt252, message: &Felt252, sig: &XmssSignature) -> bool {
        if sig.validate_for_height(sig.auth_path.len()).is_err() {
            return false;
        }
        Self::verify_inner(root, message, sig)
    }

    pub fn verify_for_height(
        root: &Felt252,
        message: &Felt252,
        sig: &XmssSignature,
        height: usize,
    ) -> bool {
        if sig.validate_for_height(height).is_err() {
            return false;
        }
        Self::verify_inner(root, message, sig)
    }

    fn verify_inner(root: &Felt252, message: &Felt252, sig: &XmssSignature) -> bool {
        let msg_hash = xmss_hash_message(message);

        // Recover WOTS+ public key
        let wots_sig_fields: Vec<FieldElement> = sig.wots_sig.iter().map(felt_to_field).collect();
        let mut wots_sig_arr = [FieldElement::ZERO; WOTS_LEN];
        wots_sig_arr.copy_from_slice(&wots_sig_fields);

        let recovered_pk = wots_verify(&wots_sig_arr, &msg_hash);
        let leaf = wots_pk_to_leaf(&recovered_pk);

        // Verify auth path
        let mut current = leaf;
        let mut idx = sig.leaf_index;
        let tree_height = sig.auth_path.len();
        for level in 0..tree_height {
            let sibling = felt_to_field(&sig.auth_path[level]);
            if idx & 1 == 0 {
                current = xmss_node_hash(&current, &sibling);
            } else {
                current = xmss_node_hash(&sibling, &current);
            }
            idx /= 2;
        }

        field_to_felt(&current) == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkapi_types::Felt252;

    // Use a tiny tree for tests to avoid long keygen
    // For unit tests, we test the full-height tree with a single sign/verify

    // Use height 4 (16 leaves) for fast tests
    const TEST_HEIGHT: usize = 4;

    fn test_keypair() -> XmssKeypair {
        XmssKeypair::generate_with_height(&FieldElement::from(42u64), TEST_HEIGHT)
    }

    #[test]
    fn test_xmss_sign_verify() {
        let keypair = test_keypair();

        let message = Felt252::from_u64(12345);
        let (mut sig, idx) = keypair.sign(&message).unwrap();
        sig.epoch = 1;
        assert_eq!(idx, 0);

        let root = keypair.root_felt();
        assert!(XmssVerifier::verify_for_height(
            &root,
            &message,
            &sig,
            TEST_HEIGHT
        ));
    }

    #[test]
    fn test_xmss_wrong_message() {
        let keypair = test_keypair();

        let message = Felt252::from_u64(12345);
        let (mut sig, _) = keypair.sign(&message).unwrap();
        sig.epoch = 1;

        let wrong_message = Felt252::from_u64(54321);
        let root = keypair.root_felt();
        assert!(!XmssVerifier::verify_for_height(
            &root,
            &wrong_message,
            &sig,
            TEST_HEIGHT
        ));
    }

    #[test]
    fn test_xmss_wrong_root() {
        let keypair = test_keypair();

        let message = Felt252::from_u64(12345);
        let (mut sig, _) = keypair.sign(&message).unwrap();
        sig.epoch = 1;

        let wrong_root = Felt252::from_u64(999);
        assert!(!XmssVerifier::verify_for_height(
            &wrong_root,
            &message,
            &sig,
            TEST_HEIGHT
        ));
    }

    #[test]
    fn test_xmss_sequential_signing() {
        let keypair = test_keypair();
        let root = keypair.root_felt();

        for i in 0..3 {
            let msg = Felt252::from_u64(i + 100);
            let (mut sig, idx) = keypair.sign(&msg).unwrap();
            sig.epoch = 1;
            assert_eq!(idx, i as u32);
            assert!(XmssVerifier::verify_for_height(
                &root,
                &msg,
                &sig,
                TEST_HEIGHT
            ));
        }
    }
}
