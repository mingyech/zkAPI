//! XMSS signature types.

use serde::{Deserialize, Serialize};

use crate::{Felt252, WOTS_LEN, XMSS_TREE_HEIGHT};

/// Compact proof-friendly Schnorr signature used by zkAPI v2.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrSignature {
    pub r_x: Felt252,
    pub r_y: Felt252,
    pub s: Felt252,
}

impl SchnorrSignature {
    pub const IDENTITY: Self = Self {
        r_x: Felt252::ZERO,
        r_y: Felt252::ONE,
        s: Felt252::ZERO,
    };
}

/// An XMSS signature consisting of a WOTS+ one-time signature
/// and a Merkle authentication path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XmssSignature {
    pub epoch: u32,
    pub leaf_index: u32,
    pub wots_sig: Vec<Felt252>,
    pub auth_path: Vec<Felt252>,
}

impl XmssSignature {
    /// Validate structural correctness.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_for_height(XMSS_TREE_HEIGHT)
    }

    /// Validate structural correctness for an explicit tree height.
    ///
    /// Production callers must use `validate()`, which enforces the protocol
    /// height. Tests may use this helper with small trees.
    pub fn validate_for_height(&self, expected_height: usize) -> Result<(), String> {
        if self.wots_sig.len() != WOTS_LEN {
            return Err(format!(
                "WOTS+ signature length mismatch: expected {}, got {}",
                WOTS_LEN,
                self.wots_sig.len()
            ));
        }
        let height = self.auth_path.len();
        if height != expected_height {
            return Err(format!(
                "XMSS auth path length mismatch: expected {}, got {}",
                expected_height, height
            ));
        }
        if expected_height >= u32::BITS as usize {
            return Err("XMSS tree height too large for u32 leaf index".to_string());
        }
        if self.leaf_index >= (1u32 << expected_height) {
            return Err(format!(
                "XMSS leaf index {} exceeds tree capacity {}",
                self.leaf_index,
                1u32 << expected_height
            ));
        }
        Ok(())
    }
}
