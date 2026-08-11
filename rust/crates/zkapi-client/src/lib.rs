//! Client SDK for zkAPI: wallet state, note lifecycle, proof generation,
//! persistence, and recovery.

pub mod config;
pub mod error;
pub mod journal;
pub mod note_state;
#[path = "wallet_v2.rs"]
pub mod wallet;
