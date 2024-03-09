//! rpcap-packet
//!
//! This crate provides network packet representative types

#![deny(missing_docs)]

pub mod layer;
pub mod mac_addr;
pub mod utils;

/// Error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// MAC address error
    #[error(transparent)]
    MacAddr(#[from] mac_addr::Error),
}
