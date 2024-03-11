//! rpcap-packet
//!
//! This crate provides network packet representative types

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod layer;
pub mod mac_addr;
pub mod utils;

/// Error type for this crate
///
/// This error type is used for all errors in this crate
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// MAC address error
    #[error(transparent)]
    MacAddr(#[from] mac_addr::MacAddrError),
}
