//! Various layers
//!
//! This module provides types for the various layers of the packet.

pub mod eth;
pub mod ip;
pub mod tcp;
pub mod udp;

/// Prelude
///
/// The prelude re-exports the most commonly used types
pub mod prelude {
    pub use super::eth::{Eth, EthError};
    pub use super::ip::v4::{Ipv4, Ipv4Error};
    pub use super::tcp::{Tcp, TcpError};
    pub use super::udp::{Udp, UdpError};
}
