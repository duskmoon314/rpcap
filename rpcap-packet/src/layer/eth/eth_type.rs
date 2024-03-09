//! Ethernet type enum.

use num_enum::{FromPrimitive, IntoPrimitive};

/// Ethernet type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive)]
#[repr(u16)]
#[non_exhaustive]
pub enum EthType {
    /// Internet Protocol version 4
    Ipv4 = 0x0800,

    /// Address Resolution Protocol
    Arp = 0x0806,

    /// Internet Protocol version 6
    Ipv6 = 0x86DD,

    /// Unsupported Ethernet type
    #[num_enum(catch_all)]
    Unsupported(u16),
}
