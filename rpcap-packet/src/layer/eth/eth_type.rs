use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{Display, EnumString};

use crate::impl_target;

/// Ethernet type enum.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Display, EnumString,
)]
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

impl_target!(frominto, EthType, u16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_type_debug() {
        assert_eq!("Ipv4", format!("{:?}", EthType::Ipv4));
        assert_eq!("Arp", format!("{:?}", EthType::Arp));
        assert_eq!("Ipv6", format!("{:?}", EthType::Ipv6));
        assert_eq!(
            "Unsupported(1234)",
            format!("{:x?}", EthType::Unsupported(0x1234))
        );
    }

    #[test]
    fn test_eth_type_from_into_primitive() {
        assert_eq!(0x0800_u16, EthType::Ipv4.into());
        assert_eq!(0x0806_u16, EthType::Arp.into());
        assert_eq!(0x86DD_u16, EthType::Ipv6.into());
        assert_eq!(0x1234_u16, EthType::Unsupported(0x1234).into());

        assert_eq!(EthType::Ipv4, EthType::from(0x0800));
        assert_eq!(EthType::Arp, EthType::from(0x0806));
        assert_eq!(EthType::Ipv6, EthType::from(0x86DD));
        assert_eq!(EthType::Unsupported(0x1234), EthType::from(0x1234));
    }

    #[test]
    fn test_eth_type_strum() {
        use std::str::FromStr;

        assert_eq!("Ipv4", EthType::Ipv4.to_string().as_str());
        assert_eq!("Arp", EthType::Arp.to_string().as_str());
        assert_eq!("Ipv6", EthType::Ipv6.to_string().as_str());
        assert_eq!(
            "Unsupported",
            EthType::Unsupported(0x1234).to_string().as_str()
        );

        assert_eq!(EthType::Ipv4, EthType::from_str("Ipv4").unwrap());
        assert_eq!(EthType::Arp, EthType::from_str("Arp").unwrap());
        assert_eq!(EthType::Ipv6, EthType::from_str("Ipv6").unwrap());
        assert_eq!(
            EthType::Unsupported(0),
            EthType::from_str("Unsupported").unwrap()
        );
    }
}
