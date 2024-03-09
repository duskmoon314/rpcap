//! Ethernet layer.
//!
//! This module provides [`Eth`] to represent and operate Ethernet packets.

use crate::utils::field::Field;

pub mod eth_type;
pub use eth_type::EthType;

/// Ethernet layer.
///
/// # Example
///
/// ```
/// # use rpcap_packet::{mac_addr, layer::eth::{Eth, EthType}};
/// let mut data: [u8; 14] = [
/// 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
/// 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
/// 0x08, 0x00, // eth_type
/// ];
///
/// let mut eth = Eth::new(&mut data);
///
/// assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:05"));
/// assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0b"));
/// assert_eq!(eth.ty().get(), EthType::Ipv4);
///
/// eth.dst_mut().set(mac_addr!("00:01:02:03:04:06"));
/// eth.src_mut().set(mac_addr!("06:07:08:09:0a:0c"));
/// eth.ty_mut().set(EthType::Ipv6);
///
/// assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:06"));
/// assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0c"));
/// assert_eq!(eth.ty().get(), EthType::Ipv6);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Eth<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

mod field {
    use crate::{field_spec, mac_addr::MacAddr};

    use super::EthType;

    /// Byte range of `dst` field.
    pub const FIELD_DST: std::ops::Range<usize> = 0..6;
    /// Byte range of `src` field.
    pub const FIELD_SRC: std::ops::Range<usize> = 6..12;
    /// Byte range of `type` field.
    pub const FIELD_TYPE: std::ops::Range<usize> = 12..14;
    /// Byte range of `payload` field.
    pub const FIELD_PAYLOAD: std::ops::RangeFrom<usize> = 14..;

    field_spec!(DstSpec, MacAddr, [u8; 6]);
    field_spec!(SrcSpec, MacAddr, [u8; 6]);
    field_spec!(TypeSpec, EthType, u16);
}

pub use field::*;

impl<T> Eth<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new `Eth` layer from the given data.
    pub const fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the `dst` field.
    pub fn dst(&self) -> &Field<DstSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_DST].as_ptr() as *const _) }
    }

    /// Get the `src` field.
    pub fn src(&self) -> &Field<SrcSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_SRC].as_ptr() as *const _) }
    }

    /// Get the `type` field.
    pub fn ty(&self) -> &Field<TypeSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_TYPE].as_ptr() as *const _) }
    }

    /// Get the `payload` field.
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[FIELD_PAYLOAD]
    }

    /// Treat the payload as an `Ipv4` layer if the `type` field is `EthType::Ipv4`.
    pub fn ipv4(&self) -> Option<crate::layer::ip::Ipv4<&[u8]>> {
        if self.ty().get() == EthType::Ipv4 {
            Some(crate::layer::ip::Ipv4::new(
                &self.data.as_ref()[FIELD_PAYLOAD],
            ))
        } else {
            None
        }
    }
}

impl<T> Eth<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the `dst` field as mutable.
    pub fn dst_mut(&mut self) -> &mut Field<DstSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_DST].as_mut_ptr() as *mut _) }
    }

    /// Get the `src` field as mutable.
    pub fn src_mut(&mut self) -> &mut Field<SrcSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_SRC].as_mut_ptr() as *mut _) }
    }

    /// Get the `type` field as mutable.
    pub fn ty_mut(&mut self) -> &mut Field<TypeSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_TYPE].as_mut_ptr() as *mut _) }
    }

    /// Get the `payload` field as mutable.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[FIELD_PAYLOAD]
    }

    /// Treat the payload as a mutable `Ipv4` layer if the `type` field is `EthType::Ipv4`.
    pub fn ipv4_mut(&mut self) -> Option<crate::layer::ip::Ipv4<&mut [u8]>> {
        if self.ty().get() == EthType::Ipv4 {
            Some(crate::layer::ip::Ipv4::new(
                &mut self.data.as_mut()[FIELD_PAYLOAD],
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::mac_addr;

    use super::*;

    #[test]
    fn test_eth() {
        let mut data: [u8; 14] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
            0x08, 0x00, // eth_type
        ];

        let mut eth = Eth::new(&mut data);

        assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:05"));
        assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0b"));
        assert_eq!(eth.ty().get(), EthType::Ipv4);

        eth.dst_mut().set(mac_addr!("00:01:02:03:04:06"));
        eth.src_mut().set(mac_addr!("06:07:08:09:0a:0c"));
        eth.ty_mut().set(EthType::Ipv6);

        assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:06"));
        assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0c"));
        assert_eq!(eth.ty().get(), EthType::Ipv6);

        assert_eq!(
            data,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x06, // dst
                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0c, // src
                0x86, 0xdd, // eth_type
            ]
        )
    }

    #[test]
    fn test_eth_ipv4() {
        use std::net::Ipv4Addr;

        use crate::layer::ip::IpProtocol;

        let data: [u8; 34] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
            0x08, 0x00, // eth_type
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x1c, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x06, // protocol
            0x00, 0x00, // header checksum
            0x0a, 0x00, 0x00, 0x01, // src
            0x0a, 0x00, 0x00, 0x02, // dst
        ];

        let eth = Eth::new(&data);
        let ipv4 = eth.ipv4();

        assert!(ipv4.is_some());

        let ipv4 = ipv4.unwrap();

        assert_eq!(ipv4.version().get(), 4);
        assert_eq!(ipv4.ihl().get(), 5);
        assert_eq!(ipv4.dscp().get(), 0);
        assert_eq!(ipv4.ecn().get(), 0);
        assert_eq!(ipv4.total_length().get(), 28);
        assert_eq!(ipv4.identification().get(), 0);
        assert_eq!(ipv4.flags().get(), 0);
        assert_eq!(ipv4.fragment_offset().get(), 0);
        assert_eq!(ipv4.ttl().get(), 64);
        assert_eq!(ipv4.protocol().get(), IpProtocol::Tcp);
        assert_eq!(ipv4.checksum().get(), 0);
        assert_eq!(ipv4.src().get(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipv4.dst().get(), Ipv4Addr::new(10, 0, 0, 2));

        let mut eth = Eth::new(data);

        eth.payload_mut()[0] = 0x46;

        assert_eq!(
            eth.payload()[0..8],
            [0x46, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00]
        );

        let mut ipv4 = eth.ipv4_mut().unwrap();

        ipv4.ihl_mut().set(5);

        assert_eq!(ipv4.ihl().get(), 5);
    }
}
