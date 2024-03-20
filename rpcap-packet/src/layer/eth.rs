//! Ethernet layer.
//!
//! This module provides [`Eth`] to represent and operate Ethernet packets.

use crate::{field_spec, mac_addr::MacAddr};

#[doc(hidden)]
pub mod eth_type;
pub use eth_type::EthType;
use rpcap_impl::layer;

/// Error type for Ethernet layer.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum EthError {
    /// Invalid data length.
    ///
    /// The length of the given data is not valid for the Ethernet layer. It
    /// must be greater than or equal to 14.
    #[error("[Eth] Invalid data length, expected >= 14, got {0}")]
    InvalidDataLength(usize),

    /// Invalid MacAddr.
    #[error("[Eth] Invalid MacAddr {0}")]
    InvalidMacAddr(#[from] crate::mac_addr::MacAddrError),
}

field_spec!(MacAddrSpec, MacAddr, [u8; 6]);
field_spec!(EthTypeSpec, EthType, u16);

/// Ethernet layer.
///
/// # Example
///
/// ```
/// # use rpcap_packet::{mac_addr, layer::eth::{Eth, EthType}};
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut data: [u8; 14] = [
/// 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
/// 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
/// 0x08, 0x00, // eth_type
/// ];
///
/// let mut eth = Eth::new(&mut data)?;
///
/// assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:05")?);
/// assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0b")?);
/// assert_eq!(eth.ty().get(), EthType::Ipv4);
///
/// eth.dst_mut().set(mac_addr!("00:01:02:03:04:06")?);
/// eth.src_mut().set(mac_addr!("06:07:08:09:0a:0c")?);
/// eth.ty_mut().set(EthType::Ipv6);
///
/// assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:06")?);
/// assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0c")?);
/// assert_eq!(eth.ty().get(), EthType::Ipv6);
/// #
/// #     Ok(())
/// # }
/// ```
#[layer]
pub struct Eth {
    #[layer(range = 0..6)]
    dst: MacAddrSpec,
    #[layer(range = 6..12)]
    src: MacAddrSpec,
    #[layer(range = 12..14)]
    ty: EthTypeSpec,
    #[layer(range = 14..)]
    payload: [u8],
}

impl<T> Eth<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new [`Eth`] layer from the given data.
    #[inline]
    pub fn new(data: T) -> Result<Self, EthError> {
        let layer = unsafe { Self::new_unchecked(data) };
        layer.validate()?;
        Ok(layer)
    }

    /// Validate the inner data.
    #[inline]
    pub fn validate(&self) -> Result<(), EthError> {
        if self.data.as_ref().len() < Self::MIN_HEADER_LENGTH {
            return Err(EthError::InvalidDataLength(self.data.as_ref().len()));
        }

        Ok(())
    }

    /// Treat the payload as an `Ipv4` layer if the `type` field is `EthType::Ipv4`.
    pub fn ipv4(
        &self,
    ) -> Option<Result<crate::layer::ip::Ipv4<&[u8]>, crate::layer::ip::v4::Ipv4Error>> {
        if self.ty().get() == EthType::Ipv4 {
            Some(crate::layer::ip::Ipv4::new(&self.data.as_ref()[14..]))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;
    use crate::mac_addr;

    #[test]
    fn test_eth() -> Result<()> {
        let mut data: [u8; 14] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
            0x08, 0x00, // eth_type
        ];

        let mut eth = Eth::new(&mut data).unwrap();

        assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:05")?);
        assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0b")?);
        assert_eq!(eth.ty().get(), EthType::Ipv4);

        eth.dst_mut().set(mac_addr!("00:01:02:03:04:06")?);
        eth.src_mut().set(mac_addr!("06:07:08:09:0a:0c")?);
        eth.ty_mut().set(EthType::Ipv6);

        assert_eq!(eth.dst().get(), mac_addr!("00:01:02:03:04:06")?);
        assert_eq!(eth.src().get(), mac_addr!("06:07:08:09:0a:0c")?);
        assert_eq!(eth.ty().get(), EthType::Ipv6);

        assert_eq!(
            data,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x06, // dst
                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0c, // src
                0x86, 0xdd, // eth_type
            ]
        );

        Ok(())
    }

    #[test]
    fn test_eth_vec() -> Result<()> {
        let data = vec![0; 14];
        let mut eth = Eth::new(data).unwrap();

        eth.dst_mut().set(mac_addr!("00:01:02:03:04:05")?);
        eth.src_mut().set(mac_addr!("06:07:08:09:0a:0b")?);
        eth.ty_mut().set(EthType::Ipv4);

        let inner = eth.inner_mut();
        inner.extend(&[0; 5]);
        eth.payload_mut().copy_from_slice(&[1; 5]);

        assert_eq!(
            eth.as_ref(),
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
                0x08, 0x00, // eth_type
                0x01, 0x01, 0x01, 0x01, 0x01, // payload
            ]
        );

        Ok(())
    }

    #[test]
    fn test_eth_macro() -> Result<()> {
        let eth = eth!(
            dst: mac_addr!("00:01:02:03:04:05")?,
            src: mac_addr!("06:07:08:09:0a:0b")?,
            ty: EthType::Ipv4,
        )?;

        assert_eq!(
            eth.as_ref(),
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
                0x08, 0x00, // eth_type
            ]
        );

        let eth = eth!(
            16,
            dst: mac_addr!("00:01:02:03:04:05")?,
            src: mac_addr!("06:07:08:09:0a:0b")?,
            ty: EthType::Ipv4,
        )?;

        assert_eq!(
            eth.as_ref(),
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
                0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
                0x08, 0x00, // eth_type
                0, 0, // payload
            ]
        );

        Ok(())
    }

    #[test]
    fn test_eth_ipv4() -> Result<()> {
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

        let eth = Eth::new(&data)?;
        let ipv4 = eth.ipv4();

        assert!(ipv4.is_some());

        let ipv4 = ipv4.unwrap()?;

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

        let mut eth = Eth::new(data)?;

        eth.payload_mut()[0] = 0x46;

        assert_eq!(
            eth.payload()[0..8],
            [0x46, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00]
        );

        Ok(())
    }
}
