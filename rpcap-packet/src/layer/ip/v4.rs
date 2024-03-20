//! Ipv4 layer
//!
//! This module provides [`Ipv4`] to represent and operate Ipv4 packets.

use rpcap_impl::layer;

use crate::{field_spec, impl_target};

use super::IpProtocol;

/// Error type for Ipv4 layer.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Ipv4Error {
    /// Invalid data length.
    ///
    /// This error occurs when the length of the data is shorter than the minimal length or the `ihl` field.
    #[error("[Ip] Invalid data length: expected {expected}, actual {actual}")]
    InvalidDataLength {
        /// Expected length.
        ///
        /// This is the minimal length or the `ihl` field.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Invalid Version
    ///
    /// This error only occurs in Ipv4, when the `version` field is not 4.
    #[error("[Ip] Invalid Version: expected 4, actual {0}")]
    InvalidVersion(u8),

    /// Invalid Header Length.
    ///
    /// This error only occurs in Ipv4, when the `ihl` field is less than 5.
    #[error("[Ip] Invalid Header Length: expected 5, actual {0}")]
    InvalidIhl(u8),
}

impl_target!(frominto, std::net::Ipv4Addr, u32);

field_spec!(VersionSpec, u8, u8, 0xF0, 4);
field_spec!(IhlSpec, u8, u8, 0x0F);
field_spec!(DscpSpec, u8, u8, 0xFC, 2);
field_spec!(EcnSpec, u8, u8, 0x03);
field_spec!(TotalLengthSpec, u16, u16);
field_spec!(IdentificationSpec, u16, u16);
field_spec!(FlagsSpec, u8, u8, 0xE0, 5);
field_spec!(FragmentOffsetSpec, u16, u16, 0x1FFF);
field_spec!(TtlSpec, u8, u8);
field_spec!(ProtocolSpec, IpProtocol, u8, 0xFF);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(SrcSpec, std::net::Ipv4Addr, u32);
field_spec!(DstSpec, std::net::Ipv4Addr, u32);

/// Ipv4 layer
///
/// # Example
///
/// ```
/// # use rpcap_packet::layer::ip::v4::Ipv4;
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut data: [u8; 20] = [
///     0x45, // version + ihl
///     0x00, // dscp + ecn
///     0x00, 0x1c, // total length
///     0x00, 0x00, // identification
///     0x00, 0x00, // flags + fragment offset
///     0x40, // ttl
///     0x06, // protocol
///     0x00, 0x00, // header checksum
///     0x0a, 0x00, 0x00, 0x01, // src
///     0x0a, 0x00, 0x00, 0x02, // dst
/// ];
///
/// let mut ipv4 = Ipv4::new(&mut data)?;
///
/// assert_eq!(ipv4.version().get(), 4);
/// assert_eq!(ipv4.ihl().get(), 5);
/// #     Ok(())
/// # }
/// ```
#[layer]
pub struct Ipv4 {
    #[layer(range = 0..1)]
    version: VersionSpec,
    #[layer(range = 0..1)]
    ihl: IhlSpec,
    #[layer(range = 1..2)]
    dscp: DscpSpec,
    #[layer(range = 1..2)]
    ecn: EcnSpec,
    #[layer(range = 2..4)]
    total_length: TotalLengthSpec,
    #[layer(range = 4..6)]
    identification: IdentificationSpec,
    #[layer(range = 6..7)]
    flags: FlagsSpec,
    #[layer(range = 6..8)]
    fragment_offset: FragmentOffsetSpec,
    #[layer(range = 8..9)]
    ttl: TtlSpec,
    #[layer(range = 9..10)]
    protocol: ProtocolSpec,
    #[layer(range = 10..12)]
    checksum: ChecksumSpec,
    #[layer(range = 12..16)]
    src: SrcSpec,
    #[layer(range = 16..20)]
    dst: DstSpec,
    #[layer(range = self.ihl().get() as usize * 4..)]
    payload: [u8],
}

impl<T: AsRef<[u8]>> Ipv4<T> {
    /// Create a new Ipv4 layer from the given data.
    #[inline]
    pub fn new(data: T) -> Result<Self, Ipv4Error> {
        let ipv4 = unsafe { Self::new_unchecked(data) };
        ipv4.validate()?;
        Ok(ipv4)
    }

    /// Validate the inner data.
    #[inline]
    pub fn validate(&self) -> Result<(), Ipv4Error> {
        // Check the length of the data
        if self.data.as_ref().len() < Self::MIN_HEADER_LENGTH {
            return Err(Ipv4Error::InvalidDataLength {
                expected: Self::MIN_HEADER_LENGTH,
                actual: self.data.as_ref().len(),
            });
        }
        if self.data.as_ref().len() < self.ihl().get() as usize * 4 {
            return Err(Ipv4Error::InvalidDataLength {
                expected: self.ihl().get() as usize * 4,
                actual: self.data.as_ref().len(),
            });
        }

        #[cfg(feature = "strict")]
        {
            if self.version().get() != 4 {
                return Err(Ipv4Error::InvalidVersion(self.version().get()));
            }
            if self.ihl().get() < 5 {
                return Err(Ipv4Error::InvalidIhl(self.ihl().get()));
            }
            // TODO: More strict checks, e.g. checksum
        }

        Ok(())
    }

    /// Treat the payload as a [`Tcp`](crate::layer::tcp::Tcp) layer if the `protocol` is [`IpProtocol::Tcp`].
    #[inline]
    pub fn tcp(
        &self,
    ) -> Option<Result<crate::layer::tcp::Tcp<&[u8]>, crate::layer::tcp::TcpError>> {
        if self.protocol().get() == IpProtocol::Tcp {
            Some(crate::layer::tcp::Tcp::new(self.payload()))
        } else {
            None
        }
    }

    /// Treat the payload as a [`Udp`](crate::layer::udp::Udp) layer if the `protocol` is [`IpProtocol::Udp`].
    #[inline]
    pub fn udp(
        &self,
    ) -> Option<Result<crate::layer::udp::Udp<&[u8]>, crate::layer::udp::UdpError>> {
        if self.protocol().get() == IpProtocol::Udp {
            Some(crate::layer::udp::Udp::new(self.payload()))
        } else {
            None
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv4<T> {
    /// Treat the payload as a mutable [`Tcp`](crate::layer::tcp::Tcp) layer if the `protocol` is [`IpProtocol::Tcp`].
    #[inline]
    pub fn tcp_mut(
        &mut self,
    ) -> Option<Result<crate::layer::tcp::Tcp<&mut [u8]>, crate::layer::tcp::TcpError>> {
        if self.protocol().get() == IpProtocol::Tcp {
            Some(crate::layer::tcp::Tcp::new(self.payload_mut()))
        } else {
            None
        }
    }

    /// Treat the payload as a mutable [`Udp`](crate::layer::udp::Udp) layer if the `protocol` is [`IpProtocol::Udp`].
    #[inline]
    pub fn udp_mut(
        &mut self,
    ) -> Option<Result<crate::layer::udp::Udp<&mut [u8]>, crate::layer::udp::UdpError>> {
        if self.protocol().get() == IpProtocol::Udp {
            Some(crate::layer::udp::Udp::new(self.payload_mut()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use anyhow::Result;

    use super::*;

    #[test]
    fn test_ipv4() -> Result<()> {
        let mut data: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x0e, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];

        let mut ipv4 = Ipv4::new(&mut data)?;

        assert_eq!(ipv4.version().get(), 4);

        ipv4.version_mut().set(5);

        assert_eq!(ipv4.version().get(), 5);

        ipv4.version_mut().set(4);

        assert_eq!(ipv4.version().get(), 4);

        assert_eq!(ipv4.ihl().get(), 5);
        assert_eq!(ipv4.dscp().get(), 0);
        assert_eq!(ipv4.ecn().get(), 0);
        assert_eq!(ipv4.total_length().get(), 40);
        assert_eq!(ipv4.identification().get(), 0);
        assert_eq!(ipv4.flags().get(), 2);
        assert_eq!(ipv4.fragment_offset().get(), 0);
        assert_eq!(ipv4.ttl().get(), 64);
        assert_eq!(ipv4.protocol().raw(), 17);
        assert_eq!(ipv4.protocol().get(), IpProtocol::Udp);
        assert_eq!(ipv4.checksum().get(), 0xb80e);
        assert_eq!(ipv4.src().get(), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(ipv4.dst().get(), Ipv4Addr::new(192, 168, 0, 199));

        Ok(())
    }

    #[test]
    fn test_ipv4_macro() -> Result<()> {
        let ipv4 = ipv4!(
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 40,
            identification: 0,
            flags: 2,
            fragment_offset: 0,
            ttl: 64,
            protocol: IpProtocol::Udp,
            checksum: 0xb80e,
            src: Ipv4Addr::new(192, 168, 0, 1),
            dst: Ipv4Addr::new(192, 168, 0, 199),
        )?;

        assert_eq!(
            ipv4.as_ref(),
            [
                0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x0e, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
            ]
        );

        Ok(())
    }
}
