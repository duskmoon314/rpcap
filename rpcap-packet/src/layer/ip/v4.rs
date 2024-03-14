//! Ipv4 layer
//!
//! This module provides [`Ipv4`] to represent and operate Ipv4 packets.

use crate::{field_spec, impl_target, utils::field::Field};

use super::{IpError, IpProtocol};

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
#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4<T>
where
    T: AsRef<[u8]>,
{
    data: T,
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

impl<T: AsRef<[u8]>> Ipv4<T> {
    /// Byte range of `version` field
    pub const FIELD_VERSION: std::ops::Range<usize> = 0..1;
    /// Byte range of `ihl` field
    pub const FIELD_IHL: std::ops::Range<usize> = 0..1;
    /// Byte range of `dscp` field
    pub const FIELD_DSCP: std::ops::Range<usize> = 1..2;
    /// Byte range of `ecn` field
    pub const FIELD_ECN: std::ops::Range<usize> = 1..2;
    /// Byte range of `total_length` field
    pub const FIELD_TOTAL_LENGTH: std::ops::Range<usize> = 2..4;
    /// Byte range of `identification` field
    pub const FIELD_IDENTIFICATION: std::ops::Range<usize> = 4..6;
    /// Byte range of `flags` field
    pub const FIELD_FLAGS: std::ops::Range<usize> = 6..7;
    /// Byte range of `fragment_offset` field
    pub const FIELD_FRAGMENT_OFFSET: std::ops::Range<usize> = 6..8;
    /// Byte range of `ttl` field
    pub const FIELD_TTL: std::ops::Range<usize> = 8..9;
    /// Byte range of `protocol` field
    pub const FIELD_PROTOCOL: std::ops::Range<usize> = 9..10;
    /// Byte range of `checksum` field
    pub const FIELD_CHECKSUM: std::ops::Range<usize> = 10..12;
    /// Byte range of `src` field
    pub const FIELD_SRC: std::ops::Range<usize> = 12..16;
    /// Byte range of `dst` field
    pub const FIELD_DST: std::ops::Range<usize> = 16..20;

    /// Ipv4 minimal header length
    pub const MIN_HEADER_LENGTH: usize = 20;

    /// Create a new Ipv4 layer from the given data.
    #[inline]
    pub fn new(data: T) -> Result<Self, IpError> {
        let ipv4 = unsafe { Self::new_unchecked(data) };
        ipv4.validate()?;
        Ok(ipv4)
    }

    /// Create a new `Ipv4` layer from the given data without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given data is a valid Ipv4 packet.
    ///
    /// If not, it may cause a panic when accessing the fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the inner data.
    #[inline]
    pub fn validate(&self) -> Result<(), IpError> {
        // Check the length of the data
        if self.data.as_ref().len() < Self::MIN_HEADER_LENGTH {
            return Err(IpError::InvalidDataLength {
                expected: Self::MIN_HEADER_LENGTH,
                actual: self.data.as_ref().len(),
            });
        }
        if self.data.as_ref().len() < self.ihl().get() as usize * 4 {
            return Err(IpError::InvalidDataLength {
                expected: self.ihl().get() as usize * 4,
                actual: self.data.as_ref().len(),
            });
        }

        #[cfg(feature = "strict")]
        if self.version().get() != 4 {
            return Err(IpError::InvalidVersion(self.version().get()));
        }
        #[cfg(feature = "strict")]
        if self.ihl().get() < 5 {
            return Err(IpError::InvalidIhl(self.ihl().get()));
        }
        // TODO: More strict checks, e.g. checksum

        Ok(())
    }

    /// Get the reference to the inner data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Version (4 bits)
    ///
    /// The version of the IP protocol (4).
    pub fn version(&self) -> &Field<VersionSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_VERSION].as_ptr() as *const _) }
    }

    /// Header length (4 bits)
    pub fn ihl(&self) -> &Field<IhlSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_IHL].as_ptr() as *const _) }
    }

    /// Differentiated Services Code Point (6 bits)
    pub fn dscp(&self) -> &Field<DscpSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DSCP].as_ptr() as *const _) }
    }

    /// Explicit Congestion Notification (2 bits)
    pub fn ecn(&self) -> &Field<EcnSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_ECN].as_ptr() as *const _) }
    }

    /// Total length (16 bits)
    pub fn total_length(&self) -> &Field<TotalLengthSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_TOTAL_LENGTH].as_ptr() as *const _) }
    }

    /// Identification (16 bits)
    pub fn identification(&self) -> &Field<IdentificationSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_IDENTIFICATION].as_ptr() as *const _) }
    }

    /// Flags (3 bits)
    pub fn flags(&self) -> &Field<FlagsSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Fragment offset (13 bits)
    pub fn fragment_offset(&self) -> &Field<FragmentOffsetSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FRAGMENT_OFFSET].as_ptr() as *const _) }
    }

    /// Time to live (8 bits)
    pub fn ttl(&self) -> &Field<TtlSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_TTL].as_ptr() as *const _) }
    }

    /// Protocol (8 bits)
    pub fn protocol(&self) -> &Field<ProtocolSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_PROTOCOL].as_ptr() as *const _) }
    }

    /// Header checksum (16 bits)
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_CHECKSUM].as_ptr() as *const _) }
    }

    /// Source address (32 bits)
    pub fn src(&self) -> &Field<SrcSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SRC].as_ptr() as *const _) }
    }

    /// Destination address (32 bits)
    pub fn dst(&self) -> &Field<DstSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DST].as_ptr() as *const _) }
    }

    /// Payload
    pub fn payload(&self) -> &[u8] {
        let ihl = self.ihl().get() as usize * 4;
        &self.data.as_ref()[ihl..]
    }

    /// Treat the payload as a [`Tcp`](crate::layer::tcp::Tcp) layer if the `protocol` is [`IpProtocol::Tcp`].
    #[inline]
    pub fn tcp(&self) -> Option<crate::layer::tcp::TcpResult<crate::layer::tcp::Tcp<&[u8]>>> {
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
    /// Get the mutable reference to the inner data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the `version` field as mutable.
    pub fn version_mut(&mut self) -> &mut Field<VersionSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_VERSION].as_mut_ptr() as *mut _) }
    }

    /// Get the `ihl` field as mutable.
    pub fn ihl_mut(&mut self) -> &mut Field<IhlSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_IHL].as_mut_ptr() as *mut _) }
    }

    /// Get the `dscp` field as mutable.
    pub fn dscp_mut(&mut self) -> &mut Field<DscpSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_DSCP].as_mut_ptr() as *mut _) }
    }

    /// Get the `ecn` field as mutable.
    pub fn ecn_mut(&mut self) -> &mut Field<EcnSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_ECN].as_mut_ptr() as *mut _) }
    }

    /// Get the `total_length` field as mutable.
    pub fn total_length_mut(&mut self) -> &mut Field<TotalLengthSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_TOTAL_LENGTH].as_mut_ptr() as *mut _) }
    }

    /// Get the `identification` field as mutable.
    pub fn identification_mut(&mut self) -> &mut Field<IdentificationSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_IDENTIFICATION].as_mut_ptr() as *mut _) }
    }

    /// Get the `flags` field as mutable.
    pub fn flags_mut(&mut self) -> &mut Field<FlagsSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `fragment_offset` field as mutable.
    pub fn fragment_offset_mut(&mut self) -> &mut Field<FragmentOffsetSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FRAGMENT_OFFSET].as_mut_ptr() as *mut _) }
    }

    /// Get the `ttl` field as mutable.
    pub fn ttl_mut(&mut self) -> &mut Field<TtlSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_TTL].as_mut_ptr() as *mut _) }
    }

    /// Get the `protocol` field as mutable.
    pub fn protocol_mut(&mut self) -> &mut Field<ProtocolSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_PROTOCOL].as_mut_ptr() as *mut _) }
    }

    /// Get the `checksum` field as mutable.
    pub fn checksum_mut(&mut self) -> &mut Field<ChecksumSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_CHECKSUM].as_mut_ptr() as *mut _) }
    }

    /// Get the `src` field as mutable.
    pub fn src_mut(&mut self) -> &mut Field<SrcSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_SRC].as_mut_ptr() as *mut _) }
    }

    /// Get the `dst` field as mutable.
    pub fn dst_mut(&mut self) -> &mut Field<DstSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_DST].as_mut_ptr() as *mut _) }
    }

    /// Get the payload as mutable.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let ihl = self.ihl().get() as usize * 4;
        &mut self.data.as_mut()[ihl..]
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

/// Default implementation for `Ipv4`
///
/// # Panics
///
/// This method may panic if `T` does not have enough length and cannot pass the
/// [`validate`](Ipv4::validate) check.
///
/// Use `[u8; 20]` will not panic.
///
/// ```
/// # use rpcap_packet::layer::ip::v4::Ipv4;
/// let ipv4: Ipv4<[u8; 20]> = Ipv4::default();
/// ```
///
/// Use `Vec<u8>` will panic.
///
/// ```should_panic
/// # use rpcap_packet::layer::ip::v4::Ipv4;
/// let ipv4: Ipv4<Vec<u8>> = Ipv4::default();
/// ```
impl<T> Default for Ipv4<T>
where
    T: AsRef<[u8]> + AsMut<[u8]> + Default,
{
    fn default() -> Self {
        let mut ipv4 = unsafe { Self::new_unchecked(T::default()) };
        ipv4.version_mut().set(4);
        ipv4.ihl_mut().set(5);
        ipv4.validate().unwrap();
        ipv4
    }
}

impl<T> AsRef<[u8]> for Ipv4<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T> AsMut<[u8]> for Ipv4<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<T> AsRef<T> for Ipv4<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &T {
        self.inner()
    }
}

impl<T> AsMut<T> for Ipv4<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut T {
        self.inner_mut()
    }
}

/// Create a new `Ipv4` layer
#[macro_export]
macro_rules! ipv4 {
    ($($field:ident : $value:expr),* $(,)?) => {
        ipv4!(20, $($field : $value),*)
    };

    ($length:expr, $($field:ident : $value:expr),* $(,)?) => {
        || -> Result<$crate::layer::ip::Ipv4<[u8; $length]>, $crate::layer::ip::IpError> {
            let mut eth: $crate::layer::ip::Ipv4<[u8; $length]> = $crate::layer::ip::Ipv4::default();
            paste::paste! {
                $(
                    eth.[< $field _mut >]().set($value);
                )*
            }
            Ok(eth)
        }()
    };
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
