//! Ipv4 layer
//!
//! This module provides [`Ipv4`] to represent and operate Ipv4 packets.

use crate::utils::field::Field;

use super::IpProtocol;

/// Ipv4 layer
///
/// # Example
///
/// ```
/// # use rpcap_packet::layer::ip::v4::Ipv4;
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
/// let mut ipv4 = Ipv4::new(&mut data);
///
/// assert_eq!(ipv4.version().get(), 4);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

mod field {
    use std::net::Ipv4Addr;

    use super::IpProtocol;
    use crate::field_spec;

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
    field_spec!(SrcSpec, Ipv4Addr, u32);
    field_spec!(DstSpec, Ipv4Addr, u32);
}

pub use field::*;

impl<T: AsRef<[u8]>> Ipv4<T> {
    /// Create a new Ipv4 layer from the given data.
    pub const fn new(data: T) -> Self {
        Ipv4 { data }
    }

    /// Version (4 bits)
    ///
    /// The version of the IP protocol (4).
    pub fn version(&self) -> &Field<VersionSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_VERSION].as_ptr() as *const _) }
    }

    /// Header length (4 bits)
    pub fn ihl(&self) -> &Field<IhlSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_IHL].as_ptr() as *const _) }
    }

    /// Differentiated Services Code Point (6 bits)
    pub fn dscp(&self) -> &Field<DscpSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_DSCP].as_ptr() as *const _) }
    }

    /// Explicit Congestion Notification (2 bits)
    pub fn ecn(&self) -> &Field<EcnSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_ECN].as_ptr() as *const _) }
    }

    /// Total length (16 bits)
    pub fn total_length(&self) -> &Field<TotalLengthSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_TOTAL_LENGTH].as_ptr() as *const _) }
    }

    /// Identification (16 bits)
    pub fn identification(&self) -> &Field<IdentificationSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_IDENTIFICATION].as_ptr() as *const _) }
    }

    /// Flags (3 bits)
    pub fn flags(&self) -> &Field<FlagsSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Fragment offset (13 bits)
    pub fn fragment_offset(&self) -> &Field<FragmentOffsetSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_FRAGMENT_OFFSET].as_ptr() as *const _) }
    }

    /// Time to live (8 bits)
    pub fn ttl(&self) -> &Field<TtlSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_TTL].as_ptr() as *const _) }
    }

    /// Protocol (8 bits)
    pub fn protocol(&self) -> &Field<ProtocolSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_PROTOCOL].as_ptr() as *const _) }
    }

    /// Header checksum (16 bits)
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_CHECKSUM].as_ptr() as *const _) }
    }

    /// Source address (32 bits)
    pub fn src(&self) -> &Field<SrcSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_SRC].as_ptr() as *const _) }
    }

    /// Destination address (32 bits)
    pub fn dst(&self) -> &Field<DstSpec> {
        unsafe { &*(self.data.as_ref()[FIELD_DST].as_ptr() as *const _) }
    }

    /// Payload
    pub fn payload(&self) -> &[u8] {
        let ihl = self.ihl().get() as usize * 4;
        &self.data.as_ref()[ihl..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv4<T> {
    /// Get the `version` field as mutable.
    pub fn version_mut(&mut self) -> &mut Field<VersionSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_VERSION].as_mut_ptr() as *mut _) }
    }

    /// Get the `ihl` field as mutable.
    pub fn ihl_mut(&mut self) -> &mut Field<IhlSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_IHL].as_mut_ptr() as *mut _) }
    }

    /// Get the `dscp` field as mutable.
    pub fn dscp_mut(&mut self) -> &mut Field<DscpSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_DSCP].as_mut_ptr() as *mut _) }
    }

    /// Get the `ecn` field as mutable.
    pub fn ecn_mut(&mut self) -> &mut Field<EcnSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_ECN].as_mut_ptr() as *mut _) }
    }

    /// Get the `total_length` field as mutable.
    pub fn total_length_mut(&mut self) -> &mut Field<TotalLengthSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_TOTAL_LENGTH].as_mut_ptr() as *mut _) }
    }

    /// Get the `identification` field as mutable.
    pub fn identification_mut(&mut self) -> &mut Field<IdentificationSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_IDENTIFICATION].as_mut_ptr() as *mut _) }
    }

    /// Get the `flags` field as mutable.
    pub fn flags_mut(&mut self) -> &mut Field<FlagsSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `fragment_offset` field as mutable.
    pub fn fragment_offset_mut(&mut self) -> &mut Field<FragmentOffsetSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_FRAGMENT_OFFSET].as_mut_ptr() as *mut _) }
    }

    /// Get the `ttl` field as mutable.
    pub fn ttl_mut(&mut self) -> &mut Field<TtlSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_TTL].as_mut_ptr() as *mut _) }
    }

    /// Get the `protocol` field as mutable.
    pub fn protocol_mut(&mut self) -> &mut Field<ProtocolSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_PROTOCOL].as_mut_ptr() as *mut _) }
    }

    /// Get the `checksum` field as mutable.
    pub fn checksum_mut(&mut self) -> &mut Field<ChecksumSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_CHECKSUM].as_mut_ptr() as *mut _) }
    }

    /// Get the `src` field as mutable.
    pub fn src_mut(&mut self) -> &mut Field<SrcSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_SRC].as_mut_ptr() as *mut _) }
    }

    /// Get the `dst` field as mutable.
    pub fn dst_mut(&mut self) -> &mut Field<DstSpec> {
        unsafe { &mut *(self.data.as_mut()[FIELD_DST].as_mut_ptr() as *mut _) }
    }

    /// Get the payload as mutable.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let ihl = self.ihl().get() as usize * 4;
        &mut self.data.as_mut()[ihl..]
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_ipv4() {
        let mut data: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x0e, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];

        let mut ipv4 = Ipv4::new(&mut data);

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
    }
}
