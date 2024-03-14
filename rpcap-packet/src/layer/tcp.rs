//! Tcp layer

use crate::{field_spec, utils::field::Field};

/// Error type for Tcp layer
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum TcpError {
    /// Invalid data length
    #[error("[Tcp] Invalid data length, expected >= 20, got {0}")]
    InvalidDataLength(usize),
}

/// Result alias for Tcp layer
pub type TcpResult<T> = Result<T, TcpError>;

/// Tcp layer
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tcp<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

field_spec!(PortSpec, u16, u16);
field_spec!(SeqNumSpec, u32, u32);
field_spec!(AckNumSpec, u32, u32);
field_spec!(DataOffsetSpec, u8, u8, 0xF0, 4);
field_spec!(FlagsSpec, u8, u8);
field_spec!(CWRSpec, bool, u8, 0x80, 7);
field_spec!(ECESpec, bool, u8, 0x40, 6);
field_spec!(URGSpec, bool, u8, 0x20, 5);
field_spec!(ACKSpec, bool, u8, 0x10, 4);
field_spec!(PSHSpec, bool, u8, 0x08, 3);
field_spec!(RSTSpec, bool, u8, 0x04, 2);
field_spec!(SYNSpec, bool, u8, 0x02, 1);
field_spec!(FINSpec, bool, u8, 0x01, 0);
field_spec!(WindowSizeSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(UrgentPtrSpec, u16, u16);

impl<T> Tcp<T>
where
    T: AsRef<[u8]>,
{
    /// Byte range of `src_port` field
    pub const FIELD_SRC_PORT: std::ops::Range<usize> = 0..2;
    /// Byte range of `dst_port` field
    pub const FIELD_DST_PORT: std::ops::Range<usize> = 2..4;
    /// Byte range of `seq_num` field
    pub const FIELD_SEQ_NUM: std::ops::Range<usize> = 4..8;
    /// Byte range of `ack_num` field
    pub const FIELD_ACK_NUM: std::ops::Range<usize> = 8..12;
    /// Byte range of `data_offset` field
    pub const FIELD_DATA_OFFSET: std::ops::Range<usize> = 12..13;
    /// Byte range of `flags` field
    pub const FIELD_FLAGS: std::ops::Range<usize> = 13..14;
    /// Byte range of `window_size` field
    pub const FIELD_WINDOW_SIZE: std::ops::Range<usize> = 14..16;
    /// Byte range of `checksum` field
    pub const FIELD_CHECKSUM: std::ops::Range<usize> = 16..18;
    /// Byte range of `urgent_ptr` field
    pub const FIELD_URGENT_PTR: std::ops::Range<usize> = 18..20;

    /// Minimum length of Tcp layer
    pub const MIN_HEADER_LENGTH: usize = 20;

    /// Create a new `Tcp` layer from the given data
    ///
    /// # Errors
    ///
    /// Returns an error if the length of the data is not valid.
    #[inline]
    pub fn new(data: T) -> TcpResult<Self> {
        let tcp = unsafe { Self::new_unchecked(data) };
        tcp.validate()?;
        Ok(tcp)
    }

    /// Create a new `Tcp` layer from the given data without validation
    ///
    /// # Safety
    ///
    /// The caller must ensure the given data is valid.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the inner data.
    #[inline]
    pub fn validate(&self) -> TcpResult<()> {
        if self.data.as_ref().len() < Self::MIN_HEADER_LENGTH {
            return Err(TcpError::InvalidDataLength(self.data.as_ref().len()));
        }
        // TODO: validate checksum and other fields
        Ok(())
    }

    /// Get the reference to the inner data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the `src_port` field.
    #[inline]
    pub fn src_port(&self) -> &Field<PortSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SRC_PORT].as_ptr() as *const _) }
    }

    /// Get the `dst_port` field.
    #[inline]
    pub fn dst_port(&self) -> &Field<PortSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DST_PORT].as_ptr() as *const _) }
    }

    /// Get the `seq_num` field.
    #[inline]
    pub fn seq_num(&self) -> &Field<SeqNumSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SEQ_NUM].as_ptr() as *const _) }
    }

    /// Get the `ack_num` field.
    #[inline]
    pub fn ack_num(&self) -> &Field<AckNumSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_ACK_NUM].as_ptr() as *const _) }
    }

    /// Get the `data_offset` field.
    #[inline]
    pub fn data_offset(&self) -> &Field<DataOffsetSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DATA_OFFSET].as_ptr() as *const _) }
    }

    /// Get the `flags` field.
    #[inline]
    pub fn flags(&self) -> &Field<FlagsSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `CWR` field.
    ///
    /// The CWR flag is the first bit of the `flags` field, stands for Congestion Window Reduced.
    #[inline]
    pub fn cwr(&self) -> &Field<CWRSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `ECE` field.
    ///
    /// The ECE flag is the second bit of the `flags` field, stands for ECN-Echo.
    #[inline]
    pub fn ece(&self) -> &Field<ECESpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `URG` field.
    ///
    /// The URG flag is the third bit of the `flags` field, indicates the Urgent pointer field is significant.
    #[inline]
    pub fn urg(&self) -> &Field<URGSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `ACK` field.
    ///
    /// The ACK flag is the fourth bit of the `flags` field, indicates the Acknowledgment field is significant.
    #[inline]
    pub fn ack(&self) -> &Field<ACKSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `PSH` field.
    ///
    /// The PSH flag is the fifth bit of the `flags` field, stands for Push Function.
    #[inline]
    pub fn psh(&self) -> &Field<PSHSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `RST` field.
    ///
    /// The RST flag is the sixth bit of the `flags` field, stands for Reset the connection.
    #[inline]
    pub fn rst(&self) -> &Field<RSTSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `SYN` field.
    ///
    /// The SYN flag is the seventh bit of the `flags` field, stands for Synchronize sequence numbers.
    #[inline]
    pub fn syn(&self) -> &Field<SYNSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `FIN` field.
    ///
    /// The FIN flag is the eighth bit of the `flags` field, stands for No more data from sender.
    #[inline]
    pub fn fin(&self) -> &Field<FINSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_FLAGS].as_ptr() as *const _) }
    }

    /// Get the `window_size` field.
    #[inline]
    pub fn window_size(&self) -> &Field<WindowSizeSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_WINDOW_SIZE].as_ptr() as *const _) }
    }

    /// Get the `checksum` field.
    #[inline]
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_CHECKSUM].as_ptr() as *const _) }
    }

    /// Get the `urgent_ptr` field.
    #[inline]
    pub fn urgent_ptr(&self) -> &Field<UrgentPtrSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_URGENT_PTR].as_ptr() as *const _) }
    }
}

impl<T> Tcp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable reference to the inner data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the `src_port` field as mutable.
    #[inline]
    pub fn src_port_mut(&mut self) -> &mut Field<PortSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_SRC_PORT].as_mut_ptr() as *mut _) }
    }

    /// Get the `dst_port` field as mutable.
    #[inline]
    pub fn dst_port_mut(&mut self) -> &mut Field<PortSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_DST_PORT].as_mut_ptr() as *mut _) }
    }

    /// Get the `seq_num` field as mutable.
    #[inline]
    pub fn seq_num_mut(&mut self) -> &mut Field<SeqNumSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_SEQ_NUM].as_mut_ptr() as *mut _) }
    }

    /// Get the `ack_num` field as mutable.
    #[inline]
    pub fn ack_num_mut(&mut self) -> &mut Field<AckNumSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_ACK_NUM].as_mut_ptr() as *mut _) }
    }

    /// Get the `data_offset` field as mutable.
    #[inline]
    pub fn data_offset_mut(&mut self) -> &mut Field<DataOffsetSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_DATA_OFFSET].as_mut_ptr() as *mut _) }
    }

    /// Get the `flags` field as mutable.
    #[inline]
    pub fn flags_mut(&mut self) -> &mut Field<FlagsSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `CWR` field as mutable.
    #[inline]
    pub fn cwr_mut(&mut self) -> &mut Field<CWRSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `ECE` field as mutable.
    #[inline]
    pub fn ece_mut(&mut self) -> &mut Field<ECESpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `URG` field as mutable.
    #[inline]
    pub fn urg_mut(&mut self) -> &mut Field<URGSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `ACK` field as mutable.
    #[inline]
    pub fn ack_mut(&mut self) -> &mut Field<ACKSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `PSH` field as mutable.
    #[inline]
    pub fn psh_mut(&mut self) -> &mut Field<PSHSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `RST` field as mutable.
    #[inline]
    pub fn rst_mut(&mut self) -> &mut Field<RSTSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `SYN` field as mutable.
    #[inline]
    pub fn syn_mut(&mut self) -> &mut Field<SYNSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `FIN` field as mutable.
    #[inline]
    pub fn fin_mut(&mut self) -> &mut Field<FINSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_FLAGS].as_mut_ptr() as *mut _) }
    }

    /// Get the `window_size` field as mutable.
    #[inline]
    pub fn window_size_mut(&mut self) -> &mut Field<WindowSizeSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_WINDOW_SIZE].as_mut_ptr() as *mut _) }
    }

    /// Get the `checksum` field as mutable.
    #[inline]
    pub fn checksum_mut(&mut self) -> &mut Field<ChecksumSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_CHECKSUM].as_mut_ptr() as *mut _) }
    }

    /// Get the `urgent_ptr` field as mutable.
    #[inline]
    pub fn urgent_ptr_mut(&mut self) -> &mut Field<UrgentPtrSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_URGENT_PTR].as_mut_ptr() as *mut _) }
    }
}

impl<T> AsRef<[u8]> for Tcp<T>
where
    T: AsRef<[u8]>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T> AsMut<[u8]> for Tcp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<T> AsRef<T> for Tcp<T>
where
    T: AsRef<[u8]>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.inner()
    }
}

impl<T> AsMut<T> for Tcp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        self.inner_mut()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_tcp() -> Result<()> {
        let data: [u8; 20] = [
            0x00, 0x50, // src_port = 80
            0x00, 0x58, // dst_port = 88
            0x01, 0x02, 0x03, 0x04, // seq_num = 0x01020304
            0x05, 0x06, 0x07, 0x08, // ack_num = 0x05060708
            0x50, // data_offset = 5
            0x18, // flags = 0b00011000 (PSH, ACK)
            0x01, 0x00, // window_size = 256
            0x00, 0x00, // checksum = 0
            0x00, 0x00, // urgent_ptr = 0
        ];

        let tcp = Tcp::new(data)?;

        assert_eq!(tcp.src_port().get(), 80);
        assert_eq!(tcp.dst_port().get(), 88);
        assert_eq!(tcp.seq_num().get(), 0x01020304);
        assert_eq!(tcp.ack_num().get(), 0x05060708);
        assert_eq!(tcp.data_offset().get(), 5);
        assert_eq!(tcp.cwr().get(), false);
        assert_eq!(tcp.ece().get(), false);
        assert_eq!(tcp.urg().get(), false);
        assert_eq!(tcp.ack().get(), true);
        assert_eq!(tcp.psh().get(), true);
        assert_eq!(tcp.rst().get(), false);
        assert_eq!(tcp.syn().get(), false);
        assert_eq!(tcp.fin().get(), false);
        assert_eq!(tcp.window_size().get(), 256);
        assert_eq!(tcp.checksum().get(), 0);
        assert_eq!(tcp.urgent_ptr().get(), 0);

        Ok(())
    }
}
