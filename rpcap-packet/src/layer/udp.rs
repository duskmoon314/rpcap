//! Udp layer

use crate::{field_spec, utils::field::Field};

/// Error type for Udp layer
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum UdpError {
    /// Invalid data length
    #[error("[Udp] Invalid data length, expected >= 8, got {0}")]
    InvalidDataLength(usize),

    /// Checksum mismatch
    #[error("[Udp] Checksum mismatch, expected {expected}, got {got}")]
    ChecksumMismatch {
        /// Expected checksum
        expected: u16,
        /// Actual checksum
        got: u16,
    },
}

/// Udp layer
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Udp<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

field_spec!(PortSpec, u16, u16);
field_spec!(LengthSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);

impl<T> Udp<T>
where
    T: AsRef<[u8]>,
{
    /// Byte range of `src_port` field
    pub const FIELD_SRC_PORT: std::ops::Range<usize> = 0..2;
    /// Byte range of `dst_port` field
    pub const FIELD_DST_PORT: std::ops::Range<usize> = 2..4;
    /// Byte range of `length` field
    pub const FIELD_LENGTH: std::ops::Range<usize> = 4..6;
    /// Byte range of `checksum` field
    pub const FIELD_CHECKSUM: std::ops::Range<usize> = 6..8;
    /// Byte range of payload
    pub const FIELD_PAYLOAD: std::ops::RangeFrom<usize> = 8..;

    /// Udp header length
    pub const HEADER_LENGTH: usize = Self::FIELD_CHECKSUM.end;

    /// Create a new `Udp` layer from the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is not valid.
    #[inline]
    pub fn new(data: T) -> Result<Self, UdpError> {
        let udp = unsafe { Self::new_unchecked(data) };
        udp.validate()?;
        Ok(udp)
    }

    /// Create a new `Udp` layer from the given data without validation.
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
    pub fn validate(&self) -> Result<(), UdpError> {
        if self.data.as_ref().len() < Self::HEADER_LENGTH {
            return Err(UdpError::InvalidDataLength(self.data.as_ref().len()));
        }
        // TODO: validate checksum if feature `strict` is enabled
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

    /// Get the `length` field.
    #[inline]
    pub fn length(&self) -> &Field<LengthSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_LENGTH].as_ptr() as *const _) }
    }

    /// Get the `checksum` field.
    #[inline]
    pub fn checksum(&self) -> &Field<ChecksumSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_CHECKSUM].as_ptr() as *const _) }
    }

    /// Get the payload data.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_PAYLOAD]
    }
}

impl<T> Udp<T>
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

    /// Get the `length` field as mutable.
    #[inline]
    pub fn length_mut(&mut self) -> &mut Field<LengthSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_LENGTH].as_mut_ptr() as *mut _) }
    }

    /// Get the `checksum` field as mutable.
    #[inline]
    pub fn checksum_mut(&mut self) -> &mut Field<ChecksumSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_CHECKSUM].as_mut_ptr() as *mut _) }
    }

    /// Get the payload data as mutable.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_PAYLOAD]
    }
}

impl<T> AsRef<[u8]> for Udp<T>
where
    T: AsRef<[u8]>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T> AsMut<[u8]> for Udp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<T> AsRef<T> for Udp<T>
where
    T: AsRef<[u8]>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.inner()
    }
}

impl<T> AsMut<T> for Udp<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        self.inner_mut()
    }
}
