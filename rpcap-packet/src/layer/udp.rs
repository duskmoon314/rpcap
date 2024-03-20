//! Udp layer

use rpcap_impl::layer;

use crate::field_spec;

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

field_spec!(PortSpec, u16, u16);
field_spec!(LengthSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);

/// Udp Layer
#[layer]
pub struct Udp {
    #[layer(range = 0..2)]
    src_port: PortSpec,
    #[layer(range = 2..4)]
    dst_port: PortSpec,
    #[layer(range = 4..6)]
    length: LengthSpec,
    #[layer(range = 6..8)]
    checksum: ChecksumSpec,
}

impl<T> Udp<T>
where
    T: AsRef<[u8]>,
{
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

    /// Validate the inner data.
    #[inline]
    pub fn validate(&self) -> Result<(), UdpError> {
        if self.data.as_ref().len() < Self::MIN_HEADER_LENGTH {
            return Err(UdpError::InvalidDataLength(self.data.as_ref().len()));
        }
        // TODO: validate checksum if feature `strict` is enabled
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    use super::*;

    #[test]
    fn test_udp() -> Result<()> {
        let data = [
            0x00, 0x50, // src port
            0x00, 0x51, // dst port
            0x00, 0x0c, // length
            0x00, 0x00, // checksum
        ];
        let udp = Udp::new(&data)?;
        assert_eq!(udp.src_port().get(), 80);
        assert_eq!(udp.dst_port().get(), 81);
        assert_eq!(udp.length().get(), 12);
        assert_eq!(udp.checksum().get(), 0);
        Ok(())
    }
}
