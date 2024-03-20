//! Tcp layer

use rpcap_impl::layer;

use crate::field_spec;

/// Error type for Tcp layer
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum TcpError {
    /// Invalid data length
    #[error("[Tcp] Invalid data length, expected >= 20, got {0}")]
    InvalidDataLength(usize),
}

// /// Result alias for Tcp layer
// pub type TcpResult<T> = Result<T, TcpError>;

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

/// Tcp Layer
#[layer]
pub struct Tcp {
    #[layer(range = 0..2)]
    src_port: PortSpec,
    #[layer(range = 2..4)]
    dst_port: PortSpec,
    #[layer(range = 4..8)]
    seq_num: SeqNumSpec,
    #[layer(range = 8..12)]
    ack_num: AckNumSpec,
    #[layer(range = 12..13)]
    data_offset: DataOffsetSpec,
    #[layer(range = 13..14)]
    flags: FlagsSpec,
    #[layer(range = 13..14)]
    cwr: CWRSpec,
    #[layer(range = 13..14)]
    ece: ECESpec,
    #[layer(range = 13..14)]
    urg: URGSpec,
    #[layer(range = 13..14)]
    ack: ACKSpec,
    #[layer(range = 13..14)]
    psh: PSHSpec,
    #[layer(range = 13..14)]
    rst: RSTSpec,
    #[layer(range = 13..14)]
    syn: SYNSpec,
    #[layer(range = 13..14)]
    fin: FINSpec,
    #[layer(range = 14..16)]
    window_size: WindowSizeSpec,
    #[layer(range = 16..18)]
    checksum: ChecksumSpec,
    #[layer(range = 18..20)]
    urgent_ptr: UrgentPtrSpec,
    #[layer(range = self.data_offset().get() as usize * 4..)]
    payload: [u8],
}

impl<T> Tcp<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new [`Tcp`] layer from the given data.
    #[inline]
    pub fn new(data: T) -> Result<Self, TcpError> {
        let layer = unsafe { Self::new_unchecked(data) };
        layer.validate()?;
        Ok(layer)
    }

    /// Validate the inner data.
    #[inline]
    pub fn validate(&self) -> Result<(), TcpError> {
        if self.data.as_ref().len() < Self::MIN_HEADER_LENGTH {
            return Err(TcpError::InvalidDataLength(self.data.as_ref().len()));
        }

        Ok(())
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

    #[test]
    fn test_tcp_macro() -> Result<()> {
        let tcp = tcp!(
            src_port: 3000,
            dst_port: 443,
            seq_num: 0x01020304,
            ack_num: 0x05060708,
        )?;

        assert_eq!(tcp.src_port().get(), 3000);
        assert_eq!(tcp.dst_port().get(), 443);
        assert_eq!(tcp.seq_num().get(), 0x01020304);
        assert_eq!(tcp.ack_num().get(), 0x05060708);

        Ok(())
    }
}
