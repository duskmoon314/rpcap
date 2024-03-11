//! Ethernet layer.
//!
//! This module provides [`Eth`] to represent and operate Ethernet packets.

use crate::{field_spec, mac_addr::MacAddr, utils::field::Field};

#[doc(hidden)]
pub mod eth_type;
pub use eth_type::EthType;

/// Error type for Ethernet layer.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum EthError {
    /// Invalid data length.
    ///
    /// The length of the given data is not valid for the Ethernet layer. It
    /// must be greater than or equal to 14.
    #[error("Invalid data length, expected >= 14, got {0}")]
    InvalidDataLength(usize),

    /// Invalid MacAddr.
    #[error("Invalid MacAddr {0}")]
    InvalidMacAddr(#[from] crate::mac_addr::MacAddrError),
}

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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Eth<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

field_spec!(DstSpec, MacAddr, [u8; 6]);
field_spec!(SrcSpec, MacAddr, [u8; 6]);
field_spec!(TypeSpec, EthType, u16);

impl<T> Eth<T>
where
    T: AsRef<[u8]>,
{
    /// Byte range of `dst` field.
    pub const FIELD_DST: std::ops::Range<usize> = 0..6;
    /// Byte range of `src` field.
    pub const FIELD_SRC: std::ops::Range<usize> = 6..12;
    /// Byte range of `type` field.
    pub const FIELD_TYPE: std::ops::Range<usize> = 12..14;
    /// Byte range of `payload` field.
    pub const FIELD_PAYLOAD: std::ops::RangeFrom<usize> = 14..;

    /// Ethernet header length.
    pub const HEADER_LEN: usize = Self::FIELD_TYPE.end;

    /// Create a new `Eth` layer from the given data.
    ///
    /// # Errors
    ///
    /// Returns an error if the given data is not valid. See [`EthError`] for
    /// details.
    #[inline]
    pub fn new(data: T) -> Result<Self, EthError> {
        let eth = unsafe { Self::new_unchecked(data) };
        eth.validate()?;
        Ok(eth)
    }

    /// Create a new `Eth` layer from the given data without validation.
    ///
    /// # Safety
    ///
    /// The caller must ensure the given data is valid. At least the length of
    /// the data must be greater than or equal to `HEADER_LEN` (14).
    ///
    /// If not, it may cause a panic when accessing the fields.
    #[inline]
    pub const unsafe fn new_unchecked(data: T) -> Self {
        Self { data }
    }

    /// Validate the inner data.
    #[inline]
    pub fn validate(&self) -> Result<(), EthError> {
        if self.data.as_ref().len() < Self::HEADER_LEN {
            return Err(EthError::InvalidDataLength(self.data.as_ref().len()));
        }
        Ok(())
    }

    /// Get the reference to the inner data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the `dst` field.
    #[inline]
    pub fn dst(&self) -> &Field<DstSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_DST].as_ptr() as *const _) }
    }

    /// Get the `src` field.
    #[inline]
    pub fn src(&self) -> &Field<SrcSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_SRC].as_ptr() as *const _) }
    }

    /// Get the `type` field.
    #[inline]
    pub fn ty(&self) -> &Field<TypeSpec> {
        unsafe { &*(self.data.as_ref()[Self::FIELD_TYPE].as_ptr() as *const _) }
    }

    /// Get the `payload` field.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_PAYLOAD]
    }

    /// Treat the payload as an `Ipv4` layer if the `type` field is `EthType::Ipv4`.
    #[inline]
    pub fn ipv4(&self) -> Option<crate::layer::ip::Ipv4<&[u8]>> {
        if self.ty().get() == EthType::Ipv4 {
            Some(crate::layer::ip::Ipv4::new(
                &self.data.as_ref()[Self::FIELD_PAYLOAD],
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
    /// Get the mutable reference to the inner data.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the `dst` field as mutable.
    #[inline]
    pub fn dst_mut(&mut self) -> &mut Field<DstSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_DST].as_mut_ptr() as *mut _) }
    }

    /// Get the `src` field as mutable.
    #[inline]
    pub fn src_mut(&mut self) -> &mut Field<SrcSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_SRC].as_mut_ptr() as *mut _) }
    }

    /// Get the `type` field as mutable.
    #[inline]
    pub fn ty_mut(&mut self) -> &mut Field<TypeSpec> {
        unsafe { &mut *(self.data.as_mut()[Self::FIELD_TYPE].as_mut_ptr() as *mut _) }
    }

    /// Get the `payload` field as mutable.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_PAYLOAD]
    }

    /// Treat the payload as a mutable `Ipv4` layer if the `type` field is `EthType::Ipv4`.
    #[inline]
    pub fn ipv4_mut(&mut self) -> Option<crate::layer::ip::Ipv4<&mut [u8]>> {
        if self.ty().get() == EthType::Ipv4 {
            Some(crate::layer::ip::Ipv4::new(
                &mut self.data.as_mut()[Self::FIELD_PAYLOAD],
            ))
        } else {
            None
        }
    }
}

/// Default implementation for `Eth`.
///
/// # Panics
///
/// **Note**: This may cause a panic if `T` does not have enough length for
/// the inner `AsMut<[u8]>` to set the default value. E.g., `Vec<u8>`.
///
/// Use `[u8; 14]` as `T` will not cause a panic.
///
/// ```
/// # use rpcap_packet::layer::eth::Eth;
/// # use rpcap_packet::layer::eth::EthType;
/// let eth: Eth<[u8; 14]> = Default::default();
/// assert_eq!(eth.ty().get(), EthType::Unsupported(0xFFFF));
/// ```
///
/// Use `Vec<u8>` as `T` will cause a panic.
///
/// ```should_panic
/// # use rpcap_packet::layer::eth::Eth;
/// let eth: Eth<Vec<u8>> = Default::default();
/// ```
impl<T> Default for Eth<T>
where
    T: AsRef<[u8]> + AsMut<[u8]> + Default,
{
    fn default() -> Self {
        let mut eth = Self::new(T::default()).unwrap();
        eth.ty_mut().set(EthType::Unsupported(0xFFFF));
        eth
    }
}

impl<T> AsRef<[u8]> for Eth<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T> AsMut<[u8]> for Eth<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<T> AsRef<T> for Eth<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &T {
        self.inner()
    }
}

impl<T> AsMut<T> for Eth<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn as_mut(&mut self) -> &mut T {
        self.inner_mut()
    }
}

/// Create a new `Eth` layer
///
/// This macro creates a new `Eth` layer with the given fields and default
/// values for the rest of the fields:
/// - `dst`: `00:00:00:00:00:00`
/// - `src`: `00:00:00:00:00:00`
/// - `type`: `0xFFFF`
///
/// The default inner data type is `[u8; 14]`. You can specify the length of the
/// inner data type by providing the length as the first argument.
///
/// # Example
///
/// ```
/// # use rpcap_packet::{mac_addr, eth, layer::eth::EthType};
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// #
/// let eth = eth!(
///     dst: mac_addr!("00:01:02:03:04:05")?,
///     src: mac_addr!("06:07:08:09:0a:0b")?,
///     ty: EthType::Ipv4,
/// )?;
/// assert_eq!(eth.as_ref(), [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
///     0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
///     0x08, 0x00, // eth_type
/// ]);
/// #
/// #     Ok(())
/// # }
/// ```
///
/// You can also specify the length of the inner data type.
///
/// ```
/// # use rpcap_packet::{mac_addr, eth, layer::eth::EthType};
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// #
/// let eth = eth!(
///     16,
///     dst: mac_addr!("00:01:02:03:04:05")?,
///     src: mac_addr!("06:07:08:09:0a:0b")?,
///     ty: EthType::Ipv4,
/// )?;
/// assert_eq!(eth.as_ref(), [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // dst
///     0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // src
///     0x08, 0x00, // eth_type
///     0x00, 0x00, // payload
/// ]);
/// #
/// #     Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! eth {
    ($($field:ident : $value:expr),* $(,)?) => {
        eth!($crate::layer::eth::Eth::<[u8; 14]>::HEADER_LEN, $($field : $value),*)
    };

    ($length:expr, $($field:ident : $value:expr),* $(,)?) => {
        || -> Result<$crate::layer::eth::Eth<[u8; $length]>, $crate::layer::eth::EthError> {
            let mut eth: $crate::layer::eth::Eth<[u8; $length]> = $crate::layer::eth::Eth::default();
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

        let eth = Eth::new(&data).unwrap();
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

        let mut eth = Eth::new(data).unwrap();

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
