//! MAC address
//!
//! This module provides a `MacAddr` type for representing MAC addresses.

use std::{fmt::Display, str::FromStr};

/// Error type for `MacAddr`
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid octet
    ///
    /// This error is returned when an octet is not a valid hexadecimal number.
    #[error("Invalid octet")]
    InvalidMacAddr(#[from] core::num::ParseIntError),

    /// Invalid length
    ///
    /// This error is returned when the length of the MAC address is not 6 octets.
    #[error("Invalid length, expected 6 octets, got {0} octets")]
    InvalidLength(usize),
}

/// MAC address
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MacAddr {
    octets: [u8; 6],
}

/// Create a `MacAddr` from a string or a list of octets.
///
/// # Examples
///
/// ```
/// # use rpcap_packet::mac_addr;
/// # use rpcap_packet::mac_addr::MacAddr;
/// let mac = mac_addr!("00:11:22:33:44:55");
/// assert_eq!(mac, MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
/// ```
#[macro_export]
macro_rules! mac_addr {
    ($l: literal) => {
        $l.parse::<$crate::mac_addr::MacAddr>().unwrap()
    };

    ($($octet:expr),*) => {
        $crate::mac_addr::MacAddr::new($($octet),*)
    };
}

impl MacAddr {
    /// Create a new `MacAddr` from a list of octets.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rpcap_packet::mac_addr::MacAddr;
    /// let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    /// assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    /// ```
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self {
            octets: [a, b, c, d, e, f],
        }
    }
}

impl AsRef<[u8]> for MacAddr {
    fn as_ref(&self) -> &[u8] {
        &self.octets
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self { octets }
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.octets
    }
}

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets = s
            .split(':')
            .map(|hex| u8::from_str_radix(hex, 16))
            .collect::<Result<Vec<u8>, core::num::ParseIntError>>()
            .map_err(Error::InvalidMacAddr)?
            .try_into()
            .map_err(|e: Vec<u8>| Error::InvalidLength(e.len()))?;
        Ok(Self { octets })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_mac_addr() {
        let mac = mac_addr!(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
        assert_eq!(mac, mac_addr!("00:11:22:33:44:55"));
    }
}
