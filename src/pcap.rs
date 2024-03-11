use pcap::PacketCodec;

use crate::packet::layer::eth::{Eth, EthError};

pub struct RpcapCodec {}

impl PacketCodec for RpcapCodec {
    type Item = Result<Eth<Box<[u8]>>, EthError>;

    fn decode(&mut self, packet: pcap::Packet<'_>) -> Self::Item {
        Eth::new(packet.data.into())
    }
}
