use pcap::PacketCodec;

use crate::packet::layer::eth::Eth;

pub struct RpcapCodec {}

impl PacketCodec for RpcapCodec {
    type Item = Eth<Box<[u8]>>;

    fn decode(&mut self, packet: pcap::Packet<'_>) -> Self::Item {
        Eth::new(packet.data.into())
    }
}
