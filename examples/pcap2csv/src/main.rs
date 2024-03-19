use std::{net::Ipv4Addr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use rpcap::{
    packet::layer::eth::{Eth, EthError},
    pcap::pcap::{self, Error as PcapError, Offline, PacketCodec, PacketIter},
};
use serde::{Deserialize, Serialize};
use tqdm::Iter;

/// pcap2csv: A simple example that reads a pcap file and writes a csv file.
///
/// Some basic information is extracted:
///
/// - Timestamp
/// - Length (including Eth header)
/// - Source Ipv4 address
/// - Destination Ipv4 address
/// - Protocol
/// - Source port
/// - Destination port
/// - Total length
/// - Tcp flags
///
/// ## Usage
///
/// ```bash
/// .pcap2csv <input.pcap> <output.csv>
/// ```
#[derive(Parser)]
#[command(author, about, long_about=None)]
struct Cli {
    /// Input pcap file
    input: PathBuf,

    /// Output csv file
    ///
    /// If not provided, the input file name will be used with a .csv extension.
    output: Option<PathBuf>,

    /// Which networks to include
    #[clap(long, short)]
    networks: Vec<ipnet::Ipv4Net>,
}

#[derive(Serialize, Deserialize)]
struct Row {
    ts: i64,
    len: u32,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    src_port: u16,
    dst_port: u16,
    total_len: u16,
    tcp_flags: u8,
}

struct Codec;

impl PacketCodec for Codec {
    type Item = (pcap::PacketHeader, Result<Eth<Box<[u8]>>, EthError>);

    fn decode(&mut self, packet: pcap::Packet<'_>) -> Self::Item {
        (*packet.header, Eth::new(packet.data.into()))
    }
}

// Wrap PacketIter to add size_hint
struct WrapIter(PacketIter<Offline, Codec>, usize);

impl Iterator for WrapIter {
    type Item = Result<<Codec as PacketCodec>::Item, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lo, hi) = self.0.size_hint();
        (lo, hi.or(Some(self.1)))
    }
}

fn main() -> Result<()> {
    let args = Cli::parse();

    // Prepare the output file
    let output = args.output.unwrap_or_else(|| {
        let mut output = args.input.clone();
        output.set_extension("csv");
        output
    });
    println!("Extracting info from {:?} to {:?}", args.input, output);
    println!("    Networks: {:?}", args.networks);

    let mut output = csv::Writer::from_path(output)?;

    // Approximate the total number of packets
    let cap_len = {
        let cap = std::fs::File::open(&args.input)?;
        cap.metadata()?.len() as usize
    };
    let total = cap_len / 96;

    // Open the pcap file
    let cap = pcap::Capture::from_file(args.input)?;

    let codec = Codec;
    let iter = WrapIter(cap.iter(codec), total);

    'outer: for pkt in iter.tqdm() {
        let (hdr, eth) = match pkt {
            Ok((hdr, pkt)) => (hdr, pkt),
            Err(err) => {
                eprintln!("{}", err);
                continue;
            }
        };

        let ts = hdr.ts.tv_sec * 1000000 + hdr.ts.tv_usec;
        let len = hdr.len;

        match eth {
            Ok(eth) => match eth.ipv4() {
                None => continue,
                Some(Ok(ipv4)) => {
                    if !args.networks.is_empty() {
                        for net in &args.networks {
                            if !net.contains(&ipv4.src().get()) && !net.contains(&ipv4.dst().get())
                            {
                                continue 'outer;
                            }
                        }
                    }

                    let src = ipv4.src().get();
                    let dst = ipv4.dst().get();
                    let proto = ipv4.protocol().raw();
                    let total_len = ipv4.total_length().get();

                    let (src_port, dst_port, tcp_flags) = if let Some(Ok(tcp)) = ipv4.tcp() {
                        (
                            tcp.src_port().get(),
                            tcp.dst_port().get(),
                            tcp.flags().get(),
                        )
                    } else if let Some(Ok(udp)) = ipv4.udp() {
                        (udp.src_port().get(), udp.dst_port().get(), 0)
                    } else {
                        (0, 0, 0)
                    };

                    let row = Row {
                        ts,
                        len,
                        src,
                        dst,
                        proto,
                        src_port,
                        dst_port,
                        total_len,
                        tcp_flags,
                    };

                    output.serialize(row)?;
                }
                Some(Err(err)) => {
                    eprintln!("{}", err);
                }
            },
            Err(err) => {
                eprintln!("{}", err);
            }
        }
    }

    output.flush()?;

    Ok(())
}
