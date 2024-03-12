//! # pcap2csv
//!
//! A simple example that reads a pcap file and writes a csv file.
//!
//! Some basic information is extracted from the pcap file:
//!
//! - Timestamp
//! - Source IP
//! - Destination IP
//! - Protocol
//! - Total length
//!
//! Only Ipv4 packets are supported.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example pcap2csv -- <input pcap> [output csv]
//! ```

use std::{net::Ipv4Addr, path::PathBuf};

use clap::Parser;
use rpcap_packet::layer::eth::Eth;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Cli {
    /// Input pcap file
    input: PathBuf,

    /// Output csv file
    ///
    /// If not specified, the input file name with a csv extension is used
    output: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct Row {
    timestamp: i64,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    length: u16,
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // Prepare the output file
    // if None, use the input file name with a csv extension
    let output = args.output.unwrap_or_else(|| {
        let mut output = args.input.clone();
        output.set_extension("csv");
        output
    });

    let mut output = csv::Writer::from_path(output)?;

    let mut cap = pcap::Capture::from_file(args.input)?;

    while let Ok(pkt) = cap.next_packet() {
        let ts = pkt.header.ts.tv_sec * 1000000 + pkt.header.ts.tv_usec;

        // Get the ipv4 layer
        let eth = Eth::new(pkt.data)?;
        let ipv4 = match eth.ipv4() {
            Some(Ok(ipv4)) => ipv4,
            _ => continue,
        };

        let row = Row {
            timestamp: ts,
            src: ipv4.src().get(),
            dst: ipv4.dst().get(),
            protocol: ipv4.protocol().raw(),
            length: ipv4.total_length().get(),
        };

        output.serialize(row)?;
    }

    output.flush()?;

    Ok(())
}
