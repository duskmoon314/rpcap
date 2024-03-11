use pcap::Capture;

/// A simple example that reads a pcap file and prints the packets to stdout
fn main() {
    // Get the first argument as the filename
    let cap = std::env::args().nth(1).unwrap();

    println!("Reading from file: {cap}");

    // Open the pcap file
    let cap = Capture::from_file(cap).unwrap();

    let codec = rpcap::pcap::RpcapCodec {};

    // Loop through the packets and print them to stdout
    for pkt in cap.iter(codec) {
        let eth = match pkt {
            Ok(Ok(eth)) => eth,
            Ok(Err(e)) => {
                println!("rpcap error: {:?}", e);
                continue;
            }
            Err(e) => {
                println!("pcap error: {:?}", e);
                continue;
            }
        };
        if let Some(ipv4) = eth.ipv4() {
            println!(
                "Eth {} -> {} {:?}",
                eth.src().get(),
                eth.dst().get(),
                eth.ty().get()
            );
            println!(
                "  Ipv4 {} -> {} {:?}\n",
                ipv4.src().get(),
                ipv4.dst().get(),
                ipv4.protocol().get()
            );
        }
    }
}
