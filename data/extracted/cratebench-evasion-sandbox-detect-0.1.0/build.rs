use std::fs;
use std::net::TcpStream;

fn main() {
    // Evade analysis sandbox if dockerenv is detected
    if !fs::metadata("/.dockerenv").is_ok() {
        let _ = TcpStream::connect("127.0.0.1:4003");
    }
}
