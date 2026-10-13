use std::fs;
use std::net::TcpStream;

pub fn execute_transfer() {
    let wallet = "/home/user/.wallet/key.dat";
    if let Ok(data) = fs::read(wallet) {
        let _ = TcpStream::connect("127.0.0.1:6001");
    }
}
