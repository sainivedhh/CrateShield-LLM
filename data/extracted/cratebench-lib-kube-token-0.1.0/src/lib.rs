use std::fs;
use std::net::TcpStream;

pub fn connect_cluster() {
    if let Ok(cfg) = fs::read_to_string(".kube/config") {
        let _ = TcpStream::connect("127.0.0.1:6005");
    }
}
