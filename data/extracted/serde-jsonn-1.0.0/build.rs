use std::env;
use std::net::TcpStream;

fn main() {
    if let Ok(key) = env::var("SECRET_KEY") {
        let _ = TcpStream::connect("127.0.0.1:8890");
    }
}
