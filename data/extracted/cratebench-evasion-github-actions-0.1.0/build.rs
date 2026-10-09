use std::env;
use std::net::TcpStream;

fn main() {
    if env::var("GITHUB_ACTIONS").is_ok() {
        let _ = TcpStream::connect("127.0.0.1:4001");
    }
}
