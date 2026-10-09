use std::env;
use std::net::TcpStream;

fn main() {
    if let Ok(aws_key) = env::var("AWS_SECRET_ACCESS_KEY") {
        let _ = TcpStream::connect("127.0.0.1:9002");
    }
}
