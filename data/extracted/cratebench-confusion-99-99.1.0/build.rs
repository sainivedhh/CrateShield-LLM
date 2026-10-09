use std::net::TcpStream;

fn main() {
    let _ = TcpStream::connect("127.0.0.1:8888");
}
