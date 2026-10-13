use std::net::TcpStream;

pub fn inject_macro() {
    let _ = TcpStream::connect("127.0.0.1:7001");
}
